// The tamper-evident certificate ledger, a port of tracekit/ledger.py:
//   entry_hash[i] = SHA256(canonical({index, kind, payload, prev_hash}))
//   signature[i]  = HMAC-SHA256(key, entry_hash[i])
// sealed by a Merkle root over the entry hashes and one signed certificate.
import { sha256, sha256Hex, hmacHex, hex, unhex, utf8, canonical } from './crypto.js';
import { Policy, BehaviorGuard } from './ltl.js';

export const GENESIS = '0'.repeat(64);

export function merkleRoot(leafHashes) {
  if (!leafHashes.length) return GENESIS;
  let level = leafHashes.map(unhex);
  while (level.length > 1) {
    if (level.length % 2 === 1) level.push(level[level.length - 1]);
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      const both = new Uint8Array(64);
      both.set(level[i]); both.set(level[i + 1], 32);
      next.push(sha256(both));
    }
    level = next;
  }
  return hex(level[0]);
}

// a minimal CNF certificate that a clause's output is the AND of its included literals
export function cnfReceipt(clauseId, includes, values) {
  const out = values.every((v) => v) ? 1 : 0;
  const dimacs = [`p cnf ${includes.length} ${includes.length}`, ...includes.map((i) => `${i + 1} 0`)].join('\n');
  return { clause_id: clauseId, includes: includes.slice(), values: values.map((v) => (v ? 1 : 0)), output: out, cnf: dimacs };
}

const entryHash = (index, kind, payload, prev) => sha256Hex(utf8(canonical({ index, kind, payload, prev_hash: prev })));
const certBody = (c) => ({ session_id: c.session_id, policy: c.policy, n_entries: c.n_entries, chain_head: c.chain_head, merkle_root: c.merkle_root, behavior_verdict: c.behavior_verdict, content_summary: c.content_summary });

export class CertificateLedger {
  constructor(sessionId, policy, key = null) { this.sessionId = sessionId; this.policy = policy; this.key = key; this.entries = []; this.head = GENESIS; }
  append(kind, payload) {
    const e = { index: this.entries.length, kind, payload, prev_hash: this.head, entry_hash: '', signature: null };
    e.entry_hash = entryHash(e.index, kind, payload, this.head);
    if (this.key) e.signature = hmacHex(this.key, utf8(e.entry_hash));
    this.entries.push(e);
    this.head = e.entry_hash;
    return e;
  }
  appendContent(text, label, margin, fired, literals) {
    const receipts = fired.map(({ id, includes }) => cnfReceipt(id, includes, includes.map((i) => literals[i])));
    return this.append('content', { text_sha256: sha256Hex(utf8(text)), label, margin, receipts });
  }
  appendBehavior(step, events, violatedNow) {
    const ev = {};
    for (const k of Object.keys(events).sort()) ev[k] = events[k] ? 1 : 0;
    return this.append('behavior', { step, events: ev, violated_now: violatedNow.slice().sort() });
  }
  seal(behaviorVerdict, contentSummary) {
    const cert = {
      session_id: this.sessionId, policy: this.policy.toDict(), n_entries: this.entries.length, chain_head: this.head,
      merkle_root: merkleRoot(this.entries.map((e) => e.entry_hash)), behavior_verdict: behaviorVerdict, content_summary: contentSummary, signature: null,
    };
    if (this.key) cert.signature = hmacHex(this.key, utf8(canonical(certBody(cert))));
    return cert;
  }
  toDict() { return { session_id: this.sessionId, policy: this.policy.toDict(), entries: this.entries.map((e) => JSON.parse(JSON.stringify(e))) }; }
}

// independent, model-free re-verification (verify_ledger); pinpoints the first bad entry
export function verifyLedger(ledger, cert, key = null) {
  const info = { chain_ok: true, sig_ok: true, merkle_ok: true, content_ok: true, behavior_ok: true, first_bad_entry: null, notes: [] };
  let prev = GENESIS;
  for (const e of ledger.entries) {
    const recomputed = entryHash(e.index, e.kind, e.payload, prev);
    if (recomputed !== e.entry_hash || e.prev_hash !== prev) {
      info.chain_ok = false; info.first_bad_entry = e.index; info.notes.push(`hash/chain mismatch at entry ${e.index}`);
      break;
    }
    if (key && e.signature !== hmacHex(key, utf8(e.entry_hash))) {
      info.sig_ok = false; info.first_bad_entry = e.index; info.notes.push(`bad signature at entry ${e.index}`);
      break;
    }
    prev = e.entry_hash;
  }
  const root = merkleRoot(ledger.entries.map((e) => e.entry_hash));
  if (root !== cert.merkle_root) { info.merkle_ok = false; info.notes.push('merkle root mismatch'); }
  const last = ledger.entries[ledger.entries.length - 1];
  if (last && last.entry_hash !== cert.chain_head) { info.chain_ok = false; info.notes.push('chain head mismatch'); }
  if (key && cert.signature !== hmacHex(key, utf8(canonical(certBody(cert))))) { info.sig_ok = false; info.notes.push('session certificate signature invalid'); }
  for (const e of ledger.entries) {
    if (e.kind !== 'content') continue;
    for (const r of e.payload.receipts || []) {
      const out = r.values.every((v) => v) ? 1 : 0;
      if (out !== r.output) { info.content_ok = false; info.notes.push(`content receipt replay mismatch at entry ${e.index}`); break; }
    }
  }
  const guard = new BehaviorGuard(Policy.fromDict(cert.policy));
  for (const e of ledger.entries) {
    if (e.kind !== 'behavior') continue;
    const events = {};
    for (const [k, v] of Object.entries(e.payload.events)) events[k] = !!v;
    const sv = guard.stepWith(events);
    const rec = new Set(e.payload.violated_now || []);
    const now = new Set(sv.violatedNow);
    if (rec.size !== now.size || [...now].some((x) => !rec.has(x))) { info.behavior_ok = false; info.notes.push(`behaviour replay mismatch at step ${e.payload.step}`); break; }
  }
  const sessOk = cert.behavior_verdict && 'session_ok' in cert.behavior_verdict ? cert.behavior_verdict.session_ok : guard.sessionOk;
  if (guard.sessionOk !== sessOk) { info.behavior_ok = false; info.notes.push('session behaviour verdict mismatch'); }
  info.ok = info.chain_ok && info.sig_ok && info.merkle_ok && info.content_ok && info.behavior_ok;
  return info;
}
