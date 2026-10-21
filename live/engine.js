// Tool-call adapters (tracekit/adapters.py) and the TRACE engine (tracekit/engine.py):
// one policy over events, any provider's wire format, a content guard on text,
// and a signed ledger of every decision.
import { BehaviorGuard } from './ltl.js';
import { CertificateLedger } from './ledger.js';

// ---- provider wire formats -> {name, arguments}
const loads = (a) => {
  if (a && typeof a === 'object') return a;
  if (typeof a === 'string') { try { return a.trim() ? JSON.parse(a) : {}; } catch { return { _raw: a }; } }
  return {};
};
export const PARSERS = {
  openai: (call) => { const fn = call.function || call; return { name: fn.name || '', arguments: loads(fn.arguments || {}) }; },
  deepseek: (call) => PARSERS.openai(call),
  anthropic: (call) => ({ name: call.name || '', arguments: loads(call.input || {}) }),
};

export class ToolCallAdapter {
  constructor({ capabilities = {}, scopeAllowlist = [], recipientKeys = ['to', 'recipient', 'url', 'dest', 'address'], internalDomains = ['internal', 'localhost', '127.0.0.1'] } = {}) {
    Object.assign(this, { capabilities, scopeAllowlist, recipientKeys, internalDomains });
  }
  parse(call, provider = 'openai') {
    const p = PARSERS[provider];
    if (!p) throw new Error(`unknown provider '${provider}'`);
    return p(call);
  }
  toEvents(tc) {
    const caps = this.capabilities[tc.name] || [];
    const events = {};
    for (const tag of caps) if (tag !== 'export') events[tag] = true;
    events.within_scope = !this.scopeAllowlist.length || this.scopeAllowlist.includes(tc.name);
    let external = false, hasRecipient = false;
    for (const k of this.recipientKeys) {
      if (!(k in tc.arguments)) continue;
      hasRecipient = true;
      const raw = tc.arguments[k];
      for (const item of Array.isArray(raw) ? raw : [raw]) {
        const s = item === null || item === undefined ? '' : String(item).trim().toLowerCase();
        if (s && !this.internalDomains.some((d) => s.includes(d))) external = true;
      }
    }
    if (external) events.target_external = true;
    if (caps.includes('export') && (external || !hasRecipient)) events.export = true;
    return events;
  }
  stepEvents(call, provider = 'openai') { return this.toEvents(this.parse(call, provider)); }
}

// ---- the engine
export class TraceEngine {
  constructor({ sessionId, policy, guard = null, adapter = null, key = null, mode = 'enforce' }) {
    Object.assign(this, { sessionId, policy, guard, adapter, mode });
    this.behavior = new BehaviorGuard(policy);
    this.ledger = new CertificateLedger(sessionId, policy, key);
    this.contentTotal = 0;
    this.contentFlagged = 0;
  }

  // content channel: the guard's verdict plus a CNF receipt for every unsafe-voting clause that fired
  guardInput(text) {
    const g = this.guard;
    const x = g.features(text);
    const F = g.F;
    const lits = new Uint8Array(2 * F);
    for (let i = 0; i < F; i++) { lits[i] = x[i]; lits[F + i] = 1 - x[i]; }
    const v = g.voteOf(x);
    const fired = v.fired.filter((c) => c.unsafe).map((c) => ({ id: c.id, includes: c.lits.slice().sort((a, b) => a - b) })).sort((a, b) => a.id - b.id);
    const label = v.vote > 0 ? 1 : 0;
    const entry = this.ledger.appendContent(text, label, v.vote, fired, lits);
    this.contentTotal += 1;
    this.contentFlagged += label;
    return { allow: this.mode === 'enforce' ? !label : true, unsafe: !!label, margin: v.vote, fired: v.fired, entry };
  }

  // behaviour channel: one tool call, in any provider's format
  observe(call, provider = 'openai') {
    const tc = this.adapter.parse(call, provider);
    const events = this.adapter.toEvents(tc);
    return { tool: tc, ...this.observeEvents(events) };
  }
  observeEvents(events) {
    const sv = this.behavior.stepWith(events);
    const entry = this.ledger.appendBehavior(sv.step, events, sv.violatedNow);
    const allow = this.mode === 'monitor' ? true : sv.ok && sv.sessionOk;
    return { events, sv, entry, allow };
  }

  contentSummary() { return { n_content_checks: this.contentTotal, n_flagged: this.contentFlagged }; }
  seal() { return this.ledger.seal(this.behavior.verdict(), this.contentSummary()); }
  bundle() { const certificate = this.seal(); return { ledger: this.ledger.toDict(), certificate }; }
}
