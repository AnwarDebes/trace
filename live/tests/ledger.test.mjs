// The ledger: canonical JSON identical to Python's, a verifier that accepts honest
// logs, and one that finds every single edited field.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { canonical, sha256Hex, utf8, hmacHex } from '../crypto.js';
import { verifyLedger } from '../ledger.js';
import { Guard } from '../guard.js';
import { ToolCallAdapter, TraceEngine } from '../engine.js';
import { POLICY, ADAPTER, SCENARIOS } from '../scenarios.js';

test('canonical JSON matches json.dumps(sort_keys=True, separators=(",", ":"))', () => {
  const golden = [
    [{ b: 1, a: [1, 2, { z: 'x', y: null }] }, '{"a":[1,2,{"y":null,"z":"x"}],"b":1}', 'f2e7f35d3559cbb7'],
    [{ t: 'Grüße “q” 🙂 \\ " \n\t\x7f' }, '{"t":"Gr\\u00fc\\u00dfe \\u201cq\\u201d \\ud83d\\ude42 \\\\ \\" \\n\\t\\u007f"}', 'e55c2e37b3dc95f1'],
  ];
  for (const [obj, str, h] of golden) {
    assert.equal(canonical(obj), str);
    assert.equal(sha256Hex(utf8(str)).slice(0, 16), h);
  }
});

test('HMAC-SHA256 matches RFC 4231 test case 2', () => {
  assert.equal(hmacHex(utf8('Jefe'), utf8('what do ya want for nothing?')), '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843');
});

function session() {
  const model = JSON.parse(fs.readFileSync(new URL('../trace-model.json', import.meta.url), 'utf8'));
  const key = utf8('demo-session-key');
  const eng = new TraceEngine({ sessionId: 'test', policy: POLICY(), guard: new Guard(model), adapter: new ToolCallAdapter(ADAPTER), key });
  for (const sc of [SCENARIOS[1], SCENARIOS[0]]) for (const st of sc.steps) st.text !== undefined ? eng.guardInput(st.text) : eng.observe(st.call, st.provider);
  return { eng, key };
}

test('an honest ledger verifies, and every edited field is caught at its entry', () => {
  const { eng, key } = session();
  const bundle = eng.bundle();
  assert.equal(verifyLedger(bundle.ledger, bundle.certificate, key).ok, true);
  fs.mkdirSync(new URL('./out/', import.meta.url), { recursive: true });
  fs.writeFileSync(new URL('./out/bundle.json', import.meta.url), JSON.stringify(bundle));
  bundle.ledger.entries.forEach((e, i) => {
    const fields = e.kind === 'behavior' ? Object.keys(e.payload.events) : ['label'];
    for (const f of fields) {
      const t = JSON.parse(JSON.stringify(bundle.ledger));
      const p = t.entries[i].payload;
      if (f === 'label') p.label = 1 - p.label; else p.events[f] = 1 - p.events[f];
      const r = verifyLedger(t, bundle.certificate, key);
      assert.equal(r.ok, false, `entry ${i} ${f}`);
      assert.equal(r.first_bad_entry, i, `entry ${i} ${f}`);
    }
  });
  assert.equal(verifyLedger(bundle.ledger, bundle.certificate, utf8('wrong key')).ok, false);
});
