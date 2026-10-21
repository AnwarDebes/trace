// Monitor semantics (the same cases tracekit's tests rely on) and the five demo sessions.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { BoundedCount, Response, Precedence, Always, BehaviorGuard } from '../ltl.js';
import { Guard } from '../guard.js';
import { ToolCallAdapter, TraceEngine } from '../engine.js';
import { POLICY, ADAPTER, SCENARIOS } from '../scenarios.js';
import { utf8 } from '../crypto.js';

test('bounded count is a sliding window', () => {
  const m = new BoundedCount('e', 2, 3);
  const seq = [1, 1, 0, 1, 1, 0, 0, 1].map((v) => m.update({ e: !!v }));
  assert.deepEqual(seq, [true, true, true, true, true, true, true, true].map((_, i) => [1, 1, 0, 1, 1, 0, 0, 1].slice(Math.max(0, i - 2), i + 1).reduce((a, b) => a + b, 0) <= 2));
});

test('response: same-step answer counts, each trigger needs its own answer, deadline is inclusive', () => {
  const now = new Response('t', 'r', 0);
  assert.equal(now.update({ t: true, r: true }), true);
  const late = new Response('t', 'r', 2);
  assert.deepEqual([{ t: true }, {}, {}, { r: true }].map((e) => late.update(e)), [true, true, false, true]);
  const two = new Response('t', 'r', 3);
  const out = [{ t: true }, { t: true }, { r: true }, {}, {}, {}].map((e) => two.update(e));
  assert.equal(out.includes(false), true);
});

test('precedence latches and always checks every step', () => {
  const p = new Precedence('a', 'b');
  assert.deepEqual([{ b: true }, { a: true }, { b: true }].map((e) => p.update(e)), [false, true, true]);
  assert.equal(p.everViolated, true);
  const al = new Always('s');
  assert.deepEqual([{ s: true }, {}].map((e) => al.update(e)), [true, false]);
});

test('memory does not grow with the session', () => {
  const g = new BehaviorGuard(POLICY());
  const before = g.memoryBytes;
  for (let i = 0; i < 10000; i++) g.stepWith({ within_scope: true, export: i % 97 === 0 });
  assert.equal(g.memoryBytes, before);
  assert.equal(before, 322);
});

test('the five sessions end the way the page says', () => {
  const model = JSON.parse(fs.readFileSync(new URL('../trace-model.json', import.meta.url), 'utf8'));
  const guard = new Guard(model);
  const expect = { exfil: [5, 'count_le(export,2,50)'], inject: ['content'], audit: [3, 'response(sensitive_read->audit_log,3)'], priv: [0, 'precedence(authorize<transfer)'], scope: [0, 'always(within_scope)'] };
  for (const sc of SCENARIOS) {
    const eng = new TraceEngine({ sessionId: sc.id, policy: POLICY(), guard, adapter: new ToolCallAdapter(ADAPTER), key: utf8('k') });
    const blocked = [];
    sc.steps.forEach((st, i) => {
      if (st.text !== undefined) { if (!eng.guardInput(st.text).allow) blocked.push(['content', i]); }
      else { const r = eng.observe(st.call, st.provider); if (!r.allow) blocked.push([r.sv.violatedNow[0], i]); }
    });
    const [want, name] = expect[sc.id];
    if (want === 'content') assert.deepEqual(blocked, [['content', sc.steps.length - 1]], sc.id);
    else {
      assert.equal(blocked.length, 1, sc.id);
      assert.equal(blocked[0][0], name, sc.id);
      assert.equal(eng.behavior.violations[0].step, want, sc.id);
    }
  }
});
