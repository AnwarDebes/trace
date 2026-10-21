// TRACE live: a simulated agent session judged by the real TRACE pieces,
// ported to the browser (content guard, temporal monitors, signed ledger).
import { Guard } from './guard.js';
import { ToolCallAdapter, TraceEngine } from './engine.js';
import { verifyLedger, merkleRoot } from './ledger.js';
import { utf8 } from './crypto.js';
import { POLICY, ADAPTER, SCENARIOS, MONITOR_INFO, perCall, call } from './scenarios.js';

const FILM = new URLSearchParams(location.search).has('film');
const KEY_TEXT = 'demo-session-key';
const KEY = utf8(KEY_TEXT);
const $ = (s, r = document) => r.querySelector(s);
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const short = (h, n = 10) => `${h.slice(0, n)}…`;
const signed = (v) => (v > 0 ? `+${v}` : v < 0 ? `−${-v}` : '0');
const reduced = !FILM && matchMedia('(prefers-reduced-motion: reduce)').matches;
const HOT = new Set(['export', 'sensitive_read', 'transfer', 'target_external', 'authorize', 'audit_log']);

const el = {
  tabs: $('#tabs'), blurb: $('#blurb'), steps: $('#steps'), empty: $('#empty'), play: $('#play'), step: $('#step'), reset: $('#reset'),
  monitors: $('#monitors'), memory: $('#memory'), verdict: $('#session-verdict'), chain: $('#chain'), seal: $('#seal'), verify: $('#verify'),
  tamper: $('#tamper'), tamperHint: $('#tamper-hint'), cert: $('#cert'), palette: $('#palette'), checkForm: $('#check-form'), checkText: $('#check-text'), toast: $('#toast'),
};

let guard = null;
const S = { sc: 0, eng: null, next: 0, playing: false, timer: 0, halted: false, cert: null, tamper: false, stored: null, edits: new Set(), openEditor: null, ticks: [] };

function newSession() {
  const adapter = new ToolCallAdapter(ADAPTER);
  S.eng = new TraceEngine({ sessionId: `live-${SCENARIOS[S.sc].id}`, policy: POLICY(), guard, adapter, key: KEY, mode: 'enforce' });
  S.next = 0; S.halted = false; S.cert = null; S.stored = null; S.edits = new Set(); S.openEditor = null; S.ticks = [];
  el.steps.innerHTML = '';
  el.empty.hidden = false;
  el.cert.innerHTML = '';
  renderMonitors();
  renderChain();
  renderVerdict();
  syncButtons();
}

// ------------------------------------------------------------------ one step
function runStep(step) {
  const eng = S.eng;
  const li = document.createElement('li');
  li.className = 'st';
  const n = eng.ledger.entries.length;
  if (step.text !== undefined) {
    const r = eng.guardInput(step.text);
    const unsafe = r.fired.filter((c) => c.unsafe);
    const top = unsafe.filter((c) => c.lits.some((k) => k < guard.F)).slice(0, 3).map((c) => {
      const words = c.lits.filter((k) => k < guard.F).map((k) => guard.vocab[k].replace('_', ' '));
      const nots = c.lits.filter((k) => k >= guard.F).length;
      return `<li><b>${words.map(esc).join(' ∧ ')}</b>${nots ? ` ∧ ${nots} absent` : ''} → unsafe</li>`;
    });
    li.classList.toggle('blocked', !r.allow);
    li.innerHTML = `<div class="st-top"><span class="st-n">#${n}</span><span class="prov ${step.who}">${step.who === 'page' ? 'web page' : 'user'}</span><span class="tool">content guard</span></div>
      <p class="txt">“${esc(step.text)}”</p>
      <div class="verdicts"><div class="vd"><b>reads it as</b>${step.who === 'page' ? 'text the agent fetched' : 'a request'}</div>
      <div class="vd trace ${r.allow ? '' : 'no-bg'}"><b>TRACE</b>${r.allow ? '<span class="ok">allowed</span>' : '<span class="no">blocked</span>'} · vote ${signed(r.margin)} · ${unsafe.length} unsafe ${unsafe.length === 1 ? 'rule' : 'rules'}</div></div>
      ${!r.allow && top.length ? `<ul class="rules-mini">${top.join('')}</ul>` : ''}`;
  } else {
    const r = eng.observe(step.call, step.provider);
    const pc = perCall(step, r.events);
    const blockedNow = !r.allow;
    const firstBlock = blockedNow && !S.halted;
    if (blockedNow) S.halted = true;
    li.classList.toggle('blocked', blockedNow);
    const evs = Object.entries(r.events).filter(([k, v]) => v || k === 'within_scope').map(([k, v]) => `<span class="ev ${!v ? 'off' : HOT.has(k) ? 'hot' : ''}">${v ? '' : '¬'}${esc(k)}</span>`).join('');
    const args = JSON.stringify(r.tool.arguments);
    const why = blockedNow ? (r.sv.violatedNow.length ? r.sv.violatedNow.map((m) => (MONITOR_INFO[m] || { title: m }).title.toLowerCase()).join(', ') : 'session already violated') : '';
    li.innerHTML = `<div class="st-top"><span class="st-n">#${n}</span><span class="prov ${step.provider}">${step.provider}</span><span class="tool">${esc(r.tool.name)}</span><span class="args">${esc(args)}</span></div>
      <div class="evs">${evs}</div>
      <div class="verdicts"><div class="vd"><b>per-call filter</b>${pc.allow ? '<span class="ok">allowed</span>' : '<span class="no">blocked</span>'} · ${esc(pc.why)}</div>
      <div class="vd trace ${blockedNow ? 'no-bg' : ''}"><b>TRACE</b>${blockedNow ? `<span class="no">blocked</span> · ${esc(why)}` : '<span class="ok">allowed</span>'}</div></div>
      <details class="raw"><summary>${esc(step.provider)} wire format</summary><pre>${esc(JSON.stringify(step.call, null, 1))}</pre></details>`;
    S.ticks.push(r.sv);
    if (firstBlock) for (const m of r.sv.violatedNow) flashMonitor(m);
  }
  el.empty.hidden = true;
  el.steps.appendChild(li);
  if (!FILM) li.scrollIntoView({ behavior: reduced ? 'auto' : 'smooth', block: 'nearest' });
  S.cert = null; S.stored = null; S.edits = new Set();
  el.cert.innerHTML = '';
  renderMonitors();
  renderChain();
  renderVerdict();
}

function stepOnce() {
  const sc = SCENARIOS[S.sc];
  if (S.next >= sc.steps.length) return false;
  runStep(sc.steps[S.next++]);
  syncButtons();
  return S.next < sc.steps.length;
}
function play() {
  if (S.playing) { pause(); return; }
  if (S.next >= SCENARIOS[S.sc].steps.length) newSession();
  S.playing = true;
  syncButtons();
  const tick = () => {
    if (!S.playing) return;
    const more = stepOnce();
    if (more) S.timer = setTimeout(tick, reduced ? 200 : 1150);
    else { S.playing = false; syncButtons(); onSessionEnd(); }
  };
  tick();
}
function pause() { S.playing = false; clearTimeout(S.timer); syncButtons(); }
let onSessionEnd = () => {};
function syncButtons() {
  const done = S.next >= SCENARIOS[S.sc].steps.length;
  el.play.querySelector('.lbl').textContent = S.playing ? 'Pause' : done && S.next ? 'Replay' : 'Play';
  el.play.querySelector('span').className = S.playing ? 'i-pause' : 'i-play';
  el.play.classList.toggle('primary', !S.playing);
  el.step.disabled = S.playing || done;
  el.seal.disabled = !S.eng || !S.eng.ledger.entries.length;
  el.verify.disabled = el.seal.disabled;
  el.tamper.disabled = el.seal.disabled;
}

// ------------------------------------------------------------------ monitors
function flashMonitor(name) {
  const card = el.monitors.querySelector(`[data-m="${CSS.escape(name)}"]`);
  if (!card) return;
  card.classList.remove('flash');
  void card.offsetWidth;
  card.classList.add('flash');
}
function renderMonitors() {
  const mons = S.eng.behavior.monitors;
  el.memory.textContent = `${S.eng.behavior.memoryBytes} B of state`;
  el.monitors.innerHTML = mons.map((m) => {
    const info = MONITOR_INFO[m.name] || { title: m.name, ltl: m.name, what: '' };
    let viz = '';
    if (m.constructor.name === 'Always' || m.spec.kind === 'always') {
      const cells = S.ticks.map((sv) => `<i class="${sv.violatedNow.includes(m.name) ? 'bad' : ''}"></i>`).join('');
      viz = `<div class="ticks">${cells || '<i class="idle"></i>'}</div>`;
    } else if (m.spec.kind === 'bounded_count') {
      const segs = Math.max(m.maxCount + 1, m.count);
      let h = '';
      for (let i = 0; i < segs; i++) h += `<i class="${i < m.count ? (i >= m.maxCount ? 'over' : 'on') : ''}"></i>`;
      viz = `<div class="meter">${h}<span>${m.count} in window · limit ${m.maxCount}</span></div>`;
    } else if (m.spec.kind === 'response') {
      const late = m.violations.length && !m.ok;
      viz = `<div class="dues">${m.pending.map((r) => `<span class="due">audit due in ${r + 1}</span>`).join('') || (late ? '<span class="due late">deadline missed</span>' : '<span>no open obligations</span>')}</div>`;
    } else if (m.spec.kind === 'precedence') {
      viz = `<div class="latch">${esc(m.first)} seen: <b>${m.seenFirst ? 'yes' : 'not yet'}</b></div>`;
    }
    return `<div class="mon ${m.everViolated ? 'violated' : ''}" data-m="${esc(m.name)}">
      <div class="mon-top"><b>${esc(info.title)}</b><span class="mon-state">${m.everViolated ? 'violated' : 'holds'}</span></div>
      <div class="ltl">${esc(info.ltl)}</div>
      <div class="mon-viz">${viz}</div>
      <div class="mon-mem">${esc(m.name)} · ${m.memoryBytes} B</div></div>`;
  }).join('');
}
function renderVerdict() {
  const b = S.eng.behavior;
  const v = b.violations;
  if (!S.eng.ledger.entries.length) { el.verdict.className = 'verdict'; el.verdict.innerHTML = 'No steps yet.'; return; }
  if (!v.length) {
    const flagged = S.eng.contentFlagged;
    el.verdict.className = flagged ? 'verdict bad' : 'verdict good';
    el.verdict.innerHTML = flagged ? `<b>Content blocked:</b> the agent never read the flagged text. Behaviour so far holds.` : `<b>Session holds.</b> Every rule is satisfied after ${b.step + 1} ${b.step === 0 ? 'step' : 'steps'}.`;
    return;
  }
  const first = v[0];
  const info = MONITOR_INFO[first.monitor] || { title: first.monitor };
  el.verdict.className = 'verdict bad';
  el.verdict.innerHTML = `<b>Violation at step ${first.step}:</b> ${esc(info.title.toLowerCase())}. ${esc(first.detail)}. Enforce mode blocked the call, and the attempt is still in the log.`;
}

// ------------------------------------------------------------------ ledger
const entries = () => (S.stored ? S.stored.entries : S.eng.ledger.entries);
function entryLabel(e) {
  if (e.kind === 'content') return `content <span>· ${e.payload.label ? 'unsafe' : 'safe'} · vote ${signed(e.payload.margin)} · ${e.payload.receipts.length} receipts</span>`;
  const on = Object.entries(e.payload.events).filter(([k, v]) => v && k !== 'within_scope').map(([k]) => k);
  const scope = e.payload.events.within_scope ? '' : ' · out of scope';
  return `behaviour <span>· step ${e.payload.step} · ${on.join(', ') || 'no events'}${scope}${e.payload.violated_now.length ? ' · violation' : ''}</span>`;
}
function renderChain(bad = null) {
  el.chain.innerHTML = entries().map((e, i) => `<li class="ent ${S.tamper ? 'tamperable' : ''} ${S.edits.has(i) ? 'edited' : ''} ${bad === i ? 'bad' : ''} ${bad !== null && i > bad ? 'after-bad' : ''}" data-i="${i}">
      <span class="ix">${i}</span>
      <div class="bd"><div class="k">${entryLabel(e)}</div><div class="h"><b>${short(e.entry_hash, 12)}</b> ← ${short(e.prev_hash, 8)}</div></div>
      ${S.openEditor === i ? editorHTML(e, i) : ''}</li>`).join('');
  el.chain.scrollTop = el.chain.scrollHeight;
}
function editorHTML(e, i) {
  if (e.kind === 'content') return `<div class="editor" data-i="${i}"><label><input type="checkbox" data-f="label" ${e.payload.label ? 'checked' : ''}> label unsafe</label></div>`;
  return `<div class="editor" data-i="${i}">${Object.entries(e.payload.events).map(([k, v]) => `<label><input type="checkbox" data-f="${esc(k)}" ${v ? 'checked' : ''}> ${esc(k)}</label>`).join('')}</div>`;
}
function seal() {
  if (!S.eng.ledger.entries.length) return null;
  S.cert = S.eng.seal();
  S.stored = JSON.parse(JSON.stringify(S.eng.ledger.toDict()));
  S.edits = new Set();
  renderChain();
  showCert();
  return S.cert;
}
function bundleURL(ledger) {
  const blob = new Blob([JSON.stringify({ ledger, certificate: S.cert }, null, 1)], { type: 'application/json' });
  return URL.createObjectURL(blob);
}
function showCert(result = null) {
  const c = S.cert;
  const sess = c.behavior_verdict.session_ok;
  const rows = [['session', c.session_id], ['entries', String(c.n_entries)], ['chain head', c.chain_head], ['merkle root', c.merkle_root], ['signature', c.signature], ['behaviour', sess ? 'no violation' : `${c.behavior_verdict.n_violations} violation steps`]];
  let checks = '';
  if (result) {
    const items = [['hash chain', result.chain_ok], ['signatures', result.sig_ok], ['Merkle root', result.merkle_ok], ['content receipts', result.content_ok], ['behaviour replay', result.behavior_ok]];
    checks = `<ul class="checks">${items.map(([k, ok]) => `<li class="${ok ? '' : 'x'}">${k}</li>`).join('')}</ul>${result.notes.length ? `<p style="margin:6px 0 0;color:#fecaca">${result.notes.map(esc).join('; ')}</p>` : ''}`;
  }
  const head = result ? (result.ok ? '<h4>Verified: the log is exactly what happened</h4>' : `<h4>Verification failed${result.first_bad_entry !== null ? `, first bad entry #${result.first_bad_entry}` : ''}</h4>`) : '<h4>Sealed certificate</h4>';
  const py = `python -c "import json; from tracekit.ledger import verify_ledger, SessionCertificate as C; b=json.load(open('trace-session.json')); print(verify_ledger(b['ledger'], C(**b['certificate']), key=b'${KEY_TEXT}')[0])"`;
  el.cert.innerHTML = `<div class="cert-box ${result ? (result.ok ? 'ok' : 'bad') : ''}">${head}
    <div class="kv">${rows.map(([k, v]) => `<span>${k}</span><span title="${esc(v)}">${esc(v)}</span>`).join('')}</div>${checks}
    <div class="dl"><a href="${bundleURL(S.stored)}" download="trace-session.json">trace-session.json</a></div>
    <pre class="py">${esc(py)}</pre></div>`;
}
function verify() {
  if (!S.cert) seal();
  if (!S.cert) return null;
  const r = verifyLedger(S.stored, S.cert, KEY);
  renderChain(r.first_bad_entry);
  showCert(r);
  return r;
}
function setTamper(on) {
  S.tamper = !!on;
  el.tamper.setAttribute('aria-pressed', S.tamper);
  el.tamperHint.hidden = !S.tamper;
  if (S.tamper && !S.cert) seal();
  if (!S.tamper) S.openEditor = null;
  renderChain();
}
function tamperField(i, field, value) {
  const e = S.stored.entries[i];
  if (!e) return;
  if (e.kind === 'content' && field === 'label') e.payload.label = value ? 1 : 0;
  else if (field in e.payload.events) e.payload.events[field] = value ? 1 : 0;
  S.edits.add(i);
  renderChain();
}

// ------------------------------------------------------------------ build your own
const OWN = [
  ['search_db', () => call.openai('search_db', { q: 'customers' })],
  ['audit_write', () => call.anthropic('audit_write', { note: 'logged' })],
  ['send_email (team)', () => call.openai('send_email', { to: 'team@internal.acme.example' })],
  ['send_email (outside)', () => call.deepseek('send_email', { to: 'someone@outside.example' })],
  ['grant_role', () => call.anthropic('grant_role', { role: 'payments' })],
  ['wire_transfer', () => call.openai('wire_transfer', { amount: 120, to_account: 'acct-1180' })],
  ['delete_records', () => call.deepseek('delete_records', { table: 'logs' })],
];

// ------------------------------------------------------------------ tour
const tour = { on: false, timers: [], watch: [] };
const later = (ms, fn) => { const t = setTimeout(() => { if (tour.on) fn(); }, ms); tour.timers.push(t); };
function stopTour() { tour.on = false; tour.timers.forEach(clearTimeout); tour.watch.forEach((io) => io.disconnect()); tour.timers = []; tour.watch = []; onSessionEnd = () => {}; }
function whenVisible(node, fn, threshold = 0.5) {
  const io = new IntersectionObserver((ents) => { if (ents.some((e) => e.isIntersecting)) { io.disconnect(); if (tour.on) fn(); } }, { threshold });
  io.observe(node); tour.watch.push(io);
}
function startTour() {
  stopTour();
  tour.on = true;
  selectScenario(0);
  whenVisible($('#session-card'), () => later(400, () => {
    onSessionEnd = () => later(1300, () => {
      seal();
      later(1300, () => {
        verify();
        later(1800, () => {
          setTamper(true);
          // the third outside email: the entry that made the session fail
          const idx = S.stored.entries.findIndex((e) => e.kind === 'behavior' && e.payload.violated_now.length);
          if (idx < 0) return;
          S.openEditor = idx;
          renderChain();
          later(1200, () => { tamperField(idx, 'export', false); later(1000, () => verify()); });
        });
      });
    });
    play();
  }), 0.25);
}

// ------------------------------------------------------------------ wiring
function selectScenario(i) {
  pause();
  S.sc = i;
  [...el.tabs.children].forEach((b, k) => b.setAttribute('aria-selected', k === i));
  el.blurb.textContent = SCENARIOS[i].blurb;
  newSession();
}
let toastT = 0;
function toast(msg) { el.toast.textContent = msg; el.toast.classList.add('on'); clearTimeout(toastT); toastT = setTimeout(() => el.toast.classList.remove('on'), 3000); }

async function boot() {
  const model = await fetch('trace-model.json').then((r) => r.json());
  guard = new Guard(model);
  el.tabs.innerHTML = SCENARIOS.map((s, i) => `<button type="button" class="tab" role="tab" aria-selected="${i === 0}" data-i="${i}"><b>${esc(s.title)}</b><span>${esc(s.short)}</span></button>`).join('');
  el.tabs.addEventListener('click', (e) => { const b = e.target.closest('.tab'); if (b) { stopTour(); selectScenario(+b.dataset.i); } });
  el.play.onclick = () => { stopTour(); play(); };
  el.step.onclick = () => { stopTour(); pause(); stepOnce(); };
  el.reset.onclick = () => { stopTour(); pause(); newSession(); };
  el.seal.onclick = () => { stopTour(); seal(); };
  el.verify.onclick = () => { stopTour(); verify(); };
  el.tamper.onclick = () => { stopTour(); setTamper(!S.tamper); };
  el.chain.addEventListener('click', (e) => {
    if (!S.tamper) return;
    const box = e.target.closest('input[type=checkbox]');
    if (box) { const i = +box.closest('.editor').dataset.i; stopTour(); tamperField(i, box.dataset.f, box.checked); S.openEditor = i; renderChain(); return; }
    const li = e.target.closest('.ent');
    if (li && !e.target.closest('.editor')) { stopTour(); S.openEditor = S.openEditor === +li.dataset.i ? null : +li.dataset.i; renderChain(); }
  });
  el.palette.innerHTML = OWN.map(([label], i) => `<button type="button" data-i="${i}">${esc(label)}</button>`).join('');
  el.palette.addEventListener('click', (e) => { const b = e.target.closest('button'); if (!b) return; stopTour(); pause(); runStep(OWN[+b.dataset.i][1]()); syncButtons(); });
  el.checkForm.addEventListener('submit', (e) => { e.preventDefault(); const t = el.checkText.value.trim(); if (!t) return; stopTour(); pause(); runStep({ text: t, who: 'user' }); el.checkText.value = ''; syncButtons(); });
  $('#start').addEventListener('click', (e) => { e.preventDefault(); $('#console').scrollIntoView({ behavior: reduced ? 'auto' : 'smooth', block: 'start' }); startTour(); });
  selectScenario(0);
  if (FILM) {
    window.__trace = { selectScenario, stepOnce, play, pause, seal, verify, setTamper, tamperField, openEditor: (i) => { S.openEditor = i; renderChain(); }, S, merkleRoot };
    window.__demo = true;
    return;
  }
  ['click', 'keydown'].forEach((ev) => addEventListener(ev, (e) => { if (e.isTrusted && !(e.target.closest && e.target.closest('#start'))) stopTour(); }, { capture: true, passive: true }));
  if (!reduced) startTour();
}
boot().catch((err) => toast(`Could not start: ${err.message}`));
