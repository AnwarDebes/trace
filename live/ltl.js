// Online, bounded-memory monitors for finite-trace temporal safety policies,
// a line-by-line port of tracekit/ltl.py. Each monitor eats one event dict per
// agent step and keeps state whose size depends only on the policy (a window
// or a deadline), never on how long the session runs. Violations latch.
export class Monitor {
  constructor(name) { this.name = name; this.reset(); }
  reset() { this.everViolated = false; this.ok = true; this.violations = []; this.step = -1; this.resetState(); }
  resetState() {}
  update(events, step = null) {
    this.step = step !== null ? step : this.step + 1;
    const okNow = this._update(events);
    this.ok = okNow;
    if (!okNow) { this.everViolated = true; this.violations.push({ monitor: this.name, step: this.step, detail: this.detail(events) }); }
    return okNow;
  }
  static fromSpec(spec) {
    const C = REGISTRY[spec.kind];
    if (!C) throw new Error(`unknown monitor kind ${spec.kind}`);
    return C.fromSpec(spec);
  }
}
const ev = (events, k) => !!(events && events[k]);

export class Always extends Monitor {
  constructor(pred, name = null) { super(name || `always(${pred})`); this.pred = pred; }
  get spec() { return { kind: 'always', name: this.name, pred: this.pred }; }
  static fromSpec(s) { return new Always(s.pred, s.name); }
  _update(e) { return ev(e, this.pred); }
  detail() { return `predicate '${this.pred}' false`; }
  get memoryBytes() { return 64; }
}

export class Never extends Monitor {
  constructor(event, name = null) { super(name || `never(${event})`); this.event = event; }
  get spec() { return { kind: 'never', name: this.name, event: this.event }; }
  static fromSpec(s) { return new Never(s.event, s.name); }
  _update(e) { return !ev(e, this.event); }
  detail() { return `forbidden event '${this.event}' occurred`; }
  get memoryBytes() { return 64; }
}

// at most maxCount occurrences of event in any sliding window of `window` steps
export class BoundedCount extends Monitor {
  constructor(event, maxCount, window, name = null) {
    super(name || `count_le(${event},${maxCount},${window})`);
    this.event = event; this.maxCount = maxCount | 0; this.window = window | 0;
    this.resetState();
  }
  get spec() { return { kind: 'bounded_count', name: this.name, event: this.event, max_count: this.maxCount, window: this.window }; }
  static fromSpec(s) { return new BoundedCount(s.event, s.max_count, s.window, s.name); }
  resetState() { this.buf = []; this.count = 0; }
  _update(e) {
    const v = ev(e, this.event) ? 1 : 0;
    if (this.window && this.buf.length === this.window) this.count -= this.buf.shift();
    this.buf.push(v);
    this.count += v;
    return this.count <= this.maxCount;
  }
  detail() { return `${this.count} occurrences of '${this.event}' in window ${this.window} (> ${this.maxCount})`; }
  get memoryBytes() { return 64 + (this.window || 0); }
}

// G (trigger -> F<=deadline response), each trigger needs its own response (FIFO)
export class Response extends Monitor {
  constructor(trigger, response, deadline, name = null) {
    super(name || `response(${trigger}->${response},${deadline})`);
    this.trigger = trigger; this.response = response; this.deadline = deadline | 0;
    this.resetState();
  }
  get spec() { return { kind: 'response', name: this.name, trigger: this.trigger, response: this.response, deadline: this.deadline }; }
  static fromSpec(s) { return new Response(s.trigger, s.response, s.deadline, s.name); }
  resetState() { this.pending = []; }
  _update(e) {
    if (ev(e, this.trigger)) this.pending.push(this.deadline);
    if (ev(e, this.response) && this.pending.length) this.pending.shift();
    let expired = false;
    const next = [];
    for (let rem of this.pending) { rem -= 1; if (rem < 0) expired = true; else next.push(rem); }
    this.pending = next;
    return !expired;
  }
  detail() { return `'${this.trigger}' not answered by '${this.response}' within ${this.deadline} steps`; }
  get memoryBytes() { return 64 + 4 * (this.deadline + 1); }
}

// !second W first: second may only happen once first has happened
export class Precedence extends Monitor {
  constructor(first, second, name = null) { super(name || `precedence(${first}<${second})`); this.first = first; this.second = second; this.resetState(); }
  get spec() { return { kind: 'precedence', name: this.name, first: this.first, second: this.second }; }
  static fromSpec(s) { return new Precedence(s.first, s.second, s.name); }
  resetState() { this.seenFirst = false; }
  _update(e) {
    if (ev(e, this.first)) this.seenFirst = true;
    if (ev(e, this.second) && !this.seenFirst) return false;
    return true;
  }
  detail() { return `'${this.second}' occurred before '${this.first}'`; }
  get memoryBytes() { return 64; }
}

const REGISTRY = { always: Always, never: Never, bounded_count: BoundedCount, response: Response, precedence: Precedence };

// policy builders (tracekit/policy.py)
export const always = (pred, name = null) => ({ kind: 'always', name: name || `always(${pred})`, pred });
export const never = (event, name = null) => ({ kind: 'never', name: name || `never(${event})`, event });
export const boundedCount = (event, maxCount, window, name = null) => ({ kind: 'bounded_count', name: name || `count_le(${event},${maxCount},${window})`, event, max_count: maxCount | 0, window: window | 0 });
export const response = (trigger, resp, deadline, name = null) => ({ kind: 'response', name: name || `response(${trigger}->${resp},${deadline})`, trigger, response: resp, deadline: deadline | 0 });
export const precedence = (first, second, name = null) => ({ kind: 'precedence', name: name || `precedence(${first}<${second})`, first, second });

export class Policy {
  constructor(name, constraints = []) { this.name = name; this.constraints = constraints.map((c) => ({ ...c })); }
  compile() { return this.constraints.map((c) => Monitor.fromSpec(c)); }
  toDict() { return { name: this.name, constraints: this.constraints.map((c) => ({ ...c })) }; }
  static fromDict(d) { return new Policy(d.name, d.constraints); }
}

// the behaviour guard (tracekit/behavior_guard.py)
export class BehaviorGuard {
  constructor(policy) { this.policy = policy; this.monitors = policy.compile(); this.step = -1; }
  reset() { this.monitors.forEach((m) => m.reset()); this.step = -1; }
  stepWith(events) {
    this.step += 1;
    const violatedNow = [];
    for (const m of this.monitors) if (!m.update(events, this.step)) violatedNow.push(m.name);
    return { step: this.step, ok: violatedNow.length === 0, violatedNow, sessionOk: this.sessionOk };
  }
  get sessionOk() { return this.monitors.every((m) => !m.everViolated); }
  get violations() { return this.monitors.flatMap((m) => m.violations); }
  get memoryBytes() { return this.monitors.reduce((a, m) => a + m.memoryBytes, 0); }
  verdict() {
    const per = {};
    for (const m of this.monitors) per[m.name] = { ever_violated: m.everViolated };
    return { session_ok: this.sessionOk, n_violations: this.violations.length, violations: this.violations.map((v) => ({ monitor: v.monitor, step: v.step, detail: v.detail })), per_monitor: per };
  }
}
