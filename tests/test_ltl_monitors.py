import pytest
from tracekit import Always, Never, BoundedCount, Response, Precedence, Monitor


def run(mon, stream):
    for i, ev in enumerate(stream):
        mon.update(ev, step=i)
    return mon


def test_always():
    m = run(Always("ok"), [{"ok": True}, {"ok": True}, {"ok": False}])
    assert m.ever_violated
    m2 = run(Always("ok"), [{"ok": True}] * 5)
    assert not m2.ever_violated


def test_never():
    assert run(Never("bad"), [{}, {"bad": True}]).ever_violated
    assert not run(Never("bad"), [{}, {}]).ever_violated


def test_bounded_count_window_slides():
    # 2 allowed per window of 3; three trues in a row -> violation
    m = run(BoundedCount("e", max_count=2, window=3),
            [{"e": True}, {"e": True}, {"e": True}])
    assert m.ever_violated
    # spaced out so no window of 3 holds >2 -> ok
    m2 = run(BoundedCount("e", max_count=1, window=2),
             [{"e": True}, {"e": False}, {"e": True}, {"e": False}])
    assert not m2.ever_violated


def test_response_deadline():
    # read at 0, no audit within 2 -> violation
    assert run(Response("r", "a", deadline=2),
               [{"r": True}, {}, {}, {}]).ever_violated
    # answered in time -> ok
    assert not run(Response("r", "a", deadline=3),
                   [{"r": True}, {}, {"a": True}, {}]).ever_violated


def test_response_window_is_inclusive_and_exact():
    # G(trigger -> F_{<=d} response): the acceptance window is [i, i+d].
    # deadline=1: a response one step late is in time...
    assert not run(Response("r", "a", deadline=1),
                   [{"r": True}, {"a": True}]).ever_violated
    # ...but two steps late is out of the F_{<=1} window -> violation.
    assert run(Response("r", "a", deadline=1),
               [{"r": True}, {}, {"a": True}]).ever_violated


def test_response_deadline_zero_means_same_step():
    # deadline=0: F_{<=0} requires the response on the trigger step itself.
    assert not run(Response("r", "a", deadline=0),
                   [{"r": True, "a": True}, {}]).ever_violated
    # a one-step-late response cannot satisfy F_{<=0} -> violation.
    assert run(Response("r", "a", deadline=0),
               [{"r": True}, {"a": True}]).ever_violated


def test_precedence_latch():
    assert run(Precedence("auth", "act"), [{"act": True}]).ever_violated
    assert not run(Precedence("auth", "act"),
                   [{"auth": True}, {"act": True}]).ever_violated


def test_monitor_spec_roundtrip():
    for m in (Always("p"), Never("e"), BoundedCount("e", 2, 5),
              Response("t", "r", 3), Precedence("a", "b")):
        spec = m.spec
        clone = Monitor.from_spec(spec)
        assert clone.spec == spec


def test_bounded_memory_is_constant_in_trace_length():
    m = BoundedCount("e", 2, window=10)
    mem0 = m.memory_bytes
    for i in range(10000):
        m.update({"e": i % 2 == 0}, step=i)
    assert m.memory_bytes == mem0   # independent of trajectory length


def test_reset_clears_state():
    m = BoundedCount("e", 1, 3)
    run(m, [{"e": True}, {"e": True}])
    m.reset()
    assert not m.ever_violated and m.ok
