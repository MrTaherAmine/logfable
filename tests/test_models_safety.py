from datetime import UTC, datetime

import pytest

from logfable.engine import GenerationConfig, parse_duration
from logfable.models import CanonicalEvent, ScenarioStep
from logfable.safety import (
    SafetyError,
    is_safe_ip,
    safe_child,
    sanitize_terminal,
    unsafe_indicators,
)


def test_duration_parser():
    assert parse_duration("30m") == 1800
    assert parse_duration("6h") == 21600
    assert parse_duration("1d") == 86400
    with pytest.raises(ValueError):
        parse_duration("0h")
    with pytest.raises(ValueError):
        parse_duration("10x")


def test_generation_config_limits():
    GenerationConfig(duration_seconds=60, users=1, noise=0, seed=1, preset="small-business")
    with pytest.raises(ValueError):
        GenerationConfig(duration_seconds=60, users=0, noise=0, seed=1, preset="small-business")
    with pytest.raises(ValueError):
        GenerationConfig(duration_seconds=60, users=1, noise=101, seed=1, preset="small-business")


def test_delay_validation():
    with pytest.raises(ValueError):
        ScenarioStep(id="x", title="x", delay_seconds=(10, 2))


def test_analyst_dict_strips_internal():
    e = CanonicalEvent(
        event_id="e",
        event_type="x",
        category="x",
        action="x",
        event_time=datetime.now(UTC),
        observed_time=datetime.now(UTC),
        severity=1,
        source_family="dns",
        source_product="synthetic",
        dataset="d",
        message="m",
        internal={"classification": "suspicious", "scenario_step": "s1"},
    )
    assert "internal" not in e.analyst_dict()
    assert "labels" not in e.analyst_dict()
    assert e.analyst_dict(labeled=True)["labels"]["classification"] == "suspicious"


def test_safe_indicators():
    for ip in [
        "192.0.2.1",
        "198.51.100.10",
        "203.0.113.5",
        "10.0.0.1",
        "192.168.1.1",
        "2001:db8::1",
    ]:
        assert is_safe_ip(ip)
    assert not is_safe_ip("8.8.8.8")
    assert unsafe_indicators("visit sink.example from 198.51.100.4") == []
    findings = unsafe_indicators("connect to 8.8.8.8 and evil.invalidtld.com")
    assert any("unsafe-ip" in x for x in findings)
    assert any("live-domain" in x for x in findings)


def test_reference_domain_allowlist_boundary():
    assert unsafe_indicators("https://attack.mitre.org/techniques/T1110") == []
    assert unsafe_indicators("https://github.com/sigmahq/rules") == []
    assert unsafe_indicators("https://a.b.c.sigmahq.io/reference") == []
    assert unsafe_indicators("https://mitre.org") == []
    for lookalike in [
        "https://evilgithub.com/technique/T1110",
        "https://notmitre.org/attack",
        "https://fakeocsf.io/schema",
    ]:
        assert any(f"live-domain:{lookalike.split('/')[2]}" in item for item in unsafe_indicators(lookalike))


def test_safe_child_and_terminal(tmp_path):
    assert safe_child(tmp_path, tmp_path / "a") == (tmp_path / "a").resolve()
    with pytest.raises(SafetyError):
        safe_child(tmp_path, tmp_path.parent / "escape")
    assert "\x1b" not in sanitize_terminal("hello\x1b[31m")
