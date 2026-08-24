import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from logfable.engine import GenerationConfig, generate
from logfable.exporters import ExportError, export
from logfable.models import CanonicalEvent
from logfable.scenarios import load_scenario


def cfg(seed=2026, noise=95, target=200):
    return GenerationConfig(
        duration_seconds=3600,
        users=50,
        noise=noise,
        seed=seed,
        preset="hybrid-enterprise",
        target_events=target,
    )


def test_generation_determinism_and_seed_change():
    scenario = load_scenario("ransomware-enterprise")
    a = generate(scenario, cfg(seed=1))[0]
    b = generate(scenario, cfg(seed=1))[0]
    c = generate(scenario, cfg(seed=2))[0]
    assert [x.model_dump(mode="json") for x in a] == [x.model_dump(mode="json") for x in b]
    assert [x.event_id for x in a] != [x.event_id for x in c]
    assert {x.internal.get("scenario_step") for x in a if x.internal.get("scenario_step")} == {
        x.internal.get("scenario_step") for x in c if x.internal.get("scenario_step")
    }


def test_noise_percentage_is_approximate():
    scenario = load_scenario("password-spray-account-takeover")
    events, *_ = generate(
        scenario,
        GenerationConfig(
            duration_seconds=3600,
            users=50,
            noise=98,
            seed=2026,
            preset="hybrid-enterprise",
        ),
    )
    benign = sum(e.internal.get("classification") == "benign" for e in events)
    assert 0.95 <= benign / len(events) <= 1.0


def test_event_order_by_observed_time():
    events, *_ = generate(load_scenario("ransomware-enterprise"), cfg())
    assert [e.observed_time for e in events] == sorted(e.observed_time for e in events)


def test_all_non_optional_exporters(tmp_path):
    events, *_ = generate(load_scenario("password-spray-account-takeover"), cfg(target=40))
    formats = [
        "canonical-json",
        "generic-jsonl",
        "ndjson",
        "csv",
        "syslog",
        "cef",
        "leef",
        "ecs",
        "ocsf",
        "otel",
        "splunk-hec",
        "elasticsearch-bulk",
    ]
    for fmt in formats:
        result = export(events, fmt, tmp_path / fmt)
        assert result["records"] == len(events)
        assert Path(result["path"]).exists()
    ecs_record = json.loads((tmp_path / "ecs/events.ecs.jsonl").read_text().splitlines()[0])
    ocsf_record = json.loads((tmp_path / "ocsf/events.ocsf.jsonl").read_text().splitlines()[0])
    assert ecs_record["ecs"]["version"] == "9.4.0"
    assert ocsf_record["metadata"]["version"] == "1.8.0"


def test_bad_export_format(tmp_path):
    with pytest.raises(ExportError):
        export([], "bad", tmp_path)


def test_parquet_fails_loudly_without_extra(tmp_path):
    if __import__("importlib").util.find_spec("pyarrow"):
        pytest.skip("pyarrow available")
    with pytest.raises(ExportError):
        export([], "parquet", tmp_path)


def test_flat_exporters_neutralize_formula_and_line_injection(tmp_path):
    event = CanonicalEvent(
        event_id="00000000-0000-4000-8000-000000000001",
        event_type="application",
        category="application",
        action="login\nforged",
        event_time=datetime(2026, 1, 1, tzinfo=UTC),
        observed_time=datetime(2026, 1, 1, tzinfo=UTC),
        severity=3,
        source_family="app-auth",
        source_product="Synthetic app",
        dataset="test",
        user='=HYPERLINK("https://example.com")',
        message="=1+1\nforged-line",
    )
    export([event], "csv", tmp_path / "csv")
    text = (tmp_path / "csv/events.csv").read_text()
    assert "'=HYPERLINK" in text and "'=1+1" in text
    for fmt, rel in [
        ("syslog", "events.syslog"),
        ("cef", "events.cef"),
        ("leef", "events.leef"),
    ]:
        export([event], fmt, tmp_path / fmt)
        lines = (tmp_path / fmt / rel).read_text().splitlines()
        assert len(lines) == 1
        assert "forged-line" in lines[0] or fmt == "leef"
