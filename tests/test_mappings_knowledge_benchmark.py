import json
from pathlib import Path

from logfable.benchmark import benchmark
from logfable.dataset import generate_dataset
from logfable.engine import GenerationConfig
from logfable.knowledge import (
    attack_index,
    d3fend_index,
    validate_attack,
    validate_attack_references,
    validate_d3fend,
    verify,
)
from logfable.mappings import build_attack, build_d3fend
from logfable.scenarios import builtins, load_scenario


def test_knowledge_versions_and_ids():
    v = verify()
    assert v["valid"]
    assert attack_index()["version"] == "19.2"
    assert d3fend_index()["version"] == "1.5.0"
    assert validate_attack(["T1110.003"]) == []
    assert validate_d3fend(["D3-NTA"]) == []
    assert validate_attack(["T-NOPE"]) == ["T-NOPE"]
    assert validate_attack(["DET0490"]) == ["DET0490"]
    assert validate_attack_references(["DET0490", "AN1352", "DC0037"]) == []
    assert validate_attack_references(["T1613"]) == ["T1613"]


def test_all_bundled_mapping_ids_resolve():
    attack = []
    refs = []
    d3 = []
    for sid in builtins():
        s = load_scenario(sid)
        attack += [m.technique_id for x in s.steps for m in x.attack]
        refs += [
            r
            for x in s.steps
            for m in x.attack
            for r in (m.detection_strategies + m.analytics + m.data_components)
        ]
        d3 += [m.d3fend_id for x in s.steps for m in x.d3fend if m.d3fend_id != "unmapped"]
    assert validate_attack(attack) == []
    assert validate_attack_references(refs) == []
    assert validate_d3fend(d3) == []


def test_mapping_records_have_provenance():
    s = load_scenario("kubernetes-service-account")
    a = build_attack(s)
    d = build_d3fend(s)
    assert any("DET0490" in r["detection_strategies"] for r in a)
    assert all(r["provenance"] for r in a)
    assert all(r["source_url"].startswith("https://d3fend.mitre.org") for r in d)


def dataset(tmp_path):
    cfg = GenerationConfig(
        duration_seconds=600,
        users=20,
        noise=80,
        seed=2026,
        preset="hybrid-enterprise",
        target_events=60,
    )
    r = generate_dataset(
        load_scenario("password-spray-account-takeover"), cfg, ["generic-jsonl"], tmp_path / "lab"
    )
    return Path(r["dataset"])


def test_perfect_benchmark(tmp_path):
    root = dataset(tmp_path)
    gt = json.loads((root / "instructor/ground-truth.json").read_text())
    alerts = tmp_path / "alerts.json"
    alerts.write_text(
        json.dumps([{"event_id": x["event_id"], "alert_time": x["event_time"]} for x in gt])
    )
    r = benchmark(root, alerts)
    assert r["precision"] == 1 and r["recall"] == 1 and r["f1"] == 1


def test_intentionally_poor_detection_scores_badly(tmp_path):
    root = dataset(tmp_path)
    alerts = tmp_path / "poor.json"
    alerts.write_text(json.dumps([{"event_id": f"not-real-{i}"} for i in range(20)]))
    r = benchmark(root, alerts)
    assert r["true_positives"] == 0
    assert r["false_positives"] == 20
    assert r["f1"] == 0


def test_jsonl_and_csv_alert_import(tmp_path):
    root = dataset(tmp_path)
    gt = json.loads((root / "instructor/ground-truth.json").read_text())
    eid = gt[0]["event_id"]
    jl = tmp_path / "a.jsonl"
    jl.write_text(json.dumps({"event_id": eid}) + "\n")
    assert benchmark(root, jl)["true_positives"] == 1
    csv = tmp_path / "a.csv"
    csv.write_text("event_id\n" + eid + "\n")
    assert benchmark(root, csv)["true_positives"] == 1


def test_richer_benchmark_matching_and_reports(tmp_path):
    from logfable.benchmark import write_reports

    root = dataset(tmp_path)
    gt = json.loads((root / "instructor/ground-truth.json").read_text())
    first = gt[0]
    # Correlation ID matcher should match the step's correlated truth events.
    alerts = tmp_path / "corr.json"
    alerts.write_text(
        json.dumps([{"correlation_id": first["correlation_id"], "alert_time": first["event_time"]}])
    )
    r = benchmark(root, alerts)
    assert r["true_positives"] >= 1
    assert first["step"] in r["scenario_step_coverage"]
    assert first["source_family"] in r["source_coverage"]
    paths = write_reports(root, r)
    assert Path(paths["json"]).exists() and Path(paths["markdown"]).exists()
    assert "universal proof" in Path(paths["markdown"]).read_text()


def test_step_technique_and_entity_window_matching(tmp_path):
    root = dataset(tmp_path)
    gt = json.loads((root / "instructor/ground-truth.json").read_text())
    first = gt[0]
    for alert in [
        {"scenario_step": first["step"]},
        {"technique_id": first["techniques"][0]},
        {
            "user": first["user"],
            "host": first["host"],
            "start_time": first["event_time"],
            "end_time": first["event_time"],
        },
    ]:
        p = tmp_path / (str(len(list(tmp_path.iterdir()))) + ".json")
        p.write_text(json.dumps([alert]))
        assert benchmark(root, p)["true_positives"] >= 1


def test_benign_lookalike_false_positive_metric(tmp_path):
    root = dataset(tmp_path)
    look = json.loads((root / "instructor/benign-lookalikes.json").read_text())
    assert look
    p = tmp_path / "lookalike-alert.json"
    p.write_text(json.dumps([{"event_id": look[0]["event_id"]}]))
    r = benchmark(root, p)
    assert r["false_positives"] == 1
    assert r["benign_lookalikes"]["false_positive_alerts"] == 1
