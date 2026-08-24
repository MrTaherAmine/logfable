from pathlib import Path

import pytest
import yaml

from logfable.environment import PRESETS, generate_environment
from logfable.scenarios import (
    ScenarioValidationError,
    builtins,
    load_scenario,
    scaffold,
    semantic_errors,
    validate_path,
)


def test_all_scenarios_validate():
    assert len(builtins()) == 28
    result = validate_path(Path("scenarios"))
    assert result["valid"]
    assert len(result["results"]) == 28


def test_required_ransomware_exists():
    s = load_scenario("ransomware-enterprise")
    assert s.id == "ransomware-enterprise"
    assert len(s.steps) >= 3
    assert any(st.benign_lookalikes for st in s.steps)


def test_environment_presets_materially_differ():
    sizes = {}
    for preset in PRESETS:
        e, r, s = generate_environment(2026, 100, preset)
        sizes[preset] = (len(e), len(r), {x.kind for x in e})
    assert len({v[0] for v in sizes.values()}) >= 4
    assert "controller" in sizes["segmented-it-ot"][2]
    assert "kubernetes-cluster" in sizes["cloud-native-saas"][2]


def test_environment_is_deterministic():
    a = generate_environment(42, 50, "hybrid-enterprise")
    b = generate_environment(42, 50, "hybrid-enterprise")
    assert [x.model_dump() for x in a[0]] == [x.model_dump() for x in b[0]]
    assert [x.model_dump() for x in a[1]] == [x.model_dump() for x in b[1]]


def test_unknown_preset():
    with pytest.raises(ValueError):
        generate_environment(1, 10, "not-real")


def test_semantic_broken_reference_and_cycle():
    s = load_scenario("password-spray-account-takeover").model_copy(deep=True)
    s.steps[1].after = ["missing"]
    assert any("broken-step-reference" in x for x in semantic_errors(s))
    s = load_scenario("password-spray-account-takeover").model_copy(deep=True)
    s.steps[0].after = [s.steps[1].id]
    assert "cycle-detected" in semantic_errors(s)


def test_semantic_invalid_ids_and_source():
    s = load_scenario("password-spray-account-takeover").model_copy(deep=True)
    s.steps[0].attack[0].technique_id = "T999999"
    s.steps[0].d3fend[0].d3fend_id = "D3-NOTREAL"
    s.steps[0].evidence[0].source = "not-a-source"
    errs = semantic_errors(s)
    assert any("invalid-attack-id" in x for x in errs)
    assert any("invalid-d3fend-id" in x for x in errs)
    assert any("unknown-source" in x for x in errs)


def test_live_indicator_rejected(tmp_path):
    p = tmp_path / "bad.yaml"
    data = load_scenario("password-spray-account-takeover").model_dump(mode="json")
    data["summary"] = "Talk to 8.8.8.8 and malicious-real-domain.com"
    p.write_text(yaml.safe_dump(data, sort_keys=False))
    with pytest.raises(ScenarioValidationError):
        load_scenario(p)


def test_scaffold(tmp_path):
    p = scaffold("My Exercise", tmp_path)
    assert p.exists()
    text = p.read_text()
    assert "synthetic_only: true" in text
    with pytest.raises(FileExistsError):
        scaffold("My Exercise", tmp_path)


def test_all_scenarios_three_deterministic_seeds():
    from logfable.engine import GenerationConfig, generate

    seeds = (1, 2026, 424242)
    for sid in builtins():
        scenario = load_scenario(sid)
        for seed in seeds:
            cfg = GenerationConfig(
                duration_seconds=300,
                users=12,
                noise=80,
                seed=seed,
                preset=scenario.environment.get("preset", "small-business"),
                target_events=30,
            )
            a, *_ = generate(scenario, cfg)
            b, *_ = generate(scenario, cfg)
            assert [e.model_dump(mode="json") for e in a] == [e.model_dump(mode="json") for e in b]
