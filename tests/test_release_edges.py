from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from logfable.cli import app
from logfable.dataset import generate_dataset
from logfable.engine import GenerationConfig, generate
from logfable.rules import validate_sigma
from logfable.safety import SafetyError, is_safe_ip, reject_symlink_tree
from logfable.scenarios import builtins, load_scenario
from logfable.update import (
    UpdateError,
    _attack_collection_version,
    _download,
    update_attack,
    update_d3fend,
)
from logfable.validate import validate_dataset

runner = CliRunner()
V11_SCENARIOS = {
    "mfa-fatigue-session-takeover",
    "privileged-credential-unusual-location",
    "helpdesk-recovery-identity-abuse",
    "business-app-data-manipulation",
    "saas-mass-download-sharing",
    "cloud-iam-privilege-escalation-rollback",
    "mobile-device-identity-anomaly",
    "session-artifact-exposure",
    "kubernetes-secret-workload-identity",
    "ci-runner-token-artifact-drift",
    "credential-stuffing-web-identity",
    "removable-media-staging-dlp",
    "dns-tunneling-like-metadata",
    "rdp-vpn-remote-access-compromise",
    "backup-control-plane-tampering",
    "it-ot-vendor-remote-access-misuse",
}


def _small_dataset(tmp_path: Path) -> Path:
    cfg = GenerationConfig(
        duration_seconds=600,
        users=12,
        noise=80,
        seed=2026,
        preset="hybrid-enterprise",
        target_events=40,
    )
    result = generate_dataset(
        load_scenario("password-spray-account-takeover"),
        cfg,
        ["generic-jsonl"],
        tmp_path / "lab",
    )
    return Path(result["dataset"])


def test_v11_realistic_scenarios_are_bundled_and_seeded():
    assert V11_SCENARIOS <= set(builtins())
    for sid in V11_SCENARIOS:
        scenario = load_scenario(sid)
        assert scenario.variables["test_seeds"] == [2026, 2027, 314159]
        assert len(scenario.steps) >= 2
        assert all(step.benign_lookalikes for step in scenario.steps)
        assert all(step.expected_detections for step in scenario.steps)
        assert len(set(scenario.telemetry)) >= 4


def test_optional_saas_branch_is_seed_deterministic_and_can_vary():
    scenario = load_scenario("saas-mass-download-sharing")
    outcomes = []
    for seed in range(1, 20):
        cfg = GenerationConfig(
            duration_seconds=600,
            users=12,
            noise=0,
            seed=seed,
            preset="cloud-native-saas",
        )
        a, *_ = generate(scenario, cfg)
        b, *_ = generate(scenario, cfg)
        a_steps = {e.internal.get("scenario_step") for e in a}
        b_steps = {e.internal.get("scenario_step") for e in b}
        assert a_steps == b_steps
        outcomes.append("followup-access" in a_steps)
    assert any(outcomes) and not all(outcomes)


def test_noise_zero_and_hundred_paths():
    scenario = load_scenario("mfa-fatigue-session-takeover")
    zero, *_ = generate(
        scenario,
        GenerationConfig(
            duration_seconds=300, users=10, noise=0, seed=1, preset="hybrid-enterprise"
        ),
    )
    hundred, *_ = generate(
        scenario,
        GenerationConfig(
            duration_seconds=300, users=10, noise=100, seed=1, preset="hybrid-enterprise"
        ),
    )
    assert all(e.internal.get("classification") == "suspicious" for e in zero)
    # Missing-event impairment may deterministically drop a small fraction of target events.
    assert len(hundred) >= int(scenario.estimated_events * 0.98)
    assert sum(event.internal.get("classification") == "benign" for event in hundred) > len(zero)


def test_download_rejects_non_https_redirect(monkeypatch):
    class Headers:
        def get(self, _key):
            return None

    class Response:
        headers = Headers()

        def geturl(self):
            return "http://raw.githubusercontent.com/redirect"

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def read(self, _n):
            return b"ok"

    monkeypatch.setattr("urllib.request.urlopen", lambda *_a, **_k: Response())
    with pytest.raises(UpdateError, match="non-HTTPS"):
        _download("https://raw.githubusercontent.com/start", limit=10)


def test_download_rejects_actual_body_over_limit(monkeypatch):
    class Headers:
        def get(self, _key):
            return None

    class Response:
        headers = Headers()

        def geturl(self):
            return "https://raw.githubusercontent.com/final"

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def read(self, n):
            return b"x" * n

    monkeypatch.setattr("urllib.request.urlopen", lambda *_a, **_k: Response())
    with pytest.raises(UpdateError, match="size limit"):
        _download("https://raw.githubusercontent.com/start", limit=10)


def test_attack_collection_version_none():
    assert _attack_collection_version({}) is None
    assert _attack_collection_version({"objects": [{"type": "note"}]}) is None


def test_attack_update_invalid_payloads_and_cleanup(monkeypatch, tmp_path):
    from logfable.constants import ATTACK_VERSION

    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    with pytest.raises(UpdateError, match="invalid ATT&CK JSON"):
        monkeypatch.setattr("logfable.update._download", lambda *_a, **_k: b"not-json")
        update_attack()

    with pytest.raises(UpdateError, match="unexpected ATT&CK payload"):
        monkeypatch.setattr(
            "logfable.update._download", lambda *_a, **_k: json.dumps({"no": "objects"}).encode()
        )
        update_attack()

    valid = json.dumps(
        {"objects": [{"type": "x-mitre-collection", "x_mitre_version": ATTACK_VERSION}]}
    ).encode()
    calls = {"n": 0}

    def mixed(_url, limit=0):
        calls["n"] += 1
        return valid if calls["n"] == 1 else b"not-json"

    monkeypatch.setattr("logfable.update._download", mixed)
    with pytest.raises(UpdateError):
        update_attack()
    attack_root = tmp_path / "logfable" / "knowledge" / "attack" / ATTACK_VERSION
    assert not list(attack_root.glob("tmp*"))
    assert not (attack_root / "manifest.json").exists()


def test_d3fend_update_success_and_wrong_version(monkeypatch, tmp_path):
    from logfable.constants import D3FEND_VERSION

    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    monkeypatch.setattr(
        "logfable.update._download", lambda *_a, **_k: f"ontology version {D3FEND_VERSION}".encode()
    )
    result = update_d3fend()
    assert Path(result["path"]).exists()
    assert (Path(result["path"]).parent / "manifest.json").exists()

    monkeypatch.setattr("logfable.update._download", lambda *_a, **_k: b"ontology version 0.0")
    with pytest.raises(UpdateError, match="does not advertise"):
        update_d3fend()


def test_cli_additional_read_and_error_paths(monkeypatch, tmp_path):
    assert (
        runner.invoke(
            app, ["scenarios", "show", "mfa-fatigue-session-takeover", "--json"]
        ).exit_code
        == 0
    )
    assert runner.invoke(app, ["knowledge", "status", "--json"]).exit_code == 0
    assert runner.invoke(app, ["knowledge", "verify", "--json"]).exit_code == 0
    assert runner.invoke(app, ["plugins", "list", "--json"]).exit_code == 0

    bad_kind = runner.invoke(app, ["knowledge", "update", "nope", "--json"])
    assert bad_kind.exit_code == 2

    monkeypatch.setattr(
        "logfable.cli.update_attack", lambda: (_ for _ in ()).throw(UpdateError("offline"))
    )
    failed_update = runner.invoke(app, ["knowledge", "update", "attack", "--json"])
    assert failed_update.exit_code == 2
    assert "Traceback" not in (failed_update.stdout + getattr(failed_update, "stderr", ""))

    out = tmp_path / "lab"
    assert (
        runner.invoke(
            app,
            [
                "generate",
                "password-spray-account-takeover",
                "--target-events",
                "10",
                "--output",
                str(out),
                "--json",
            ],
        ).exit_code
        == 0
    )
    bad_sink = runner.invoke(app, ["replay", str(out), "--sink", "network"])
    assert bad_sink.exit_code == 2

    existing = tmp_path / "workspace"
    existing.mkdir()
    assert runner.invoke(app, ["init", str(existing)]).exit_code == 2


def test_rules_unsupported_and_parse_failure(tmp_path):
    p = tmp_path / "unsupported.yml"
    p.write_text(
        "title: x\nid: 00000000-0000-4000-8000-000000000001\nstatus: test\nlogsource: {}\n"
        "detection:\n  selection: {action: x}\n  condition: 1 of them\n"
    )
    result = validate_sigma(p)
    assert not result["valid"]
    assert "unsupported-condition-construct" in result["results"][0]["errors"]

    broken = tmp_path / "broken.yml"
    broken.write_text("title: [unterminated")
    result = validate_sigma(broken)
    assert not result["valid"]


def test_reject_symlink_tree_and_invalid_ip(tmp_path):
    assert not is_safe_ip("not-an-ip")
    target = tmp_path / "target"
    target.write_text("x")
    link = tmp_path / "link"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlinks unavailable")
    with pytest.raises(SafetyError, match="symlink"):
        reject_symlink_tree(tmp_path)


def test_validator_deep_error_and_warning_paths(tmp_path):
    root = _small_dataset(tmp_path)
    events = root / "telemetry/canonical/events.jsonl"
    rows = [json.loads(x) for x in events.read_text().splitlines()]
    first = rows[0]
    # Valid JSON but missing ID, leaking labels/internal, a live indicator,
    # and a deliberately old observed time.
    bad = dict(first)
    bad.pop("event_id", None)
    bad["internal"] = {"classification": "suspicious"}
    bad["labels"] = {"classification": "suspicious"}
    bad["source_ip"] = "8.8.8.8"
    bad["message"] = "Synthetic record mentions live-domain.invalidtld.com"
    bad["observed_time"] = "2000-01-01T00:00:00+00:00"
    events.write_text(events.read_text() + "not-json\n" + json.dumps(bad) + "\n")

    # Force mapping parse/ID errors.
    (root / "mappings/attack.json").write_text("not-json")
    (root / "mappings/d3fend.json").write_text(json.dumps([{"d3fend_id": "D3-NOTREAL"}]))
    # Exercise invalid checksum line and missing referenced file.
    (root / "checksums.sha256").write_text("bad-line\n" + "0" * 64 + "  missing.file\n")

    result = validate_dataset(root)
    assert not result["valid"]
    joined = "\n".join(result["errors"])
    for needle in [
        "invalid-jsonl-line",
        "missing-event-id",
        "ground-truth-leak:internal",
        "ground-truth-leak:labels",
        "unsafe-ip:8.8.8.8",
        "live-domain:live-domain.invalidtld.com",
        "manifest-event-count-mismatch",
        "invalid-attack-mapping",
        "invalid-d3fend-id:D3-NOTREAL",
        "invalid-checksum-line",
        "checksum-missing-file:missing.file",
    ]:
        assert needle in joined
    assert "out-of-order-observed-time" in result["warnings"]


def test_validator_missing_required_and_invalid_manifest(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    result = validate_dataset(empty)
    assert not result["valid"]
    assert any(x.startswith("missing:") for x in result["errors"])

    root = _small_dataset(tmp_path / "second")
    (root / "manifest.json").write_text("not-json")
    result = validate_dataset(root)
    assert any(x.startswith("invalid-manifest:") for x in result["errors"])
