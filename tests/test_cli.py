import json

from typer.testing import CliRunner

from logfable.cli import app

runner = CliRunner()


def test_version_doctor_and_scenarios():
    r = runner.invoke(app, ["version", "--json"])
    assert r.exit_code == 0
    assert json.loads(r.stdout)["version"] == "1.0.0"
    r = runner.invoke(app, ["doctor", "--json"])
    assert r.exit_code == 0
    assert json.loads(r.stdout)["ok"]
    r = runner.invoke(app, ["about", "--json"])
    assert r.exit_code == 0
    assert json.loads(r.stdout)["author"] == "Taher Amine ELHOUARI"
    r = runner.invoke(app, ["scenarios", "list", "--json"])
    assert r.exit_code == 0
    assert len(json.loads(r.stdout)) == 28


def test_cli_generate_validate_inspect_diff(tmp_path):
    out = tmp_path / "lab"
    r = runner.invoke(
        app,
        [
            "generate",
            "ransomware-enterprise",
            "--duration",
            "30m",
            "--users",
            "20",
            "--noise",
            "90",
            "--seed",
            "2026",
            "--formats",
            "generic-jsonl,ecs",
            "--output",
            str(out),
            "--student-package",
            "--instructor-package",
            "--json",
        ],
    )
    assert r.exit_code == 0, r.stdout
    r = runner.invoke(app, ["validate", str(out), "--json"])
    assert r.exit_code == 0
    r = runner.invoke(app, ["inspect", str(out), "--report", "--json"])
    assert r.exit_code == 0
    assert json.loads(r.stdout)["report"]
    r = runner.invoke(app, ["diff", str(out), str(out), "--json"])
    assert r.exit_code == 0
    assert json.loads(r.stdout)["identical"]


def test_cli_mapping_and_rules(tmp_path):
    out = tmp_path / "lab"
    runner.invoke(
        app,
        [
            "generate",
            "password-spray-account-takeover",
            "--target-events",
            "30",
            "--output",
            str(out),
            "--json",
        ],
    )
    assert runner.invoke(app, ["mappings", "attack", str(out), "--json"]).exit_code == 0
    assert runner.invoke(app, ["mappings", "d3fend", str(out), "--json"]).exit_code == 0
    p = tmp_path / "r.yml"
    p.write_text(
        "title: x\n"
        "id: 00000000-0000-4000-8000-000000000001\n"
        "status: test\n"
        "logsource: {}\n"
        "detection: {selection: {action: x}, condition: selection}\n"
    )
    assert runner.invoke(app, ["rules", "validate", str(p), "--json"]).exit_code == 0


def test_cli_scaffold_and_init(tmp_path):
    ws = tmp_path / "ws"
    assert runner.invoke(app, ["init", str(ws)]).exit_code == 0
    sc = tmp_path / "sc"
    assert runner.invoke(app, ["scenarios", "scaffold", "Demo", "--output", str(sc)]).exit_code == 0


def test_cli_replay_stdout(tmp_path):
    out = tmp_path / "lab"
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
    )
    r = runner.invoke(app, ["replay", str(out), "--sink", "stdout"])
    assert r.exit_code == 0
    assert "event_id" in r.stdout


def test_cli_generate_existing_output_is_clean_error(tmp_path):
    out = tmp_path / "lab"
    out.mkdir()
    r = runner.invoke(
        app,
        [
            "generate",
            "ransomware-enterprise",
            "--target-events",
            "20",
            "--output",
            str(out),
        ],
    )
    assert r.exit_code == 2
    combined = r.stdout + getattr(r, "stderr", "")
    assert "Error:" in combined
    assert "Traceback" not in combined


def test_cli_uses_scenario_declared_defaults(tmp_path):
    out = tmp_path / "ot-lab"
    r = runner.invoke(
        app,
        [
            "generate",
            "it-ot-lateral-movement",
            "--target-events",
            "30",
            "--output",
            str(out),
            "--json",
        ],
    )
    assert r.exit_code == 0, r.stdout
    manifest = json.loads((out / "manifest.json").read_text())
    assert manifest["configuration"]["preset"] == "segmented-it-ot"
    assert manifest["configuration"]["duration_seconds"] == 4 * 3600
    assert manifest["configuration"]["noise"] == 95
    entities = json.loads((out / "environment/entities.json").read_text())
    assert any(e["kind"] == "controller" for e in entities)


def test_common_user_errors_do_not_traceback(tmp_path):
    commands = [
        ["scenarios", "show", "not-a-real-scenario"],
        ["mappings", "attack", str(tmp_path / "missing")],
        ["mappings", "d3fend", str(tmp_path / "missing")],
        ["diff", str(tmp_path / "a"), str(tmp_path / "b")],
        ["replay", str(tmp_path / "missing")],
        [
            "benchmark",
            "--dataset",
            str(tmp_path / "missing"),
            "--alerts",
            str(tmp_path / "missing.json"),
        ],
    ]
    for command in commands:
        r = runner.invoke(app, command)
        assert r.exit_code == 2, (command, r.stdout, getattr(r, "stderr", ""))
        combined = r.stdout + getattr(r, "stderr", "")
        assert "Traceback" not in combined
        assert "Error:" in combined or "Invalid value" in combined
