import json
import zipfile
from pathlib import Path

import pytest

from logfable.dataset import DatasetError, generate_dataset
from logfable.diffing import diff
from logfable.engine import GenerationConfig
from logfable.scenarios import load_scenario
from logfable.validate import validate_dataset


def make(tmp_path, name="run", seed=2026, student=True, instructor=True):
    cfg = GenerationConfig(
        duration_seconds=1800,
        users=30,
        noise=90,
        seed=seed,
        preset="hybrid-enterprise",
        target_events=100,
    )
    return generate_dataset(
        load_scenario("ransomware-enterprise"),
        cfg,
        ["generic-jsonl", "ecs", "ocsf", "cef"],
        tmp_path / name,
        student_package=student,
        instructor_package=instructor,
    )


def test_dataset_structure_and_validation(tmp_path):
    r = make(tmp_path)
    root = Path(r["dataset"])
    v = validate_dataset(root)
    assert v["valid"], v["errors"]
    for rel in [
        "manifest.json",
        "scenario/resolved-scenario.yaml",
        "environment/entities.json",
        "mappings/attack.json",
        "instructor/ground-truth.json",
        "reports/report.html",
        "checksums.sha256",
    ]:
        assert (root / rel).exists()


def test_student_package_has_no_instructor_clues(tmp_path):
    r = make(tmp_path)
    z = Path(r["student_package"])
    with zipfile.ZipFile(z) as f:
        names = f.namelist()
        assert not any(n.startswith(("instructor/", "mappings/", "scenario/")) for n in names)
        manifest = json.loads(f.read("manifest.json"))
        assert "suspicious_events" not in manifest
        assert "ground_truth_summary" not in manifest
        stream = f.read("telemetry/canonical/events.jsonl").decode()
        assert '"labels"' not in stream
        assert '"internal"' not in stream
        report = f.read("reports/report.html").decode()
        assert "Student-safe" in report
        assert "Ground truth" not in report


def test_instructor_package_contains_ground_truth(tmp_path):
    r = make(tmp_path)
    z = Path(r["instructor_package"])
    with zipfile.ZipFile(z) as f:
        assert "instructor/ground-truth.json" in f.namelist()


def test_same_seed_dataset_diff_identical(tmp_path):
    a = make(tmp_path, "a", student=False, instructor=False)
    b = make(tmp_path, "b", student=False, instructor=False)
    d = diff(Path(a["dataset"]), Path(b["dataset"]))
    assert d["identical"], d


def test_different_seed_diff_explains_seed(tmp_path):
    a = make(tmp_path, "a", seed=1, student=False, instructor=False)
    b = make(tmp_path, "b", seed=2, student=False, instructor=False)
    d = diff(Path(a["dataset"]), Path(b["dataset"]))
    assert not d["identical"]
    assert "seed" in d["expected_change_dimensions"]


def test_validator_catches_corruption(tmp_path):
    r = make(tmp_path, student=False, instructor=False)
    root = Path(r["dataset"])
    p = root / "telemetry/canonical/events.jsonl"
    p.write_text(p.read_text() + p.read_text().splitlines()[0] + "\n")
    v = validate_dataset(root)
    assert not v["valid"]
    assert any("checksum-mismatch" in x or "duplicate-event-id" in x for x in v["errors"])


def test_refuse_overwrite_and_labeled_student(tmp_path):
    r = make(tmp_path, "x", student=False, instructor=False)
    cfg = GenerationConfig(
        duration_seconds=60, users=10, noise=90, seed=1, preset="small-business", target_events=20
    )
    with pytest.raises(FileExistsError):
        generate_dataset(
            load_scenario("ransomware-enterprise"), cfg, ["generic-jsonl"], Path(r["dataset"])
        )
    cfg2 = GenerationConfig(
        duration_seconds=60,
        users=10,
        noise=90,
        seed=1,
        preset="small-business",
        target_events=20,
        labeled=True,
    )
    with pytest.raises(DatasetError):
        generate_dataset(
            load_scenario("ransomware-enterprise"),
            cfg2,
            ["generic-jsonl"],
            tmp_path / "labeled",
            student_package=True,
        )


def test_unknown_format(tmp_path):
    cfg = GenerationConfig(
        duration_seconds=60, users=10, noise=90, seed=1, preset="small-business", target_events=20
    )
    with pytest.raises(DatasetError):
        generate_dataset(
            load_scenario("ransomware-enterprise"), cfg, ["not-real"], tmp_path / "bad"
        )


def test_overwrite_refuses_symlink_and_non_logfable_directory(tmp_path):
    cfg = GenerationConfig(
        duration_seconds=60, users=10, noise=90, seed=1, preset="small-business", target_events=20
    )
    scenario = load_scenario("ransomware-enterprise")
    unrelated = tmp_path / "unrelated"
    unrelated.mkdir()
    (unrelated / "keep.txt").write_text("keep")
    with pytest.raises(DatasetError, match="non-LogFable"):
        generate_dataset(scenario, cfg, ["generic-jsonl"], unrelated, overwrite=True)
    assert (unrelated / "keep.txt").read_text() == "keep"
    target = tmp_path / "target"
    target.mkdir()
    (target / "keep.txt").write_text("keep")
    link = tmp_path / "linked-output"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks unavailable")
    with pytest.raises(DatasetError, match="symlink"):
        generate_dataset(scenario, cfg, ["generic-jsonl"], link, overwrite=True)
    assert (target / "keep.txt").read_text() == "keep"


def test_overwrite_allows_existing_logfable_dataset(tmp_path):
    cfg = GenerationConfig(
        duration_seconds=60, users=10, noise=90, seed=1, preset="small-business", target_events=20
    )
    scenario = load_scenario("ransomware-enterprise")
    root = tmp_path / "lab"
    generate_dataset(scenario, cfg, ["generic-jsonl"], root)
    generate_dataset(scenario, cfg, ["generic-jsonl"], root, overwrite=True)
    assert validate_dataset(root)["valid"]


def test_validator_rejects_checksum_path_traversal(tmp_path):
    from logfable.validate import validate_dataset

    root = tmp_path / "dataset"
    root.mkdir()
    # The validator must reject the path before attempting to read outside root.
    (root / "checksums.sha256").write_text("0" * 64 + "  ../outside.txt\n", encoding="utf-8")
    (tmp_path / "outside.txt").write_text("outside", encoding="utf-8")
    result = validate_dataset(root)
    assert not result["valid"]
    assert "unsafe-dataset-path:../outside.txt" in result["errors"]


def test_validator_rejects_checksum_symlink(tmp_path):
    from logfable.validate import validate_dataset

    root = tmp_path / "dataset"
    root.mkdir()
    target = tmp_path / "outside.txt"
    target.write_text("outside", encoding="utf-8")
    link = root / "linked.txt"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        import pytest

        pytest.skip("symlinks unavailable")
    (root / "checksums.sha256").write_text("0" * 64 + "  linked.txt\n", encoding="utf-8")
    result = validate_dataset(root)
    assert not result["valid"]
    assert "unsafe-dataset-symlink:linked.txt" in result["errors"]
