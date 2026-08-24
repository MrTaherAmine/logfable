from __future__ import annotations

import json
import platform
from pathlib import Path
from typing import Annotated, Any, NoReturn

import typer
from rich.console import Console
from rich.table import Table

from . import __version__
from .benchmark import benchmark as run_benchmark
from .benchmark import write_reports as write_benchmark_reports
from .branding import (
    AUTHOR,
    COPYRIGHT,
    DESCRIPTION,
    GITHUB_HANDLE,
    LICENSE_NAME,
    PROJECT_NAME,
    REPOSITORY_URL,
    TAGLINE,
    WEBSITE,
)
from .branding import metadata as branding_metadata
from .dataset import generate_dataset, write_checksums
from .diffing import diff as diff_datasets
from .engine import GenerationConfig, parse_duration
from .knowledge import status as kb_status
from .knowledge import verify as kb_verify
from .models import CanonicalEvent
from .plugins import list_plugins
from .report import generate_report
from .rules import validate_sigma
from .safety import sanitize_terminal
from .scenarios import builtins, load_scenario, scaffold, validate_path
from .update import update_attack, update_d3fend
from .validate import validate_dataset

APP_HELP = f"{TAGLINE}\n\nCreated and maintained by {AUTHOR} · {WEBSITE} · GitHub @{GITHUB_HANDLE}"

app = typer.Typer(
    help=APP_HELP,
    no_args_is_help=True,
    pretty_exceptions_enable=False,
)
scenarios_app = typer.Typer(help="Scenario-as-code operations")
knowledge_app = typer.Typer(help="Pinned ATT&CK and D3FEND knowledge")
mappings_app = typer.Typer(help="Framework mapping reports")
rules_app = typer.Typer(help="Detection-rule helpers")
plugins_app = typer.Typer(help="Plugin discovery")
app.add_typer(scenarios_app, name="scenarios")
app.add_typer(knowledge_app, name="knowledge")
app.add_typer(mappings_app, name="mappings")
app.add_typer(rules_app, name="rules")
app.add_typer(plugins_app, name="plugins")
console = Console(stderr=False)

DEFAULT_WORKSPACE = Path("logfable-workspace")
DEFAULT_SCENARIO_DIR = Path("scenarios")
DEFAULT_OUTPUT_DIR = Path("./lab")


def emit(value: object, as_json: bool = False) -> None:
    if as_json:
        typer.echo(json.dumps(value, indent=2, sort_keys=True, default=str))
    elif isinstance(value, (dict, list)):
        console.print_json(json.dumps(value, default=str))
    else:
        console.print(value)


def _user_error(exc: Exception) -> NoReturn:
    typer.echo(f"Error: {sanitize_terminal(str(exc))}", err=True)
    raise typer.Exit(2) from None


@app.command()
def version(json_output: bool = typer.Option(False, "--json")) -> None:
    if json_output:
        emit({"name": "logfable", "version": __version__}, True)
    else:
        console.print(f"{PROJECT_NAME} {__version__}")


@app.command()
def about(json_output: bool = typer.Option(False, "--json")) -> None:
    """Show project ownership, licensing, and maintainer information."""
    value = branding_metadata(__version__)
    if json_output:
        emit(value, True)
        return
    table = Table(show_header=False, box=None, pad_edge=False)
    table.add_row("Project", f"[bold]{PROJECT_NAME}[/bold] v{__version__}")
    table.add_row("Tagline", TAGLINE)
    table.add_row("About", DESCRIPTION)
    table.add_row("Creator / Maintainer", f"[bold]{AUTHOR}[/bold]")
    table.add_row("Website", WEBSITE)
    table.add_row("GitHub", f"@{GITHUB_HANDLE}")
    table.add_row("Repository", REPOSITORY_URL)
    table.add_row("Copyright", COPYRIGHT)
    table.add_row("License", LICENSE_NAME)
    console.print(table)


@app.command()
def doctor(json_output: bool = typer.Option(False, "--json")) -> None:
    knowledge = kb_verify()
    value: dict[str, Any] = {
        "ok": bool(knowledge.get("valid")),
        "name": PROJECT_NAME,
        "version": __version__,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "network_required_for_generation": False,
        "knowledge": knowledge,
        "maintainer": AUTHOR,
        "website": WEBSITE,
    }
    emit(value, json_output)
    if not value["ok"]:
        raise typer.Exit(2)


@app.command("init")
def init_project(
    path: Annotated[Path, typer.Argument()] = DEFAULT_WORKSPACE,
) -> None:
    if path.exists():
        raise typer.BadParameter(f"path already exists: {path}")
    path.mkdir(parents=True)
    (path / "scenarios").mkdir()
    (path / "output").mkdir()
    (path / "README.md").write_text(
        "# LogFable workspace\n\n"
        f"Created with LogFable {__version__}.\n\n"
        f"{COPYRIGHT}  \n{WEBSITE} · GitHub @{GITHUB_HANDLE}\n",
        encoding="utf-8",
    )
    console.print(sanitize_terminal(f"Created {path}"))


@scenarios_app.command("list")
def scenarios_list(json_output: bool = typer.Option(False, "--json")) -> None:
    rows: list[dict[str, str]] = []
    for scenario_id in sorted(builtins()):
        scenario = load_scenario(scenario_id)
        rows.append(
            {
                "id": scenario.id,
                "title": scenario.title,
                "difficulty": scenario.difficulty,
                "version": scenario.version,
            }
        )
    if json_output:
        emit(rows, True)
        return
    table = Table("ID", "Title", "Difficulty", "Version")
    for row in rows:
        table.add_row(row["id"], row["title"], row["difficulty"], row["version"])
    console.print(table)


@scenarios_app.command("show")
def scenarios_show(
    scenario: str,
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    try:
        loaded = load_scenario(scenario)
    except (FileNotFoundError, ValueError, OSError) as exc:
        _user_error(exc)
    emit(loaded.model_dump(mode="json"), json_output)


@scenarios_app.command("validate")
def scenarios_validate(
    path: Path,
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    result = validate_path(path)
    emit(result, json_output)
    raise typer.Exit(0 if result["valid"] else 2)


@scenarios_app.command("scaffold")
def scenarios_scaffold(
    name: str,
    output: Annotated[Path, typer.Option("--output")] = DEFAULT_SCENARIO_DIR,
) -> None:
    try:
        result = scaffold(name, output)
    except (FileExistsError, ValueError, OSError) as exc:
        _user_error(exc)
    console.print(sanitize_terminal(str(result)))


def generate_cmd(
    scenario: str = typer.Argument(...),
    duration: str | None = typer.Option(None),
    users: int = typer.Option(100),
    noise: int | None = typer.Option(None),
    seed: int = typer.Option(2026),
    formats: str = typer.Option("generic-jsonl,ecs"),
    output: Annotated[Path, typer.Option()] = DEFAULT_OUTPUT_DIR,
    preset: str | None = typer.Option(None),
    target_events: int | None = typer.Option(None),
    student_package: bool = typer.Option(False, "--student-package"),
    instructor_package: bool = typer.Option(False, "--instructor-package"),
    labeled: bool = typer.Option(False, "--labeled"),
    overwrite: bool = typer.Option(False, "--overwrite"),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    try:
        loaded = load_scenario(scenario)
        config = GenerationConfig(
            duration_seconds=parse_duration(duration or loaded.duration),
            users=users,
            noise=noise if noise is not None else int(loaded.noise.get("percentage", 95)),
            seed=seed,
            preset=preset or str(loaded.environment.get("preset", "hybrid-enterprise")),
            target_events=target_events,
            labeled=labeled,
        )
        result = generate_dataset(
            loaded,
            config,
            [item.strip() for item in formats.split(",") if item.strip()],
            output,
            student_package=student_package,
            instructor_package=instructor_package,
            overwrite=overwrite,
        )
    except (FileExistsError, FileNotFoundError, ValueError, OSError) as exc:
        _user_error(exc)
    emit(result, json_output)


app.command("generate")(generate_cmd)


@app.command()
def validate(
    dataset: Path,
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    result = validate_dataset(dataset)
    emit(result, json_output)
    raise typer.Exit(0 if result["valid"] else 2)


@app.command()
def inspect(
    dataset: Path,
    report: bool = typer.Option(False, "--report"),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    result = validate_dataset(dataset)
    manifest_raw = result.get("manifest", {})
    manifest = manifest_raw if isinstance(manifest_raw, dict) else {}
    quality_path = dataset / "reports/quality.json"
    quality_raw: object = (
        json.loads(quality_path.read_text(encoding="utf-8")) if quality_path.exists() else {}
    )
    quality: dict[str, Any] = quality_raw if isinstance(quality_raw, dict) else {}
    if report and result["valid"]:
        scenario = load_scenario(dataset / "scenario/resolved-scenario.yaml")
        events = [
            CanonicalEvent.model_validate_json(line)
            for line in (dataset / "telemetry/canonical/events.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
            if line.strip()
        ]
        generate_report(
            dataset / "reports/report.html",
            scenario,
            events,
            manifest,
            quality,
            student_safe=not (dataset / "instructor").exists(),
        )
        write_checksums(dataset)
        result = validate_dataset(dataset)
        updated = result.get("manifest", manifest)
        manifest = updated if isinstance(updated, dict) else manifest
    value = {
        "dataset": str(dataset),
        "valid": result["valid"],
        "events": result["events"],
        "scenario": manifest.get("scenario_id"),
        "seed": manifest.get("seed"),
        "sources": quality.get("sources"),
        "report": str(dataset / "reports/report.html") if report else None,
    }
    emit(value, json_output)


@app.command()
def diff(
    dataset_a: Path,
    dataset_b: Path,
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    try:
        result = diff_datasets(dataset_a, dataset_b)
    except (FileNotFoundError, ValueError, OSError, json.JSONDecodeError) as exc:
        _user_error(exc)
    emit(result, json_output)


@knowledge_app.command("status")
def knowledge_status(json_output: bool = typer.Option(False, "--json")) -> None:
    emit(kb_status(), json_output)


@knowledge_app.command("verify")
def knowledge_verify(json_output: bool = typer.Option(False, "--json")) -> None:
    result = kb_verify()
    emit(result, json_output)
    raise typer.Exit(0 if result["valid"] else 2)


@knowledge_app.command("update")
def knowledge_update(
    kind: str,
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    if kind not in {"attack", "d3fend"}:
        raise typer.BadParameter("kind must be attack or d3fend")
    try:
        result = update_attack() if kind == "attack" else update_d3fend()
    except Exception as exc:
        raise typer.BadParameter(f"knowledge update failed: {exc}") from exc
    emit(result, json_output)


@mappings_app.command("attack")
def mapping_attack(
    dataset: Path,
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    try:
        result: object = json.loads((dataset / "mappings/attack.json").read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError) as exc:
        _user_error(exc)
    emit(result, json_output)


@mappings_app.command("d3fend")
def mapping_d3fend(
    dataset: Path,
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    try:
        result: object = json.loads((dataset / "mappings/d3fend.json").read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError) as exc:
        _user_error(exc)
    emit(result, json_output)


@rules_app.command("validate")
def rules_validate(
    path: Path,
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    result = validate_sigma(path)
    emit(result, json_output)
    raise typer.Exit(0 if result["valid"] else 2)


@app.command()
def benchmark(
    dataset: Annotated[Path, typer.Option("--dataset")],
    alerts: Annotated[Path, typer.Option("--alerts")],
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    try:
        result = run_benchmark(dataset, alerts)
        result["reports"] = write_benchmark_reports(dataset, result)
    except (FileNotFoundError, ValueError, OSError, json.JSONDecodeError) as exc:
        _user_error(exc)
    emit(result, json_output)


@app.command()
def replay(
    dataset: Path,
    sink: str = typer.Option("stdout", "--sink"),
) -> None:
    if sink != "stdout":
        raise typer.BadParameter(
            "v1.0 supports only the stdout replay sink; it never transmits automatically"
        )
    path = dataset / "telemetry/canonical/events.jsonl"
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (FileNotFoundError, OSError) as exc:
        _user_error(exc)
    for line in lines:
        typer.echo(line)


@plugins_app.command("list")
def plugins_list(json_output: bool = typer.Option(False, "--json")) -> None:
    emit(list_plugins(), json_output)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
