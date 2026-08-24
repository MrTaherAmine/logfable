import socket
import urllib.request
from pathlib import Path

from logfable.dataset import generate_dataset
from logfable.engine import GenerationConfig
from logfable.scenarios import load_scenario


def test_generation_performs_no_network_access(monkeypatch, tmp_path: Path):
    def blocked(*args, **kwargs):
        raise AssertionError("network access attempted during generation")

    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(urllib.request, "urlopen", blocked)

    scenario = load_scenario("password-spray-account-takeover")
    cfg = GenerationConfig(
        duration_seconds=900,
        users=20,
        noise=90,
        seed=2026,
        preset="small-business",
        target_events=60,
    )
    result = generate_dataset(
        scenario,
        cfg,
        ["generic-jsonl", "ecs"],
        tmp_path / "offline-run",
    )
    assert result["events"] > 0
