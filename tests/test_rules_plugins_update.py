import json

import pytest

from logfable.constants import ATTACK_VERSION
from logfable.plugins import list_plugins
from logfable.rules import validate_sigma
from logfable.update import (
    ATTACK_URLS,
    UpdateError,
    _attack_collection_version,
    _download,
    cache_root,
    update_attack,
)


def test_plugin_listing_is_metadata_only():
    assert isinstance(list_plugins(), list)


def test_sigma_subset(tmp_path):
    p = tmp_path / "r.yml"
    p.write_text(
        "title: Example\n"
        "id: 00000000-0000-4000-8000-000000000001\n"
        "status: test\n"
        "logsource:\n"
        "  category: authentication\n"
        "detection:\n"
        "  selection:\n"
        "    action: login-failure\n"
        "  condition: selection\n"
    )
    assert validate_sigma(p)["valid"]
    p.write_text("title: bad\n")
    assert not validate_sigma(p)["valid"]


def test_update_cache_path(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    assert cache_root() == tmp_path / "logfable" / "knowledge"


def test_download_size_limit(monkeypatch):
    class H:
        def get(self, k):
            return "999999"

    class R:
        headers = H()

        def geturl(self):
            return "https://example.com/x"

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

        def read(self, n):
            return b"x"

    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: R())
    with pytest.raises(UpdateError):
        _download("https://example.com/x", limit=10)


def test_attack_collection_version_and_pinned_update(monkeypatch, tmp_path):
    payload = {
        "objects": [
            {"type": "x-mitre-collection", "x_mitre_version": ATTACK_VERSION},
            {"type": "attack-pattern", "id": "attack-pattern--example"},
        ]
    }
    assert _attack_collection_version(payload) == ATTACK_VERSION
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    monkeypatch.setattr(
        "logfable.update._download", lambda _url, limit=0: json.dumps(payload).encode()
    )
    result = update_attack()
    assert set(result["files"]) == set(ATTACK_URLS)
    assert all(v["embedded_version"] == ATTACK_VERSION for v in result["files"].values())


def test_attack_update_rejects_wrong_embedded_version(monkeypatch, tmp_path):
    payload = {"objects": [{"type": "x-mitre-collection", "x_mitre_version": "0.0"}]}
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    monkeypatch.setattr(
        "logfable.update._download", lambda _url, limit=0: json.dumps(payload).encode()
    )
    with pytest.raises(UpdateError, match="pinned LogFable release requires"):
        update_attack()


def test_download_rejects_cross_host_redirect(monkeypatch):
    class H:
        def get(self, k):
            return None

    class R:
        headers = H()

        def geturl(self):
            return "https://evil.example/payload"

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

        def read(self, n):
            return b"{}"

    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: R())
    with pytest.raises(UpdateError, match="unpinned host"):
        _download("https://d3fend.mitre.org/version/", limit=100)
