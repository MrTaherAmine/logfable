from __future__ import annotations

import hashlib
import json
import os
import ssl
import tempfile
import urllib.request
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlparse

from .constants import ATTACK_VERSION, D3FEND_VERSION

# ATT&CK's unversioned STIX bundles track the current release. LogFable still
# pins the release by verifying each x-mitre-collection version before commit.
ATTACK_URLS = {
    "enterprise": (
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
        "master/enterprise-attack/enterprise-attack.json"
    ),
    "ics": (
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
        "master/ics-attack/ics-attack.json"
    ),
    "mobile": (
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
        "master/mobile-attack/mobile-attack.json"
    ),
}
D3FEND_VERSION_URL = "https://d3fend.mitre.org/version/"
ALLOWED_UPDATE_HOSTS = {
    "raw.githubusercontent.com",
    "d3fend.mitre.org",
}


class UpdateError(RuntimeError):
    pass


def cache_root() -> Path:
    base = os.environ.get("XDG_CACHE_HOME")
    root = Path(base) if base else Path.home() / ".cache"
    return root / "logfable" / "knowledge"


def _validated_update_host(url: str) -> str:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme.lower() != "https":
        raise UpdateError("knowledge update requires HTTPS")
    if not host or host not in ALLOWED_UPDATE_HOSTS:
        raise UpdateError("knowledge update refused an unpinned host")
    if parsed.username or parsed.password:
        raise UpdateError("knowledge update URL must not contain credentials")
    return host


def _download(url: str, limit: int = 80 * 1024 * 1024) -> bytes:
    expected_host = _validated_update_host(url)
    request = urllib.request.Request(  # noqa: S310
        url,
        headers={"User-Agent": "LogFable/1.0 knowledge-updater"},
    )
    context = ssl.create_default_context()
    # B310/S310 is reviewed here: scheme + host are pinned before the request,
    # and the final redirect target is validated again before data is accepted.
    with urllib.request.urlopen(  # noqa: S310  # nosec B310
        request,
        timeout=30,
        context=context,
    ) as response:
        final_url = response.geturl()
        final = urlparse(final_url)
        if final.scheme.lower() != "https":
            raise UpdateError("knowledge update refused non-HTTPS redirect")
        if (final.hostname or "").lower() != expected_host:
            raise UpdateError("knowledge update refused redirect to an unpinned host")
        declared = response.headers.get("Content-Length")
        if declared and int(declared) > limit:
            raise UpdateError("knowledge download exceeds configured size limit")
        raw = response.read(limit + 1)
    data = cast(bytes, raw)
    if len(data) > limit:
        raise UpdateError("knowledge download exceeds configured size limit")
    return data


def _attack_collection_version(payload: dict[str, Any]) -> str | None:
    for obj in payload.get("objects", []):
        if isinstance(obj, dict) and obj.get("type") == "x-mitre-collection":
            version = obj.get("x_mitre_version")
            return str(version) if version is not None else None
    return None


def update_attack() -> dict[str, Any]:
    root = cache_root() / "attack" / ATTACK_VERSION
    root.mkdir(parents=True, exist_ok=True)
    result: dict[str, Any] = {"version": ATTACK_VERSION, "files": {}}
    staged: list[tuple[Path, Path]] = []
    try:
        for domain, url in ATTACK_URLS.items():
            data = _download(url)
            try:
                parsed: object = json.loads(data)
            except json.JSONDecodeError as exc:
                raise UpdateError(f"invalid ATT&CK JSON for {domain}") from exc
            if not isinstance(parsed, dict) or not isinstance(parsed.get("objects"), list):
                raise UpdateError(f"unexpected ATT&CK payload for {domain}")
            payload = cast(dict[str, Any], parsed)
            observed = _attack_collection_version(payload)
            if observed != ATTACK_VERSION:
                raise UpdateError(
                    f"ATT&CK {domain} current bundle advertises {observed!r}; "
                    f"pinned LogFable release requires {ATTACK_VERSION}"
                )
            digest = hashlib.sha256(data).hexdigest()
            destination = root / f"{domain}.json"
            with tempfile.NamedTemporaryFile("wb", delete=False, dir=root) as temp_file:
                temp_file.write(data)
                temp_path = Path(temp_file.name)
            staged.append((temp_path, destination))
            result["files"][domain] = {
                "path": str(destination),
                "sha256": digest,
                "objects": len(payload["objects"]),
                "source_url": url,
                "embedded_version": observed,
            }
        for temp_path, destination in staged:
            os.replace(temp_path, destination)
        manifest = root / "manifest.json"
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            delete=False,
            dir=root,
        ) as temp_file:
            json.dump(result, temp_file, indent=2, sort_keys=True)
            temp_file.write("\n")
            manifest_temp = Path(temp_file.name)
        os.replace(manifest_temp, manifest)
        return result
    except Exception:
        for temp_path, _ in staged:
            temp_path.unlink(missing_ok=True)
        raise


def update_d3fend() -> dict[str, Any]:
    # v1.0 verifies the pinned public version endpoint and records provenance.
    # Bundled project mappings remain immutable until a maintainer reviews a refresh.
    data = _download(D3FEND_VERSION_URL, limit=2 * 1024 * 1024)
    text = data.decode("utf-8", errors="replace")
    if D3FEND_VERSION not in text:
        raise UpdateError(f"D3FEND endpoint does not advertise pinned version {D3FEND_VERSION}")
    root = cache_root() / "d3fend" / D3FEND_VERSION
    root.mkdir(parents=True, exist_ok=True)
    destination = root / "version-page.html"
    with tempfile.NamedTemporaryFile("wb", delete=False, dir=root) as temp_file:
        temp_file.write(data)
        temp_path = Path(temp_file.name)
    os.replace(temp_path, destination)
    result: dict[str, Any] = {
        "version": D3FEND_VERSION,
        "path": str(destination),
        "sha256": hashlib.sha256(data).hexdigest(),
        "source_url": D3FEND_VERSION_URL,
    }
    manifest = root / "manifest.json"
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        delete=False,
        dir=root,
    ) as temp_file:
        json.dump(result, temp_file, indent=2, sort_keys=True)
        temp_file.write("\n")
        manifest_temp = Path(temp_file.name)
    os.replace(manifest_temp, manifest)
    return result
