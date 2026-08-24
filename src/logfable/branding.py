from __future__ import annotations

PROJECT_NAME = "LogFable"
TAGLINE = "Generate complete cyber incidents without launching a single attack."
DESCRIPTION = (
    "Local-first scenario-as-code engine for deterministic, causally coherent, "
    "multi-source synthetic cybersecurity telemetry."
)
AUTHOR = "Taher Amine ELHOUARI"
WEBSITE = "https://www.taheramine.org"
GITHUB_HANDLE = "MrTaherAmine"
REPOSITORY_URL = "https://github.com/MrTaherAmine/logfable"
COPYRIGHT = "Copyright © 2026 Taher Amine ELHOUARI"
LICENSE_NAME = "Apache License 2.0"


def metadata(version: str) -> dict[str, str]:
    return {
        "name": PROJECT_NAME,
        "version": version,
        "tagline": TAGLINE,
        "description": DESCRIPTION,
        "author": AUTHOR,
        "website": WEBSITE,
        "github": f"@{GITHUB_HANDLE}",
        "repository": REPOSITORY_URL,
        "copyright": COPYRIGHT,
        "license": LICENSE_NAME,
    }
