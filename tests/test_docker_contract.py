"""Keep every SDK source pin deterministic and in lockstep."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).parents[1]
SHA_PATTERN = re.compile(r"[0-9a-f]{40}")


def _single_sha(path: str, marker: str) -> str:
    matching_lines = [
        line for line in (ROOT / path).read_text(encoding="utf-8").splitlines() if marker in line
    ]
    assert matching_lines, f"{marker!r} is missing from {path}"
    matches = SHA_PATTERN.findall("\n".join(matching_lines))
    assert len(set(matches)) == 1, f"expected one exact SHA for {marker!r} in {path}"
    return matches[0]


def test_sdk_dependency_docker_and_compose_pins_match() -> None:
    python_pin = _single_sha("pyproject.toml", "arvancld/archive/")
    docker_pin = _single_sha("Dockerfile", "ARG ARVANCLD_GIT_REF=")
    compose_pin = _single_sha("compose.yaml", "ARVANCLD_GIT_REF:")

    assert python_pin == docker_pin == compose_pin


def test_docker_clones_verifies_and_checks_totp_capability() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert "https://github.com/faridrasidov/arvancld.git" in dockerfile
    assert 'git -C /build/arvancld rev-parse HEAD)" = "${ARVANCLD_GIT_REF}"' in dockerfile
    assert "hasattr(AsyncAuthService, 'submit_totp')" in dockerfile
    assert "COPY --from=wheel-builder /wheels /wheels" in dockerfile
    assert "ARVANCLD_SDK_REF" in dockerfile
    assert "io.github.faridrasidov.arvancld.revision" in dockerfile
