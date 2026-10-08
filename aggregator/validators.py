from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any


class CoreValidationError(RuntimeError):
    """Raised when a configured client rejects generated configuration."""


def _run(command: list[str], timeout: float) -> dict[str, object]:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CoreValidationError(type(exc).__name__) from exc
    if result.returncode != 0:
        raise CoreValidationError("client_rejected_config")
    return {"status": "passed", "exit_code": 0}


def _version(command: list[str], timeout: float) -> str:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CoreValidationError(type(exc).__name__) from exc
    if result.returncode != 0:
        raise CoreValidationError("client_version_failed")
    return (result.stdout or result.stderr).splitlines()[0][:200]


def validate_generated_artifacts(
    root: Path,
    *,
    mihomo_path: str | None = None,
    sing_box_path: str | None = None,
    timeout: float = 30.0,
    require: bool = False,
) -> dict[str, Any]:
    """Run real client syntax checks without logging their output."""
    result: dict[str, Any] = {"status": "not_tested", "clients": {}}
    clash_config = root / "clash" / "config.yaml"
    sing_box_config = root / "sing-box" / "config.json"
    selected_mihomo = mihomo_path
    selected_sing_box = sing_box_path
    if selected_mihomo:
        mihomo_version = _version([selected_mihomo, "-v"], timeout)
        result["clients"]["mihomo"] = _run(
            [selected_mihomo, "-t", "-f", str(clash_config), "-d", str(root / "clash")],
            timeout,
        )
        result["clients"]["mihomo"]["version"] = mihomo_version
    elif require:
        raise CoreValidationError("mihomo_path_missing")
    else:
        result["clients"]["mihomo"] = {"status": "not_available"}
    if selected_sing_box:
        sing_box_version = _version([selected_sing_box, "version"], timeout)
        result["clients"]["sing-box"] = _run(
            [selected_sing_box, "check", "-c", str(sing_box_config)], timeout
        )
        result["clients"]["sing-box"]["version"] = sing_box_version
    elif require and selected_mihomo is None:
        raise CoreValidationError("sing_box_path_missing")
    else:
        result["clients"]["sing-box"] = {"status": "not_available"}
    statuses = [item["status"] for item in result["clients"].values()]
    result["status"] = (
        "passed"
        if "passed" in statuses
        and all(status != "not_available" for status in statuses)
        else "not_tested"
    )
    return result
