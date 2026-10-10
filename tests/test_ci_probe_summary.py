from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "update.yml"


def _run_summary(
    tmp_path: Path, health: dict[str, object] | None
) -> tuple[subprocess.CompletedProcess[str], str]:
    health_path = tmp_path / "dist" / "health.json"
    if health is not None:
        health_path.parent.mkdir(parents=True)
        health_path.write_text(json.dumps(health), encoding="utf-8")
    github_env = tmp_path / "github-env"
    environment = os.environ.copy()
    environment["GITHUB_ENV"] = str(github_env)
    result = subprocess.run(
        [sys.executable, "-m", "aggregator.ci_probe_summary", str(health_path)],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    return result, github_env.read_text(encoding="utf-8")


def _env_values(text: str) -> dict[str, str]:
    return dict(line.split("=", 1) for line in text.splitlines() if line)


def test_summary_keeps_only_redacted_multiple_categories(tmp_path: Path) -> None:
    result, env_text = _run_summary(
        tmp_path,
        {
            "verification": {
                "error_categories": {
                    "timeout": 2,
                    "controller_http_error": 1,
                    "unknown": 99,
                    "process_exit": True,
                    "network_error": -1,
                },
                "node": "node.example.invalid",
                "endpoint": "https://endpoint.example.invalid/path",
                "uuid": "11111111-1111-1111-1111-111111111111",
                "password": "secret-value",
            }
        },
    )

    assert result.returncode == 0
    assert result.stdout == ""
    assert result.stderr == ""
    values = _env_values(env_text)
    assert json.loads(values["PROBE_ERROR_CATEGORIES"]) == {
        "controller_http_error": 1,
        "timeout": 2,
    }
    assert values["PROBE_ERROR_TOTAL"] == "3"
    for secret in (
        "node.example.invalid",
        "endpoint.example.invalid",
        "11111111-1111-1111-1111-111111111111",
        "secret-value",
    ):
        assert secret not in env_text


def test_summary_falls_back_to_one_allowed_category(tmp_path: Path) -> None:
    result, env_text = _run_summary(
        tmp_path,
        {"verification": {"error_category": "controller_auth_error"}},
    )

    assert result.returncode == 0
    values = _env_values(env_text)
    assert json.loads(values["PROBE_ERROR_CATEGORIES"]) == {"controller_auth_error": 1}
    assert values["PROBE_ERROR_TOTAL"] == "1"


def test_summary_handles_missing_health_without_changing_failure_reporting(
    tmp_path: Path,
) -> None:
    result, env_text = _run_summary(tmp_path, None)

    assert result.returncode == 0
    values = _env_values(env_text)
    assert values == {"PROBE_ERROR_CATEGORIES": "{}", "PROBE_ERROR_TOTAL": "0"}


def test_workflow_removes_runner_build_and_failure_heredoc() -> None:
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    deploy = workflow["jobs"]["deploy"]
    serialized = json.dumps(deploy)
    assert "Build public artifacts" not in serialized
    assert "aggregator.ci_probe_summary" not in serialized
    assert "python - <<'PY'" not in serialized
