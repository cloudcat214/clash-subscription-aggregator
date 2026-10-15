from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts" / "update_history.py"
SOURCE_COMMIT = "a" * 40

ENTRY_KEYS = {
    "recorded_at",
    "run_id",
    "run_attempt",
    "event",
    "source_commit",
    "run_url",
    "status",
    "manifest_generated_at",
    "manifest_status",
    "published",
    "parsed",
    "accepted",
    "tested",
    "pool_size_before",
    "pool_size",
    "pool_retested",
    "pool_added",
    "pool_evicted",
    "failure_stage",
    "failure_reason",
}

CLEARED_ENV = (
    "JOB_STATUS",
    "RUN_URL",
    "FAILURE_STAGE",
    "GITHUB_SERVER_URL",
    "GITHUB_REPOSITORY",
    "GITHUB_RUN_ID",
    "GITHUB_RUN_ATTEMPT",
    "GITHUB_EVENT_NAME",
    "GITHUB_SHA",
)


def _run(
    args: list[str],
    cwd: Path,
    env_extra: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    for name in CLEARED_ENV:
        environment.pop(name, None)
    environment.update(env_extra or {})
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=cwd,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )


def _read_history(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_manifest(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_success_run_appends_redacted_manifest_summary(tmp_path: Path) -> None:
    manifest = tmp_path / "dist-auto" / "manifest.json"
    _write_manifest(
        manifest,
        {
            "generated_at": "2026-10-13T06:00:00Z",
            "status": "success",
            "counts": {"published": 500, "parsed": 5890, "accepted": 4950},
            "node_quality": {"tested": 1000},
            "verification": {
                "pool_size_before": 900,
                "pool_size": 850,
                "pool_retested": 900,
                "pool_added": 42,
                "pool_evicted": 92,
            },
        },
    )
    history = tmp_path / "docs" / "history" / "update-history.json"
    result = _run(
        [
            "--history-path",
            str(history),
            "--status",
            "success",
            "--run-id",
            "123456789",
            "--run-attempt",
            "2",
            "--event",
            "schedule",
            "--source-commit",
            SOURCE_COMMIT.upper(),
            "--run-url",
            "https://github.com/cloudcat214/clash-subscription-aggregator/actions/runs/123456789",
            "--manifest",
            str(manifest),
        ],
        cwd=tmp_path,
    )

    assert result.returncode == 0, result.stderr
    document = _read_history(history)
    assert document["schema_version"] == 1
    assert len(document["entries"]) == 1
    entry = document["entries"][0]
    assert set(entry) == ENTRY_KEYS
    assert entry["status"] == "success"
    assert entry["run_id"] == "123456789"
    assert entry["run_attempt"] == 2
    assert entry["event"] == "schedule"
    assert entry["source_commit"] == SOURCE_COMMIT
    assert entry["run_url"].endswith("/actions/runs/123456789")
    assert entry["manifest_generated_at"] == "2026-10-13T06:00:00Z"
    assert entry["manifest_status"] == "success"
    assert entry["published"] == 500
    assert entry["parsed"] == 5890
    assert entry["accepted"] == 4950
    assert entry["tested"] == 1000
    assert entry["pool_size_before"] == 900
    assert entry["pool_size"] == 850
    assert entry["pool_retested"] == 900
    assert entry["pool_added"] == 42
    assert entry["pool_evicted"] == 92
    assert entry["failure_stage"] is None
    assert entry["failure_reason"] is None
    assert datetime.fromisoformat(entry["recorded_at"]).tzinfo is not None


def test_failed_run_without_manifest_still_appends(tmp_path: Path) -> None:
    history = tmp_path / "docs" / "history" / "update-history.json"
    result = _run(
        [
            "--history-path",
            str(history),
            "--status",
            "failure",
            "--run-id",
            "42",
            "--event",
            "schedule",
        ],
        cwd=tmp_path,
    )

    assert result.returncode == 0, result.stderr
    entry = _read_history(history)["entries"][-1]
    assert entry["status"] == "failed"
    assert entry["run_id"] == "42"
    assert entry["manifest_generated_at"] is None
    assert entry["manifest_status"] is None
    assert entry["published"] is None
    assert entry["parsed"] is None
    assert entry["accepted"] is None
    assert entry["tested"] is None
    assert entry["pool_size_before"] is None
    assert entry["pool_size"] is None
    assert entry["pool_retested"] is None
    assert entry["pool_added"] is None
    assert entry["pool_evicted"] is None
    assert entry["failure_stage"] is None
    assert entry["failure_reason"] is None


def test_failure_reason_and_counts_fall_back_to_health(tmp_path: Path) -> None:
    health = tmp_path / "dist-auto" / "health.json"
    health.parent.mkdir(parents=True)
    health.write_text(
        json.dumps(
            {
                "status": "failed",
                "published": 12,
                "failure_reason": "probe_no_candidates",
                "sources": [
                    {"parsed": 3, "accepted": 2},
                    {"parsed": 4, "accepted": 3},
                ],
                "node_quality": {"tested": 9},
                "verification": {
                    "pool_size_before": 10,
                    "pool_size": 8,
                    "pool_retested": 10,
                    "pool_added": 1,
                    "pool_evicted": 3,
                },
            }
        ),
        encoding="utf-8",
    )
    history = tmp_path / "docs" / "history" / "update-history.json"
    result = _run(
        [
            "--history-path",
            str(history),
            "--status",
            "cancelled",
            "--health",
            str(health),
        ],
        cwd=tmp_path,
    )

    assert result.returncode == 0, result.stderr
    entry = _read_history(history)["entries"][-1]
    assert entry["status"] == "cancelled"
    assert entry["failure_reason"] == "probe_no_candidates"
    assert entry["published"] == 12
    assert entry["parsed"] == 7
    assert entry["accepted"] == 5
    assert entry["tested"] == 9
    assert entry["pool_size_before"] == 10
    assert entry["pool_size"] == 8
    assert entry["pool_retested"] == 10
    assert entry["pool_added"] == 1
    assert entry["pool_evicted"] == 3


def test_history_keeps_only_latest_500_entries(tmp_path: Path) -> None:
    history = tmp_path / "docs" / "history" / "update-history.json"
    history.parent.mkdir(parents=True)
    seeded = {
        "schema_version": 1,
        "entries": [{"run_id": str(index)} for index in range(500)],
    }
    history.write_text(json.dumps(seeded), encoding="utf-8")

    result = _run(
        [
            "--history-path",
            str(history),
            "--status",
            "success",
            "--run-id",
            "777",
        ],
        cwd=tmp_path,
    )

    assert result.returncode == 0, result.stderr
    document = _read_history(history)
    assert len(document["entries"]) == 500
    assert document["entries"][0]["run_id"] == "1"
    assert document["entries"][-1]["run_id"] == "777"


def test_duplicate_after_history_exceeds_500_is_checked_after_truncation(
    tmp_path: Path,
) -> None:
    history = tmp_path / "docs" / "history" / "update-history.json"
    history.parent.mkdir(parents=True)
    seeded = {
        "schema_version": 1,
        "entries": [{"run_id": str(index), "run_attempt": 1} for index in range(501)],
    }
    history.write_text(json.dumps(seeded), encoding="utf-8")

    result = _run(
        [
            "--history-path",
            str(history),
            "--status",
            "success",
            "--run-id",
            "500",
            "--run-attempt",
            "1",
        ],
        cwd=tmp_path,
    )

    assert result.returncode == 0, result.stderr
    entries = _read_history(history)["entries"]
    assert len(entries) == 500
    assert entries[0]["run_id"] == "1"
    assert entries[-1]["run_id"] == "500"


def test_existing_entries_are_normalized_to_the_v1_whitelist(tmp_path: Path) -> None:
    history = tmp_path / "docs" / "history" / "update-history.json"
    history.parent.mkdir(parents=True)
    history.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "entries": [
                    {
                        "run_id": "old",
                        "status": "success",
                        "unknown_field": "must be removed",
                        "password": "secret-password",
                        "raw_manifest_body": "sensitive payload",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    result = _run(
        ["--history-path", str(history), "--status", "success", "--run-id", "new"],
        cwd=tmp_path,
    )

    assert result.returncode == 0, result.stderr
    entries = _read_history(history)["entries"]
    assert entries[0] == {"run_id": "old", "status": "success"}
    assert "unknown_field" not in history.read_text(encoding="utf-8")
    assert "password" not in history.read_text(encoding="utf-8")
    assert "sensitive payload" not in history.read_text(encoding="utf-8")


def test_sensitive_fields_and_values_never_enter_history(tmp_path: Path) -> None:
    manifest = tmp_path / "dist-auto" / "manifest.json"
    _write_manifest(
        manifest,
        {
            "generated_at": "2026-10-13T06:00:00Z",
            "status": "success",
            "counts": {"published": 1, "parsed": 2, "accepted": 1},
            "server": "node.example.invalid",
            "port": 8443,
            "uuid": "11111111-1111-1111-1111-111111111111",
            "password": "secret-password",
            "uri": "ss://secret@example.invalid",
            "proxy_name": "hk-01",
            "secret": "top-secret",
            "raw_manifest_body": "MANIFEST-FULL-BODY",
        },
    )
    health = tmp_path / "dist-auto" / "health.json"
    health.write_text(
        json.dumps(
            {
                "failure_reason": "probe_error",
                "sources": [{"id": "x", "url": "https://secret.invalid/a"}],
            }
        ),
        encoding="utf-8",
    )
    history = tmp_path / "docs" / "history" / "update-history.json"
    result = _run(
        [
            "--history-path",
            str(history),
            "--status",
            "success",
            "--manifest",
            str(manifest),
            "--health",
            str(health),
        ],
        cwd=tmp_path,
    )

    assert result.returncode == 0, result.stderr
    text = history.read_text(encoding="utf-8")
    for banned_value in (
        "node.example.invalid",
        "8443",
        "11111111-1111-1111-1111-111111111111",
        "secret-password",
        "ss://secret",
        "example.invalid",
        "hk-01",
        "top-secret",
        "MANIFEST-FULL-BODY",
        "secret.invalid",
    ):
        assert banned_value not in text
    for banned_key in (
        "server",
        "port",
        "uuid",
        "password",
        "secret",
        "token",
        "uri",
        "proxy",
    ):
        assert f'"{banned_key}"' not in text


def test_corrupt_history_is_not_overwritten(tmp_path: Path) -> None:
    history = tmp_path / "docs" / "history" / "update-history.json"
    history.parent.mkdir(parents=True)
    history.write_text('{"schema_version": 1, "entries": [', encoding="utf-8")
    before = history.read_bytes()

    result = _run(
        ["--history-path", str(history), "--status", "success", "--run-id", "1"],
        cwd=tmp_path,
    )

    assert result.returncode != 0
    assert "refusing to overwrite" in result.stderr
    assert history.read_bytes() == before


def test_identifiers_prefer_github_env_defaults(tmp_path: Path) -> None:
    history = tmp_path / "docs" / "history" / "update-history.json"
    result = _run(
        ["--history-path", str(history)],
        cwd=tmp_path,
        env_extra={
            "JOB_STATUS": "success",
            "GITHUB_RUN_ID": "987654321",
            "GITHUB_RUN_ATTEMPT": "3",
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_SHA": SOURCE_COMMIT,
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_REPOSITORY": "cloudcat214/clash-subscription-aggregator",
        },
    )

    assert result.returncode == 0, result.stderr
    entry = _read_history(history)["entries"][-1]
    assert entry["status"] == "success"
    assert entry["run_id"] == "987654321"
    assert entry["run_attempt"] == 3
    assert entry["event"] == "workflow_dispatch"
    assert entry["source_commit"] == SOURCE_COMMIT
    assert (
        entry["run_url"]
        == "https://github.com/cloudcat214/clash-subscription-aggregator/actions/runs/987654321"
    )


def test_completed_run_workflow_records_and_directly_deploys_history() -> None:
    import yaml

    auto_refresh = (ROOT / ".github" / "workflows" / "auto-refresh.yml").read_text(
        encoding="utf-8"
    )
    assert "Record update history" not in auto_refresh
    assert "(run ${GITHUB_RUN_ID} attempt ${GITHUB_RUN_ATTEMPT})" in auto_refresh
    assert "--probe-min-verdict stable" in auto_refresh
    text = (ROOT / ".github/workflows/update-history.yml").read_text(encoding="utf-8")
    workflow = yaml.safe_load(text)
    triggers = workflow.get("on") or workflow.get(True)
    assert triggers["workflow_run"] == {
        "workflows": ["Cloud auto refresh"],
        "types": ["completed"],
    }
    job = workflow["jobs"]["record"]
    assert "head_repository.full_name == github.repository" in job["if"]
    assert "head_branch == 'main'" in job["if"]
    assert "PUBLIC_NODE_REDISTRIBUTION_APPROVED" in job["if"]
    assert job["steps"][0]["with"]["ref"] == "main"
    assert "Deploy Pages" in text
    assert "git add -- docs/history/update-history.json" in text
    assert "git add -- docs/dist" not in text
    assert text.index("Record only update history") < text.index("Deploy Pages")
    assert "git restore --source=origin/main -- docs" in text
    assert "for attempt in 1 2 3; do" in text
    assert "failed to read completed run jobs metadata after 3 attempts" in text
    assert "exit 1" in text
    assert 'printf \'{"jobs": []}' not in text

    pages_workflow = (ROOT / ".github" / "workflows" / "update.yml").read_text(
        encoding="utf-8"
    )
    assert "history/update-history\\.json" in pages_workflow
    assert "grep -Eq '^docs/(dist/|history/update-history\\.json$)'" in pages_workflow


def _module():
    spec = importlib.util.spec_from_file_location("update_history", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _completed_run(conclusion="success"):
    return {
        "status": "completed",
        "conclusion": conclusion,
        "id": 42,
        "run_attempt": 1,
        "event": "workflow_dispatch",
        "head_sha": SOURCE_COMMIT,
        "head_branch": "main",
        "head_repository": {"full_name": "cloudcat214/clash-subscription-aggregator"},
        "html_url": "https://github.com/cloudcat214/clash-subscription-aggregator/actions/runs/42",
        "run_started_at": "2026-10-13T12:00:00Z",
        "updated_at": "2026-10-13T12:05:00Z",
    }


def test_completed_success_uses_run_bound_manifest_and_final_result():
    module = _module()
    manifest = {
        "counts": {"published": 7},
        "status": "success",
        "verification": {
            "pool_size_before": 20,
            "pool_size": 22,
            "pool_retested": 20,
            "pool_added": 5,
            "pool_evicted": 3,
        },
    }
    jobs = {"jobs": [{"steps": [{"name": "Deploy Pages", "conclusion": "success"}]}]}
    entry = module.completed_entry(_completed_run(), jobs, manifest, manifest, "b" * 40)
    assert entry["status"] == "success"
    assert entry["published"] == 7
    assert entry["pool_size_before"] == 20
    assert entry["pool_size"] == 22
    assert entry["pool_retested"] == 20
    assert entry["pool_added"] == 5
    assert entry["pool_evicted"] == 3
    assert entry["publish_commit"] == "b" * 40
    assert entry["subscription_updated"] is True
    assert entry["duration_seconds"] == 300


def test_completed_failure_does_not_report_old_snapshot_as_this_runs_output():
    module = _module()
    snapshot = {"counts": {"published": 500}, "generated_at": "2026-10-12T12:00:00Z"}
    jobs = {
        "jobs": [
            {
                "steps": [
                    {"name": "Run cloud aggregation and probe", "conclusion": "failure"}
                ]
            }
        ]
    }
    entry = module.completed_entry(_completed_run("failure"), jobs, {}, snapshot, None)
    assert entry["status"] == "failed"
    assert entry["published"] is None
    assert entry["current_published"] == 500
    assert entry["subscription_updated"] is False
    assert entry["failure_stage"] == "probe"
    assert entry["failure_reason"] == "unclassified_failure"


def test_completed_cancellation_records_even_without_manifest_or_steps():
    entry = _module().completed_entry(_completed_run("cancelled"), {}, {}, {}, None)
    assert entry["status"] == "cancelled"
    assert entry["published"] is None
    assert entry["pages_deployed"] is None
    assert entry["failure_reason"] == "unclassified_failure"


def test_repeated_attempt_is_idempotent_but_rerun_is_distinct(tmp_path):
    history = tmp_path / "docs/history/update-history.json"
    args = ["--status", "success", "--run-id", "42", "--run-attempt", "1"]
    assert _run(args, tmp_path).returncode == 0
    before = history.read_bytes()
    assert _run(args, tmp_path).returncode == 0
    assert history.read_bytes() == before
    assert _run(args[:-1] + ["2"], tmp_path).returncode == 0
    assert len(_read_history(history)["entries"]) == 2


def test_events_are_kept_in_processing_order_when_finished_at_is_out_of_order(
    tmp_path,
):
    history = tmp_path / "docs/history/update-history.json"
    first = [
        "--history-path",
        str(history),
        "--status",
        "success",
        "--run-id",
        "2",
        "--run-attempt",
        "1",
    ]
    second = [
        "--history-path",
        str(history),
        "--status",
        "success",
        "--run-id",
        "1",
        "--run-attempt",
        "1",
    ]
    assert _run(first, tmp_path).returncode == 0
    assert _run(second, tmp_path).returncode == 0
    assert [entry["run_id"] for entry in _read_history(history)["entries"]] == [
        "2",
        "1",
    ]


def test_explicit_missing_manifest_does_not_fall_back_to_old_dist(tmp_path):
    _write_manifest(
        tmp_path / "docs/dist/manifest.json", {"counts": {"published": 500}}
    )
    result = _run(["--status", "failure", "--manifest", "missing.json"], tmp_path)
    assert result.returncode == 0
    assert (
        _read_history(tmp_path / "docs/history/update-history.json")["entries"][0][
            "published"
        ]
        is None
    )


def test_url_and_free_text_error_cannot_leak_credentials():
    module = _module()
    assert (
        module.resolve_run_url("https://user:secret@github.com/repo/actions/runs/42")
        is None
    )
    assert (
        module.resolve_run_url("https://github.com/o/r/actions/runs/42?token=secret")
        is None
    )
    summary = module.summarize_inputs(
        {"status": {"secret": "value"}}, {"failure_reason": "node.example.invalid"}
    )
    assert summary["manifest_status"] is None
    assert summary["failure_reason"] is None


def test_untrusted_completed_run_rejected_without_history_write(tmp_path):
    run = _completed_run()
    run["head_repository"]["full_name"] = "attacker/fork"
    event = tmp_path / "event.json"
    event.write_text(json.dumps({"workflow_run": run}), encoding="utf-8")
    result = _run(
        ["--workflow-run", str(event)],
        tmp_path,
        {"GITHUB_REPOSITORY": "cloudcat214/clash-subscription-aggregator"},
    )
    assert result.returncode != 0
    assert "untrusted" in result.stderr
    assert not (tmp_path / "docs/history/update-history.json").exists()


def test_completed_cli_binds_to_git_publish_commit_and_keeps_failed_snapshot(tmp_path):
    def git(*args):
        result = subprocess.run(
            [
                "git",
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                *args,
            ],
            cwd=tmp_path,
            text=True,
            capture_output=True,
            check=True,
        )
        return result.stdout.strip()

    git("init")
    manifest = tmp_path / "docs/dist/manifest.json"
    _write_manifest(
        manifest,
        {
            "status": "success",
            "generated_at": "2026-10-13T12:01:00Z",
            "counts": {"published": 7},
            "node_quality": {"tested": 30},
        },
    )
    git("add", "docs")
    git("commit", "-m", "refresh: cloud verified nodes (run 42 attempt 1)")
    commit = git("rev-parse", "HEAD")
    git("update-ref", "refs/remotes/origin/main", commit)
    event = tmp_path / "event.json"
    event.write_text(json.dumps({"workflow_run": _completed_run()}), encoding="utf-8")
    jobs = tmp_path / "jobs.json"
    jobs.write_text(
        json.dumps(
            {
                "jobs": [
                    {
                        "steps": [
                            {"name": "Deploy Pages", "conclusion": "success"},
                        ]
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    env = {"GITHUB_REPOSITORY": "cloudcat214/clash-subscription-aggregator"}
    args = ["--workflow-run", str(event), "--jobs", str(jobs)]
    result = _run(args, tmp_path, env)
    assert result.returncode == 0, result.stderr
    history = tmp_path / "docs/history/update-history.json"
    entry = _read_history(history)["entries"][0]
    assert entry["publish_commit"] == commit
    assert entry["published"] == 7
    assert entry["tested"] == 30
    assert entry["subscription_updated"] is True
    before = history.read_bytes()
    assert _run(args, tmp_path, env).returncode == 0
    assert history.read_bytes() == before

    failed_run = _completed_run("failure")
    failed_run["id"] = 43
    event.write_text(json.dumps({"workflow_run": failed_run}), encoding="utf-8")
    jobs.write_text('{"jobs": []}', encoding="utf-8")
    snapshot_before = manifest.read_bytes()
    result = _run(args, tmp_path, env)
    assert result.returncode == 0, result.stderr
    failed_entry = _read_history(history)["entries"][-1]
    assert failed_entry["status"] == "failed"
    assert failed_entry["published"] is None
    assert failed_entry["current_published"] == 7
    assert failed_entry["subscription_updated"] is False
    assert manifest.read_bytes() == snapshot_before
