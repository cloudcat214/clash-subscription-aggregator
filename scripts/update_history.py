#!/usr/bin/env python3
"""Append one redacted record per cloud refresh run to the public update history.

Only whitelisted status fields and aggregate counts are copied out of
manifest/health documents. Node endpoints, credentials, raw manifest bodies
and proxy names never reach the history file.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

DEFAULT_HISTORY_PATH = Path("docs/history/update-history.json")
DEFAULT_MANIFEST_CANDIDATES = (
    Path("dist-auto/manifest.json"),
    Path("docs/dist/manifest.json"),
)
DEFAULT_HEALTH_CANDIDATES = (
    Path("dist-auto/health.json"),
    Path("docs/dist/health.json"),
)
MAX_ENTRIES = 500
SCHEMA_VERSION = 1
MAX_TOKEN_LENGTH = 120

STATUS_ALIASES = {
    "success": "success",
    "failure": "failed",
    "failed": "failed",
    "cancelled": "cancelled",
    "canceled": "cancelled",
}

_TOKEN_PATTERN = re.compile(rf"^[A-Za-z0-9._-]{{1,{MAX_TOKEN_LENGTH}}}$")
_TIMESTAMP_PATTERN = re.compile(r"^[0-9TZ:.+-]{10,40}$")
_COMMIT_PATTERN = re.compile(r"^[0-9a-fA-F]{7,40}$")
_RUN_ID_PATTERN = re.compile(r"^[0-9]{1,24}$")
_RUN_URL_PATTERN = re.compile(
    r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/actions/runs/[0-9]+$"
)
MANIFEST_STATUSES = {"success", "degraded", "bootstrap", "failed"}
FAILURE_STAGES = {
    "checkout",
    "setup",
    "install",
    "download",
    "probe",
    "stage",
    "commit",
    "sync",
    "configure_pages",
    "upload",
    "deploy",
    "unknown",
}
FAILURE_REASONS = {
    "probe_error",
    "probe_no_candidates",
    "probe_no_qualified_nodes",
    "probe_direct_control_failed",
    "probe_execution_failed",
    "probe_parameters_over_budget",
    "probe_interface_required",
    "all_sources_failed",
    "empty_result",
    "min_publish_nodes",
    "shrink_guard",
    "core_validation_failed",
    "unclassified_failure",
}
STEP_STAGES = {
    "Checkout main": "checkout",
    "Set up Python": "setup",
    "Install project": "install",
    "Download and verify Mihomo": "download",
    "Run cloud aggregation and probe": "probe",
    "Stage dist and auto Pages channels": "stage",
    "Commit changed auto artifacts": "commit",
    "Sync workspace to latest main before deploy": "sync",
    "Configure Pages": "configure_pages",
    "Upload Pages artifact": "upload",
    "Deploy Pages": "deploy",
}


class UpdateHistoryError(Exception):
    """Raised when the history record must not be written."""


def utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _clean_env(name: str) -> str | None:
    value = os.environ.get(name, "").strip()
    return value or None


def _token_or_none(value: object) -> str | None:
    if isinstance(value, str) and _TOKEN_PATTERN.match(value):
        return value
    return None


def _timestamp_or_none(value: object) -> str | None:
    if isinstance(value, str) and _TIMESTAMP_PATTERN.match(value):
        return value
    return None


def _int_or_none(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _first_int(*values: object) -> int | None:
    for value in values:
        parsed = _int_or_none(value)
        if parsed is not None:
            return parsed
    return None


def _dict_or_empty(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def _enum_or_none(value: object, allowed: set[str]) -> str | None:
    return value if isinstance(value, str) and value in allowed else None


def _load_json_object(path: Path | None) -> dict:
    if path is None:
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _sum_source_counts(health: dict) -> tuple[int | None, int | None]:
    sources = health.get("sources")
    if not isinstance(sources, list):
        return None, None
    parsed_total = 0
    accepted_total = 0
    seen = False
    for source in sources:
        if not isinstance(source, dict):
            continue
        parsed = _int_or_none(source.get("parsed"))
        accepted = _int_or_none(source.get("accepted"))
        if parsed is None and accepted is None:
            continue
        seen = True
        parsed_total += parsed or 0
        accepted_total += accepted or 0
    if not seen:
        return None, None
    return parsed_total, accepted_total


def summarize_inputs(manifest: dict, health: dict) -> dict[str, object]:
    counts = _dict_or_empty(manifest.get("counts"))
    quality = _dict_or_empty(manifest.get("node_quality"))
    verification = _dict_or_empty(manifest.get("verification"))
    health_quality = _dict_or_empty(health.get("node_quality"))
    health_verification = _dict_or_empty(health.get("verification"))
    health_parsed, health_accepted = _sum_source_counts(health)
    return {
        "manifest_generated_at": _timestamp_or_none(manifest.get("generated_at")),
        "manifest_status": _enum_or_none(manifest.get("status"), MANIFEST_STATUSES),
        "published": _first_int(counts.get("published"), health.get("published")),
        "parsed": _first_int(counts.get("parsed"), health_parsed),
        "accepted": _first_int(counts.get("accepted"), health_accepted),
        "tested": _first_int(quality.get("tested"), health_quality.get("tested")),
        "pool_size_before": _first_int(
            verification.get("pool_size_before"),
            health_verification.get("pool_size_before"),
        ),
        "pool_size": _first_int(
            verification.get("pool_size"), health_verification.get("pool_size")
        ),
        "pool_retested": _first_int(
            verification.get("pool_retested"),
            health_verification.get("pool_retested"),
        ),
        "pool_added": _first_int(
            verification.get("pool_added"), health_verification.get("pool_added")
        ),
        "pool_evicted": _first_int(
            verification.get("pool_evicted"),
            health_verification.get("pool_evicted"),
        ),
        "failure_reason": _enum_or_none(health.get("failure_reason"), FAILURE_REASONS),
    }


def build_entry(
    *,
    status: str,
    run_id: str | None,
    run_attempt: int | None,
    event: str | None,
    source_commit: str | None,
    run_url: str | None,
    manifest: dict,
    health: dict,
    failure_stage: str | None,
) -> dict[str, object]:
    summary = summarize_inputs(manifest, health)
    return {
        "recorded_at": utc_now(),
        "run_id": run_id,
        "run_attempt": run_attempt,
        "event": event,
        "source_commit": source_commit,
        "run_url": run_url,
        "status": status,
        "manifest_generated_at": summary["manifest_generated_at"],
        "manifest_status": summary["manifest_status"],
        "published": summary["published"],
        "parsed": summary["parsed"],
        "accepted": summary["accepted"],
        "tested": summary["tested"],
        "pool_size_before": summary["pool_size_before"],
        "pool_size": summary["pool_size"],
        "pool_retested": summary["pool_retested"],
        "pool_added": summary["pool_added"],
        "pool_evicted": summary["pool_evicted"],
        "failure_stage": failure_stage,
        "failure_reason": summary["failure_reason"],
    }


def completed_entry(
    run: dict, jobs: dict, manifest: dict, snapshot: dict, publish_commit: str | None
) -> dict[str, object]:
    """Record finalized GitHub metadata; an old snapshot is never this run's output."""
    conclusion = run.get("conclusion")
    if (
        conclusion
        not in {
            "success",
            "failure",
            "cancelled",
            "timed_out",
            "action_required",
            "startup_failure",
            "stale",
            "skipped",
            "neutral",
        }
        or run.get("status") != "completed"
    ):
        raise UpdateHistoryError("workflow run must have a finalized conclusion")
    status = STATUS_ALIASES.get(conclusion, "failed")
    run_id = resolve_run_id(str(run.get("id", "")))
    attempt = _int_or_none(run.get("run_attempt"))
    if not run_id or not attempt:
        raise UpdateHistoryError("completed run requires a valid id and attempt")
    stage = None
    deployed = None
    for job in jobs.get("jobs", []):
        for step in job.get("steps", []):
            name, outcome = step.get("name"), step.get("conclusion")
            if name == "Deploy Pages":
                deployed = outcome == "success"
            if stage is None and outcome in {"failure", "cancelled", "timed_out"}:
                stage = STEP_STAGES.get(name, "unknown")
    if status != "success" and stage is None:
        stage = "unknown"
    entry = build_entry(
        status=status,
        run_id=run_id,
        run_attempt=attempt,
        event=_token_or_none(run.get("event")),
        source_commit=resolve_commit(run.get("head_sha")),
        run_url=resolve_run_url(run.get("html_url", "")),
        manifest=manifest,
        health={},
        failure_stage=stage,
    )
    started = _timestamp_or_none(run.get("run_started_at") or run.get("created_at"))
    finished = _timestamp_or_none(run.get("updated_at"))
    duration = None
    if started and finished:
        try:
            duration = max(
                0,
                int(
                    (
                        datetime.fromisoformat(finished)
                        - datetime.fromisoformat(started)
                    ).total_seconds()
                ),
            )
        except (ValueError, TypeError):
            pass
    entry.update(
        {
            "started_at": started,
            "finished_at": finished,
            "duration_seconds": duration,
            "publish_commit": publish_commit,
            "pages_deployed": deployed,
            "subscription_updated": bool(publish_commit and deployed),
            "current_published": _int_or_none(
                _dict_or_empty(snapshot.get("counts")).get("published")
            ),
            "subscription_generated_at": _timestamp_or_none(
                snapshot.get("generated_at")
            ),
        }
    )
    if status != "success":
        entry["failure_reason"] = _enum_or_none(conclusion, FAILURE_REASONS)
        if entry["failure_reason"] is None:
            entry["failure_reason"] = "unclassified_failure"
    return entry


def manifest_for_run(run_id: str, attempt: int) -> tuple[str | None, dict]:
    """The producer's commit marker binds counts to this exact run attempt."""
    marker = f"refresh: cloud verified nodes (run {run_id} attempt {attempt})"
    result = subprocess.run(
        [
            "git",
            "log",
            "origin/main",
            "--format=%H",
            "--fixed-strings",
            f"--grep={marker}",
            "--",
            "docs/dist/manifest.json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        raise UpdateHistoryError("cannot inspect trusted main publish history")
    commits = result.stdout.splitlines()
    if not commits:
        return None, {}
    commit = commits[0]
    if not _COMMIT_PATTERN.fullmatch(commit):
        raise UpdateHistoryError("invalid publish commit")
    result = subprocess.run(
        ["git", "show", f"{commit}:docs/dist/manifest.json"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    if result.returncode:
        raise UpdateHistoryError("cannot read run-bound manifest")
    payload = json.loads(result.stdout)
    if not isinstance(payload, dict):
        raise UpdateHistoryError("invalid run-bound manifest")
    return commit, payload


def load_history(path: Path) -> dict[str, object]:
    if not path.exists():
        return {"schema_version": SCHEMA_VERSION, "entries": []}
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise UpdateHistoryError(f"existing file is unreadable or invalid JSON ({exc})")
    if (
        not isinstance(document, dict)
        or document.get("schema_version") != SCHEMA_VERSION
    ):
        raise UpdateHistoryError("unexpected top-level structure or schema_version")
    entries = document.get("entries")
    if not isinstance(entries, list) or any(
        not isinstance(item, dict) for item in entries
    ):
        raise UpdateHistoryError("entries must be a list of objects")
    return document


def save_history(path: Path, document: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(document, ensure_ascii=False, indent=2) + "\n"
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", newline="\n", dir=path.parent, delete=False
        ) as handle:
            temporary = Path(handle.name)
            handle.write(payload)
        os.replace(temporary, path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink(missing_ok=True)


def resolve_status(explicit: str | None) -> str:
    raw = explicit if explicit is not None else _clean_env("JOB_STATUS")
    normalized = STATUS_ALIASES.get((raw or "").strip().lower())
    if normalized is None:
        raise UpdateHistoryError(
            f"unknown job status {raw!r}; expected success, failure or cancelled"
        )
    return normalized


def resolve_run_id(explicit: str | None) -> str | None:
    raw = explicit if explicit is not None else _clean_env("GITHUB_RUN_ID")
    if isinstance(raw, str) and _RUN_ID_PATTERN.match(raw):
        return raw
    return None


def resolve_run_attempt(explicit: int | None) -> int | None:
    if explicit is not None:
        return explicit if explicit >= 1 else None
    raw = _clean_env("GITHUB_RUN_ATTEMPT")
    if raw is not None and raw.isdigit() and int(raw) >= 1:
        return int(raw)
    return None


def resolve_commit(explicit: str | None) -> str | None:
    raw = explicit if explicit is not None else _clean_env("GITHUB_SHA")
    if isinstance(raw, str) and _COMMIT_PATTERN.match(raw):
        return raw.lower()
    return None


def resolve_run_url(explicit: str | None) -> str | None:
    raw = explicit if explicit is not None else _clean_env("RUN_URL")
    if not raw:
        server = _clean_env("GITHUB_SERVER_URL")
        repository = _clean_env("GITHUB_REPOSITORY")
        run_id = _clean_env("GITHUB_RUN_ID")
        if server and repository and run_id:
            raw = f"{server.rstrip('/')}/{repository}/actions/runs/{run_id}"
    if isinstance(raw, str) and _RUN_URL_PATTERN.match(raw):
        return raw
    return None


def resolve_input_path(
    explicit: Path | None, candidates: tuple[Path, ...]
) -> Path | None:
    if explicit is not None:
        return explicit if explicit.is_file() else None
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Append one redacted record of the latest cloud refresh run "
            "to the public update history."
        )
    )
    parser.add_argument(
        "--history-path",
        type=Path,
        default=DEFAULT_HISTORY_PATH,
        help=f"history file to append to (default: {DEFAULT_HISTORY_PATH})",
    )
    parser.add_argument(
        "--status",
        help="job result: success/failure/cancelled (default: $JOB_STATUS)",
    )
    parser.add_argument("--run-id", help="run id (default: $GITHUB_RUN_ID)")
    parser.add_argument(
        "--run-attempt", type=int, help="run attempt (default: $GITHUB_RUN_ATTEMPT)"
    )
    parser.add_argument("--event", help="event name (default: $GITHUB_EVENT_NAME)")
    parser.add_argument("--source-commit", help="source commit (default: $GITHUB_SHA)")
    parser.add_argument(
        "--run-url", help="run URL (default: $RUN_URL or built from $GITHUB_SERVER_URL)"
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        help="manifest to summarize; falls back to dist-auto/docs/dist manifests",
    )
    parser.add_argument(
        "--health",
        type=Path,
        help="health file to summarize; falls back to dist-auto/docs/dist health",
    )
    parser.add_argument(
        "--failure-stage",
        help="optional failure stage label (default: $FAILURE_STAGE)",
    )
    parser.add_argument(
        "--workflow-run", type=Path, help="GitHub workflow_run event file"
    )
    parser.add_argument(
        "--jobs", type=Path, help="completed run jobs metadata (optional)"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.workflow_run:
            run = _dict_or_empty(
                _load_json_object(args.workflow_run).get("workflow_run")
            )
            repository = _clean_env("GITHUB_REPOSITORY")
            if (
                not repository
                or _dict_or_empty(run.get("head_repository")).get("full_name")
                != repository
                or run.get("head_branch") != "main"
                or run.get("event") not in {"schedule", "workflow_dispatch"}
            ):
                raise UpdateHistoryError("untrusted workflow run")
            run_id = resolve_run_id(str(run.get("id", "")))
            attempt = _int_or_none(run.get("run_attempt"))
            if not run_id or not attempt:
                raise UpdateHistoryError("invalid completed run identifiers")
            commit, manifest = manifest_for_run(run_id, attempt)
            entry = completed_entry(
                run,
                _load_json_object(args.jobs),
                manifest,
                _load_json_object(Path("docs/dist/manifest.json")),
                commit,
            )
        else:
            status = resolve_status(args.status)
            manifest_path = resolve_input_path(
                args.manifest, DEFAULT_MANIFEST_CANDIDATES
            )
            health_path = resolve_input_path(args.health, DEFAULT_HEALTH_CANDIDATES)
            stage = args.failure_stage or _clean_env("FAILURE_STAGE")
            entry = build_entry(
                status=status,
                run_id=resolve_run_id(args.run_id),
                run_attempt=resolve_run_attempt(args.run_attempt),
                event=_token_or_none(args.event or _clean_env("GITHUB_EVENT_NAME")),
                source_commit=resolve_commit(args.source_commit),
                run_url=resolve_run_url(args.run_url),
                manifest=_load_json_object(manifest_path),
                health=_load_json_object(health_path),
                failure_stage=stage if stage in FAILURE_STAGES else None,
            )
    except (UpdateHistoryError, ValueError, OSError) as exc:
        print(f"update-history: {exc}", file=sys.stderr)
        return 2

    history_path: Path = args.history_path
    try:
        document = load_history(history_path)
    except UpdateHistoryError as exc:
        print(
            f"update-history: refusing to overwrite {history_path}: {exc}",
            file=sys.stderr,
        )
        return 3

    entries = document["entries"]
    identity = entry["run_id"], entry["run_attempt"]
    if all(identity) and any(
        (item.get("run_id"), item.get("run_attempt")) == identity for item in entries
    ):
        print("update-history: run attempt already recorded; no change")
        return 0
    entries.append(entry)
    if len(entries) > MAX_ENTRIES:
        del entries[:-MAX_ENTRIES]
    try:
        save_history(history_path, document)
    except OSError as exc:
        print(f"update-history: failed to write {history_path}: {exc}", file=sys.stderr)
        return 4

    print(
        "update-history: recorded "
        f"status={entry['status']} run_id={entry['run_id']} "
        f"entries={len(entries)} path={history_path}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
