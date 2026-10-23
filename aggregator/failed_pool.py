from __future__ import annotations

import copy
import json
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

from .quality import classify_node, node_key

FAILED_POOL_SCHEMA_VERSION = 1
FAILED_POOL_CAP = 5000
BACKOFF_SECONDS = (3600, 6 * 3600, 24 * 3600, 72 * 3600)
_VERDICT_ORDER = {"fast": 0, "verified": 1, "stable": 2, "not_tested": 3}


def _meets_minimum(verdict: str, minimum: str) -> bool:
    return _VERDICT_ORDER.get(verdict, 4) <= _VERDICT_ORDER.get(minimum, 4)


def _parse_time(value: object) -> datetime:
    if not isinstance(value, str):
        raise TypeError("failed_pool_invalid")
    try:
        return datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError("failed_pool_invalid") from exc


def _iso(value: datetime) -> str:
    return (
        value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    )


def _next_retry_at(now: str, failures: int) -> str:
    delay = BACKOFF_SECONDS[min(max(failures, 1) - 1, len(BACKOFF_SECONDS) - 1)]
    return _iso(_parse_time(now) + timedelta(seconds=delay))


def _completeness(entry: dict[str, object]) -> tuple[str, int]:
    """Order duplicates so the newest, most-failed entry wins."""
    return (
        str(entry.get("last_rechecked_at") or ""),
        cast(int, entry.get("total_failures") or 0),
    )


def _dedupe_by_key(entries: list[dict[str, object]]) -> list[dict[str, object]]:
    best: dict[str, dict[str, object]] = {}
    for entry in entries:
        key = str(entry["key"])
        prior = best.get(key)
        if prior is None or _completeness(entry) > _completeness(prior):
            best[key] = entry
    return list(best.values())


def load_failed_pool(path: Path) -> list[dict[str, object]]:
    if not path.is_file():
        return []
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("failed_pool_invalid") from exc
    if (
        not isinstance(document, dict)
        or document.get("schema_version") != FAILED_POOL_SCHEMA_VERSION
    ):
        raise ValueError("failed_pool_invalid")
    raw_nodes = document.get("nodes")
    if not isinstance(raw_nodes, list):
        raise TypeError("failed_pool_invalid")
    entries: list[dict[str, object]] = []
    for raw_entry in raw_nodes:
        if not isinstance(raw_entry, dict):
            raise TypeError("failed_pool_invalid")
        node = raw_entry.get("node")
        # The stored key is only a hint (older files hashed the display name).
        stored_key = raw_entry.get("key")
        source_id = raw_entry.get("source_id")
        if (
            not isinstance(node, dict)
            or not isinstance(stored_key, str)
            or not stored_key
        ):
            raise TypeError("failed_pool_invalid")
        if not isinstance(source_id, str) or not source_id:
            raise TypeError("failed_pool_invalid")
        for field in ("first_failed_at", "last_rechecked_at", "next_retry_at"):
            _parse_time(raw_entry.get(field))
        if not isinstance(raw_entry.get("last_conclusion"), str):
            raise TypeError("failed_pool_invalid")
        for field in ("consecutive_failures", "total_failures"):
            value = raw_entry.get(field)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise TypeError("failed_pool_invalid")
        if raw_entry.get("last_error_category") is not None and not isinstance(
            raw_entry.get("last_error_category"), str
        ):
            raise TypeError("failed_pool_invalid")
        entry = copy.deepcopy(raw_entry)
        entry["key"] = node_key(node)
        entries.append(entry)
    return _dedupe_by_key(entries)


def load_runtime_pools(
    verified_path: Path, failed_path: Path
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    from .verified_pool import load_verified_pool

    verified_entries = load_verified_pool(verified_path)
    failed_entries = load_failed_pool(failed_path)
    verified_keys = {str(entry["key"]) for entry in verified_entries}
    # A cache written before the identity change may hold the same physical
    # node twice (verified under one display name, failed under another).
    # Re-keying collapses those entries, so resolve the overlap instead of
    # aborting the whole cache: verified entries win and are not retried as
    # failures.
    failed_entries = [
        entry for entry in failed_entries if str(entry["key"]) not in verified_keys
    ]
    return verified_entries, failed_entries


def failed_pool_document(
    entries: list[dict[str, object]], updated_at: str
) -> dict[str, object]:
    return {
        "schema_version": FAILED_POOL_SCHEMA_VERSION,
        "updated_at": updated_at,
        "nodes": copy.deepcopy(entries),
    }


def due_failed_pool_nodes(
    entries: list[dict[str, object]], now: str, limit: int
) -> list[dict[str, object]]:
    now_dt = _parse_time(now)
    due = [entry for entry in entries if _parse_time(entry["next_retry_at"]) <= now_dt]
    due.sort(
        key=lambda entry: (str(entry["next_retry_at"]), int(entry["total_failures"]))
    )
    return [
        copy.deepcopy(cast(dict[str, object], entry["node"]))
        for entry in due[: max(0, limit)]
    ]


def merge_failed_pool(
    entries: list[dict[str, object]],
    retry_nodes: list[dict[str, object]],
    results_by_key: Mapping[str, Mapping[str, object]],
    source_by_key: Mapping[str, str],
    evicted_active_entries: list[dict[str, object]],
    *,
    now: str,
    min_verdict: str,
    verified_min_rounds: int,
    stable_min_rounds: int,
    stable_success_rate: float,
    fast_latency_ms: float,
    max_entries: int = FAILED_POOL_CAP,
) -> tuple[list[dict[str, object]], dict[str, int], list[dict[str, object]]]:
    current = {str(entry["key"]): copy.deepcopy(entry) for entry in entries}
    stats = {"retested": 0, "promoted": 0, "added": 0, "evicted_active": 0, "pruned": 0}
    seen_retry: set[str] = set()
    promoted_nodes: list[dict[str, object]] = []

    for node in retry_nodes:
        key = node_key(node)
        if key in seen_retry:
            continue
        seen_retry.add(key)
        row = results_by_key.get(key)
        if row is None:
            continue
        verdict = classify_node(
            node,
            row,
            verified_min_rounds=verified_min_rounds,
            stable_min_rounds=stable_min_rounds,
            stable_success_rate=stable_success_rate,
            fast_latency_ms=fast_latency_ms,
        )
        if _meets_minimum(verdict, min_verdict):
            if key in current:
                source_id = str(
                    current[key].get("source_id") or source_by_key.get(key, "unknown")
                )
                del current[key]
                stats["promoted"] += 1
                promoted_nodes.append(
                    {
                        "key": key,
                        "node": copy.deepcopy(node),
                        "source_id": source_id,
                        "verdict": verdict,
                    }
                )
            continue
        existing = current.get(key)
        if existing is None:
            failures = 1
            current[key] = {
                "key": key,
                "node": copy.deepcopy(node),
                "source_id": str(source_by_key.get(key, "unknown")),
                "first_failed_at": now,
                "last_rechecked_at": now,
                "next_retry_at": _next_retry_at(now, failures),
                "last_conclusion": verdict,
                "last_error_category": str(row.get("error_category") or "failed"),
                "consecutive_failures": failures,
                "total_failures": failures,
            }
            stats["added"] += 1
        else:
            failures = int(existing["consecutive_failures"]) + 1
            existing["node"] = copy.deepcopy(node)
            existing["last_rechecked_at"] = now
            existing["next_retry_at"] = _next_retry_at(now, failures)
            existing["last_conclusion"] = verdict
            existing["last_error_category"] = str(row.get("error_category") or "failed")
            existing["consecutive_failures"] = failures
            existing["total_failures"] = int(existing["total_failures"]) + 1
            stats["retested"] += 1

    for active_entry in evicted_active_entries:
        key = str(active_entry["key"])
        if key in current:
            continue
        failures = max(1, int(active_entry.get("consecutive_failures", 1)))
        current[key] = {
            "key": key,
            "node": copy.deepcopy(cast(dict[str, object], active_entry["node"])),
            "source_id": str(active_entry.get("source_id", "unknown")),
            "first_failed_at": str(active_entry.get("last_rechecked_at", now)),
            "last_rechecked_at": now,
            "next_retry_at": _next_retry_at(now, failures),
            "last_conclusion": str(active_entry.get("last_conclusion", "failed")),
            "last_error_category": "active_pool_evicted",
            "consecutive_failures": failures,
            "total_failures": failures,
        }
        stats["evicted_active"] += 1
        stats["added"] += 1

    if len(current) > max_entries:
        ordered = sorted(
            current.values(),
            key=lambda entry: (
                str(entry["next_retry_at"]),
                int(entry["total_failures"]),
            ),
        )
        keep = ordered[:max_entries]
        stats["pruned"] = len(ordered) - len(keep)
        current = {str(entry["key"]): entry for entry in keep}

    stats["size"] = len(current)
    return list(current.values()), stats, promoted_nodes
