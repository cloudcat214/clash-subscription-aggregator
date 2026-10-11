from __future__ import annotations

import copy
import json
from collections import OrderedDict
from collections.abc import Mapping
from pathlib import Path
from typing import cast

from .quality import classify_node, node_key

POOL_SCHEMA_VERSION = 1
EVICTION_FAILURES = 2
PROTECTED_SOURCE_PREFIX = "chrome147-embedded"
PROTECTED_EVICTION_FAILURES = 4
_VERDICT_ORDER = {"fast": 0, "verified": 1, "stable": 2, "not_tested": 3}


def _eviction_limit(source_id: str) -> int:
    """User-provided nodes keep a larger failure budget against transient probe errors."""
    if source_id.startswith(PROTECTED_SOURCE_PREFIX):
        return PROTECTED_EVICTION_FAILURES
    return EVICTION_FAILURES


def load_verified_pool(path: Path) -> list[dict[str, object]]:
    if not path.is_file():
        return []
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("verified_pool_invalid") from exc
    if (
        not isinstance(document, dict)
        or document.get("schema_version") != POOL_SCHEMA_VERSION
    ):
        raise ValueError("verified_pool_invalid")
    raw_nodes = document.get("nodes")
    if not isinstance(raw_nodes, list):
        raise TypeError("verified_pool_invalid")
    entries: list[dict[str, object]] = []
    seen: set[str] = set()
    for raw_entry in raw_nodes:
        if not isinstance(raw_entry, dict):
            raise TypeError("verified_pool_invalid")
        node = raw_entry.get("node")
        key = raw_entry.get("key")
        if not isinstance(node, dict) or not isinstance(key, str) or not key:
            raise TypeError("verified_pool_invalid")
        if node_key(node) != key or key in seen:
            raise ValueError("verified_pool_invalid")
        source_id = raw_entry.get("source_id")
        if not isinstance(source_id, str) or not source_id:
            raise TypeError("verified_pool_invalid")
        for field in (
            "first_seen_at",
            "last_rechecked_at",
            "last_conclusion",
        ):
            if not isinstance(raw_entry.get(field), str):
                raise TypeError("verified_pool_invalid")
        for field in ("consecutive_failures", "total_passes"):
            value = raw_entry.get(field)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise TypeError("verified_pool_invalid")
        if cast(int, raw_entry["consecutive_failures"]) >= _eviction_limit(source_id):
            raise ValueError("verified_pool_invalid")
        entries.append(copy.deepcopy(raw_entry))
        seen.add(key)
    return entries


def pool_document(
    entries: list[dict[str, object]], updated_at: str
) -> dict[str, object]:
    return {
        "schema_version": POOL_SCHEMA_VERSION,
        "updated_at": updated_at,
        "nodes": copy.deepcopy(entries),
    }


def round_robin_by_source(
    nodes: list[dict[str, object]], source_by_key: Mapping[str, str], limit: int
) -> list[dict[str, object]]:
    """Take candidates in source turns so one large source cannot fill the budget."""
    if limit <= 0:
        return []
    buckets: OrderedDict[str, list[dict[str, object]]] = OrderedDict()
    for node in nodes:
        source_id = str(source_by_key.get(node_key(node), "unknown"))
        buckets.setdefault(source_id, []).append(node)
    sampled: list[dict[str, object]] = []
    while len(sampled) < limit and buckets:
        exhausted: list[str] = []
        for source_id, bucket in buckets.items():
            if bucket:
                sampled.append(bucket.pop(0))
                if len(sampled) >= limit:
                    break
            if not bucket:
                exhausted.append(source_id)
        for source_id in exhausted:
            buckets.pop(source_id, None)
    return sampled


def _meets_minimum(verdict: str, minimum: str) -> bool:
    return _VERDICT_ORDER.get(verdict, 4) <= _VERDICT_ORDER[minimum]


def merge_verified_pool(
    entries: list[dict[str, object]],
    probe_nodes: list[dict[str, object]],
    results_by_key: Mapping[str, Mapping[str, object]],
    source_by_key: Mapping[str, str],
    *,
    now: str,
    min_verdict: str,
    verified_min_rounds: int,
    stable_min_rounds: int,
    stable_success_rate: float,
    fast_latency_ms: float,
) -> tuple[list[dict[str, object]], dict[str, int]]:
    if min_verdict not in _VERDICT_ORDER:
        raise ValueError("invalid_min_verdict")
    current = {str(entry["key"]): copy.deepcopy(entry) for entry in entries}
    probe_keys = {node_key(node) for node in probe_nodes}
    stats = {"retested": 0, "retained": 0, "added": 0, "evicted": 0}

    for key, entry in list(current.items()):
        if key not in probe_keys:
            continue
        row = results_by_key.get(key)
        if row is None:
            continue
        stats["retested"] += 1
        node = entry["node"]
        assert isinstance(node, dict)
        verdict = classify_node(
            node,
            row,
            verified_min_rounds=verified_min_rounds,
            stable_min_rounds=stable_min_rounds,
            stable_success_rate=stable_success_rate,
            fast_latency_ms=fast_latency_ms,
        )
        entry["last_rechecked_at"] = now
        entry["last_conclusion"] = verdict
        if _meets_minimum(verdict, min_verdict):
            entry["consecutive_failures"] = 0
            entry["total_passes"] = cast(int, entry["total_passes"]) + 1
            stats["retained"] += 1
        else:
            failures = cast(int, entry["consecutive_failures"]) + 1
            entry["consecutive_failures"] = failures
            if failures >= _eviction_limit(str(entry.get("source_id", ""))):
                del current[key]
                stats["evicted"] += 1
            else:
                stats["retained"] += 1

    for node in probe_nodes:
        key = node_key(node)
        if key in current:
            continue
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
        if not _meets_minimum(verdict, min_verdict):
            continue
        current[key] = {
            "key": key,
            "node": copy.deepcopy(node),
            "source_id": str(source_by_key.get(key, "unknown")),
            "first_seen_at": now,
            "last_rechecked_at": now,
            "last_conclusion": verdict,
            "consecutive_failures": 0,
            "total_passes": 1,
        }
        stats["added"] += 1
        stats["retained"] += 1

    return list(current.values()), stats


def active_pool_nodes(
    entries: list[dict[str, object]], max_nodes: int
) -> list[dict[str, object]]:
    valid = [
        cast(dict[str, object], entry["node"])
        for entry in entries
        if cast(int, entry["consecutive_failures"])
        < _eviction_limit(str(entry.get("source_id", "")))
    ]
    return [copy.deepcopy(node) for node in valid[: max(0, max_nodes)]]
