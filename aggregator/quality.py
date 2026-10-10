from __future__ import annotations

import hashlib
import math
from collections.abc import Iterable, Mapping

from .parsing import quality_score as structure_quality_score

_VERDICT_ORDER = {"fast": 0, "verified": 1, "stable": 2, "not_tested": 3}


def node_key(node: Mapping[str, object]) -> str:
    """Return a stable identifier without exposing a node name or credentials."""
    name = str(node.get("name") or "")
    return hashlib.sha256(name.encode("utf-8")).hexdigest()[:16]


def _number(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) and number >= 0 else None


def _count(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def probe_verdict(
    rounds_passed: int,
    rounds: int,
    latency_ms: float | None = None,
    *,
    p95_latency_ms: float | None = None,
    verified_min_rounds: int = 3,
    stable_min_rounds: int = 3,
    stable_success_rate: float = 2 / 3,
    fast_latency_ms: float = 800.0,
    error_category: str | None = None,
) -> dict[str, object]:
    total = max(0, _count(rounds))
    passed = min(total, max(0, _count(rounds_passed)))
    rate = passed / total if total else 0.0
    average = _number(latency_ms)
    p95 = _number(p95_latency_ms)
    if p95 is None:
        p95 = average
    verified = total >= max(1, verified_min_rounds) and passed == total
    stable = total >= max(1, stable_min_rounds) and rate >= stable_success_rate
    fast_limit = _number(fast_latency_ms)
    fast = average is not None and fast_limit is not None and average <= fast_limit
    return {
        "rounds_passed": passed,
        "rounds_total": total,
        "rounds": total,
        "success_rate": rate,
        "latency_ms": average,
        "p95_latency_ms": p95,
        "verified": verified,
        "fast": fast,
        "stable": stable,
        "error_category": error_category,
    }


def classify_node(
    node: Mapping[str, object],
    probe: Mapping[str, object] | None = None,
    *,
    verified_min_rounds: int = 3,
    stable_min_rounds: int = 3,
    stable_success_rate: float = 2 / 3,
    fast_latency_ms: float = 800.0,
) -> str:
    if not isinstance(probe, Mapping):
        return "not_tested"
    total = probe.get("rounds_total", probe.get("rounds", 0))
    verdict = probe_verdict(
        _count(probe.get("rounds_passed")),
        _count(total),
        _number(probe.get("latency_ms")),
        p95_latency_ms=_number(probe.get("p95_latency_ms")),
        verified_min_rounds=verified_min_rounds,
        stable_min_rounds=stable_min_rounds,
        stable_success_rate=stable_success_rate,
        fast_latency_ms=fast_latency_ms,
    )
    if not verdict["rounds_total"]:
        return "not_tested"
    if verdict["verified"] and verdict["fast"]:
        return "fast"
    if verdict["verified"]:
        return "verified"
    if verdict["stable"]:
        return "stable"
    return "failed"


def score_node(
    node: Mapping[str, object],
    probe: Mapping[str, object] | None = None,
    *,
    verified_min_rounds: int = 3,
    stable_min_rounds: int = 3,
    stable_success_rate: float = 2 / 3,
    fast_latency_ms: float = 800.0,
    latency_cap_ms: float = 5000.0,
) -> float:
    try:
        structure = float(max(0, min(100, structure_quality_score(node))))
    except (TypeError, ValueError):
        structure = 0.0
    if not isinstance(probe, Mapping):
        return round(structure * 0.05, 2)

    total = _count(probe.get("rounds_total", probe.get("rounds", 0)))
    verdict = probe_verdict(
        _count(probe.get("rounds_passed")),
        total,
        _number(probe.get("latency_ms")),
        p95_latency_ms=_number(probe.get("p95_latency_ms")),
        verified_min_rounds=verified_min_rounds,
        stable_min_rounds=stable_min_rounds,
        stable_success_rate=stable_success_rate,
        fast_latency_ms=fast_latency_ms,
    )
    if not total:
        return round(structure * 0.05, 2)

    rate = _number(verdict["success_rate"]) or 0.0
    latency = _number(verdict["p95_latency_ms"])
    cap = _number(latency_cap_ms) or 5000.0
    latency_factor = 0.0
    if latency is not None:
        # Keep the latency contribution bounded so one fast partial result cannot
        # outrank a fully passing multi-round result.
        latency_factor = 0.5 + 0.5 * max(0.0, 1.0 - latency / cap)
    stability = rate * min(1.0, total / max(1, stable_min_rounds))
    score = 40 * rate + 35 * latency_factor + 20 * stability + 5 * structure / 100
    return round(max(0.0, min(100.0, score)), 2)


def _index_results(
    results: Mapping[str, object] | Iterable[Mapping[str, object]],
) -> dict[str, Mapping[str, object]]:
    indexed: dict[str, Mapping[str, object]] = {}
    if isinstance(results, Mapping):
        for key, value in results.items():
            if isinstance(value, Mapping):
                indexed[str(key)] = value
                for field in ("name", "node_key", "name_hash"):
                    identity = value.get(field)
                    if isinstance(identity, str) and identity:
                        indexed[identity] = value
        return indexed
    if isinstance(results, Iterable) and not isinstance(results, (str, bytes)):
        for value in results:
            if not isinstance(value, Mapping):
                continue
            for field in ("name", "node_key", "name_hash"):
                identity = value.get(field)
                if isinstance(identity, str) and identity:
                    indexed[identity] = value
    return indexed


def select_published(
    nodes: Iterable[Mapping[str, object]],
    results: Mapping[str, object] | Iterable[Mapping[str, object]],
    *,
    min_verdict: str = "not_tested",
    max_nodes: int | None = None,
    verified_min_rounds: int = 3,
    stable_min_rounds: int = 3,
    stable_success_rate: float = 2 / 3,
    fast_latency_ms: float = 800.0,
    latency_cap_ms: float = 5000.0,
) -> list[dict[str, object]]:
    if min_verdict not in _VERDICT_ORDER:
        raise ValueError("invalid_min_verdict")
    indexed = _index_results(results)
    minimum_rank = _VERDICT_ORDER[min_verdict]
    selected: list[tuple[int, float, str, dict[str, object]]] = []
    for node in nodes:
        name = str(node.get("name") or "")
        probe = indexed.get(name) or indexed.get(node_key(node))
        verdict = classify_node(
            node,
            probe,
            verified_min_rounds=verified_min_rounds,
            stable_min_rounds=stable_min_rounds,
            stable_success_rate=stable_success_rate,
            fast_latency_ms=fast_latency_ms,
        )
        rank = _VERDICT_ORDER.get(verdict, 4)
        if rank > minimum_rank:
            continue
        selected.append(
            (
                rank,
                -score_node(
                    node,
                    probe,
                    verified_min_rounds=verified_min_rounds,
                    stable_min_rounds=stable_min_rounds,
                    stable_success_rate=stable_success_rate,
                    fast_latency_ms=fast_latency_ms,
                    latency_cap_ms=latency_cap_ms,
                ),
                name.casefold(),
                {
                    **dict(node),
                    "verdict": verdict,
                    "verified": verdict in {"fast", "verified"},
                    "fast": verdict == "fast",
                    "stable": verdict in {"fast", "verified", "stable"},
                },
            )
        )
    selected.sort(key=lambda item: item[:3])
    if max_nodes is not None:
        budget = max(0, min(30, _count(max_nodes)))
        selected = selected[:budget]
    return [item[3] for item in selected]
