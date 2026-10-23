import json
from pathlib import Path

import yaml

from aggregator.failed_pool import (
    due_failed_pool_nodes,
    failed_pool_document,
    merge_failed_pool,
)
from aggregator.pipeline import run_pipeline
from aggregator.quality import node_key, probe_verdict
from aggregator.verified_pool import pool_document


def node(name: str) -> dict[str, object]:
    return {
        "name": name,
        "type": "http",
        "server": f"{name}.example",
        "port": 8080,
    }


def failed(n: dict[str, object]) -> dict[str, object]:
    return {
        "node_key": node_key(n),
        **probe_verdict(0, 3, None, error_category="timeout"),
    }


def passed(n: dict[str, object]) -> dict[str, object]:
    return {"node_key": node_key(n), **probe_verdict(3, 3, 120.0)}


def test_failed_pool_backoff_and_promotion() -> None:
    n = node("failed")
    now = "2026-10-14T00:00:00Z"
    entries, stats, promoted = merge_failed_pool(
        [],
        [n],
        {node_key(n): failed(n)},
        {node_key(n): "source"},
        [],
        now=now,
        min_verdict="stable",
        verified_min_rounds=3,
        stable_min_rounds=3,
        stable_success_rate=2 / 3,
        fast_latency_ms=800,
    )
    assert len(entries) == 1
    assert stats["added"] == 1
    assert promoted == []
    assert due_failed_pool_nodes(entries, "2026-10-14T00:59:59Z", 10) == []
    due = due_failed_pool_nodes(entries, "2026-10-14T01:00:00Z", 10)
    assert [item["name"] for item in due] == ["failed"]

    remaining, stats, promoted = merge_failed_pool(
        entries,
        due,
        {node_key(n): passed(n)},
        {node_key(n): "source"},
        [],
        now="2026-10-14T01:00:00Z",
        min_verdict="stable",
        verified_min_rounds=3,
        stable_min_rounds=3,
        stable_success_rate=2 / 3,
        fast_latency_ms=800,
    )
    assert remaining == []
    assert stats["promoted"] == 1
    assert promoted[0]["key"] == node_key(n)


def test_evicted_active_node_enters_failed_pool() -> None:
    n = node("evicted")
    active = {
        "key": node_key(n),
        "node": n,
        "source_id": "source",
        "last_rechecked_at": "2026-10-14T00:00:00Z",
        "last_conclusion": "failed",
        "consecutive_failures": 2,
        "total_passes": 2,
    }
    entries, stats, promoted = merge_failed_pool(
        [],
        [],
        {},
        {},
        [active],
        now="2026-10-14T01:00:00Z",
        min_verdict="stable",
        verified_min_rounds=3,
        stable_min_rounds=3,
        stable_success_rate=2 / 3,
        fast_latency_ms=800,
    )
    assert len(entries) == 1
    assert entries[0]["last_error_category"] == "active_pool_evicted"
    assert stats["evicted_active"] == 1
    assert promoted == []


def test_pipeline_moves_evicted_active_node_to_failed_pool(tmp_path: Path) -> None:
    source = tmp_path / "source.yaml"
    source.write_text(
        yaml.safe_dump({"proxies": [node("candidate")]}, sort_keys=False),
        encoding="utf-8",
    )
    config = tmp_path / "sources.yaml"
    config.write_text(
        yaml.safe_dump(
            {
                "settings": {
                    "active_probe": True,
                    "probe_max_nodes": 2,
                    "filters": {"min_quality_score": 0},
                },
                "sources": {
                    "public": [
                        {
                            "id": "fixture",
                            "path": str(source),
                            "enabled": True,
                            "publish": True,
                            "requires_review": False,
                        }
                    ],
                    "private": [],
                },
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    old = node("old")
    state = tmp_path / "state"
    state.mkdir()
    active_path = state / "verified-pool.json"
    active_path.write_text(
        json.dumps(
            pool_document(
                [
                    {
                        "key": node_key(old),
                        "node": old,
                        "source_id": "fixture",
                        "first_seen_at": "2026-10-14T00:00:00Z",
                        "last_rechecked_at": "2026-10-14T00:10:00Z",
                        "last_conclusion": "failed",
                        "consecutive_failures": 1,
                        "total_passes": 1,
                    }
                ],
                "2026-10-14T00:10:00Z",
            )
        ),
        encoding="utf-8",
    )
    failed_path = state / "failed-pool.json"

    def probe(nodes: list[dict[str, object]]) -> dict[str, object]:
        return {
            "status": "performed",
            "tested": len(nodes),
            "results": [
                failed(old) if n["name"] == "old" else passed(n) for n in nodes
            ],
        }

    result = run_pipeline(
        config,
        tmp_path / "dist",
        state,
        probe_runner=probe,
        verified_pool_path=active_path,
        failed_pool_path=failed_path,
    )

    assert result.success is True
    active = json.loads(active_path.read_text(encoding="utf-8"))
    failed_doc = json.loads(failed_path.read_text(encoding="utf-8"))
    assert [entry["node"]["name"] for entry in active["nodes"]] == [
        "[fixture] candidate"
    ]
    assert [entry["node"]["name"] for entry in failed_doc["nodes"]] == ["old"]
    assert failed_doc["nodes"][0]["consecutive_failures"] == 2
    assert failed_doc["nodes"][0]["total_failures"] == 2
    manifest = json.loads(
        (tmp_path / "dist" / "manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["verification"]["failed_pool_evicted_active"] == 1
    assert manifest["verification"]["pool_recovered"] == 0


def test_pipeline_promotes_due_failed_node_back_to_active_pool(tmp_path: Path) -> None:
    source = tmp_path / "source.yaml"
    source.write_text(
        yaml.safe_dump({"proxies": [node("candidate")]}, sort_keys=False),
        encoding="utf-8",
    )
    config = tmp_path / "sources.yaml"
    config.write_text(
        yaml.safe_dump(
            {
                "settings": {
                    "active_probe": True,
                    "probe_max_nodes": 2,
                    "filters": {"min_quality_score": 0},
                },
                "sources": {
                    "public": [
                        {
                            "id": "fixture",
                            "path": str(source),
                            "enabled": True,
                            "publish": True,
                            "requires_review": False,
                        }
                    ],
                    "private": [],
                },
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    retry = node("[fixture] retry")
    state = tmp_path / "state"
    state.mkdir()
    active_path = state / "verified-pool.json"
    active_path.write_text(
        json.dumps(pool_document([], "2026-10-14T00:00:00Z")), encoding="utf-8"
    )
    failed_path = state / "failed-pool.json"
    failed_entry = merge_failed_pool(
        [],
        [retry],
        {node_key(retry): failed(retry)},
        {node_key(retry): "fixture"},
        [],
        now="2026-10-14T00:00:00Z",
        min_verdict="stable",
        verified_min_rounds=3,
        stable_min_rounds=3,
        stable_success_rate=2 / 3,
        fast_latency_ms=800,
    )[0][0]
    failed_entry["next_retry_at"] = "2026-10-13T23:00:00Z"
    failed_path.write_text(
        json.dumps(failed_pool_document([failed_entry], "2026-10-14T00:00:00Z")),
        encoding="utf-8",
    )
    source.write_text(
        yaml.safe_dump(
            {"proxies": [node("candidate"), node("retry")]}, sort_keys=False
        ),
        encoding="utf-8",
    )

    def probe(nodes: list[dict[str, object]]) -> dict[str, object]:
        return {
            "status": "performed",
            "tested": len(nodes),
            "results": [passed(n) for n in nodes],
        }

    result = run_pipeline(
        config,
        tmp_path / "dist",
        state,
        probe_runner=probe,
        verified_pool_path=active_path,
        failed_pool_path=failed_path,
    )

    assert result.success is True
    active = json.loads(active_path.read_text(encoding="utf-8"))
    failed_doc = json.loads(failed_path.read_text(encoding="utf-8"))
    assert {entry["node"]["name"] for entry in active["nodes"]} == {
        "[fixture] retry",
        "[fixture] candidate",
    }
    assert failed_doc["nodes"] == []
    manifest = json.loads(
        (tmp_path / "dist" / "manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["verification"]["failed_pool_promoted"] == 1
    assert manifest["verification"]["pool_recovered"] == 1


def test_probe_budget_keeps_new_candidates_when_pools_nearly_fill_budget(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.yaml"
    source.write_text(
        yaml.safe_dump(
            {"proxies": [node(f"candidate-{index}") for index in range(4)]},
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    config = tmp_path / "sources.yaml"
    config.write_text(
        yaml.safe_dump(
            {
                "settings": {
                    "active_probe": True,
                    "probe_max_nodes": 4,
                    "filters": {"min_quality_score": 0},
                },
                "sources": {
                    "public": [
                        {
                            "id": "fixture",
                            "path": str(source),
                            "enabled": True,
                            "publish": True,
                            "requires_review": False,
                        }
                    ],
                    "private": [],
                },
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    state = tmp_path / "state"
    state.mkdir()
    active_nodes = [node(f"old-{index}") for index in range(3)]
    active_path = state / "verified-pool.json"
    active_path.write_text(
        json.dumps(
            pool_document(
                [
                    {
                        "key": node_key(active_node),
                        "node": active_node,
                        "source_id": "old-source",
                        "first_seen_at": "2026-10-14T00:00:00Z",
                        "last_rechecked_at": "2026-10-14T00:10:00Z",
                        "last_conclusion": "stable",
                        "consecutive_failures": 0,
                        "total_passes": 1,
                    }
                    for active_node in active_nodes
                ],
                "2026-10-14T00:10:00Z",
            )
        ),
        encoding="utf-8",
    )
    retry = node("[fixture] retry")
    failed_entry = merge_failed_pool(
        [],
        [retry],
        {node_key(retry): failed(retry)},
        {node_key(retry): "fixture"},
        [],
        now="2026-10-14T00:00:00Z",
        min_verdict="stable",
        verified_min_rounds=3,
        stable_min_rounds=3,
        stable_success_rate=2 / 3,
        fast_latency_ms=800,
    )[0][0]
    failed_entry["next_retry_at"] = "2026-10-13T23:00:00Z"
    failed_path = state / "failed-pool.json"
    failed_path.write_text(
        json.dumps(failed_pool_document([failed_entry], "2026-10-14T00:00:00Z")),
        encoding="utf-8",
    )
    seen: list[list[str]] = []

    def probe(nodes: list[dict[str, object]]) -> dict[str, object]:
        seen.append([str(item["name"]) for item in nodes])
        return {
            "status": "performed",
            "tested": len(nodes),
            "results": [passed(item) for item in nodes],
        }

    result = run_pipeline(
        config,
        tmp_path / "dist",
        state,
        probe_runner=probe,
        verified_pool_path=active_path,
        failed_pool_path=failed_path,
    )

    assert result.success is True
    assert len(seen[0]) == 4
    manifest = json.loads(
        (tmp_path / "dist" / "manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["verification"]["pool_probe_candidates"] == 2
    assert manifest["verification"]["failed_pool_due"] == 1
    assert manifest["verification"]["new_candidates_tested"] == 1
