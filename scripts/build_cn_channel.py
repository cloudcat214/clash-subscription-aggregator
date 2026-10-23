"""Build the /cn channel: current published nodes filtered by mainland feedback.

The feedback file (``cn-feedback/latest.json``) is produced by a one-shot local
probe (``scripts/cn_feedback_probe.py`` via ``scripts/refresh-cn-feedback.ps1``)
and committed to the repository. This builder intersects its stable keys with
the freshly generated cloud set and renders a standalone Clash config for the
``/cn`` subscription. It never invents data: no feedback, no rebuild.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from aggregator.outputs import render_artifacts
from aggregator.quality import node_key

FEEDBACK_SCHEMA_VERSION = 1
MIN_SELECTED = 1
# The client audit rewrites blocked.json on every run, so this TTL also acts as
# an automatic renewal: an entry only dies if no audit has refreshed it for
# three days (i.e. the node is no longer in the locally loaded profile).
BLOCKED_TTL_HOURS = 72
DEFAULT_MAX_NODES = 400
MAX_NODES_CEILING = 800
REQUIRED_NODE_FIELDS = ("name", "type", "server", "port")


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def load_feedback(path: Path) -> dict[str, object] | None:
    """Load and validate the feedback document; None means unusable."""
    if not path.is_file():
        return None
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(document, dict):
        return None
    if document.get("schema_version") != FEEDBACK_SCHEMA_VERSION:
        return None
    keys = document.get("stable_keys")
    if not isinstance(keys, list) or not all(
        isinstance(item, str) and item for item in keys
    ):
        return None
    return document


def _feedback_keys(document: dict[str, object]) -> set[str]:
    keys = document.get("stable_keys")
    assert isinstance(keys, list)
    return {str(item) for item in keys}


def _feedback_meta(document: dict[str, object]) -> dict[str, object]:
    meta: dict[str, object] = {"keys": len(_feedback_keys(document))}
    feedback_time = _parse_time(document.get("generated_at"))
    if feedback_time is not None:
        meta["generated_at"] = (
            feedback_time.astimezone(UTC).isoformat().replace("+00:00", "Z")
        )
        age_hours = (datetime.now(UTC) - feedback_time).total_seconds() / 3600
        meta["age_hours"] = round(max(0.0, age_hours), 1)
    for field in ("tested", "stable", "verified"):
        value = document.get(field)
        if isinstance(value, int) and not isinstance(value, bool):
            meta[field] = value
    return meta


def load_blocked(
    path: Path | None,
    proxies: list[dict[str, object]] | None = None,
    *,
    now: datetime | None = None,
) -> set[str]:
    """Return the blocked node keys that still apply.

    ``blocked.json`` stores node *names* (a name is only meaningful for the
    client profile that produced it) plus an expiry stamp. Names are mapped onto
    the current candidate set here, so a blocked entry survives the name-based
    identity problem and expires instead of lasting forever.
    """
    info = blocked_info(path, now=now)
    return _blocked_keys(info, proxies or [])


def _split_timezone(moment: datetime) -> datetime:
    return moment.replace(tzinfo=UTC) if moment.tzinfo is None else moment


def blocked_info(
    path: Path | None, *, now: datetime | None = None
) -> dict[str, object]:
    """Resolve whether a blocklist applies, and why it does not.

    An entry is ignored entirely when it has no usable expiry. That covers the
    legacy ``{"keys": [...]}`` form (no ttl, would otherwise block forever) and
    an expired ``expires_at``. When ``expires_at`` is missing, it is derived
    from ``generated_at + ttl_hours`` so hand-written files still work.
    """
    info: dict[str, object] = {
        "applied": False,
        "reason": None,
        "names": [],
        "expires_at": None,
        "ttl_hours": BLOCKED_TTL_HOURS,
    }
    if path is None:
        info["reason"] = "not_configured"
        return info
    if not path.is_file():
        info["reason"] = "missing"
        return info
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        info["reason"] = "unreadable"
        return info
    if not isinstance(document, dict):
        info["reason"] = "invalid_document"
        return info

    names = document.get("names")
    if not isinstance(names, list):
        info["reason"] = "no_names"
        return info
    ttl_hours = float(BLOCKED_TTL_HOURS)
    ttl = document.get("ttl_hours")
    if isinstance(ttl, (int, float)) and not isinstance(ttl, bool):
        ttl_hours = float(ttl)
    info["ttl_hours"] = ttl_hours

    expires_at = _parse_time(document.get("expires_at"))
    if expires_at is None:
        generated_at = _parse_time(document.get("generated_at"))
        if generated_at is not None:
            expires_at = generated_at + timedelta(hours=ttl_hours)
    if expires_at is None:
        info["reason"] = "no_expiry"
        return info
    expires_at = _split_timezone(expires_at)
    info["expires_at"] = expires_at

    moment = _split_timezone(now) if now is not None else datetime.now(UTC)
    if expires_at <= moment:
        info["reason"] = "expired"
        return info
    info["applied"] = True
    info["names"] = [item for item in names if isinstance(item, str) and item]
    return info


def _blocked_keys(
    info: dict[str, object], proxies: list[dict[str, object]]
) -> set[str]:
    if not info["applied"]:
        return set()
    names = info["names"]
    assert isinstance(names, list)
    key_by_name = {
        str(proxy["name"]): node_key(proxy)
        for proxy in proxies
        if isinstance(proxy.get("name"), str)
    }
    return {key_by_name[str(name)] for name in names if str(name) in key_by_name}


def _blocked_meta(info: dict[str, object], matched: int) -> dict[str, object]:
    meta: dict[str, object] = {
        "applied": info["applied"],
        "matched_keys": matched,
        "ttl_hours": info["ttl_hours"],
        "names": len(info["names"]) if isinstance(info["names"], list) else 0,
    }
    expires_at = info["expires_at"]
    if isinstance(expires_at, datetime):
        meta["expires_at"] = (
            expires_at.astimezone(UTC).isoformat().replace("+00:00", "Z")
        )
    if info["reason"] is not None:
        meta["skipped_reason"] = info["reason"]
    return meta


def _valid_snapshot_node(node: object) -> bool:
    """A snapshot is renderable only when every mandatory Clash field is present."""
    if not isinstance(node, dict):
        return False
    name = node.get("name")
    node_type = node.get("type")
    server = node.get("server")
    port = node.get("port")
    if not (isinstance(name, str) and name.strip()):
        return False
    if not (isinstance(node_type, str) and node_type.strip()):
        return False
    if not (isinstance(server, str) and server.strip()):
        return False
    if isinstance(port, bool):
        return False
    if isinstance(port, int):
        return port > 0
    if isinstance(port, str):
        return port.isdigit() and int(port) > 0
    return False


def _load_snapshot_nodes(
    documents: list[dict[str, object]],
) -> tuple[dict[str, dict[str, object]], int]:
    """Collect full node snapshots carried by feedback documents.

    Only nodes whose recomputed key matches the stored key are accepted, so a
    snapshot written under an older identity algorithm is skipped instead of
    silently attaching to the wrong node.
    """
    nodes: dict[str, dict[str, object]] = {}
    invalid = 0
    for document in documents:
        raw = document.get("nodes")
        if not isinstance(raw, dict):
            continue
        for key, node in raw.items():
            if not isinstance(key, str) or not _valid_snapshot_node(node):
                invalid += 1
                continue
            assert isinstance(node, dict)
            if node_key(node) != key:
                invalid += 1
                continue
            nodes.setdefault(key, node)
    return nodes, invalid


def build_cn_channel(
    dist_dir: Path,
    feedback_path: Path,
    output_dir: Path,
    extra_feedback_path: Path | None = None,
    blocked_path: Path | None = None,
    *,
    max_nodes: int = DEFAULT_MAX_NODES,
) -> dict[str, object]:
    feedback = load_feedback(feedback_path)
    extra_feedback = (
        load_feedback(extra_feedback_path) if extra_feedback_path is not None else None
    )
    if feedback is None and extra_feedback is None:
        return {"status": "skipped", "reason": "feedback_missing_or_invalid"}

    config_path = dist_dir / "clash" / "config.yaml"
    if not config_path.is_file():
        return {"status": "skipped", "reason": "dist_config_missing"}
    try:
        document = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return {"status": "skipped", "reason": "dist_config_unreadable"}
    proxies = document.get("proxies") if isinstance(document, dict) else None
    if not isinstance(proxies, list) or not proxies:
        return {"status": "skipped", "reason": "dist_proxies_missing"}
    valid_proxies = [
        proxy for proxy in proxies if isinstance(proxy, dict) and proxy.get("name")
    ]

    keys: set[str] = set()
    feedback_documents = [
        document for document in (feedback, extra_feedback) if document is not None
    ]
    for feedback_document in feedback_documents:
        keys |= _feedback_keys(feedback_document)
    snapshots, snapshot_invalid = _load_snapshot_nodes(feedback_documents)

    blocked_document = blocked_info(blocked_path)
    blocked: set[str] = set()
    if not blocked_document["applied"] and blocked_path is not None:
        reason = blocked_document["reason"]
        expires = blocked_document["expires_at"]
        suffix = f" expires_at={expires}" if isinstance(expires, datetime) else ""
        print(f"[cn-blocked] skipped: {reason}{suffix}", flush=True)

    published: list[dict[str, object]] = []
    published_keys: set[str] = set()
    for proxy in valid_proxies:
        key = node_key(proxy)
        if key in keys:
            published.append(proxy)
            published_keys.add(key)
    blocked = _blocked_keys(blocked_document, [*valid_proxies, *snapshots.values()])

    selected = [proxy for proxy in published if node_key(proxy) not in blocked]
    used_names = {str(proxy.get("name")) for proxy in selected}
    from_snapshot = 0
    name_conflicts = 0
    for key in sorted(snapshots):
        if key not in keys or key in published_keys or key in blocked:
            continue
        node = snapshots[key]
        name = str(node.get("name"))
        if name in used_names:
            name_conflicts += 1
            continue
        selected.append(node)
        used_names.add(name)
        from_snapshot += 1

    budget = max(1, min(MAX_NODES_CEILING, max_nodes))
    selected = selected[:budget]
    if len(selected) < MIN_SELECTED:
        return {
            "status": "skipped",
            "reason": "no_selected_nodes",
            "source_published": len(valid_proxies),
        }
    from_published = min(len(selected), len(published))
    from_snapshot = min(from_snapshot, len(selected) - from_published)

    manifest: dict[str, object] = {
        "schema_version": 1,
        "generated_at": _utc_now(),
        "filter": "cn-feedback",
        "blocked_applied": bool(blocked_document["applied"]),
        "blocked_expires_at": (
            blocked_document["expires_at"]
            .astimezone(UTC)
            .isoformat()
            .replace("+00:00", "Z")
            if isinstance(blocked_document["expires_at"], datetime)
            else None
        ),
        "counts": {
            "source_published": len(valid_proxies),
            "selected": len(selected),
            "from_published": from_published,
            "from_snapshot": from_snapshot,
            "snapshot_invalid": snapshot_invalid,
            "snapshot_name_conflicts": name_conflicts,
            "max_nodes": budget,
            "blocked_keys": len(blocked),
        },
    }
    if feedback is not None:
        manifest["feedback"] = _feedback_meta(feedback)
    if extra_feedback is not None:
        manifest["feedback_extra"] = _feedback_meta(extra_feedback)
    if blocked_path is not None:
        manifest["blocked"] = _blocked_meta(blocked_document, len(blocked))

    artifacts = render_artifacts(selected)
    if output_dir.exists():
        shutil.rmtree(output_dir)
    (output_dir / "clash").mkdir(parents=True)
    (output_dir / "clash" / "config.yaml").write_text(
        artifacts["clash/config.yaml"], encoding="utf-8"
    )
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return {"status": "built", "selected": len(selected), "manifest": manifest}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist-dir", type=Path, default=ROOT / "dist-auto")
    parser.add_argument(
        "--feedback", type=Path, default=ROOT / "cn-feedback" / "latest.json"
    )
    parser.add_argument(
        "--feedback-extra",
        type=Path,
        default=None,
        help="可选的第二份反馈（如云端大陆 TCP 预筛结果），与 --feedback 取并集",
    )
    parser.add_argument(
        "--blocked",
        type=Path,
        default=None,
        help="可选黑名单（客户端审计两次均失败的节点 key），从发布集合中剔除",
    )
    parser.add_argument("--output", type=Path, default=ROOT / "docs" / "cn")
    parser.add_argument(
        "--max-nodes",
        type=int,
        default=DEFAULT_MAX_NODES,
        help=(
            f"/cn 输出上限（默认 {DEFAULT_MAX_NODES}，最大 {MAX_NODES_CEILING}）；"
            "超限时优先保留当前发布集内的节点"
        ),
    )
    args = parser.parse_args()

    result = build_cn_channel(
        args.dist_dir,
        args.feedback,
        args.output,
        args.feedback_extra,
        args.blocked,
        max_nodes=args.max_nodes,
    )
    if result.get("status") == "built":
        counts = result["manifest"]["counts"]  # type: ignore[index]
        manifest = result["manifest"]  # type: ignore[assignment]
        feedback_meta = manifest.get("feedback", {})  # type: ignore[union-attr]
        extra_meta = manifest.get("feedback_extra", {})  # type: ignore[union-attr]
        blocked_applied = manifest["blocked_applied"]  # type: ignore[index]
        print(
            f"cn channel built: selected={counts['selected']} "
            f"(from_published={counts['from_published']} "
            f"from_snapshot={counts['from_snapshot']}) of "
            f"{counts['source_published']} "
            f"blocked_applied={blocked_applied} "
            f"feedback_stable={feedback_meta.get('stable')} "
            f"extra_stable={extra_meta.get('stable')} "
            f"age_hours={feedback_meta.get('age_hours')}"
        )
        return 0
    print(f"cn channel skipped: {result.get('reason')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
