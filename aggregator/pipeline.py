from __future__ import annotations

import hashlib
import json
import math
import os
import shutil
import subprocess
import tempfile
import uuid
from collections import Counter
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit

import yaml

from .fastprobe import TARGET_URL as FASTPROBE_TARGET_URL
from .fetch import FetchError, fetch_http_source_with_meta
from .outputs import render_artifacts
from .parsing import (
    ParseError,
    deduplicate_proxies,
    filter_proxies,
    normalize_proxies_with_drops,
    parse_source_payload_with_drops,
    quality_score,
)
from .probe import DEFAULT_TARGET_URL, PROBE_ERROR_CATEGORIES
from .quality import classify_node, node_key, probe_verdict, select_published
from .validators import CoreValidationError


class SourceError(RuntimeError):
    """Raised when a source cannot be loaded without exposing source details."""


@dataclass
class SourceResult:
    id: str
    kind: str
    status: str
    parsed: int = 0
    accepted: int = 0
    error: str | None = None
    drops: dict[str, int] = field(default_factory=dict)
    cached: bool = False
    source_repo: str | None = None
    license: str | None = None
    evidence: str | None = None
    publicly_offered: bool | None = None
    sha256: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            key: value
            for key, value in asdict(self).items()
            if value is not None and value != {} and value is not False
        }


@dataclass
class PipelineResult:
    success: bool
    used_last_known_good: bool = False
    failure_reason: str = ""
    manifest_path: Path | None = None
    health_path: Path | None = None
    source_results: list[SourceResult] = field(default_factory=list)
    private_manifest_path: Path | None = None


SourceLoader = Callable[[dict[str, Any], Path, dict[str, Any], bool], str]
ArtifactValidator = Callable[[Path], dict[str, Any]]
ProbeRunner = Callable[[list[dict[str, object]]], dict[str, object]]

_PROBE_BACKEND_CAPS = {
    "spawn": {"max_nodes": 500, "concurrency": 8},
    "delay": {"max_nodes": 2000, "concurrency": 16},
}


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_config(config_path: Path) -> dict[str, Any]:
    try:
        document = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise SourceError("configuration could not be read") from exc
    if not isinstance(document, dict):
        raise SourceError("configuration root must be a mapping")
    return document


def _source_entries(config: dict[str, Any]) -> list[dict[str, Any]]:
    sources = config.get("sources") or {}
    if not isinstance(sources, dict):
        raise SourceError("sources must be a mapping")
    entries: list[dict[str, Any]] = []
    for kind in ("public", "private"):
        values = sources.get(kind) or []
        if not isinstance(values, list):
            raise SourceError(f"sources.{kind} must be a list")
        for source in values:
            if not isinstance(source, dict):
                raise SourceError("source entry must be a mapping")
            entry = dict(source)
            entry["kind"] = kind
            entries.append(entry)
    return entries


def _read_file(path: Path, max_bytes: int) -> str:
    try:
        body = path.read_bytes()
    except OSError as exc:
        raise SourceError(type(exc).__name__) from exc
    if len(body) > max_bytes:
        raise SourceError("source payload exceeds configured size limit")
    try:
        return body.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise SourceError("source payload is not UTF-8") from exc


def _source_cache_path(source: dict[str, Any], settings: dict[str, Any]) -> Path | None:
    cache_root = settings.get("_source_cache_dir")
    if not cache_root:
        return None
    source_id = str(source.get("id") or "unnamed")
    cache_key = hashlib.sha256(source_id.encode("utf-8")).hexdigest()[:24]
    return Path(str(cache_root)) / f"{cache_key}.json"


def _read_source_cache(
    source: dict[str, Any], settings: dict[str, Any]
) -> dict[str, object] | None:
    path = _source_cache_path(source, settings)
    if path is None or not path.is_file():
        return None
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return (
        document
        if isinstance(document, dict) and isinstance(document.get("payload"), str)
        else None
    )


def _cache_source_payload(
    source: dict[str, Any], settings: dict[str, Any], payload: str
) -> None:
    path = _source_cache_path(source, settings)
    if path is None:
        return
    fetch_meta = settings.get("_fetch_meta", {})
    meta = (
        fetch_meta.get(str(source.get("id") or "unnamed"), {})
        if isinstance(fetch_meta, dict)
        else {}
    )
    document = {
        "payload": payload,
        "etag": meta.get("etag") if isinstance(meta, dict) else None,
        "last_modified": meta.get("last-modified") if isinstance(meta, dict) else None,
    }
    _write_json_direct(path, document)


def load_source(
    source: dict[str, Any],
    config_dir: Path,
    settings: dict[str, Any],
    offline: bool = False,
) -> str:
    max_bytes = int(settings.get("max_payload_bytes", 5 * 1024 * 1024))
    timeout = float(settings.get("timeout_seconds", 15))
    retries = int(settings.get("retries", 2))
    backoff_seconds = float(settings.get("retry_backoff_seconds", 0.5))
    max_redirects = int(settings.get("max_redirects", 3))
    allowed_hosts = {
        str(host).strip().rstrip(".").lower()
        for host in settings.get("allowed_source_hosts", [])
        if str(host).strip()
    }
    trust_hosts = {
        str(host).strip().rstrip(".").lower()
        for host in settings.get("trust_hosts", [])
        if str(host).strip()
    }
    controlled_proxy_addresses = {
        str(address).strip()
        for address in settings.get("controlled_proxy_addresses", [])
        if str(address).strip()
    }

    def fetch(url: str, source_id: str) -> str:
        try:
            payload, meta = fetch_http_source_with_meta(
                url,
                timeout,
                max_bytes,
                allowed_hosts=allowed_hosts,
                trust_hosts=trust_hosts,
                controlled_proxy_addresses=controlled_proxy_addresses,
                retries=retries,
                backoff_seconds=backoff_seconds,
                max_redirects=max_redirects,
                request_headers=request_headers,
                cached_payload=cache_payload,
            )
        except FetchError as exc:
            raise SourceError(str(exc)) from exc
        settings.setdefault("_fetch_meta", {})[source_id] = meta
        return payload

    if source.get("path"):
        path = Path(str(source["path"]))
        if not path.is_absolute():
            path = config_dir / path
        return _read_file(path, max_bytes)
    if source.get("url"):
        if offline:
            raise SourceError("offline_mode")
        cache = _read_source_cache(source, settings)
        cache_payload = str(cache["payload"]) if cache else None
        request_headers: dict[str, str] = {}
        if cache and cache.get("etag"):
            request_headers["If-None-Match"] = str(cache["etag"])
        if cache and cache.get("last_modified"):
            request_headers["If-Modified-Since"] = str(cache["last_modified"])
        return fetch(str(source["url"]), str(source.get("id") or "unnamed"))
    if source.get("env"):
        env_name = str(source["env"])
        value = os.environ.get(env_name, "").strip()
        if not value:
            raise SourceError("source environment variable is empty")
        parsed = urlsplit(value)
        if parsed.scheme in {"http", "https"}:
            if offline:
                raise SourceError("offline_mode")
            cache = _read_source_cache(source, settings)
            cache_payload = str(cache["payload"]) if cache else None
            request_headers: dict[str, str] = {}
            if cache and cache.get("etag"):
                request_headers["If-None-Match"] = str(cache["etag"])
            if cache and cache.get("last_modified"):
                request_headers["If-Modified-Since"] = str(cache["last_modified"])
            return fetch(value, str(source.get("id") or "unnamed"))
        path = Path(value)
        if path.is_file():
            return _read_file(path, max_bytes)
        raise SourceError(
            "source environment value must be an HTTP(S) URL or file path"
        )
    raise SourceError("source has no url, path, or env")


def _safe_error(exc: Exception) -> str:
    return type(exc).__name__


def _settings(config: dict[str, Any]) -> dict[str, Any]:
    settings = config.get("settings") or {}
    if not isinstance(settings, dict):
        raise SourceError("settings must be a mapping")
    return settings


def _filtered_source_nodes(
    raw_nodes: list[dict[str, object]], settings: dict[str, Any]
) -> tuple[list[dict[str, object]], dict[str, int]]:
    normalized, drops = normalize_proxies_with_drops(raw_nodes)
    filters = settings.get("filters") or {}
    if not isinstance(filters, dict):
        raise SourceError("settings.filters must be a mapping")
    filtered = filter_proxies(
        normalized,
        allow_protocols=filters.get("allow_protocols", []),
        deny_protocols=filters.get("deny_protocols", []),
        deny_name_keywords=filters.get("deny_name_keywords", []),
        min_quality_score=int(filters.get("min_quality_score", 0)),
    )
    removed = len(normalized) - len(filtered)
    if removed:
        drops["filtered_by_policy"] = drops.get("filtered_by_policy", 0) + removed
    return filtered, drops


def _tag_source_nodes(
    nodes: list[dict[str, object]], source_id: str
) -> list[dict[str, object]]:
    tag = (
        "".join(
            character if character.isalnum() or character in "-_" else "-"
            for character in source_id
        ).strip("-")
        or "source"
    )
    tagged: list[dict[str, object]] = []
    for node in nodes:
        copy_node = dict(node)
        copy_node["name"] = f"[{tag}] {copy_node.get('name') or 'proxy'!s}"
        tagged.append(copy_node)
    return tagged


def _merge_drop_counts(target: dict[str, int], *sources: dict[str, int]) -> None:
    for source in sources:
        for reason, count in source.items():
            target[reason] = target.get(reason, 0) + count


def _sort_and_limit(
    proxies: list[dict[str, object]],
    settings: dict[str, Any],
    drops: dict[str, int] | None = None,
) -> list[dict[str, object]]:
    unique = deduplicate_proxies(proxies)
    duplicate_count = len(proxies) - len(unique)
    if drops is not None and duplicate_count:
        drops["duplicate"] = drops.get("duplicate", 0) + duplicate_count
    unique.sort(
        key=lambda proxy: (-quality_score(proxy), str(proxy.get("name", "")).casefold())
    )
    used_names: set[str] = set()
    for proxy in unique:
        original = str(proxy.get("name") or "proxy")
        name = original
        suffix = 2
        while name in used_names:
            name = f"{original}-{suffix}"
            suffix += 1
        proxy["name"] = name
        used_names.add(name)
    max_nodes = int(settings.get("max_nodes", 0) or 0)
    limited = unique[:max_nodes] if max_nodes > 0 else unique
    if drops is not None and len(limited) < len(unique):
        drops["max_nodes"] = drops.get("max_nodes", 0) + len(unique) - len(limited)
    return limited


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _empty_node_quality(
    candidates: int,
    *,
    published: int = 0,
    dropped: int = 0,
    not_tested_budget: int = 0,
    failed_probe: int = 0,
    below_quality_threshold: int = 0,
) -> dict[str, object]:
    return {
        "candidates": candidates,
        "tested": 0,
        "verified": 0,
        "fast": 0,
        "stable": 0,
        "failed": 0,
        "not_tested": candidates,
        "not_tested_budget": not_tested_budget,
        "failed_probe": failed_probe,
        "below_quality_threshold": below_quality_threshold,
        "dropped": dropped,
        "published": published,
        "success_rate": None,
    }


def _probe_error_category(exc: Exception) -> str:
    core_categories = {
        "probe_process_start_failed": "process_start_error",
        "probe_process_exited": "process_exit",
        "probe_controller_timeout": "controller_timeout",
        "probe_controller_auth_failed": "controller_auth_error",
        "probe_controller_http_error": "controller_http_error",
        "probe_direct_control_failed": "probe_direct_control_failed",
        "probe_interface_invalid": "probe_interface_invalid",
        "probe_interface_required": "probe_interface_required",
    }
    if isinstance(exc, CoreValidationError):
        return core_categories.get(str(exc), "core_validation_error")
    if isinstance(exc, (TimeoutError, subprocess.TimeoutExpired)):
        return "timeout"
    if isinstance(exc, OSError):
        return "network_error"
    if isinstance(exc, ValueError):
        return "invalid_probe_result"
    return "probe_error"


def _probe_policy(settings: dict[str, Any]) -> dict[str, object]:
    backend = str(settings.get("probe_backend", "spawn"))
    caps = _PROBE_BACKEND_CAPS.get(backend)
    if caps is None:
        raise ValueError("invalid_probe_policy")
    if backend == "delay":
        interface = settings.get("probe_interface")
        if not isinstance(interface, str):
            raise ValueError("probe_interface_invalid")
        if not interface.strip():
            raise ValueError("probe_interface_required")
    minimum = str(settings.get("probe_min_verdict", "stable"))
    if minimum not in {"stable", "verified", "fast"}:
        raise ValueError("invalid_probe_min_verdict")

    def bounded_int(name: str, default: int, maximum: int) -> int:
        value = settings.get(name, default)
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError("invalid_probe_policy")
        return max(1, min(value, maximum))

    for name, default, maximum in (
        ("probe_max_nodes", 30, int(caps["max_nodes"])),
        ("probe_concurrency", 1, int(caps["concurrency"])),
        ("probe_publish_max_nodes", 30, 500),
    ):
        value = settings.get(name, default)
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError("invalid_probe_policy")
        if value > maximum:
            raise ValueError("probe_parameters_over_budget")

    try:
        stable_rate = float(settings.get("probe_min_success_rate", 2 / 3))
        fast_latency = float(settings.get("probe_fast_latency_ms", 800.0))
        latency_cap = float(settings.get("probe_score_latency_cap_ms", 5000.0))
        timeout_seconds = float(settings.get("probe_timeout_seconds", 10.0))
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid_probe_policy") from exc
    if (
        not math.isfinite(stable_rate)
        or not 0 < stable_rate <= 1
        or not math.isfinite(fast_latency)
        or fast_latency <= 0
        or not math.isfinite(latency_cap)
        or latency_cap <= 0
        or not math.isfinite(timeout_seconds)
        or not 0 < timeout_seconds <= 30
    ):
        raise ValueError("invalid_probe_policy")
    probe_rounds = bounded_int("probe_rounds", 3, 3)
    verified_min_rounds = bounded_int("probe_verified_min_rounds", 3, 3)
    stable_min_rounds = bounded_int("probe_stable_min_rounds", 3, 3)
    if probe_rounds < stable_min_rounds:
        raise ValueError("probe_rounds_below_stable_min_rounds")
    if probe_rounds < verified_min_rounds:
        raise ValueError("probe_rounds_below_verified_min_rounds")
    return {
        "backend": backend,
        "max_nodes_cap": int(caps["max_nodes"]),
        "concurrency_cap": int(caps["concurrency"]),
        "min_verdict": minimum,
        "probe_max_nodes": bounded_int("probe_max_nodes", 30, int(caps["max_nodes"])),
        "probe_rounds": probe_rounds,
        "probe_concurrency": bounded_int(
            "probe_concurrency", 1, int(caps["concurrency"])
        ),
        "probe_timeout_seconds": timeout_seconds,
        "verified_min_rounds": verified_min_rounds,
        "stable_min_rounds": stable_min_rounds,
        "stable_success_rate": stable_rate,
        "fast_latency_ms": fast_latency,
        "latency_cap_ms": latency_cap,
        "publish_max_nodes": bounded_int("probe_publish_max_nodes", 30, 500),
    }


def _normalize_probe_rows(
    raw: object,
    candidates: list[dict[str, object]],
    *,
    rounds_default: int,
    policy: dict[str, object],
) -> tuple[dict[str, dict[str, object]], list[dict[str, object]]]:
    by_name = {str(node.get("name") or ""): node for node in candidates}
    by_key = {node_key(node): node for node in candidates}
    if isinstance(raw, dict):
        raw_rows: list[dict[str, object]] = []
        for identity, value in raw.items():
            if not isinstance(value, dict):
                raise TypeError("probe_results_invalid")
            row = dict(value)
            if identity in by_name:
                row.setdefault("name", identity)
            else:
                row.setdefault("node_key", identity)
            raw_rows.append(row)
    elif isinstance(raw, list):
        if any(not isinstance(row, dict) for row in raw):
            raise ValueError("probe_results_invalid")
        raw_rows = [dict(row) for row in raw]
    else:
        raise TypeError("probe_results_invalid")
    if len(raw_rows) > 500:
        raise ValueError("probe_results_over_budget")

    normalized: dict[str, dict[str, object]] = {}
    rows: list[dict[str, object]] = []
    allowed_errors = set(PROBE_ERROR_CATEGORIES)
    for row in raw_rows:
        name = row.get("name")
        key = row.get("node_key", row.get("name_hash"))
        node = by_name.get(name) if isinstance(name, str) else None
        if node is None and isinstance(key, str):
            node = by_key.get(key)
        if node is None:
            raise TypeError("probe_results_invalid")
        normalized_name = str(node.get("name") or "")
        if normalized_name in normalized:
            raise ValueError("probe_results_duplicate")
        passed = row.get("rounds_passed")
        total = row.get("rounds_total", row.get("rounds", rounds_default))
        if (
            isinstance(passed, bool)
            or not isinstance(passed, int)
            or isinstance(total, bool)
            or not isinstance(total, int)
            or passed < 0
            or total < 1
            or passed > total
        ):
            raise TypeError("probe_results_invalid")
        raw_error = row.get("error_category")
        error_category = None
        if raw_error:
            error_category = (
                raw_error
                if isinstance(raw_error, str) and raw_error in allowed_errors
                else "probe_error"
            )
        latency_value = row.get("latency_ms")
        p95_value = row.get("p95_latency_ms")
        latency = (
            float(latency_value)
            if isinstance(latency_value, (int, float))
            and not isinstance(latency_value, bool)
            else None
        )
        p95 = (
            float(p95_value)
            if isinstance(p95_value, (int, float)) and not isinstance(p95_value, bool)
            else None
        )
        verdict = probe_verdict(
            passed,
            total,
            latency,
            p95_latency_ms=p95,
            verified_min_rounds=cast(int, policy["verified_min_rounds"]),
            stable_min_rounds=cast(int, policy["stable_min_rounds"]),
            stable_success_rate=cast(float, policy["stable_success_rate"]),
            fast_latency_ms=cast(float, policy["fast_latency_ms"]),
            error_category=error_category,
        )
        verdict["node_key"] = node_key(node)
        normalized[normalized_name] = verdict
        rows.append(verdict)
    return normalized, rows


def _node_quality_counts(
    candidates: int,
    rows: list[dict[str, object]],
    published: int,
    policy: dict[str, object],
    *,
    not_tested_budget: int,
) -> dict[str, object]:
    statuses = [
        classify_node(
            {},
            row,
            verified_min_rounds=cast(int, policy["verified_min_rounds"]),
            stable_min_rounds=cast(int, policy["stable_min_rounds"]),
            stable_success_rate=cast(float, policy["stable_success_rate"]),
            fast_latency_ms=cast(float, policy["fast_latency_ms"]),
        )
        for row in rows
    ]
    failed_probe = sum(1 for row in rows if cast(int, row["rounds_passed"]) == 0)
    below_quality_threshold = sum(
        1
        for row, status in zip(rows, statuses)
        if status == "failed" and cast(int, row["rounds_passed"]) > 0
    )
    passed = sum(cast(int, row["rounds_passed"]) for row in rows)
    total = sum(cast(int, row["rounds_total"]) for row in rows)
    return {
        "candidates": candidates,
        "tested": len(rows),
        "verified": sum(1 for row in rows if row["verified"]),
        "fast": sum(1 for row in rows if row["fast"]),
        "stable": sum(1 for row in rows if row["stable"]),
        "failed": statuses.count("failed"),
        "not_tested": max(0, candidates - len(rows)),
        "not_tested_budget": max(0, not_tested_budget),
        "failed_probe": failed_probe,
        "below_quality_threshold": below_quality_threshold,
        "dropped": failed_probe + below_quality_threshold,
        "published": published,
        "success_rate": passed / total if total else 0.0,
    }


def build_manifest(
    *,
    status: str,
    generated_at: str,
    proxies: list[dict[str, object]],
    source_results: list[SourceResult],
    artifacts: dict[str, str],
    active_probe: bool = False,
    drops: dict[str, int] | None = None,
    sing_box: dict[str, object] | None = None,
    verification: dict[str, object] | None = None,
    node_quality: dict[str, object] | None = None,
    base_url: str | None = None,
) -> dict[str, object]:
    protocols: dict[str, int] = {}
    for proxy in proxies:
        protocol = str(proxy.get("type", "unknown"))
        protocols[protocol] = protocols.get(protocol, 0) + 1
    document: dict[str, object] = {
        "schema_version": 1,
        "generated_at": generated_at,
        "status": status,
        "active_probe": active_probe,
        "counts": {
            "published": len(proxies),
            "sources": len(source_results),
            "parsed": sum(result.parsed for result in source_results),
            "accepted": sum(result.accepted for result in source_results),
        },
        "protocols": dict(sorted(protocols.items())),
        "sources": [result.to_dict() for result in source_results],
        "artifacts": [
            {
                "path": path,
                "sha256": _sha256_text(content),
                "bytes": len(content.encode("utf-8")),
            }
            for path, content in sorted(artifacts.items())
        ],
        "drops": drops or {},
        "sing_box": sing_box or {"unsupported": 0, "drop_reasons": {}},
        "verification": verification
        or {"status": "not_tested", "reason": "active_probe_disabled"},
        "node_quality": node_quality
        or _empty_node_quality(len(proxies), published=len(proxies)),
        "limitations": [
            "HTTP(S) checks only fetch and parse the configured source.",
            "Node-level active probing is disabled and not tested in this run."
            if not active_probe
            else "Bounded active probing is evidence from this runner only.",
            "Source host addresses are pinned for each request and every HTTPS redirect is revalidated.",
        ],
    }
    if base_url:
        document["publish"] = {
            "base_url": base_url,
            "clash_config": f"{base_url.rstrip('/')}/clash/config.yaml",
            "clash_http_provider_config": f"{base_url.rstrip('/')}/clash/config-provider.yaml",
            "provider": f"{base_url.rstrip('/')}/clash/providers/aggregate.yaml",
        }
    return document


def _health_document(
    *,
    status: str,
    generated_at: str,
    source_results: list[SourceResult],
    published: int,
    fallback: str | None = None,
    active_probe: bool = False,
    validation: dict[str, object] | None = None,
    verification: dict[str, object] | None = None,
    node_quality: dict[str, object] | None = None,
) -> dict[str, object]:
    document: dict[str, object] = {
        "schema_version": 1,
        "generated_at": generated_at,
        "status": status,
        "active_probe": active_probe,
        "published": published,
        "sources": [result.to_dict() for result in source_results],
        "checks": {
            "source_fetch": "performed_for_enabled_publishable_sources",
            "node_active_probe": "performed" if active_probe else "not_tested",
        },
        "verification": verification
        or {"status": "not_tested", "reason": "active_probe_disabled"},
        "node_quality": node_quality or _empty_node_quality(0, published=published),
    }
    if fallback:
        document["fallback"] = fallback
    if validation:
        document["core_validation"] = validation
    return document


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", newline="\n", dir=path.parent, delete=False
    ) as handle:
        handle.write(content)
        temporary = Path(handle.name)
    os.replace(temporary, path)


def _write_json(path: Path, document: dict[str, object]) -> None:
    _write_text(path, json.dumps(document, ensure_ascii=False, indent=2) + "\n")


def _write_json_direct(path: Path, document: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        temporary.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink(missing_ok=True)


def _lkg_files(state_dir: Path) -> list[Path]:
    root = state_dir / "last-known-good"
    return [
        root / "clash" / "providers" / "aggregate.yaml",
        root / "clash" / "config.yaml",
        root / "sing-box" / "config.json",
        root / "manifest.json",
    ]


def _has_lkg(state_dir: Path) -> bool:
    return all(path.is_file() for path in _lkg_files(state_dir))


def _copy_release_files(source_root: Path, target_root: Path) -> None:
    for relative in (
        Path("clash/providers/aggregate.yaml"),
        Path("clash/config.yaml"),
        Path("sing-box/config.json"),
        Path("manifest.json"),
    ):
        source = source_root / relative
        target = target_root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    provider_config = source_root / "clash/config-provider.yaml"
    if provider_config.is_file():
        target = target_root / "clash/config-provider.yaml"
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(provider_config, target)


def _save_lkg(source_root: Path, state_dir: Path) -> None:
    state_dir.mkdir(parents=True, exist_ok=True)
    root = state_dir / "last-known-good"
    staging = state_dir / f".last-known-good-{uuid.uuid4().hex}.tmp"
    backup = state_dir / f".last-known-good-{uuid.uuid4().hex}.bak"
    try:
        _copy_release_files(source_root, staging)
        if root.exists():
            root.replace(backup)
        staging.replace(root)
    except OSError:
        if not root.exists() and backup.exists():
            backup.replace(root)
        raise
    else:
        if backup.exists():
            shutil.rmtree(backup, ignore_errors=True)
    finally:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)


def _restore_lkg(output_dir: Path, state_dir: Path) -> None:
    staging = output_dir.parent / f".{output_dir.name}-restore-{uuid.uuid4().hex}.tmp"
    try:
        _copy_release_files(state_dir / "last-known-good", staging)
        _replace_directory(staging, output_dir)
    finally:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)


def _replace_directory(
    staging: Path, target: Path, *, keep_backup: bool = False
) -> Path | None:
    target.parent.mkdir(parents=True, exist_ok=True)
    backup = target.parent / f".{target.name}-{uuid.uuid4().hex}.bak"
    moved_old = False
    installed_new = False
    try:
        if target.exists():
            target.replace(backup)
            moved_old = True
        staging.replace(target)
        installed_new = True
    except OSError:
        if installed_new and target.exists():
            shutil.rmtree(target, ignore_errors=True)
        if moved_old and backup.exists():
            backup.replace(target)
        raise
    else:
        if backup.exists() and not keep_backup:
            shutil.rmtree(backup, ignore_errors=True)
    return backup if moved_old and keep_backup else None


def _publish_transaction(
    output_dir: Path,
    state_dir: Path,
    artifacts: dict[str, str],
    manifest: dict[str, object],
    health: dict[str, object],
    validator: ArtifactValidator | None = None,
) -> dict[str, object] | None:
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(prefix=f".{output_dir.name}-staging-", dir=output_dir.parent)
    )
    validation: dict[str, object] | None = None
    try:
        for relative, content in artifacts.items():
            _write_text(staging / relative, content)
        if validator is not None:
            validation = validator(staging)
            manifest["core_validation"] = validation
            health["core_validation"] = validation
        _write_json(staging / "manifest.json", manifest)
        _write_json(staging / "health.json", health)
        backup = _replace_directory(staging, output_dir, keep_backup=True)
        try:
            _save_lkg(output_dir, state_dir)
        except OSError:
            if output_dir.exists():
                shutil.rmtree(output_dir, ignore_errors=True)
            if backup and backup.exists():
                backup.replace(output_dir)
            raise
        else:
            if backup and backup.exists():
                shutil.rmtree(backup, ignore_errors=True)
        return validation
    finally:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)


def _write_failure(
    output_dir: Path,
    state_dir: Path,
    source_results: list[SourceResult],
    reason: str,
    generated_at: str,
    *,
    active_probe: bool = False,
    verification: dict[str, object] | None = None,
    node_quality: dict[str, object] | None = None,
) -> PipelineResult:
    output_dir.mkdir(parents=True, exist_ok=True)
    has_lkg = _has_lkg(state_dir)
    if has_lkg:
        try:
            _restore_lkg(output_dir, state_dir)
        except OSError:
            has_lkg = False
    health = _health_document(
        status="failed",
        generated_at=generated_at,
        source_results=source_results,
        published=0,
        fallback="last-known-good" if has_lkg else None,
        active_probe=active_probe,
        verification=verification,
        node_quality=node_quality,
    )
    health["failure_reason"] = reason
    health_path = output_dir / "health.json"
    try:
        _write_json(health_path, health)
    except OSError:
        pass
    return PipelineResult(
        success=False,
        used_last_known_good=has_lkg,
        failure_reason=reason,
        manifest_path=output_dir / "manifest.json"
        if (output_dir / "manifest.json").exists()
        else None,
        health_path=health_path,
        source_results=source_results,
    )


def _previous_published_count(output_dir: Path, state_dir: Path) -> int:
    for root in (output_dir, state_dir / "last-known-good"):
        try:
            manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
            if manifest.get("status") not in {"success", "degraded", "local-private"}:
                continue
            counts = manifest.get("counts")
            count = counts.get("published", 0) if isinstance(counts, dict) else 0
            if isinstance(count, int) and count > 0:
                return count
        except (OSError, ValueError, AttributeError):
            continue
    return 0


def run_pipeline(
    config_path: Path,
    output_dir: Path,
    state_dir: Path,
    *,
    offline: bool = False,
    source_loader: SourceLoader | None = None,
    include_private: bool = False,
    no_private: bool = False,
    private_output_dir: Path | None = None,
    validator: ArtifactValidator | None = None,
    probe_runner: ProbeRunner | None = None,
) -> PipelineResult:
    """Run the safe publish pipeline and preserve the previous good output on failure."""
    generated_at = utc_now()
    try:
        config = load_config(config_path)
        settings = dict(_settings(config))
        settings["_source_cache_dir"] = str(state_dir / "source-cache")
        settings["_fetch_meta"] = {}
        sources = _source_entries(config)
    except SourceError as exc:
        return _write_failure(output_dir, state_dir, [], _safe_error(exc), generated_at)

    loader = source_loader or load_source
    public_results: list[SourceResult] = []
    private_results: list[SourceResult] = []
    candidates: list[dict[str, object]] = []
    private_candidates: list[dict[str, object]] = []
    aggregate_drops: dict[str, int] = {}
    enabled_public = 0
    live_public = 0
    config_dir = config_path.parent
    for source in sources:
        source_id = str(source.get("id") or "unnamed")
        kind = str(source.get("kind") or "unknown")
        result = SourceResult(
            id=source_id,
            kind=kind,
            status="skipped",
            source_repo=str(source.get("source_repo"))
            if source.get("source_repo")
            else None,
            license=str(source.get("license")) if source.get("license") else None,
            evidence=str(source.get("license_evidence"))
            if source.get("license_evidence")
            else None,
            publicly_offered=bool(source["publicly_offered"])
            if "publicly_offered" in source
            else None,
        )
        if not bool(source.get("enabled", False)):
            result.status = "disabled"
            (private_results if kind == "private" else public_results).append(result)
            continue
        if kind == "public":
            enabled_public += 1
        if kind == "public" and not bool(source.get("publish", False)):
            result.status = "not_publishable"
            public_results.append(result)
            continue
        if bool(source.get("requires_review", False)):
            result.status = "requires_review"
            (private_results if kind == "private" else public_results).append(result)
            continue
        if kind == "private" and no_private:
            result.status = "private_disabled"
            private_results.append(result)
            continue
        try:
            payload = loader(source, config_dir, settings, offline)
            result.sha256 = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            parsed, parse_drops = parse_source_payload_with_drops(
                str(payload), str(source.get("format", "auto"))
            )
            result.parsed = len(parsed)
            parsed = _tag_source_nodes(parsed, source_id)
            accepted, normalize_drops = _filtered_source_nodes(parsed, settings)
            _merge_drop_counts(result.drops, parse_drops, normalize_drops)
            if kind == "public":
                _merge_drop_counts(aggregate_drops, parse_drops, normalize_drops)
            result.accepted = len(accepted)
            if source_loader is None:
                _cache_source_payload(source, settings, str(payload))
            if kind == "private":
                result.status = "validated_not_published"
                private_candidates.extend(accepted)
            else:
                result.status = "ok"
                candidates.extend(accepted)
                live_public += 1
        except (ParseError, SourceError, OSError, ValueError) as exc:
            cache = (
                _read_source_cache(source, settings) if source_loader is None else None
            )
            if cache is not None:
                try:
                    cached, parse_drops = parse_source_payload_with_drops(
                        str(cache["payload"]), str(source.get("format", "auto"))
                    )
                    result.parsed = len(cached)
                    cached = _tag_source_nodes(cached, source_id)
                    accepted, normalize_drops = _filtered_source_nodes(cached, settings)
                    result.sha256 = hashlib.sha256(
                        str(cache["payload"]).encode("utf-8")
                    ).hexdigest()
                    result.accepted = len(accepted)
                    result.cached = True
                    result.status = "stale_cache"
                    _merge_drop_counts(result.drops, parse_drops, normalize_drops)
                    if kind == "public":
                        _merge_drop_counts(
                            aggregate_drops, parse_drops, normalize_drops
                        )
                    if kind == "private":
                        private_candidates.extend(accepted)
                    else:
                        candidates.extend(accepted)
                except (ParseError, SourceError, OSError, ValueError):
                    result.status = "error"
                    result.error = _safe_error(exc)
            else:
                result.status = "error"
                result.error = _safe_error(exc)
        (private_results if kind == "private" else public_results).append(result)

    proxies = _sort_and_limit(candidates, settings, aggregate_drops)
    if enabled_public and live_public == 0:
        return _write_failure(
            output_dir, state_dir, public_results, "all_sources_failed", generated_at
        )
    if not proxies:
        failure = _write_failure(
            output_dir, state_dir, public_results, "empty_result", generated_at
        )
        failure.source_results = [*public_results, *private_results]
        return failure

    previous_count = _previous_published_count(output_dir, state_dir)
    min_publish_nodes = int(settings.get("min_publish_nodes", 1))
    max_shrink_ratio = float(settings.get("max_shrink_ratio", 0.0) or 0.0)
    if len(proxies) < min_publish_nodes:
        return _write_failure(
            output_dir, state_dir, public_results, "min_publish_nodes", generated_at
        )
    if (
        previous_count > 0
        and 0 < max_shrink_ratio <= 1
        and len(proxies) < previous_count * max_shrink_ratio
    ):
        return _write_failure(
            output_dir, state_dir, public_results, "shrink_guard", generated_at
        )

    active_probe = bool(settings.get("active_probe", False))
    requested_backend = str(settings.get("probe_backend", "spawn"))
    verification: dict[str, object] = {
        "status": "not_tested",
        "reason": "active_probe_disabled",
        "backend": requested_backend,
    }
    node_quality = _empty_node_quality(
        len(proxies), published=0 if active_probe else len(proxies)
    )
    if active_probe:
        try:
            policy = _probe_policy(settings)
        except (TypeError, ValueError) as exc:
            policy_error = str(exc)
            if policy_error not in {
                "probe_rounds_below_stable_min_rounds",
                "probe_rounds_below_verified_min_rounds",
                "probe_parameters_over_budget",
                "probe_interface_required",
                "probe_interface_invalid",
            }:
                policy_error = "invalid_probe_policy"
            verification = {
                "status": "failed",
                "reason": "probe_policy_invalid",
                "error_category": (
                    policy_error
                    if policy_error in PROBE_ERROR_CATEGORIES
                    else "invalid_probe_policy"
                ),
                "policy_error": policy_error,
                "backend": requested_backend,
            }
            node_quality = _empty_node_quality(len(proxies))
            return _write_failure(
                output_dir,
                state_dir,
                public_results,
                policy_error,
                generated_at,
                active_probe=True,
                verification=verification,
                node_quality=node_quality,
            )
        if probe_runner is None:
            verification = {
                "status": "failed",
                "reason": "probe_unavailable",
                "error_category": "probe_unavailable",
                "target": DEFAULT_TARGET_URL,
                "min_verdict": policy["min_verdict"],
                "backend": policy["backend"],
            }
            node_quality = _empty_node_quality(len(proxies))
            return _write_failure(
                output_dir,
                state_dir,
                public_results,
                "probe_unavailable",
                generated_at,
                active_probe=True,
                verification=verification,
                node_quality=node_quality,
            )
        candidate_pool = proxies
        candidates_before_probe = candidate_pool[: cast(int, policy["probe_max_nodes"])]
        if not candidates_before_probe:
            return _write_failure(
                output_dir,
                state_dir,
                public_results,
                "probe_no_candidates",
                generated_at,
                active_probe=True,
                verification=verification,
                node_quality=_empty_node_quality(len(candidate_pool)),
            )
        try:
            raw_verification = probe_runner(candidates_before_probe)
        except Exception as exc:  # noqa: BLE001 - runner errors are redacted below
            error_category = _probe_error_category(exc)
            failure_reason = (
                str(exc)
                if str(exc)
                in {
                    "probe_direct_control_failed",
                    "probe_interface_required",
                    "probe_interface_invalid",
                }
                else "probe_execution_failed"
            )
            verification = {
                "status": "failed",
                "reason": failure_reason,
                "error_category": error_category,
                "target": (
                    FASTPROBE_TARGET_URL
                    if policy["backend"] == "delay"
                    else DEFAULT_TARGET_URL
                ),
                "min_verdict": policy["min_verdict"],
                "backend": policy["backend"],
            }
            node_quality = _empty_node_quality(len(candidate_pool))
            return _write_failure(
                output_dir,
                state_dir,
                public_results,
                failure_reason,
                generated_at,
                active_probe=True,
                verification=verification,
                node_quality=node_quality,
            )
        try:
            if not isinstance(raw_verification, dict):
                raise TypeError("probe_results_invalid")
            if raw_verification.get("status") != "performed":
                raise ValueError("probe_not_performed")
            raw_backend = raw_verification.get("backend", policy["backend"])
            if raw_backend != policy["backend"]:
                raise ValueError("probe_backend_mismatch")
            raw_target = raw_verification.get("target")
            expected_target = (
                FASTPROBE_TARGET_URL
                if policy["backend"] == "delay"
                else DEFAULT_TARGET_URL
            )
            if raw_target not in (None, expected_target):
                raise ValueError("probe_target_invalid")
            raw_rounds = raw_verification.get("rounds", settings.get("probe_rounds", 3))
            raw_max_nodes = raw_verification.get(
                "max_nodes", settings.get("probe_max_nodes", 30)
            )
            raw_concurrency = raw_verification.get(
                "concurrency", settings.get("probe_concurrency", 1)
            )
            raw_timeout = raw_verification.get(
                "timeout_seconds", settings.get("probe_timeout_seconds", 10.0)
            )
            raw_probe_interface = raw_verification.get("probe_interface")
            raw_interface_mode = raw_verification.get("interface_mode")
            raw_direct_control = raw_verification.get("direct_control")
            if raw_probe_interface is not None and not isinstance(
                raw_probe_interface, str
            ):
                raise TypeError("probe_parameters_invalid")
            if raw_interface_mode is not None and raw_interface_mode not in {
                "top-level",
                "proxy",
            }:
                raise ValueError("probe_parameters_invalid")
            if raw_direct_control is not None and not isinstance(
                raw_direct_control, dict
            ):
                raise TypeError("probe_parameters_invalid")
            stage_stats: dict[str, int] = {}
            for field_name in (
                "stage1_tested",
                "stage1_passed",
                "stage2_tested",
                "stage2_stable",
            ):
                value = raw_verification.get(field_name)
                if value is None:
                    continue
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    raise TypeError("probe_results_invalid")
                stage_stats[field_name] = value
            if any(
                isinstance(value, bool) or not isinstance(value, int)
                for value in (raw_rounds, raw_max_nodes, raw_concurrency)
            ):
                raise TypeError("probe_parameters_invalid")
            if cast(int, raw_max_nodes) > cast(int, policy["max_nodes_cap"]) or cast(
                int, raw_concurrency
            ) > cast(int, policy["concurrency_cap"]):
                raise ValueError("probe_parameters_over_budget")
            if isinstance(raw_timeout, bool) or not isinstance(
                raw_timeout, (int, float)
            ):
                raise TypeError("probe_parameters_invalid")
            timeout_seconds = float(raw_timeout)
            if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
                raise ValueError("probe_parameters_invalid")
            rounds_total = max(1, min(cast(int, raw_rounds), 3))
            max_nodes = max(
                1, min(cast(int, raw_max_nodes), cast(int, policy["max_nodes_cap"]))
            )
            concurrency = max(
                1,
                min(cast(int, raw_concurrency), cast(int, policy["concurrency_cap"])),
            )
            if timeout_seconds > 30:
                raise ValueError("probe_parameters_over_budget")
            result_map, probe_rows = _normalize_probe_rows(
                raw_verification.get("results"),
                candidates_before_probe,
                rounds_default=rounds_total,
                policy=policy,
            )
            if any(
                cast(int, row["rounds_total"]) < 1
                or cast(int, row["rounds_total"]) > rounds_total
                for row in probe_rows
            ):
                raise ValueError("probe_results_over_budget")
            reported_tested = raw_verification.get("tested")
            if "tested" in raw_verification and (
                isinstance(reported_tested, bool)
                or not isinstance(reported_tested, int)
                or reported_tested != len(probe_rows)
            ):
                raise ValueError("probe_results_invalid")
            if len(probe_rows) > max_nodes:
                raise ValueError("probe_results_over_budget")
            selected = select_published(
                candidates_before_probe,
                result_map,
                min_verdict=cast(str, policy["min_verdict"]),
                max_nodes=cast(int, policy["publish_max_nodes"]),
                verified_min_rounds=cast(int, policy["verified_min_rounds"]),
                stable_min_rounds=cast(int, policy["stable_min_rounds"]),
                stable_success_rate=cast(float, policy["stable_success_rate"]),
                fast_latency_ms=cast(float, policy["fast_latency_ms"]),
                latency_cap_ms=cast(float, policy["latency_cap_ms"]),
            )
            original_by_name = {
                str(proxy.get("name") or ""): proxy for proxy in candidates_before_probe
            }
            proxies = [
                original_by_name[str(item["name"])]
                for item in selected
                if str(item.get("name") or "") in original_by_name
            ]
            node_quality = _node_quality_counts(
                len(candidate_pool),
                probe_rows,
                len(proxies),
                policy,
                not_tested_budget=len(candidate_pool) - len(candidates_before_probe),
            )
            error_counts = Counter(
                str(row["error_category"])
                for row in probe_rows
                if row.get("error_category")
            )
            verification = {
                "status": "performed",
                "backend": policy["backend"],
                "target": raw_target or expected_target,
                "max_nodes": max_nodes,
                "rounds": rounds_total,
                "timeout_seconds": timeout_seconds,
                "concurrency": concurrency,
                "execution_mode": raw_verification.get("execution_mode", "serial"),
                "min_verdict": policy["min_verdict"],
                "verified_min_rounds": policy["verified_min_rounds"],
                "stable_min_rounds": policy["stable_min_rounds"],
                "stable_success_rate": policy["stable_success_rate"],
                "fast_latency_ms": policy["fast_latency_ms"],
                "latency_score_cap_ms": policy["latency_cap_ms"],
                "error_categories": dict(sorted(error_counts.items())),
            }
            verification.update(stage_stats)
            if raw_probe_interface:
                verification["probe_interface"] = raw_probe_interface
                verification["interface_mode"] = raw_interface_mode
                verification["direct_control"] = raw_direct_control or {
                    "status": "not_tested",
                    "reason": "probe_interface_missing_control_result",
                }
        except (TypeError, ValueError, OverflowError) as exc:
            failure_reason = (
                "probe_parameters_over_budget"
                if str(exc) == "probe_parameters_over_budget"
                else "probe_results_invalid"
            )
            verification = {
                "status": "failed",
                "reason": failure_reason,
                "error_category": "invalid_probe_result",
                "target": DEFAULT_TARGET_URL,
                "min_verdict": policy["min_verdict"],
            }
            node_quality = _empty_node_quality(len(candidate_pool))
            return _write_failure(
                output_dir,
                state_dir,
                public_results,
                failure_reason,
                generated_at,
                active_probe=True,
                verification=verification,
                node_quality=node_quality,
            )
        if not proxies:
            return _write_failure(
                output_dir,
                state_dir,
                public_results,
                "probe_no_qualified_nodes",
                generated_at,
                active_probe=True,
                verification=verification,
                node_quality=node_quality,
            )
        if len(proxies) < min_publish_nodes:
            return _write_failure(
                output_dir,
                state_dir,
                public_results,
                "min_publish_nodes",
                generated_at,
                active_probe=True,
                verification=verification,
                node_quality=node_quality,
            )
        if (
            previous_count > 0
            and 0 < max_shrink_ratio <= 1
            and len(proxies) < previous_count * max_shrink_ratio
        ):
            return _write_failure(
                output_dir,
                state_dir,
                public_results,
                "shrink_guard",
                generated_at,
                active_probe=True,
                verification=verification,
                node_quality=node_quality,
            )

    publish = config.get("publish") if isinstance(config.get("publish"), dict) else {}
    base_url = (
        str(publish.get("base_url")) if publish and publish.get("base_url") else None
    )
    output_metadata: dict[str, object] = {}
    artifacts = render_artifacts(proxies, base_url=base_url, metadata=output_metadata)
    sing_box_stats: dict[str, object] = {
        "unsupported": output_metadata.get("sing_box_unsupported", 0),
        "drop_reasons": output_metadata.get("sing_box_drop_reasons", {}),
    }
    manifest = build_manifest(
        status="degraded"
        if any(result.status == "error" for result in public_results)
        else "success",
        generated_at=generated_at,
        proxies=proxies,
        source_results=public_results,
        artifacts=artifacts,
        active_probe=active_probe,
        drops=aggregate_drops,
        sing_box=sing_box_stats,
        verification=verification,
        node_quality=node_quality,
        base_url=base_url,
    )
    health_status = "degraded" if manifest["status"] == "degraded" else "ok"
    health = _health_document(
        status=health_status,
        generated_at=generated_at,
        source_results=public_results,
        published=len(proxies),
        active_probe=active_probe,
        verification=verification,
        node_quality=node_quality,
    )
    try:
        _publish_transaction(
            output_dir, state_dir, artifacts, manifest, health, validator
        )
    except (OSError, CoreValidationError, ValueError) as exc:
        return _write_failure(
            output_dir,
            state_dir,
            public_results,
            _safe_error(exc),
            generated_at,
            active_probe=active_probe,
            verification=verification,
            node_quality=node_quality,
        )

    private_manifest_path: Path | None = None
    if include_private and private_output_dir and private_candidates:
        private_drops = dict(aggregate_drops)
        _merge_drop_counts(private_drops, *(result.drops for result in private_results))
        private_proxies = _sort_and_limit(
            [*proxies, *private_candidates], settings, private_drops
        )
        private_metadata: dict[str, object] = {}
        private_artifacts = render_artifacts(private_proxies, metadata=private_metadata)
        private_manifest = build_manifest(
            status="local-private",
            generated_at=generated_at,
            proxies=private_proxies,
            source_results=[*public_results, *private_results],
            artifacts=private_artifacts,
            active_probe=False,
            drops=private_drops,
            sing_box={
                "unsupported": private_metadata.get("sing_box_unsupported", 0),
                "drop_reasons": private_metadata.get("sing_box_drop_reasons", {}),
            },
        )
        private_health = _health_document(
            status="local-private",
            generated_at=generated_at,
            source_results=[*public_results, *private_results],
            published=len(private_proxies),
        )
        try:
            _publish_transaction(
                private_output_dir,
                private_output_dir / ".state",
                private_artifacts,
                private_manifest,
                private_health,
                None,
            )
            private_manifest_path = private_output_dir / "manifest.json"
        except (OSError, ValueError):
            private_manifest_path = None
    return PipelineResult(
        success=True,
        manifest_path=output_dir / "manifest.json",
        health_path=output_dir / "health.json",
        source_results=[*public_results, *private_results],
        private_manifest_path=private_manifest_path,
    )


def initialize_dist(output_dir: Path) -> None:
    """Create a safe, empty bootstrap output without marking it as last-known-good."""
    generated_at = utc_now()
    artifacts = render_artifacts([])
    manifest = build_manifest(
        status="bootstrap",
        generated_at=generated_at,
        proxies=[],
        source_results=[],
        artifacts=artifacts,
    )
    health = _health_document(
        status="bootstrap",
        generated_at=generated_at,
        source_results=[],
        published=0,
    )
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(prefix=f".{output_dir.name}-bootstrap-", dir=output_dir.parent)
    )
    try:
        for relative, content in artifacts.items():
            _write_text(staging / relative, content)
        _write_json(staging / "manifest.json", manifest)
        _write_json(staging / "health.json", health)
        _replace_directory(staging, output_dir)
    finally:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)
