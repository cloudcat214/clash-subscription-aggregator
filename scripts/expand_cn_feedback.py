"""Expand the /cn channel with a mainland TCP port check (cloud-side).

For a rotating window of published TCP-based nodes, this asks the apihz free
API (mainland probe, ``type=1``) whether ``server:port`` is reachable. The
result is written to ``cn-feedback/cloud.json`` and unioned with the local
feedback by ``scripts/build_cn_channel.py``.

The cloud-side full-protocol probe (the published set) already verifies that a
node actually works from a foreign vantage; this check adds the missing
"reachable from the mainland" leg without needing any local machine.

The API treats a handshake slower than one second as "off", so a single "off"
is not trusted: it is re-checked once, and a node already in the list needs two
confirmed "off" observations (across runs) before it is dropped.

State file format (same envelope the builder understands):
{
  "schema_version": 1,
  "generated_at": "...",
  "vantage": "cloud+apihz-mainland-tcp",
  "method": "apihz-cn-tcp; rotating-window; two-strike",
  "tested": <published count>,
  "stable": <len(stable_keys)>,
  "verified": <len(stable_keys)>,
  "stable_keys": [<node keys currently reachable>],
  "nodes": {<key>: <full node config>},   # snapshots so /cn survives rotation
  "cn_off": {<key>: <confirmed off count>},
  "tested_this_run": n, "on_this_run": x, "off_this_run": y, "errors": z
}
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import sys
import time
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from aggregator.quality import node_key

UDP_TYPES = {"hysteria", "hysteria2", "tuic", "wireguard"}
DEFAULT_API = "https://cn.apihz.cn/api/wangzhan/port.php"


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_published(dist_dir: Path) -> list[dict[str, object]]:
    config_path = dist_dir / "clash" / "config.yaml"
    document = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    proxies = document.get("proxies") if isinstance(document, dict) else None
    if not isinstance(proxies, list):
        raise TypeError("dist_proxies_missing")
    return [
        proxy
        for proxy in proxies
        if isinstance(proxy, dict)
        and isinstance(proxy.get("name"), str)
        and proxy.get("server")
        and proxy.get("port")
    ]


def tcp_nodes(
    proxies: list[dict[str, object]], allowed_types: set[str] | None = None
) -> list[dict[str, object]]:
    nodes = [
        proxy
        for proxy in proxies
        if str(proxy.get("type", "")).lower() not in UDP_TYPES
    ]
    if allowed_types:
        nodes = [
            proxy
            for proxy in nodes
            if str(proxy.get("type", "")).lower() in allowed_types
        ]
    nodes.sort(key=lambda proxy: str(proxy.get("name")))
    return nodes


def select_window(
    nodes: list[dict[str, object]], limit: int, offset: int
) -> list[dict[str, object]]:
    if not nodes or limit <= 0:
        return []
    limit = min(limit, len(nodes))
    start = offset % len(nodes)
    return [nodes[(start + index) % len(nodes)] for index in range(limit)]


def merge_on_state(
    previous_on: list[str],
    previous_off: dict[str, int],
    published_keys: set[str],
    results: dict[str, str],
) -> tuple[list[str], dict[str, int]]:
    """Carry forward the "on" set; only a tested, twice-confirmed "off" removes.

    Absence from ``published_keys`` is *not* evidence of failure: the rotating
    window and the hourly cloud refresh both mean a node can be missing from a
    single run through no fault of its own. Pruning on absence is what made the
    /cn set shrink run after run, so records are kept until the probe itself
    says otherwise.
    """
    on_keys = {key for key in previous_on}
    off_state = {
        key: int(count)
        for key, count in previous_off.items()
        if key in on_keys and isinstance(count, int) and not isinstance(count, bool)
    }
    for key, state in results.items():
        if key not in published_keys:
            continue
        if state == "on":
            on_keys.add(key)
            off_state.pop(key, None)
            continue
        if key not in on_keys:
            continue
        count = off_state.get(key, 0) + 1
        if count >= 2:
            on_keys.discard(key)
            off_state.pop(key, None)
        else:
            off_state[key] = count
    return sorted(on_keys), dict(sorted(off_state.items()))


def check_port(
    api_base: str,
    dev_id: str,
    dev_key: str,
    host: str,
    port: int,
    *,
    timeout: float = 20.0,
) -> str:
    query = urllib.parse.urlencode(
        {"id": dev_id, "key": dev_key, "type": 1, "host": host, "port": port}
    )
    request = urllib.request.Request(
        f"{api_base}?{query}", headers={"User-Agent": "Mozilla/5.0"}
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        document = json.loads(response.read().decode("utf-8", "replace"))
    if not isinstance(document, dict) or document.get("code") != 200:
        raise RuntimeError(f"api_rejected: {document}")
    return str(document.get("state") or "")


def legacy_name_key(name: str) -> str:
    """The pre-stable-identity algorithm: hash of the display name."""
    return hashlib.sha256(name.encode("utf-8")).hexdigest()[:16]


def legacy_key_map(
    proxies: list[dict[str, object]],
) -> dict[str, str]:
    """Map old name-hash keys onto the current content-based keys."""
    return {
        legacy_name_key(str(proxy["name"])): node_key(proxy)
        for proxy in proxies
        if isinstance(proxy.get("name"), str)
    }


def migrate_legacy_keys(keys: list[str], mapping: dict[str, str]) -> list[str]:
    """Rewrite keys written before the identity change; unknown keys are kept.

    Keeping unknown keys is deliberate: absence from one rotation is not
    evidence of failure, and the builder simply ignores keys it cannot render.
    """
    return [mapping.get(key, key) for key in keys]


def collect_snapshots(
    stable_keys: list[str],
    published_nodes: dict[str, dict[str, object]],
    previous_nodes: dict[str, dict[str, object]],
) -> dict[str, dict[str, object]]:
    """Return a full config snapshot for every node that is currently "on".

    The /cn builder must not depend on the node still being inside the rotating
    published set: a node that was reachable once keeps its config here even
    after the publisher drops it from the current top-N. Only "on" keys are
    kept, so this stays small (~400 nodes).
    """
    snapshots: dict[str, dict[str, object]] = {}
    for key in stable_keys:
        node = published_nodes.get(key)
        if node is None:
            node = previous_nodes.get(key)
        if isinstance(node, dict):
            snapshots[key] = copy.deepcopy(node)
    return snapshots


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist-dir", type=Path, default=ROOT / "dist-auto")
    parser.add_argument(
        "--output", type=Path, default=ROOT / "cn-feedback" / "cloud.json"
    )
    parser.add_argument("--api-base", default=DEFAULT_API)
    parser.add_argument("--id", default=os.environ.get("APIHZ_ID", "88888888"))
    parser.add_argument("--key", default=os.environ.get("APIHZ_KEY", "88888888"))
    parser.add_argument(
        "--types",
        default="http",
        help="逗号分隔的类型白名单（默认 http）；空串表示不按类型过滤",
    )
    parser.add_argument("--limit", type=int, default=60)
    parser.add_argument("--delay", type=float, default=1.0)
    parser.add_argument(
        "--offset",
        type=int,
        default=int(os.environ.get("GITHUB_RUN_NUMBER", "0") or 0),
    )
    parser.add_argument("--max-consecutive-errors", type=int, default=6)
    args = parser.parse_args()

    proxies = load_published(args.dist_dir)
    legacy_map = legacy_key_map(proxies)
    allowed_types = {
        item.strip().lower() for item in str(args.types).split(",") if item.strip()
    }
    nodes = tcp_nodes(proxies, allowed_types)
    window = select_window(nodes, args.limit, args.offset)
    print(
        f"[cn-expand] published={len(proxies)} tcp_nodes={len(nodes)} "
        f"window={len(window)} offset={args.offset}",
        flush=True,
    )
    if not window:
        print("[cn-expand] no TCP nodes to test", flush=True)
        return 0

    output_path = Path(args.output)
    previous_on: list[str] = []
    previous_off: dict[str, int] = {}
    previous_nodes: dict[str, dict[str, object]] = {}
    if output_path.is_file():
        try:
            previous = json.loads(output_path.read_text(encoding="utf-8"))
            keys = previous.get("stable_keys")
            if isinstance(keys, list):
                previous_on = [str(key) for key in keys]
            off_counts = previous.get("cn_off")
            if isinstance(off_counts, dict):
                previous_off = {
                    str(key): int(count)
                    for key, count in off_counts.items()
                    if isinstance(count, int) and not isinstance(count, bool)
                }
            raw_nodes = previous.get("nodes")
            if isinstance(raw_nodes, dict):
                previous_nodes = {
                    str(key): node
                    for key, node in raw_nodes.items()
                    if isinstance(node, dict)
                }
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            previous_on = []
            previous_off = {}
            previous_nodes = {}
    previous_on = migrate_legacy_keys(previous_on, legacy_map)
    previous_off = {
        legacy_map.get(key, key): count for key, count in previous_off.items()
    }
    previous_nodes = {
        legacy_map.get(key, key): node for key, node in previous_nodes.items()
    }

    published_keys = {node_key(proxy) for proxy in proxies}
    results: dict[str, str] = {}
    on_count = 0
    off_count = 0
    errors = 0
    consecutive_errors = 0

    def probe(host: str, port: int) -> str:
        for attempt in range(2):
            try:
                return check_port(args.api_base, args.id, args.key, host, port)
            except Exception as exc:
                if "调用频次过快" in str(exc) and attempt == 0:
                    time.sleep(3.0)
                    continue
                raise
        raise RuntimeError("rate_limited")

    for proxy in window:
        key = node_key(proxy)
        host = str(proxy.get("server"))
        port_value = proxy.get("port")
        if isinstance(port_value, bool) or not isinstance(port_value, (int, str)):
            continue
        try:
            port = int(port_value)
        except (TypeError, ValueError):
            continue
        try:
            state = probe(host, port)
            if state == "off":
                time.sleep(1.0)
                confirm = probe(host, port)
                if confirm == "on":
                    state = "on"
        except Exception as exc:  # noqa: BLE001
            errors += 1
            consecutive_errors += 1
            print(
                f"  ! {host}:{port} -> {type(exc).__name__}: {str(exc)[:120]}",
                flush=True,
            )
            if consecutive_errors >= args.max_consecutive_errors:
                print(
                    "[cn-expand] too many consecutive errors; stopping early",
                    flush=True,
                )
                break
            time.sleep(max(0.0, args.delay))
            continue
        consecutive_errors = 0
        results[key] = state
        if state == "on":
            on_count += 1
        else:
            off_count += 1
        time.sleep(max(0.0, args.delay))

    stable, off_state = merge_on_state(
        previous_on, previous_off, published_keys, results
    )
    published_nodes = {node_key(proxy): copy.deepcopy(proxy) for proxy in proxies}
    nodes = collect_snapshots(stable, published_nodes, previous_nodes)
    document = {
        "schema_version": 1,
        "generated_at": _utc_now(),
        "vantage": "cloud+apihz-mainland-tcp",
        "method": "apihz-cn-tcp; rotating-window; two-strike",
        "tested": len(proxies),
        "stable": len(stable),
        "verified": len(stable),
        "stable_keys": stable,
        "nodes": nodes,
        "cn_off": off_state,
        "tested_this_run": len(results),
        "on_this_run": on_count,
        "off_this_run": off_count,
        "errors": errors,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(
        f"[cn-expand] tested={document['tested_this_run']} on={on_count} "
        f"off={off_count} errors={errors} stable_total={len(stable)} "
        f"snapshots={len(nodes)} -> {output_path}",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
