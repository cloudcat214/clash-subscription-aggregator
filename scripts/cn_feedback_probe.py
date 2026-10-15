"""One-shot mainland probe for the /cn channel (run by scripts/refresh-cn-feedback.ps1).

Fetches the current live /dist subscription, tests every node from this machine
with the local Clash Verge Mihomo core, and writes ``cn-feedback/latest.json``
containing the stable node keys. The cloud workflow intersects those keys with
the fresh cloud-verified set to build the /cn subscription. This is a one-shot
input, not a cloud runtime dependency; it only writes local/repo files.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from aggregator.fastprobe import probe_nodes

DEFAULT_DIST_URL = (
    "https://cloudcat214.github.io/clash-subscription-aggregator/dist/clash/config.yaml"
)
DEFAULT_MIHOMO = r"D:\Program Files\Clash Verge\verge-mihomo.exe"
TARGET_URL = "https://www.gstatic.com/generate_204"


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def fetch_proxies(url: str) -> list[dict[str, object]]:
    request = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(request, timeout=30) as response:
        raw = response.read()
    document = yaml.safe_load(raw.decode("utf-8-sig"))
    if not isinstance(document, dict):
        raise TypeError("dist_config_invalid")
    proxies = document.get("proxies")
    if not isinstance(proxies, list):
        raise TypeError("dist_config_invalid")
    return [
        proxy
        for proxy in proxies
        if isinstance(proxy, dict) and isinstance(proxy.get("name"), str)
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist-url", default=DEFAULT_DIST_URL)
    parser.add_argument(
        "--mihomo", default=os.environ.get("CN_FEEDBACK_MIHOMO", DEFAULT_MIHOMO)
    )
    parser.add_argument(
        "--output", type=Path, default=ROOT / "cn-feedback" / "latest.json"
    )
    parser.add_argument("--max-nodes", type=int, default=500)
    parser.add_argument("--concurrency", type=int, default=16)
    parser.add_argument("--timeout", type=float, default=12.0)
    args = parser.parse_args()

    print(f"[1/3] 拉取线上订阅并解析（{args.dist_url}）...")
    try:
        proxies = fetch_proxies(args.dist_url)
    except Exception as exc:  # noqa: BLE001
        print(f"拉取或解析失败：{type(exc).__name__}: {exc}")
        return 2
    if not proxies:
        print("订阅中没有可测试节点。")
        return 2
    print(f"      节点数={len(proxies)}")

    print(f"[2/3] 本机实测中（最多 {args.max_nodes} 个，3 轮，约 3-5 分钟，请耐心等待）...")
    try:
        result = probe_nodes(
            proxies,
            mihomo_path=args.mihomo,
            max_nodes=args.max_nodes,
            rounds=3,
            timeout=args.timeout,
            concurrency=args.concurrency,
            target_url=TARGET_URL,
        )
    except Exception as exc:  # noqa: BLE001
        print(f"实测失败：{type(exc).__name__}: {str(exc)[:300]}")
        return 2

    items = result.get("results") or []
    stable_keys: list[str] = []
    verified = 0
    for item in items:
        if not isinstance(item, dict):
            continue
        key = item.get("node_key")
        if not isinstance(key, str) or not key:
            continue
        if item.get("stable"):
            stable_keys.append(key)
        if item.get("verified"):
            verified += 1
    stable_keys = sorted(set(stable_keys))

    tested = result.get("tested")
    tested = (
        tested
        if isinstance(tested, int) and not isinstance(tested, bool)
        else len(items)
    )

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    document = {
        "schema_version": 1,
        "generated_at": _utc_now(),
        "vantage": "cn-one-shot",
        "source_url": args.dist_url,
        "tested": tested,
        "stable": len(stable_keys),
        "verified": verified,
        "stable_keys": stable_keys,
    }
    output_path.write_text(
        json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"[3/3] 已写入 {output_path}")
    print(f"      实测 {tested} 个，可用 {len(stable_keys)} 个（3/3 全通过 {verified} 个）。")
    if not stable_keys:
        print("警告：本轮没有实测到可用节点，反馈文件为空的可用列表。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
