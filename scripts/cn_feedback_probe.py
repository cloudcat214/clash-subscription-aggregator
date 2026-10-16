"""Mainland scan over the live /dist list, expanding the /cn channel.

Fetches the current live /dist subscription, tests every node from this machine
with the local Clash Verge Mihomo core, and merges results into
``cn-feedback/latest.json``. The cloud workflow intersects the recorded keys
with the fresh cloud-verified set to build the /cn subscription. This is a
one-shot input, not a cloud runtime dependency; it only writes local/repo files.

Measurement rules (aligned with the Clash Verge client):
- the probe core is bound to the physical NIC (``interface-name``), so tests are
  direct and cannot loop through a running TUN/proxy;
- ``unified-delay`` is enabled, matching the client's delay semantics;
- every node must pass two independent passes at 3/3 each to be recorded as
  verified this round;
- accumulation: a node keeps its recorded place until it fails two consecutive
  full scans, so repeated refreshes grow the list instead of resetting it.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from aggregator.fastprobe import probe_nodes
from aggregator.quality import node_key

DEFAULT_DIST_URL = (
    "https://cloudcat214.github.io/clash-subscription-aggregator/dist/clash/config.yaml"
)
DEFAULT_MIHOMO = r"D:\Program Files\Clash Verge\verge-mihomo.exe"
TARGET_URL = "https://www.gstatic.com/generate_204"

_NIC_PS = (
    "$excluded='Meta|Tunnel|Wintun|TAP|VPN';"
    "$adapters=@(Get-NetAdapter -IncludeHidden | Where-Object {"
    "$_.Status -eq 'Up' -and $_.Name -notmatch $excluded -and "
    "$_.InterfaceDescription -notmatch $excluded -and $_.Virtual -ne $true});"
    "$byIdx=@{}; foreach($a in $adapters){ $byIdx[[int]$a.ifIndex]=$a };"
    "$routes=@(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 | "
    "Sort-Object RouteMetric, ifIndex);"
    "foreach($r in $routes){ if($byIdx.ContainsKey([int]$r.ifIndex)){"
    "$byIdx[[int]$r.ifIndex].Name; break } }"
)


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def detect_physical_interface() -> str | None:
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", _NIC_PS],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    lines = (result.stdout or "").strip().splitlines()
    return lines[0].strip() if lines and lines[0].strip() else None


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


def merge_into_state(
    output_path: Path,
    tested_keys: set[str],
    verified_keys: set[str],
    *,
    failure_weight: int,
) -> tuple[list[str], dict[str, dict[str, object]]]:
    checked: dict[str, dict[str, object]] = {}
    if output_path.is_file():
        try:
            previous = json.loads(output_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            previous = {}
        if isinstance(previous, dict):
            prior = previous.get("checked")
            if isinstance(prior, dict):
                checked = {
                    str(key): dict(value)
                    for key, value in prior.items()
                    if isinstance(value, dict)
                }
            prior_keys = previous.get("stable_keys")
            prior_time = previous.get("generated_at")
            if isinstance(prior_keys, list) and isinstance(prior_time, str):
                for key in prior_keys:
                    entry = checked.setdefault(str(key), {"p": None, "f": 0})
                    if not entry.get("p"):
                        entry["p"] = prior_time

    now = _utc_now()
    for key in sorted(tested_keys):
        entry = checked.get(key)
        if not isinstance(entry, dict):
            entry = {"p": None, "f": 0}
        if key in verified_keys:
            entry["p"] = now
            entry["f"] = 0
        else:
            try:
                entry["f"] = int(entry.get("f") or 0) + failure_weight
            except (TypeError, ValueError):
                entry["f"] = failure_weight
        checked[key] = entry

    keep = sorted(
        key
        for key, entry in checked.items()
        if isinstance(entry, dict) and entry.get("p") and int(entry.get("f") or 0) <= 1
    )
    return keep, checked


def run_pass(
    nodes: list[dict[str, object]],
    *,
    mihomo: str,
    interface: str,
    label: str,
) -> tuple[set[str], set[str], dict[str, object]]:
    started = time.time()
    result = probe_nodes(
        nodes,
        mihomo_path=mihomo,
        max_nodes=1000,
        rounds=3,
        timeout=12.0,
        concurrency=16,
        target_url=TARGET_URL,
        probe_interface=interface,
    )
    elapsed = round(time.time() - started, 1)
    items = result.get("results") or []
    stable: set[str] = set()
    verified: set[str] = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        key = item.get("node_key")
        if not isinstance(key, str) or not key:
            continue
        if item.get("stable"):
            stable.add(key)
        if item.get("verified"):
            verified.add(key)
    summary = {
        "label": label,
        "elapsed_seconds": elapsed,
        "tested": result.get("tested"),
        "stage1_passed": result.get("stage1_passed"),
        "interface_mode": result.get("interface_mode"),
    }
    print(
        f"      轮次 {label}：实测 {summary['tested']}，稳定 {len(stable)}，"
        f"全过 {len(verified)}，用时 {elapsed}s",
        flush=True,
    )
    return stable, verified, summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist-url", default=DEFAULT_DIST_URL)
    parser.add_argument(
        "--mihomo", default=os.environ.get("CN_FEEDBACK_MIHOMO", DEFAULT_MIHOMO)
    )
    parser.add_argument(
        "--output", type=Path, default=ROOT / "cn-feedback" / "latest.json"
    )
    parser.add_argument("--probe-interface", default=None)
    parser.add_argument("--confirm-wait", type=int, default=60)
    args = parser.parse_args()

    interface = args.probe_interface or detect_physical_interface()
    if not interface:
        print(
            "未检测到可用的物理网卡（Up 状态且非 TUN/虚拟网卡）。"
            "为避免测出被代理绕路的结果已中止；"
            "请检查网络适配器，或用 --probe-interface 手动指定网卡名重试。"
        )
        return 2
    print(f"物理网卡：{interface}（探测流量直连，不经过系统代理/TUN）", flush=True)

    print(f"[1/4] 拉取线上订阅并解析（{args.dist_url}）...")
    try:
        proxies = fetch_proxies(args.dist_url)
    except Exception as exc:  # noqa: BLE001
        print(f"拉取或解析失败：{type(exc).__name__}: {exc}")
        return 2
    if not proxies:
        print("订阅中没有可测试节点。")
        return 2
    print(f"      节点数={len(proxies)}")

    print("[2/4] 第一轮实测（请耐心等待）...")
    try:
        _stable_a, verified_a, summary_a = run_pass(
            proxies, mihomo=args.mihomo, interface=interface, label="A"
        )
    except Exception as exc:  # noqa: BLE001
        print(f"实测失败：{type(exc).__name__}: {str(exc)[:300]}")
        return 2

    survivors = [proxy for proxy in proxies if node_key(proxy) in verified_a]
    print(
        f"[3/4] 等待 {args.confirm_wait}s 后进行第二轮复核（剔除时好时坏的抖动节点）..."
    )
    time.sleep(max(0, args.confirm_wait))

    _stable_b: set[str] = set()
    verified_b: set[str] = set()
    summary_b: dict[str, object] = {}
    if survivors:
        try:
            _stable_b, verified_b, summary_b = run_pass(
                survivors, mihomo=args.mihomo, interface=interface, label="B"
            )
        except Exception as exc:  # noqa: BLE001
            print(f"复核失败：{type(exc).__name__}: {str(exc)[:300]}")
            return 2
    verified_now = set(verified_a & verified_b)
    tested_keys = {node_key(proxy) for proxy in proxies}

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    keep, checked = merge_into_state(
        output_path, tested_keys, verified_now, failure_weight=1
    )

    document = {
        "schema_version": 1,
        "generated_at": _utc_now(),
        "vantage": "cn-one-shot",
        "method": "direct-bind+unified-delay; two-pass-verified-3of3; accumulate-fail<=1",
        "source_url": args.dist_url,
        "probe_interface": interface,
        "tested": summary_a.get("tested"),
        "stable": len(keep),
        "verified": len(verified_now),
        "stable_keys": keep,
        "pass_a": summary_a,
        "pass_b": summary_b,
        "checked": checked,
    }
    output_path.write_text(
        json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"[4/4] 已写入 {output_path}")
    print(
        f"      本轮两轮 3/3 全通过：{len(verified_now)} 个；"
        f"累积保留（历史通过且未连续失效）：{len(keep)} 个"
    )
    if not keep:
        print("警告：过滤名单为空。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
