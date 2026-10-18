"""Client-side audit of the currently loaded Clash Verge profile.

Tests every loaded proxy node with two delay rounds through the running Clash
Verge core (named pipe, the same path the UI uses), then:

- writes ``cn-feedback/blocked.json`` with nodes that failed both rounds, so the
  /cn builder can subtract them from the union of local + cloud candidates;
- prints pass-rate statistics by protocol type and by source prefix, which the
  cloud-side expansion can use to avoid wasting probes on hopeless families.

This is a one-shot local audit; the cloud pipeline keeps working without it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = Path(os.environ["APPDATA"]) / "io.github.clash-verge-rev.clash-verge-rev"
MERGE_CONFIG = APP / "clash-verge.yaml"
TARGET = "https://www.gstatic.com/generate_204"
TIMEOUT_MS = 5000
GROUP_TYPES = {
    "Selector",
    "URLTest",
    "Fallback",
    "LoadBalance",
    "Relay",
    "Compatible",
    "Direct",
    "Reject",
    "Pass",
    "PassRule",
    "RejectDrop",
}


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def discover_pipe() -> str:
    names = [
        name
        for name in os.listdir("\\\\.\\pipe\\")
        if "mihomo" in name.lower() or "verge" in name.lower()
    ]
    for name in names:
        if "sidecar" in name or "mihomo" in name:
            return name
    if names:
        return names[0]
    raise RuntimeError("client_mihomo_pipe_not_found")


def load_secret() -> str:
    try:
        text = MERGE_CONFIG.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    match = re.search(r"^secret:\s*(.*)$", text, re.MULTILINE)
    return match.group(1).strip().strip("'\"") if match else ""


def http_over_pipe(
    pipe: str, secret: str, path: str, timeout: float = 25.0
) -> str | None:
    result: dict[str, object] = {}

    def worker() -> None:
        try:
            pipe_path = r"\\.\pipe" + "\\" + pipe
            with open(pipe_path, "r+b", buffering=0) as handle:
                request = (
                    f"GET {path} HTTP/1.1\r\nHost: localhost\r\n"
                    f"Authorization: Bearer {secret}\r\nConnection: close\r\n\r\n"
                ).encode()
                handle.write(request)
                data = b""
                while len(data) < 4_000_000:
                    chunk = handle.read(65536)
                    if not chunk:
                        break
                    data += chunk
                result["data"] = data
        except Exception as exc:  # noqa: BLE001
            result["error"] = f"{type(exc).__name__}: {exc}"

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    thread.join(timeout)
    if thread.is_alive() or "error" in result:
        return None
    data = result.get("data")
    if not isinstance(data, (bytes, bytearray)):
        return None
    text = bytes(data).decode("utf-8", errors="replace")
    if "\r\n\r\n" not in text:
        return ""
    headers, body = text.split("\r\n\r\n", 1)
    if "transfer-encoding: chunked" in headers.lower():
        try:
            parts = body.split("\r\n")
            chunks: list[str] = []
            index = 0
            while index < len(parts):
                size = int(parts[index].split(";", 1)[0], 16)
                if size == 0:
                    break
                chunks.append(parts[index + 1])
                index += 2
            body = "\r\n".join(chunks)
        except Exception:  # noqa: BLE001, S110
            pass
    return body


def client_delay(pipe: str, secret: str, name: str) -> int | None:
    encoded_name = urllib.parse.quote(name, safe="")
    encoded_url = urllib.parse.quote(TARGET, safe="")
    path = f"/proxies/{encoded_name}/delay?timeout={TIMEOUT_MS}&url={encoded_url}"
    body = http_over_pipe(pipe, secret, path)
    if not body:
        return None
    try:
        document = json.loads(body.strip())
    except Exception:  # noqa: BLE001
        return None
    value = document.get("delay")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return int(value)
    return None


def source_of(name: str) -> str:
    match = re.match(r"\[([^\]]+)\]", name)
    return match.group(1) if match else "?"


def audit_node(pipe: str, secret: str, name: str, rounds: int) -> dict[str, object]:
    delays: list[int | None] = []
    for round_index in range(rounds):
        delays.append(client_delay(pipe, secret, name))
        if round_index + 1 < rounds:
            time.sleep(0.25)
    passed = sum(value is not None for value in delays)
    return {
        "name": name,
        "delays": delays,
        "passed": passed,
        "pass_any": passed > 0,
        "pass_all": passed == rounds,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rounds", type=int, default=2)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument(
        "--blocked",
        type=Path,
        default=ROOT / "cn-feedback" / "blocked.json",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=ROOT / "reports" / "cn-audit-latest" / "client_audit.json",
    )
    args = parser.parse_args()

    pipe = discover_pipe()
    secret = load_secret()
    print(f"pipe={pipe} secret_loaded={bool(secret)}", flush=True)

    proxies_body = http_over_pipe(pipe, secret, "/proxies")
    if not proxies_body:
        print("failed to read /proxies from the client")
        return 2
    document = json.loads(proxies_body)
    entries = document.get("proxies") or {}
    nodes = [
        (name, value.get("type"))
        for name, value in entries.items()
        if isinstance(value, dict) and value.get("type") not in GROUP_TYPES
    ]
    print(f"loaded nodes={len(nodes)}", flush=True)
    if not nodes:
        return 2

    started = time.time()
    results: list[dict[str, object]] = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [
            pool.submit(audit_node, pipe, secret, name, args.rounds)
            for name, _ in nodes
        ]
        for index, future in enumerate(futures, 1):
            try:
                results.append(future.result())
            except Exception as exc:  # noqa: BLE001
                results.append({"name": nodes[index - 1][0], "error": str(exc)})
            if index % 20 == 0:
                print(f"  progress {index}/{len(nodes)}", flush=True)
    elapsed = round(time.time() - started, 1)

    type_by_name = {name: node_type for name, node_type in nodes}
    pass_any = sum(1 for row in results if row.get("pass_any"))
    pass_all = sum(1 for row in results if row.get("pass_all"))
    blocked = sorted(
        str(row["name"])
        for row in results
        if not row.get("pass_any") and isinstance(row.get("name"), str)
    )

    def stats(group_key):
        totals: dict[str, int] = {}
        passes: dict[str, int] = {}
        for row in results:
            key = group_key(str(row.get("name")))
            totals[key] = totals.get(key, 0) + 1
            if row.get("pass_any"):
                passes[key] = passes.get(key, 0) + 1
        return {
            key: {
                "total": totals[key],
                "pass_any": passes.get(key, 0),
                "rate": round(passes.get(key, 0) / totals[key], 3),
            }
            for key in sorted(totals)
        }

    summary = {
        "generated_at": utc_now(),
        "rounds": args.rounds,
        "nodes": len(nodes),
        "elapsed_seconds": elapsed,
        "pass_any": pass_any,
        "pass_all": pass_all,
        "blocked": len(blocked),
        "by_type": stats(lambda name: str(type_by_name.get(name, "?"))),
        "by_source": stats(source_of),
    }
    print(
        f"audit done in {elapsed}s: nodes={len(nodes)} pass_any={pass_any} "
        f"pass_all={pass_all} blocked={len(blocked)}",
        flush=True,
    )
    for name, value in summary["by_type"].items():
        print(
            f"  type {name}: {value['pass_any']}/{value['total']} ({value['rate']:.0%})",
            flush=True,
        )

    args.blocked.parent.mkdir(parents=True, exist_ok=True)
    blocked_keys = sorted(
        {hashlib.sha256(name.encode("utf-8")).hexdigest()[:16] for name in blocked}
    )
    args.blocked.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "generated_at": summary["generated_at"],
                "keys": blocked_keys,
                "count": len(blocked_keys),
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(
        json.dumps(
            {"summary": summary, "results": results},
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"blocked list -> {args.blocked} ({len(blocked_keys)} keys)")
    print(f"report -> {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
