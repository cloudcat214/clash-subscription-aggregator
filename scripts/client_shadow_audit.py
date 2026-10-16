import hashlib
import json
import os
import re
import secrets
import socket
import subprocess
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "reports" / "cn-audit-20261016"
OUTPUT = ROOT / "cn-feedback" / "latest.json"
REPORT.mkdir(parents=True, exist_ok=True)
MIHOMO = r"D:\Program Files\Clash Verge\verge-mihomo.exe"
APP = Path(os.environ["APPDATA"]) / "io.github.clash-verge-rev.clash-verge-rev"
RUNTIME_CONFIG = APP / "clash-verge.yaml"
MERGE_CONFIG = APP / "clash-verge.yaml"
TARGET = "https://www.gstatic.com/generate_204"
TIMEOUT_MS = 5000


def pipe_names():
    return [n for n in os.listdir(r"\\.\pipe") if "mihomo" in n.lower() or "verge" in n.lower()]


PIPES = pipe_names()
PIPE = next((p for p in PIPES if "sidecar" in p or "mihomo" in p), PIPES[0] if PIPES else None)
if not PIPE:
    raise RuntimeError("client_mihomo_pipe_not_found")

secret_text = MERGE_CONFIG.read_text(encoding="utf-8", errors="replace")
secret_match = re.search(r"^secret:\s*(.*)$", secret_text, re.MULTILINE)
SECRET = secret_match.group(1).strip().strip("'\"") if secret_match else ""


def pipe_get(path, timeout=25):
    result = {}

    def worker():
        try:
            pipe_path = r"\\.\pipe" + "\\" + PIPE
            with open(pipe_path, "r+b", buffering=0) as f:
                req = (
                f"GET {path} HTTP/1.1\r\nHost: localhost\r\n"
                f"Authorization: Bearer {SECRET}\r\nConnection: close\r\n\r\n"
                ).encode()
                f.write(req)
                data = b""
                while len(data) < 4_000_000:
                    chunk = f.read(65536)
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
    text = result.get("data", b"").decode("utf-8", errors="replace")
    if "\r\n\r\n" not in text:
        return ""
    headers, body = text.split("\r\n\r\n", 1)
    if "transfer-encoding: chunked" in headers.lower():
        try:
            parts = body.split("\r\n")
            chunks = []
            i = 0
            while i < len(parts):
                size = int(parts[i].split(";", 1)[0], 16)
                if size == 0:
                    break
                chunks.append(parts[i + 1])
                i += 2
            body = "\r\n".join(chunks)
        except Exception:  # noqa: BLE001, S110
            pass
    return body


all_body = pipe_get("/proxies")
print("pipes=", PIPES, "selected=", PIPE, "secret_loaded=", bool(SECRET))
print("proxies_body_len=", len(all_body or ""), "prefix=", repr((all_body or "")[:200]))
if not all_body:
    raise RuntimeError("client_pipe_empty_response")
all_doc = json.loads(all_body)
all_proxies = all_doc.get("proxies") or {}
auto_body = pipe_get("/proxies/AUTO")
auto_doc = json.loads(auto_body or "{}")
candidates = auto_doc.get("all") or []
if not candidates:
    group_types = {"Selector", "URLTest", "Fallback", "LoadBalance", "Direct", "Reject", "Compatible"}
    candidates = [
        name for name, value in all_proxies.items()
        if isinstance(value, dict) and value.get("type") not in group_types
    ]
print(f"client pipe={PIPE} loaded={len(all_proxies)} AUTO_candidates={len(candidates)}")

runtime = yaml.safe_load(RUNTIME_CONFIG.read_text(encoding="utf-8")) or {}
proxy_map = {
    str(proxy.get("name")): proxy
    for proxy in (runtime.get("proxies") or [])
    if isinstance(proxy, dict) and proxy.get("name")
}
node_configs = [proxy_map[name] for name in candidates if name in proxy_map]
print(f"candidate configs available={len(node_configs)}")
if len(node_configs) != len(candidates):
    raise RuntimeError("client_proxy_config_missing")


def client_delay(name):
    path = f"/proxies/{urllib.parse.quote(name, safe='')}/delay?timeout={TIMEOUT_MS}&url={urllib.parse.quote(TARGET, safe='')}"
    body = pipe_get(path)
    if not body:
        return None
    try:
        value = json.loads(body.strip()).get("delay")
        return int(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None
    except Exception:  # noqa: BLE001
        return None


def free_port():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def shadow_audit(nodes):
    port, controller = free_port(), free_port()
    controller_secret = secrets.token_urlsafe(24)
    config = {
        "mixed-port": port,
        "bind-address": "127.0.0.1",
        "allow-lan": False,
        "mode": "rule",
        "log-level": "warning",
        "external-controller": f"127.0.0.1:{controller}",
        "secret": controller_secret,
        "interface-name": "WLAN",
        "unified-delay": True,
        "tcp-concurrent": True,
        "dns": {
            "enable": True,
            "ipv6": False,
            "enhanced-mode": "normal",
            "nameserver": ["udp://223.5.5.5", "udp://119.29.29.29"],
            "default-nameserver": ["223.5.5.5", "119.29.29.29"],
        },
        "proxies": nodes,
        "proxy-groups": [{"name": "PROBE", "type": "select", "proxies": [n["name"] for n in nodes]}],
        "rules": ["MATCH,PROBE"],
    }
    results = {n["name"]: [] for n in nodes}
    with tempfile.TemporaryDirectory(prefix="cn-shadow-audit-") as temp:
        cfg = Path(temp) / "config.yaml"
        cfg.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
        process = subprocess.Popen([MIHOMO, "-d", temp, "-f", str(cfg)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        ready = False
        for _ in range(60):
            time.sleep(0.25)
            try:
                req = urllib.request.Request(
                    f"http://127.0.0.1:{controller}/version",
                    headers={"Authorization": f"Bearer {controller_secret}"},
                )
                urllib.request.urlopen(req, timeout=2).read()
                ready = True
                break
            except Exception:  # noqa: BLE001, S112
                continue
        if not ready:
            process.terminate()
            return results

        for name, values in results.items():
            path = f"/proxies/{urllib.parse.quote(name, safe='')}/delay?timeout={TIMEOUT_MS}&url={urllib.parse.quote(TARGET, safe='')}"
            for _ in range(3):
                try:
                    req = urllib.request.Request(
                        f"http://127.0.0.1:{controller}{path}",
                        headers={"Authorization": f"Bearer {controller_secret}"},
                    )
                    data = json.loads(urllib.request.urlopen(req, timeout=12).read().decode())
                    delay = data.get("delay")
                    values.append(int(delay) if isinstance(delay, (int, float)) and not isinstance(delay, bool) else None)
                except Exception:  # noqa: BLE001
                    values.append(None)
                time.sleep(0.5)
        process.terminate()
        try:
            process.wait(timeout=5)
        except Exception:  # noqa: BLE001
            process.kill()
    return results


client_results = {name: [] for name in candidates}
for round_no in range(3):
    for name in candidates:
        client_results[name].append(client_delay(name))
    if round_no < 2:
        time.sleep(3)

shadow_results = shadow_audit(node_configs)
rows = []
for name in candidates:
    actual = client_results.get(name, [])
    shadow = shadow_results.get(name, [])
    rows.append({
        "name": name,
        "type": (all_proxies.get(name) or {}).get("type"),
        "client_delays": actual,
        "shadow_delays": shadow,
        "client_passes": sum(value is not None for value in actual),
        "shadow_passes": sum(value is not None for value in shadow),
        "both_3of3": sum(value is not None for value in actual) == 3 and sum(value is not None for value in shadow) == 3,
    })

summary = {
    "candidate_count": len(candidates),
    "client_3of3": sum(row["client_passes"] == 3 for row in rows),
    "shadow_3of3": sum(row["shadow_passes"] == 3 for row in rows),
    "both_3of3": sum(row["both_3of3"] for row in rows),
    "client_shadow_disagreement": sum((row["client_passes"] == 3) != (row["shadow_passes"] == 3) for row in rows),
}
if rows and ((rows[0]["client_passes"] == 3) != (rows[0]["shadow_passes"] == 3)):
    raise RuntimeError("client_shadow_calibration_mismatch")

stable_keys = sorted(
    hashlib.sha256(row["name"].encode("utf-8")).hexdigest()[:16]
    for row in rows
    if row["both_3of3"]
)
feedback = {
    "schema_version": 1,
    "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "vantage": "actual-client-pipe+shadow-mihomo",
    "method": "client-pipe+shadow; calibration+three-round-both-3of3",
    "tested": len(candidates),
    "stable": len(stable_keys),
    "verified": len(stable_keys),
    "stable_keys": stable_keys,
    "audit": summary,
}
OUTPUT.parent.mkdir(parents=True, exist_ok=True)
OUTPUT.write_text(json.dumps(feedback, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
result = {
    "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
    "target": TARGET,
    "timeout_ms": TIMEOUT_MS,
    "source": "actual-client-named-pipe + shadow-mihomo",
    "summary": summary,
    "rows": rows,
}
path = REPORT / "client_shadow_audit.json"
path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
print(json.dumps(summary, ensure_ascii=False))
for row in rows:
    print(row["client_passes"], row["shadow_passes"], row["name"][:90])
print(f"saved {path}")
print(f"feedback saved {OUTPUT}: {len(stable_keys)} nodes")
