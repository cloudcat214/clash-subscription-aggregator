"""One-shot migration of feedback key files to the stable node identity.

The old identity was ``sha256(display name)[:16]``; it now hashes the
protocol-relevant node fields instead. Every existing ``cn-feedback/*.json``
still carries old keys, so a straight switch would make the /cn channel select
zero nodes. This maps old keys onto the current published config (by name
hash) and drops keys that no longer correspond to any published node.

Idempotent: keys that already are stable keys are kept as they are.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from aggregator.quality import node_key

KEY_ALGORITHM = "stable-v1"
BLOCKED_TTL_HOURS = 72
DEFAULT_FILES = (
    ROOT / "cn-feedback" / "latest.json",
    ROOT / "cn-feedback" / "cloud.json",
    ROOT / "cn-feedback" / "blocked.json",
)


def legacy_key(name: str) -> str:
    return hashlib.sha256(name.encode("utf-8")).hexdigest()[:16]


def load_proxies(dist_dir: Path) -> list[dict[str, object]]:
    document = yaml.safe_load(
        (dist_dir / "clash" / "config.yaml").read_text(encoding="utf-8")
    )
    proxies = document.get("proxies") if isinstance(document, dict) else None
    if not isinstance(proxies, list):
        raise TypeError("dist_proxies_missing")
    return [
        proxy
        for proxy in proxies
        if isinstance(proxy, dict) and isinstance(proxy.get("name"), str)
    ]


def migrate_document(
    document: dict[str, object], mapping: dict[str, str]
) -> tuple[dict[str, object], dict[str, int]]:
    stats = {"kept": 0, "migrated": 0, "dropped": 0}
    stable: set[str] = set()
    raw_keys = document.get("stable_keys")
    for key in raw_keys if isinstance(raw_keys, list) else []:
        text = str(key)
        if text in mapping:
            stable.add(mapping[text])
            stats["migrated"] += 1
        elif text in mapping.values():
            stable.add(text)
            stats["kept"] += 1
        else:
            stats["dropped"] += 1
    migrated = dict(document)
    migrated["stable_keys"] = sorted(stable)
    migrated["stable"] = len(stable)
    migrated["verified"] = len(stable)
    migrated["key_algorithm"] = KEY_ALGORITHM
    off = document.get("cn_off")
    if isinstance(off, dict) and off:
        migrated["cn_off"] = {
            mapping.get(str(key), str(key)): count
            for key, count in off.items()
            if str(key) in mapping or str(key) in mapping.values()
        }
    return migrated, stats


def migrate_blocked(
    document: dict[str, object], name_by_legacy: dict[str, str]
) -> tuple[dict[str, object], dict[str, int]]:
    """blocked.json: legacy name hashes -> names + an honest TTL stamp."""
    stats = {"names": 0, "dropped": 0}
    names: set[str] = set()
    existing = document.get("names")
    if isinstance(existing, list):
        names.update(str(item) for item in existing if isinstance(item, str) and item)
    legacy = document.get("keys")
    for key in legacy if isinstance(legacy, list) else []:
        name = name_by_legacy.get(str(key))
        if name is None:
            stats["dropped"] += 1
        else:
            names.add(name)
    stats["names"] = len(names)
    generated_at = document.get("generated_at")
    expires_at = document.get("expires_at")
    if not isinstance(expires_at, str) and isinstance(generated_at, str):
        # The TTL starts from the audit that produced the list; if that is
        # already older than 72h the entries stay expired rather than being
        # silently renewed without a fresh test.
        expires_at = (
            (datetime.fromisoformat(generated_at) + timedelta(hours=BLOCKED_TTL_HOURS))
            .astimezone(UTC)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )
    migrated = dict(document)
    migrated.pop("keys", None)
    migrated["names"] = sorted(names)
    migrated["count"] = len(names)
    migrated["ttl_hours"] = BLOCKED_TTL_HOURS
    if isinstance(expires_at, str):
        migrated["expires_at"] = expires_at
    return migrated, stats


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist-dir", type=Path, default=ROOT / "docs" / "dist")
    parser.add_argument("--files", type=Path, nargs="*", default=list(DEFAULT_FILES))
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    proxies = load_proxies(args.dist_dir)
    mapping = {legacy_key(str(p["name"])): node_key(p) for p in proxies}
    name_by_legacy = {legacy_key(str(p["name"])): str(p["name"]) for p in proxies}
    print(f"[migrate] published={len(proxies)} legacy_keys={len(mapping)}")
    for path in args.files:
        if not path.is_file():
            print(f"[migrate] skip missing {path}")
            continue
        document = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(document, dict):
            print(f"[migrate] skip non-object {path}")
            continue
        if path.name == "blocked.json":
            migrated, stats = migrate_blocked(document, name_by_legacy)
            print(
                f"[migrate] {path.name}: names={stats['names']} "
                f"dropped={stats['dropped']} expires_at={migrated.get('expires_at')}"
            )
        else:
            migrated, stats = migrate_document(document, mapping)
            print(
                f"[migrate] {path.name}: stable={migrated['stable']} "
                f"migrated={stats['migrated']} kept={stats['kept']} "
                f"dropped={stats['dropped']}"
            )
        if not args.dry_run:
            path.write_text(
                json.dumps(migrated, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
