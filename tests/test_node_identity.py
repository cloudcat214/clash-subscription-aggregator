from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from aggregator.failed_pool import failed_pool_document, load_failed_pool
from aggregator.parsing import deduplicate_proxies
from aggregator.quality import node_key
from aggregator.verified_pool import load_verified_pool, pool_document

_HEX16 = re.compile(r"^[0-9a-f]{16}$")


def _vless(name: str = "node") -> dict[str, object]:
    return {
        "name": name,
        "type": "vless",
        "server": "edge.example.invalid",
        "port": 443,
        "uuid": "11111111-2222-3333-4444-555555555555",
        "tls": True,
        "servername": "sni.example.invalid",
        "network": "ws",
        "ws-opts": {"path": "/ws", "headers": {"Host": "sni.example.invalid"}},
        "udp": True,
        "up": 1024,
        "down": 4096,
        "sub_tag": "source-a",
        "ports": "443",
        "country": "NL",
    }


def _legacy_key(node: dict[str, object]) -> str:
    """The pre-fix algorithm: identity was the display name."""
    return hashlib.sha256(str(node.get("name") or "").encode("utf-8")).hexdigest()[:16]


def test_key_shape_is_unchanged() -> None:
    key = node_key(_vless())
    assert _HEX16.match(key)
    assert key == node_key(_vless())


def test_rename_keeps_identity() -> None:
    before = _vless("[sub-a] NL-01")
    after = _vless("[sub-a] 🇳🇱 036  | ⬇️ 4KB/s")  # speed / flag / re-tag noise
    assert node_key(before) == node_key(after)


def test_volatile_fields_do_not_change_identity() -> None:
    base = _vless()
    mutated = {
        **_vless(),
        "name": "renamed",
        "up": 999999,
        "down": 123456,
        "sub_tag": "source-b",
        "sub-tag": "source-b",
        "ports": "8443",
        "udp": False,
        "delay": 321,
        "country": "US",
    }
    assert node_key(base) == node_key(mutated)


def test_credential_change_changes_identity() -> None:
    base = _vless()
    assert node_key(base) != node_key({**base, "uuid": "other-uuid"})


def test_port_change_changes_identity() -> None:
    base = _vless()
    assert node_key(base) != node_key({**base, "port": 8443})


def test_servername_change_changes_identity() -> None:
    base = _vless()
    assert node_key(base) != node_key({**base, "servername": "other.example.invalid"})


def test_network_and_transport_change_changes_identity() -> None:
    base = _vless()
    assert node_key(base) != node_key({**base, "network": "grpc"})
    assert node_key(base) != node_key({**base, "ws-opts": {"path": "/other"}})


def test_plugin_options_change_changes_identity() -> None:
    ss = {
        "name": "ss",
        "type": "ss",
        "server": "edge.example.invalid",
        "port": 8388,
        "cipher": "aes-256-gcm",
        "password": "hunter2",
        "plugin": "obfs",
        "plugin-opts": {"mode": "http"},
    }
    assert node_key(ss) != node_key({**ss, "plugin-opts": {"mode": "tls"}})


def test_key_does_not_leak_credentials() -> None:
    key = node_key(_vless())
    assert "11111111" not in key
    assert "hunter2" not in key


def test_dedupe_uses_the_same_identity_as_node_key() -> None:
    """Two records of one physical node must not both reach the probe queue."""
    first = _vless("[sub-a] NL-01")
    second = {
        **_vless("[sub-b] 🇳🇱 036  | ⬇️ 4KB/s"),
        "up": 5,
        "sub_tag": "sub-b",
        "udp": False,
        "country": "US",
    }
    assert node_key(first) == node_key(second)
    unique = deduplicate_proxies([first, second])
    assert len(unique) == 1
    assert node_key(unique[0]) == node_key(first)


def _verified_entry(node: dict[str, object], *, rechecked: str, passes: int) -> dict:
    return {
        "key": _legacy_key(node),
        "node": node,
        "source_id": "source-a",
        "first_seen_at": "2026-10-11T00:00:00Z",
        "last_rechecked_at": rechecked,
        "last_conclusion": "stable",
        "consecutive_failures": 0,
        "total_passes": passes,
    }


def test_load_verified_pool_migrates_legacy_keys(tmp_path: Path) -> None:
    node = _vless("[sub-a] old-name")
    old_node = {**node, "name": "[sub-a] old-name"}
    new_node = {**node, "name": "[sub-a] new-name"}
    path = tmp_path / "verified-pool.json"
    path.write_text(
        json.dumps(
            pool_document(
                [
                    _verified_entry(
                        old_node, rechecked="2026-10-11T00:10:00Z", passes=1
                    ),
                    # Same physical node after a rename, stored under the old
                    # name-hash identity: must collapse into one fresh-key entry.
                    _verified_entry(
                        new_node, rechecked="2026-10-12T00:10:00Z", passes=4
                    ),
                ],
                "2026-10-12T00:10:00Z",
            )
        ),
        encoding="utf-8",
    )

    entries = load_verified_pool(path)

    assert len(entries) == 1
    assert entries[0]["key"] == node_key(node)
    assert entries[0]["key"] != _legacy_key(node)
    assert entries[0]["total_passes"] == 4  # newest wins
    node_field = entries[0]["node"]
    assert isinstance(node_field, dict)
    assert node_field["name"] == "[sub-a] new-name"


def test_load_failed_pool_migrates_legacy_keys(tmp_path: Path) -> None:
    node = _vless("[sub-a] flaky")
    path = tmp_path / "failed-pool.json"
    path.write_text(
        json.dumps(
            failed_pool_document(
                [
                    {
                        "key": _legacy_key(node),
                        "node": node,
                        "source_id": "source-a",
                        "first_failed_at": "2026-10-11T00:00:00Z",
                        "last_rechecked_at": "2026-10-11T00:10:00Z",
                        "next_retry_at": "2026-10-11T01:10:00Z",
                        "last_conclusion": "failed",
                        "last_error_category": "timeout",
                        "consecutive_failures": 1,
                        "total_failures": 1,
                    }
                ],
                "2026-10-11T00:10:00Z",
            )
        ),
        encoding="utf-8",
    )

    entries = load_failed_pool(path)

    assert [entry["key"] for entry in entries] == [node_key(node)]
