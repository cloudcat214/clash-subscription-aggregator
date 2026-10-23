import importlib.util
import json
import sys
from pathlib import Path

from aggregator.quality import node_key

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts" / "expand_cn_feedback.py"
_MODULE = None


def _load():
    global _MODULE
    if _MODULE is None:
        spec = importlib.util.spec_from_file_location("expand_cn_feedback", SCRIPT)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _MODULE = module
    return _MODULE


def _node(name: str, node_type: str = "vless") -> dict[str, object]:
    return {
        "name": name,
        "type": node_type,
        "server": f"{name}.example",
        "port": 443,
    }


def test_tcp_nodes_skips_udp_types() -> None:
    module = _load()
    proxies = [
        _node("a"),
        _node("b", "hysteria2"),
        _node("c", "wireguard"),
        _node("d", "ss"),
    ]
    names = [node["name"] for node in module.tcp_nodes(proxies)]
    assert names == ["a", "d"]


def test_select_window_wraps_around() -> None:
    module = _load()
    nodes = [_node(str(index)) for index in range(5)]
    window = module.select_window(nodes, 3, 4)
    assert [node["name"] for node in window] == ["4", "0", "1"]
    assert len(module.select_window(nodes, 10, 0)) == 5


def test_merge_on_state_adds_and_keeps_untested() -> None:
    module = _load()
    on, off = module.merge_on_state(
        previous_on=["a", "b", "gone"],
        previous_off={},
        published_keys={"a", "b", "c", "d"},
        results={"b": "off", "c": "on"},
    )
    # a was not tested -> kept; b got its first confirmed off -> kept with a
    # strike; gone is missing from this run's published set but absence is not
    # evidence, so it is retained; c is newly on -> added.
    assert on == ["a", "b", "c", "gone"]
    assert off == {"b": 1}


def test_merge_on_state_keeps_records_absent_from_publication() -> None:
    module = _load()
    on, off = module.merge_on_state(
        previous_on=["kept", "also-kept"],
        previous_off={},
        published_keys=set(),
        results={},
    )
    assert on == ["also-kept", "kept"]
    assert off == {}


def test_merge_on_state_drops_after_two_off_strikes() -> None:
    module = _load()
    on, off = module.merge_on_state(
        previous_on=["a", "b"],
        previous_off={"b": 1},
        published_keys={"a", "b"},
        results={"a": "off", "b": "off"},
    )
    assert on == ["a"]
    assert off == {"a": 1}


def test_merge_on_state_on_resets_off_strike() -> None:
    module = _load()
    on, off = module.merge_on_state(
        previous_on=["a"],
        previous_off={"a": 1},
        published_keys={"a"},
        results={"a": "on"},
    )
    assert on == ["a"]
    assert off == {}


def test_tcp_nodes_type_whitelist() -> None:
    module = _load()
    proxies = [_node("a", "http"), _node("b", "vless"), _node("c", "vmess")]
    names = [node["name"] for node in module.tcp_nodes(proxies, {"http"})]
    assert names == ["a"]


def test_collect_snapshots_keeps_only_on_nodes() -> None:
    module = _load()
    on_node = _node("on")
    carried = _node("carried")
    untested = _node("untested")
    snapshots = module.collect_snapshots(
        [node_key(on_node), node_key(carried)],
        {node_key(on_node): on_node},
        {node_key(carried): carried, node_key(untested): untested},
    )
    assert set(snapshots) == {node_key(on_node), node_key(carried)}
    assert snapshots[node_key(carried)]["name"] == "carried"


def test_legacy_name_hash_keys_are_migrated() -> None:
    module = _load()
    node = _node("legacy")
    mapping = module.legacy_key_map([node])
    assert mapping[module.legacy_name_key("legacy")] == node_key(node)
    assert module.migrate_legacy_keys(
        [module.legacy_name_key("legacy"), "unknown-key"], mapping
    ) == [node_key(node), "unknown-key"]


def test_main_writes_snapshots_for_run_on_nodes(tmp_path, monkeypatch) -> None:
    module = _load()
    on_node = _node("on", "http")
    off_node = _node("off", "http")
    monkeypatch.setattr(module, "load_published", lambda dist_dir: [on_node, off_node])
    monkeypatch.setattr(module.time, "sleep", lambda seconds: None)

    def fake_check(api_base, dev_id, dev_key, host, port, *, timeout=20.0):
        return "on" if host == on_node["server"] else "off"

    monkeypatch.setattr(module, "check_port", fake_check)
    output = tmp_path / "cn-feedback" / "cloud.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "expand_cn_feedback.py",
            "--dist-dir",
            str(tmp_path / "dist"),
            "--output",
            str(output),
            "--limit",
            "10",
            "--delay",
            "0",
            "--types",
            "",
        ],
    )

    assert module.main() == 0

    document = json.loads(output.read_text(encoding="utf-8"))
    assert document["stable_keys"] == [node_key(on_node)]
    assert set(document["nodes"]) == {node_key(on_node)}
    assert document["nodes"][node_key(on_node)]["name"] == "on"
