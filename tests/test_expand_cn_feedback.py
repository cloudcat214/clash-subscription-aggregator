import importlib.util
from pathlib import Path

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
    return {"name": name, "type": node_type, "server": "1.2.3.4", "port": 443}


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
    # strike; gone is no longer published -> dropped; c is newly on -> added.
    assert on == ["a", "b", "c"]
    assert off == {"b": 1}


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
