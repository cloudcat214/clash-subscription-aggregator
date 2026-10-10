from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from pathlib import Path

from . import __version__
from .pipeline import initialize_dist, load_config, run_pipeline
from .probe import probe_nodes
from .validators import validate_generated_artifacts


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="安全聚合 Clash/Mihomo 订阅并生成 sing-box 配置"
    )
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    run = subparsers.add_parser("run", help="抓取、解析、过滤并发布聚合结果")
    run.add_argument("--config", type=Path, default=Path("config/sources.yaml"))
    run.add_argument("--output", type=Path, default=Path("dist"))
    run.add_argument("--state", type=Path, default=Path("state"))
    run.add_argument(
        "--offline", action="store_true", help="拒绝 HTTP(S) 来源，仅允许本地文件来源"
    )
    run.add_argument(
        "--no-private", action="store_true", help="禁止读取或生成私有来源，CI 必须使用"
    )
    run.add_argument(
        "--include-private", action="store_true", help="生成公开+自有节点的独立本机产物"
    )
    run.add_argument("--private-output", type=Path, default=Path("dist-private"))
    run.add_argument("--base-url", help="公开 Pages dist 的固定 URL 前缀")
    run.add_argument("--mihomo", help="用于 -t 和可选 probe 的 Mihomo 可执行文件")
    run.add_argument("--sing-box", help="用于 check 的 sing-box 可执行文件")
    run.add_argument(
        "--require-core", action="store_true", help="缺少核心或校验失败时禁止替换产物"
    )
    run.add_argument(
        "--probe", action="store_true", help="独立临时 Mihomo 实测，最多 500 节点×3轮"
    )
    run.add_argument("--probe-max-nodes", type=int, default=30)
    run.add_argument("--probe-rounds", type=int, default=3)
    run.add_argument("--probe-timeout", type=float, default=10.0)
    run.add_argument("--probe-concurrency", type=int, default=1)
    run.add_argument(
        "--probe-min-verdict",
        choices=("stable", "verified", "fast"),
        help="最低发布等级；默认 stable（3 轮且成功率至少 2/3）",
    )

    validate = subparsers.add_parser("validate", help="使用真实核心检查现有产物")
    validate.add_argument("--output", type=Path, default=Path("dist"))
    validate.add_argument("--mihomo", required=True)
    validate.add_argument("--sing-box")

    init_dist = subparsers.add_parser("init-dist", help="生成无节点的安全初始产物")
    init_dist.add_argument("--output", type=Path, default=Path("dist"))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "init-dist":
        initialize_dist(args.output)
        print(f"bootstrap artifacts written to {args.output}")
        return 0
    if args.command == "validate":
        validation = validate_generated_artifacts(
            args.output,
            mihomo_path=args.mihomo,
            sing_box_path=args.sing_box,
        )
        print(json.dumps(validation, ensure_ascii=False))
        return 0

    validator: Callable[[Path], dict[str, object]] | None = None
    if args.mihomo or args.sing_box or args.require_core:

        def _validator(root: Path) -> dict[str, object]:
            return validate_generated_artifacts(
                root,
                mihomo_path=args.mihomo,
                sing_box_path=args.sing_box,
                require=args.require_core,
            )

        validator = _validator

    probe_runner: Callable[[list[dict[str, object]]], dict[str, object]] | None = None
    if args.probe:
        if not args.mihomo:
            print("--probe requires --mihomo", file=sys.stderr)
            return 2

        def _probe_runner(proxies: list[dict[str, object]]) -> dict[str, object]:
            return probe_nodes(
                proxies,
                mihomo_path=args.mihomo,
                max_nodes=args.probe_max_nodes,
                rounds=args.probe_rounds,
                timeout=args.probe_timeout,
                concurrency=args.probe_concurrency,
            )

        probe_runner = _probe_runner

    config_path = args.config
    temporary_config: Path | None = None
    if args.base_url or args.probe:
        import tempfile

        import yaml

        config = load_config(config_path)
        if args.base_url:
            config.setdefault("publish", {})["base_url"] = args.base_url
        if args.probe:
            settings = config.setdefault("settings", {})
            settings["active_probe"] = True
            settings["probe_max_nodes"] = args.probe_max_nodes
            settings["probe_rounds"] = args.probe_rounds
            settings["probe_timeout_seconds"] = args.probe_timeout
            settings["probe_concurrency"] = args.probe_concurrency
            if args.probe_min_verdict:
                settings["probe_min_verdict"] = args.probe_min_verdict
        with tempfile.NamedTemporaryFile(
            "w", dir=config_path.parent, suffix=".yaml", encoding="utf-8", delete=False
        ) as handle:
            yaml.safe_dump(config, handle, sort_keys=False)
            temporary_config = Path(handle.name)
        config_path = temporary_config
    try:
        result = run_pipeline(
            config_path,
            args.output,
            args.state,
            offline=args.offline,
            include_private=args.include_private and not args.no_private,
            no_private=args.no_private,
            private_output_dir=args.private_output,
            validator=validator,
            probe_runner=probe_runner,
        )
    finally:
        if temporary_config:
            temporary_config.unlink(missing_ok=True)
    if result.success:
        print(f"published {result.manifest_path}")
        return 0
    print(
        f"aggregation failed: {result.failure_reason}; last-known-good={result.used_last_known_good}",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
