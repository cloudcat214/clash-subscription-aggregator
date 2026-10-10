from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

ALLOWED_ERROR_CATEGORIES = frozenset(
    {
        "timeout",
        "http_error",
        "network_error",
        "invalid_response",
        "invalid_probe_result",
        "invalid_probe_policy",
        "probe_unavailable",
        "process_start_error",
        "process_exit",
        "controller_timeout",
        "controller_auth_error",
        "controller_http_error",
        "core_validation_error",
        "probe_error",
    }
)


def _categories_from_payload(payload: object) -> dict[str, int]:
    if not isinstance(payload, dict):
        return {}
    verification = payload.get("verification")
    if not isinstance(verification, dict):
        return {}

    raw_categories = verification.get("error_categories")
    categories: dict[str, int] = {}
    if isinstance(raw_categories, dict):
        categories = {
            key: value
            for key, value in raw_categories.items()
            if isinstance(key, str)
            and key in ALLOWED_ERROR_CATEGORIES
            and isinstance(value, int)
            and not isinstance(value, bool)
            and value >= 0
        }

    single = verification.get("error_category")
    if (
        not categories
        and isinstance(single, str)
        and single in ALLOWED_ERROR_CATEGORIES
    ):
        categories = {single: 1}
    return dict(sorted(categories.items()))


def load_error_categories(health_path: Path) -> dict[str, int]:
    try:
        payload = json.loads(health_path.read_text(encoding="utf-8"))
    except (OSError, TypeError, ValueError):
        return {}
    return _categories_from_payload(payload)


def write_summary(
    categories: dict[str, int], github_env: str | os.PathLike[str] | None
) -> None:
    if not github_env:
        return
    try:
        with Path(github_env).open("a", encoding="utf-8", newline="\n") as env:
            env.write(
                "PROBE_ERROR_CATEGORIES="
                f"{json.dumps(categories, sort_keys=True, separators=(',', ':'))}\n"
            )
            env.write(f"PROBE_ERROR_TOTAL={sum(categories.values())}\n")
    except (OSError, TypeError, ValueError):
        pass


def build_summary(health_path: Path, github_env: str | os.PathLike[str] | None) -> None:
    categories = load_error_categories(health_path)
    write_summary(categories, github_env)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Write a redacted probe failure summary."
    )
    parser.add_argument(
        "health_path",
        nargs="?",
        type=Path,
        default=Path("dist/health.json"),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    build_summary(args.health_path, os.environ.get("GITHUB_ENV"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
