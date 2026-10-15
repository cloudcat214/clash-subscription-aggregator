"""Build the /cn channel: current published nodes filtered by mainland feedback.

The feedback file (``cn-feedback/latest.json``) is produced by a one-shot local
probe (``scripts/cn_feedback_probe.py`` via ``scripts/refresh-cn-feedback.ps1``)
and committed to the repository. This builder intersects its stable keys with
the freshly generated cloud set and renders a standalone Clash config for the
``/cn`` subscription. It never invents data: no feedback, no rebuild.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from aggregator.outputs import render_artifacts
from aggregator.quality import node_key

FEEDBACK_SCHEMA_VERSION = 1
MIN_SELECTED = 1


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def load_feedback(path: Path) -> dict[str, object] | None:
    """Load and validate the feedback document; None means unusable."""
    if not path.is_file():
        return None
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(document, dict):
        return None
    if document.get("schema_version") != FEEDBACK_SCHEMA_VERSION:
        return None
    keys = document.get("stable_keys")
    if not isinstance(keys, list) or not all(
        isinstance(item, str) and item for item in keys
    ):
        return None
    return document


def _feedback_keys(document: dict[str, object]) -> set[str]:
    keys = document.get("stable_keys")
    assert isinstance(keys, list)
    return {str(item) for item in keys}


def build_cn_channel(
    dist_dir: Path, feedback_path: Path, output_dir: Path
) -> dict[str, object]:
    feedback = load_feedback(feedback_path)
    if feedback is None:
        return {"status": "skipped", "reason": "feedback_missing_or_invalid"}

    config_path = dist_dir / "clash" / "config.yaml"
    if not config_path.is_file():
        return {"status": "skipped", "reason": "dist_config_missing"}
    try:
        document = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return {"status": "skipped", "reason": "dist_config_unreadable"}
    proxies = document.get("proxies") if isinstance(document, dict) else None
    if not isinstance(proxies, list) or not proxies:
        return {"status": "skipped", "reason": "dist_proxies_missing"}
    valid_proxies = [
        proxy for proxy in proxies if isinstance(proxy, dict) and proxy.get("name")
    ]

    keys = _feedback_keys(feedback)
    selected = [proxy for proxy in valid_proxies if node_key(proxy) in keys]
    if len(selected) < MIN_SELECTED:
        return {
            "status": "skipped",
            "reason": "no_selected_nodes",
            "source_published": len(valid_proxies),
        }

    manifest: dict[str, object] = {
        "schema_version": 1,
        "generated_at": _utc_now(),
        "filter": "cn-feedback",
        "counts": {
            "source_published": len(valid_proxies),
            "selected": len(selected),
        },
    }
    feedback_meta: dict[str, object] = {}
    feedback_time = _parse_time(feedback.get("generated_at"))
    if feedback_time is not None:
        feedback_meta["generated_at"] = (
            feedback_time.astimezone(UTC).isoformat().replace("+00:00", "Z")
        )
        age_hours = (datetime.now(UTC) - feedback_time).total_seconds() / 3600
        feedback_meta["age_hours"] = round(max(0.0, age_hours), 1)
    for field in ("tested", "stable", "verified"):
        value = feedback.get(field)
        if isinstance(value, int) and not isinstance(value, bool):
            feedback_meta[field] = value
    if feedback_meta:
        manifest["feedback"] = feedback_meta

    artifacts = render_artifacts(selected)
    if output_dir.exists():
        shutil.rmtree(output_dir)
    (output_dir / "clash").mkdir(parents=True)
    (output_dir / "clash" / "config.yaml").write_text(
        artifacts["clash/config.yaml"], encoding="utf-8"
    )
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return {"status": "built", "selected": len(selected), "manifest": manifest}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist-dir", type=Path, default=ROOT / "dist-auto")
    parser.add_argument(
        "--feedback", type=Path, default=ROOT / "cn-feedback" / "latest.json"
    )
    parser.add_argument("--output", type=Path, default=ROOT / "docs" / "cn")
    args = parser.parse_args()

    result = build_cn_channel(args.dist_dir, args.feedback, args.output)
    if result.get("status") == "built":
        counts = result["manifest"]["counts"]  # type: ignore[index]
        manifest = result["manifest"]  # type: ignore[assignment]
        feedback_meta = manifest.get("feedback", {})  # type: ignore[union-attr]
        print(
            f"cn channel built: selected={counts['selected']} of "
            f"{counts['source_published']} feedback_stable={feedback_meta.get('stable')} "
            f"age_hours={feedback_meta.get('age_hours')}"
        )
        return 0
    print(f"cn channel skipped: {result.get('reason')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
