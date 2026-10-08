from pathlib import Path

import yaml

from aggregator.pipeline import initialize_dist, run_pipeline

FIXTURES = Path(__file__).parent / "fixtures"


def write_config(path: Path, source_path: Path) -> None:
    path.write_text(
        yaml.safe_dump(
            {
                "settings": {
                    "active_probe": False,
                    "filters": {"min_quality_score": 0},
                },
                "sources": {
                    "public": [
                        {
                            "id": "fixture",
                            "kind": "public",
                            "path": str(source_path),
                            "enabled": True,
                            "publish": True,
                            "requires_review": False,
                        }
                    ],
                    "private": [],
                },
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )


def test_manifest_generation_and_last_known_good_fallback(tmp_path: Path) -> None:
    config_path = tmp_path / "sources.yaml"
    source_path = tmp_path / "source.yaml"
    source_path.write_text(
        (FIXTURES / "clash.yaml").read_text(encoding="utf-8"), encoding="utf-8"
    )
    output_dir = tmp_path / "dist"
    state_dir = tmp_path / "state"
    write_config(config_path, source_path)

    first = run_pipeline(config_path, output_dir, state_dir)

    assert first.success is True
    assert (output_dir / "clash" / "providers" / "aggregate.yaml").exists()
    manifest = yaml.safe_load(
        (output_dir / "manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["counts"]["published"] == 2
    assert manifest["protocols"] == {"http": 1, "socks5": 1}

    previous_provider = (
        output_dir / "clash" / "providers" / "aggregate.yaml"
    ).read_text(encoding="utf-8")
    source_path.write_text("proxies: []\n", encoding="utf-8")

    second = run_pipeline(config_path, output_dir, state_dir)

    assert second.success is False
    assert second.used_last_known_good is True
    assert (output_dir / "clash" / "providers" / "aggregate.yaml").read_text(
        encoding="utf-8"
    ) == previous_provider
    health = yaml.safe_load((output_dir / "health.json").read_text(encoding="utf-8"))
    assert health["status"] == "failed"
    assert health["fallback"] == "last-known-good"


def test_empty_result_without_last_known_good_is_rejected(tmp_path: Path) -> None:
    config_path = tmp_path / "sources.yaml"
    source_path = tmp_path / "source.yaml"
    source_path.write_text("proxies: []\n", encoding="utf-8")
    output_dir = tmp_path / "dist"
    state_dir = tmp_path / "state"
    write_config(config_path, source_path)

    result = run_pipeline(config_path, output_dir, state_dir)

    assert result.success is False
    assert result.used_last_known_good is False
    assert "empty_result" in result.failure_reason


def test_private_source_never_enters_public_dist_even_when_publish_is_true(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "sources.yaml"
    source_path = tmp_path / "private-source.yaml"
    source_path.write_text(
        (FIXTURES / "clash.yaml").read_text(encoding="utf-8"), encoding="utf-8"
    )
    config_path.write_text(
        yaml.safe_dump(
            {
                "settings": {"active_probe": False},
                "sources": {
                    "public": [],
                    "private": [
                        {
                            "id": "owned",
                            "path": str(source_path),
                            "enabled": True,
                            "publish": True,
                            "requires_review": False,
                        }
                    ],
                },
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    output_dir = tmp_path / "dist"
    initialize_dist(output_dir)
    result = run_pipeline(config_path, output_dir, tmp_path / "state")

    assert result.success is False
    assert result.failure_reason == "empty_result"
    assert result.source_results[0].status == "validated_not_published"
    provider = (output_dir / "clash/providers/aggregate.yaml").read_text(
        encoding="utf-8"
    )
    assert provider == "proxies: []\n"
