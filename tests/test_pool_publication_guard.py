from pathlib import Path

ROOT = Path(__file__).parents[1]


def test_pool_files_are_ignored_and_not_tracked() -> None:
    gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "/state/*" in gitignore
    assert "!/state/verified-pool.json" not in gitignore
    assert "!/state/verified-pool-auto.json" not in gitignore


def test_cloud_workflow_keeps_runtime_pool_but_does_not_stage_it() -> None:
    workflow = (ROOT / ".github/workflows/auto-refresh.yml").read_text(encoding="utf-8")
    assert "--verified-pool state/verified-pool-auto.json" in workflow
    assert (
        "git add -- docs/dist docs/auto state/verified-pool-auto.json" not in workflow
    )
    assert "git add -- docs/dist docs/auto" in workflow
    assert "verified-pool-auto\\.json" not in workflow


def test_local_publish_keeps_runtime_pool_but_does_not_commit_it() -> None:
    script = (ROOT / "scripts/refresh-publish.ps1").read_text(encoding="utf-8-sig")
    assert (
        '"state/verified-pool.json"'
        not in script.split("$MaterialArtifactPaths", 1)[1].split(")", 1)[0]
    )
    assert 'Invoke-Git @("add", "--all", "--", "docs/dist")' in script
    assert (
        'Invoke-Git @("add", "--all", "--", "docs/dist", "state/verified-pool.json")'
        not in script
    )
    assert '"--verified-pool", $VerifiedPoolPath' in script


def test_history_workflow_remains_present() -> None:
    assert (ROOT / ".github/workflows/update-history.yml").is_file()
    assert (ROOT / "scripts/update_history.py").is_file()
