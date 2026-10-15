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
    assert "--failed-pool state/failed-pool-auto.json" in workflow
    assert (
        "git add -- docs/dist docs/auto state/verified-pool-auto.json" not in workflow
    )
    assert "git add -- docs/dist docs/auto" in workflow
    assert "verified-pool-auto\\.json" not in workflow


def test_cloud_workflow_persists_pool_via_encrypted_cache() -> None:
    workflow = (ROOT / ".github/workflows/auto-refresh.yml").read_text(encoding="utf-8")
    assert "actions/cache/restore@v4" in workflow
    assert "actions/cache/save@v4" in workflow
    assert workflow.count("state/verified-pool-auto.json.enc") >= 2
    assert workflow.count("state/verified-pool-auto.json.enc.mac") >= 2
    assert workflow.count("state/failed-pool-auto.json.enc") >= 2
    assert workflow.count("state/failed-pool-auto.json.enc.mac") >= 2
    assert "secrets.POOL_ENCRYPTION_PASSPHRASE" in workflow
    assert "-pass env:POOL_PASS" in workflow
    assert "openssl enc -d -aes-256-cbc -pbkdf2" in workflow
    assert "openssl enc -aes-256-cbc -pbkdf2" in workflow
    assert "load_runtime_pools" in workflow
    assert "hmac.new" in workflow
    for line in workflow.splitlines():
        if line.strip().startswith("git add"):
            assert "state/" not in line


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
