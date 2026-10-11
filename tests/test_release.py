"""VERSION is the single source of truth, and scripts/release.sh honors it."""

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest
import yaml

from loom_computer import VERSION

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "release.sh"
IMAGE = "ghcr.io/bvaughan7/loom-computer"
SEMVER = r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"


def run(*cmd, **kw):
    return subprocess.run([str(c) for c in cmd], capture_output=True, text=True, **kw)


def test_version_file_is_semver_and_is_what_the_package_serves():
    import re
    text = (ROOT / "VERSION").read_text()
    assert re.match(SEMVER, text.strip())
    assert VERSION == text.strip()


def test_guide_version_is_the_version_file():
    from fastapi.testclient import TestClient
    from loom_computer.app import create_app
    r = TestClient(create_app("t")).post(
        "/mcp", headers={"Authorization": "Bearer t"},
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
              "params": {"name": "state", "arguments": {"action": "guide"}}})
    guide = r.json()["result"]["structuredContent"]
    assert guide["version"] == (ROOT / "VERSION").read_text().strip()


def test_dockerfile_reads_version_for_label_and_build_arg():
    df = (ROOT / "Dockerfile").read_text()
    assert "ARG VERSION" in df
    assert "COPY VERSION" in df
    assert "org.opencontainers.image.version" in df
    assert 'test "$VERSION" = "$(cat VERSION)"' in df


def load_workflow():
    text = (ROOT / ".github/workflows/release.yml").read_text()
    return yaml.safe_load(text), text


def test_workflow_shape():
    wf, text = load_workflow()
    triggers = wf[True]  # YAML 1.1 parses the bare key `on` as True
    assert triggers["push"]["tags"] == ["v[0-9]+.[0-9]+.[0-9]+"]
    assert "image_tag" in triggers["workflow_dispatch"]["inputs"]
    assert wf["permissions"] == {"contents": "read"}
    assert set(wf["jobs"]) == {"build", "publish"}
    assert ":latest" not in text
    assert "VERSION" in text


def test_dispatch_path_holds_no_write_permissions():
    wf, _ = load_workflow()
    build, publish = wf["jobs"]["build"], wf["jobs"]["publish"]
    # build runs on both events (no job-level `if`) and is read-only
    assert "if" not in build
    assert build["permissions"] == {"contents": "read"}
    for scope, level in {**wf["permissions"], **build["permissions"]}.items():
        assert level in ("read", "none"), scope
    # everything that can write is in publish, which only runs on tag push
    assert publish["if"] == "github.event_name == 'push'"
    assert publish["needs"] == "build"
    assert publish["permissions"] == {"contents": "write", "packages": "write"}
    build_text = yaml.safe_dump(build)
    for needle in ("login-action", "secrets.GITHUB_TOKEN", "docker push", "gh release"):
        assert needle not in build_text


def test_published_image_is_the_smoke_checked_image():
    wf, _ = load_workflow()
    build, publish = wf["jobs"]["build"], wf["jobs"]["publish"]
    # exactly one build, in the build job, never pushed from there
    builds = [s for j in (build, publish) for s in j["steps"]
              if str(s.get("uses", "")).startswith("docker/build-push-action")]
    assert len(builds) == 1 and builds[0]["with"]["push"] is False
    smoke = [i for i, s in enumerate(build["steps"]) if "Smoke check" in s.get("name", "")]
    export = [i for i, s in enumerate(build["steps"]) if "docker save" in s.get("run", "")]
    assert smoke and export and smoke[0] < export[0]
    # publish pushes the loaded artifact, after verifying its image ID
    run_steps = [s.get("run", "") for s in publish["steps"]]
    load_i = next(i for i, r in enumerate(run_steps) if "docker load" in r)
    push_i = next(i for i, r in enumerate(run_steps) if "docker push" in r)
    assert load_i < push_i
    assert "needs.build.outputs.image_id" in str(publish["steps"][load_i])
    assert 'docker image inspect --format \'{{.Id}}\'' in run_steps[load_i]
    assert "docker build" not in "".join(run_steps)


def semver_ok(value):
    """The resolve step's regex, exactly as written in the workflow."""
    import re
    _, text = load_workflow()
    pattern = re.search(r"semver='([^']+)'", text).group(1)
    assert pattern == SEMVER
    return re.match(pattern, value) is not None


@pytest.mark.parametrize("good", ["0.0.0", "0.10.3", "1.2.3", "10.20.30"])
def test_semver_regex_accepts_plain_semver(good):
    assert semver_ok(good)


@pytest.mark.parametrize("bad", ["01.2.3", "1.02.3", "1.2.03", "1.2", "1.2.3-rc1", "v1.2.3", ""])
def test_semver_regex_rejects_leading_zeros_and_non_semver(bad):
    assert not semver_ok(bad)


def test_workflow_resolve_step_enforces_semver_on_tag():
    _, text = load_workflow()
    assert 'grep -Eq "$semver"' in text
    assert "is not plain semver" in text


# --- scripts/release.sh --dry-run ---

FAKE_DOCKER = """#!/bin/sh
echo "$@" >> "$FAKE_DOCKER_LOG"
case "$1" in
  run) echo fakecid ;;
  exec) case "$*" in *tools/call*|*structuredContent*) echo "$FAKE_GUIDE_VERSION" ;; esac ;;
esac
exit 0
"""


@pytest.fixture
def fake_docker(tmp_path):
    exe = tmp_path / "fake-docker"
    exe.write_text(FAKE_DOCKER)
    exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
    log = tmp_path / "docker.log"
    return exe, log


def dry_run(fake, *args, guide_version):
    exe, log = fake
    env = {**os.environ, "DOCKER": str(exe), "FAKE_DOCKER_LOG": str(log),
           "FAKE_GUIDE_VERSION": guide_version}
    return run(SCRIPT, "--dry-run", *args, env=env, cwd=ROOT)


def test_dry_run_builds_with_version_arg_and_ghcr_tag(fake_docker):
    r = dry_run(fake_docker, "9.8.7", guide_version="9.8.7")
    assert r.returncode == 0, r.stderr
    calls = fake_docker[1].read_text().splitlines()
    build = next(c for c in calls if c.startswith("build "))
    assert "--build-arg VERSION=9.8.7" in build
    assert f"-t {IMAGE}:9.8.7" in build
    assert not any(c.startswith(("push", "login", "tag")) for c in calls)
    assert any(c.startswith("rm -f fakecid") for c in calls)
    assert "nothing pushed" in r.stdout


def test_dry_run_defaults_to_version_file(fake_docker):
    r = dry_run(fake_docker, guide_version=VERSION)
    assert r.returncode == 0, r.stderr
    assert f"-t {IMAGE}:{VERSION}" in fake_docker[1].read_text()


def test_dry_run_fails_when_guide_serves_another_version(fake_docker):
    r = dry_run(fake_docker, "9.8.7", guide_version="0.0.1")
    assert r.returncode == 1
    assert "expected '9.8.7'" in r.stderr


@pytest.mark.parametrize("bad", ["v1.2.3", "1.2", "1.2.3-rc1", "01.2.3", "latest"])
def test_rejects_non_semver(fake_docker, bad):
    r = dry_run(fake_docker, bad, guide_version="x")
    assert r.returncode == 2
    assert not fake_docker[1].exists()


def test_dry_run_leaves_the_tree_untouched(fake_docker):
    before = (ROOT / "VERSION").read_text()
    dry_run(fake_docker, "9.8.7", guide_version="9.8.7")
    assert (ROOT / "VERSION").read_text() == before


@pytest.mark.skipif(not shutil.which("docker")
                    or run("docker", "info").returncode != 0, reason="docker unavailable")
def test_dry_run_with_real_docker_serves_the_version():
    r = run(SCRIPT, "--dry-run", "0.0.1", timeout=1500, cwd=ROOT)
    assert r.returncode == 0, r.stdout[-2000:] + r.stderr
    assert f"{IMAGE}:0.0.1 serves guide version 0.0.1" in r.stdout
    label = run("docker", "image", "inspect", f"{IMAGE}:0.0.1", "--format",
                '{{index .Config.Labels "org.opencontainers.image.version"}}')
    assert label.stdout.strip() == "0.0.1"
    run("docker", "rmi", f"{IMAGE}:0.0.1")


# --- real (non-dry) run against a throwaway repo with a local origin ---

def test_release_commits_tags_and_pushes_to_origin(tmp_path):
    origin = tmp_path / "origin.git"
    work = tmp_path / "work"
    git = lambda *a, cwd=work: subprocess.run(["git", *a], cwd=cwd, check=True,
                                              capture_output=True, text=True)
    subprocess.run(["git", "init", "--bare", str(origin)], check=True, capture_output=True)
    (work / "scripts").mkdir(parents=True)
    shutil.copy(SCRIPT, work / "scripts" / "release.sh")
    (work / "VERSION").write_text("1.0.0\n")
    git("init", "-q", "-b", "main")
    git("config", "user.email", "t@example.com")
    git("config", "user.name", "t")
    git("remote", "add", "origin", str(origin))
    git("add", "-A")
    git("commit", "-qm", "init")

    r = run(work / "scripts" / "release.sh", "--yes", "1.0.1", cwd=work)
    assert r.returncode == 0, r.stderr
    assert (work / "VERSION").read_text() == "1.0.1\n"
    assert git("log", "-1", "--format=%s").stdout.strip() == "release: 1.0.1"
    assert git("rev-parse", "v1.0.1^{commit}").stdout == git("rev-parse", "HEAD").stdout
    assert "refs/tags/v1.0.1" in git("ls-remote", "--tags", "origin").stdout
    assert "read:packages" in r.stdout and "docker login ghcr.io" in r.stdout

    again = run(work / "scripts" / "release.sh", "--yes", "1.0.1", cwd=work)
    assert again.returncode == 1 and "already exists" in again.stderr
