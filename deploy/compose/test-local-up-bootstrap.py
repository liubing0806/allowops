#!/usr/bin/env python3
"""local-up.sh must run bootstrap until it has succeeded once (needs no Docker).

Copies deploy/compose to a temporary directory and runs the real local-up.sh
with stub docker, python3 and prepare.sh on PATH. The stub docker logs its
arguments and can fail the readiness wait, which models a first run interrupted
after prepare.sh created .local and before bootstrap (admin-tool) ran.
"""
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import tempfile

COMPOSE = pathlib.Path(__file__).resolve().parent

DOCKER = """#!/bin/sh
echo "$*" >> "$STUB_LOG"
if [ "$1" = context ]; then
    echo unix:///var/run/docker.sock
    exit 0
fi
case "$*" in
    *" wait ready")
        if [ -n "${STUB_FAIL_READY:-}" ]; then echo 'stub: gateway not ready' >&2; exit 1; fi ;;
    *" admin-tool")
        if [ -n "${STUB_FAIL_BOOTSTRAP:-}" ]; then echo 'stub: bootstrap failed' >&2; exit 1; fi
        # What bootstrap.py leaves behind: one join token per demo host.
        for host in demo-1 demo-2 demo-3; do echo token > "$STUB_COMPOSE/.local/joins/$host.token"; done ;;
    *" admin-tool ensure-mcp")
        echo token > "$STUB_COMPOSE/.local/mcp-token" ;;
esac
"""
PYTHON3 = """#!/bin/sh
echo "python3 $*" >> "$STUB_LOG"
if [ "$1" = local-origin.py ]; then echo unchanged; fi
"""
PREPARE = """#!/bin/sh
mkdir -p .local/joins .local/secrets
"""


def write_executable(path: pathlib.Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


class Sandbox:
    def __init__(self, root: pathlib.Path) -> None:
        self.compose = root / "compose"
        shutil.copytree(COMPOSE, self.compose, ignore=shutil.ignore_patterns(".local"))
        write_executable(self.compose / "prepare.sh", PREPARE)
        self.bin = root / "bin"
        self.bin.mkdir()
        write_executable(self.bin / "docker", DOCKER)
        write_executable(self.bin / "python3", PYTHON3)
        self.log = root / "stub.log"

    def run(self, fail_ready: bool = False, fail_bootstrap: bool = False) -> subprocess.CompletedProcess:
        env = {name: value for name, value in os.environ.items()
               if not name.startswith(("DOCKER_", "COMPOSE_", "ALLOWOPS_"))}
        env.update(PATH=f"{self.bin}:/usr/bin:/bin", STUB_LOG=str(self.log), STUB_COMPOSE=str(self.compose))
        if fail_ready:
            env["STUB_FAIL_READY"] = "1"
        if fail_bootstrap:
            env["STUB_FAIL_BOOTSTRAP"] = "1"
        return subprocess.run(["/bin/sh", str(self.compose / "local-up.sh")], env=env,
                              capture_output=True, text=True, timeout=60, check=False)

    def bootstrap_runs(self) -> int:
        lines = self.log.read_text().splitlines() if self.log.exists() else []
        return sum(1 for line in lines if line.endswith(" admin-tool"))


def check(condition: bool, message: str) -> None:
    if not condition:
        print("FAIL: " + message, file=sys.stderr)
        sys.exit(1)


def interrupted_first_run_is_retried() -> None:
    with tempfile.TemporaryDirectory() as root:
        box = Sandbox(pathlib.Path(root))
        first = box.run(fail_ready=True)
        check(first.returncode != 0, "first run must fail at the readiness wait")
        check(box.bootstrap_runs() == 0, "first run must stop before bootstrap")
        check((box.compose / ".local").is_dir(), "first run must have created .local")
        second = box.run()
        check(second.returncode == 0, f"second run failed:\n{second.stderr}")
        check(box.bootstrap_runs() == 1,
              f"second run must invoke admin-tool bootstrap once, actual {box.bootstrap_runs()} (log: {box.log.read_text()!r})")
        check((box.compose / ".local/bootstrap.done").is_file(), "bootstrap success must write .local/bootstrap.done")
        third = box.run()
        check(third.returncode == 0, f"third run failed:\n{third.stderr}")
        check(box.bootstrap_runs() == 1, f"completed bootstrap must not run again, actual {box.bootstrap_runs()}")


def failed_bootstrap_leaves_no_marker() -> None:
    with tempfile.TemporaryDirectory() as root:
        box = Sandbox(pathlib.Path(root))
        result = box.run(fail_bootstrap=True)
        check(result.returncode != 0, "run must fail when admin-tool fails")
        check(not (box.compose / ".local/bootstrap.done").exists(), "failed bootstrap must not write the marker")


def environment_without_marker_but_bootstrapped_is_not_repeated() -> None:
    with tempfile.TemporaryDirectory() as root:
        box = Sandbox(pathlib.Path(root))
        joins = box.compose / ".local/joins"
        joins.mkdir(parents=True)
        (joins / "demo-1.token").write_text("token\n")
        result = box.run()
        check(result.returncode == 0, f"run failed:\n{result.stderr}")
        check(box.bootstrap_runs() == 0, "an environment with join tokens must not be bootstrapped again")
        check((box.compose / ".local/bootstrap.done").is_file(), "existing bootstrap must be recorded in the marker")


for scenario in (interrupted_first_run_is_retried, failed_bootstrap_leaves_no_marker,
                 environment_without_marker_but_bootstrapped_is_not_repeated):
    scenario()
    print(f"PASS: {scenario.__name__}")
