#!/usr/bin/env python3
"""D06: CI must reject embedded dist drift (tracked + untracked) after web build.

Uses the real .github/workflows/ci.yml web-job run commands and temporary
Git fixtures. Fails when the web job has no dist check (old CI would miss
a stale build) and passes only when the extracted check rejects both
tracked and untracked drift while accepting a clean tree.
"""
import pathlib
import shutil
import subprocess
import sys
import tempfile

import yaml

REPO = pathlib.Path(__file__).resolve().parents[1]
CI = REPO / ".github" / "workflows" / "ci.yml"
DIST_REL_FROM_WEB = "../internal/gateway/console/dist"


def sh(args, cwd, timeout=20):
    return subprocess.run(
        args, cwd=cwd, capture_output=True, text=True, timeout=timeout
    )


def web_runs():
    data = yaml.safe_load(CI.read_text(encoding="utf-8"))
    steps = data["jobs"]["web"]["steps"]
    runs = []
    for step in steps:
        if isinstance(step.get("run"), str):
            runs.append(step["run"])
    return runs


def dist_checks(runs):
    return [r for r in runs if "console/dist" in r or "console\\dist" in r]


def make_fixture(kind):
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="allowops-ci-dist-"))
    try:
        sh(["git", "init", "-q"], cwd=tmp)
        sh(["git", "config", "user.email", "test@example.invalid"], cwd=tmp)
        sh(["git", "config", "user.name", "test"], cwd=tmp)
        dist = tmp / "internal" / "gateway" / "console" / "dist"
        dist.mkdir(parents=True)
        (dist / "index.html").write_text("clean", encoding="utf-8")
        (tmp / "web").mkdir()
        sh(["git", "add", "."], cwd=tmp)
        sh(["git", "commit", "-qm", "clean"], cwd=tmp)
        if kind == "tracked":
            (dist / "index.html").write_text("dirty-build", encoding="utf-8")
        elif kind == "untracked":
            (dist / "assets").mkdir(exist_ok=True)
            (dist / "assets" / "new-chunk.js").write_text(
                "untracked", encoding="utf-8"
            )
        elif kind == "clean":
            pass
        else:
            raise AssertionError(kind)
        return tmp
    except Exception:
        shutil.rmtree(tmp, ignore_errors=True)
        raise


def run_checks_in_fixture(checks, fixture):
    # Run each extracted `run:` script from the web working directory,
    # exactly as CI would (defaults.run.working-directory: web).
    web_cwd = fixture / "web"
    results = []
    for script in checks:
        # CI uses `run:` shell snippets; execute via sh -c to preserve
        # multi-line semantics (git diff + test -z).
        proc = subprocess.run(
            ["sh", "-c", script],
            cwd=web_cwd,
            capture_output=True,
            text=True,
            timeout=20,
        )
        results.append(proc)
    return results


def main():
    runs = web_runs()
    checks = dist_checks(runs)
    if not checks:
        # Old CI: web job builds but never inspects the embedded dist.
        # Prove the leak with a real fixture: a dirty dist exists yet no
        # web-job command would fail.
        fixture = make_fixture("tracked")
        try:
            status = sh(
                ["git", "status", "--porcelain", "--", DIST_REL_FROM_WEB],
                cwd=fixture / "web",
            )
            print(
                "FAIL: web job has no dist consistency check; "
                f"dirty dist status={status.stdout.strip()!r} would be missed",
                file=sys.stderr,
            )
            return 1
        finally:
            shutil.rmtree(fixture, ignore_errors=True)
    failures = []
    for kind, expect_rc in (
        ("tracked", "reject"),
        ("untracked", "reject"),
        ("clean", "accept"),
    ):
        fixture = make_fixture(kind)
        try:
            results = run_checks_in_fixture(checks, fixture)
            rcs = [r.returncode for r in results]
            if expect_rc == "reject":
                if all(rc == 0 for rc in rcs):
                    failures.append(
                        f"{kind}: expected dist check to reject, got rc={rcs}"
                    )
            else:
                if any(rc != 0 for rc in rcs):
                    failures.append(
                        f"{kind}: expected dist check to accept clean, got rc={rcs}"
                    )
        finally:
            shutil.rmtree(fixture, ignore_errors=True)
    if failures:
        print("FAIL: dist check does not cover drift", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print("PASS: CI rejects tracked and untracked dist drift")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
