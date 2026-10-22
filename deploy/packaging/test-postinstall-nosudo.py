#!/usr/bin/env python3
"""D04: postinstall must tolerate a missing visudo (no sudo) but still
strictly validate when visudo exists. Executes the real
deploy/packaging/postinstall.sh with a controlled PATH and stubs so the
host install/systemctl are never touched.
"""
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = REPO / "deploy" / "packaging" / "postinstall.sh"


def write_stub(path: pathlib.Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)


def run_postinstall(bin_dir: pathlib.Path, extra_path: str) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["PATH"] = f"{bin_dir}{extra_path}"
    # Keep Go/cache env out of the way; run with a bounded timeout.
    # Absolute /bin/sh so the isolated PATH still finds the interpreter
    # while hiding the host visudo for the no-sudo case.
    return subprocess.run(
        ["/bin/sh", str(SCRIPT)],
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
    )


def main() -> int:
    failures = []
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="allowops-postinstall-"))
    try:
        bin_dir = tmp / "bin"
        bin_dir.mkdir()
        log = tmp / "calls.log"
        # Stubs prevent any real host mutation.
        write_stub(
            bin_dir / "install",
            f"#!/bin/sh\necho \"install $@\" >> {log}\nexit 0\n",
        )
        write_stub(
            bin_dir / "systemctl",
            f"#!/bin/sh\necho \"systemctl $@\" >> {log}\nexit 0\n",
        )
        # Case 1: no visudo on PATH (sudo not installed). Must succeed.
        # Isolated PATH (only stubs) so the host /usr/bin/visudo is invisible.
        result = run_postinstall(bin_dir, "")
        if result.returncode != 0:
            failures.append(
                f"no-visudo: expected exit 0, got {result.returncode}\n"
                f"stdout={result.stdout!r}\nstderr={result.stderr!r}"
            )
        else:
            calls = log.read_text() if log.exists() else ""
            if "install -d" not in calls or "systemctl" not in calls:
                failures.append(
                    f"no-visudo: expected install/systemctl stubs to run, got {calls!r}"
                )
        # Case 2: visudo present and valid. Must succeed and validate.
        log.unlink(missing_ok=True)
        write_stub(
            bin_dir / "visudo",
            f"#!/bin/sh\necho \"visudo $@\" >> {log}\n"
            "case \"$*\" in *-cf*) exit 0;; *) exit 0;; esac\n",
        )
        result = run_postinstall(bin_dir, "")
        if result.returncode != 0:
            failures.append(
                f"visudo-valid: expected exit 0, got {result.returncode} "
                f"stderr={result.stderr!r}"
            )
        # Case 3: visudo present but invalid. Must fail, never silently pass.
        write_stub(bin_dir / "visudo", "#!/bin/sh\nexit 1\n")
        result = run_postinstall(bin_dir, "")
        if result.returncode == 0:
            failures.append("visudo-invalid: expected non-zero exit, got 0")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if failures:
        print("FAIL: postinstall sudo compatibility", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print("PASS: postinstall tolerates missing visudo and validates strictly")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
