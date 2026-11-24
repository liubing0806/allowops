#!/usr/bin/env python3
"""Check the PR workflow using its own path filter and real Go builds."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml

REPO = Path(__file__).resolve().parents[1]
CHECK = REPO / "test/cross-compile-check.sh"
# Keep Actions keys such as "on" as strings (PyYAML otherwise interprets YAML 1.1 booleans).
WORKFLOW = yaml.load(
    (REPO / ".github/workflows/pr-gates.yml").read_text(encoding="utf-8"), Loader=yaml.BaseLoader
)
TARGETS = ("linux/amd64", "darwin/arm64", "darwin/amd64", "windows/amd64")


def run(args, cwd, env):
    return subprocess.run(
        args, cwd=cwd, env=env, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, text=True, timeout=300,
    )


class WorkflowTests(unittest.TestCase):
    def test_workflow(self):
        self.assertEqual(WORKFLOW["on"], {"pull_request": "", "workflow_dispatch": ""})
        self.assertEqual(WORKFLOW["permissions"], {"contents": "read"})
        concurrency = WORKFLOW["concurrency"]
        self.assertIn("github.event.pull_request.number", concurrency["group"])
        self.assertEqual(concurrency["cancel-in-progress"], "${{ github.event_name == 'pull_request' }}")
        jobs = WORKFLOW["jobs"]
        self.assertEqual(set(jobs), {"cli-cross-compile", "console-e2e-pr"})
        for job in jobs.values():
            self.assertNotIn("needs", job)
            self.assertNotIn("permissions", job)
            self.assertEqual(job["runs-on"], "ubuntu-latest")
        cli = jobs["cli-cross-compile"]["steps"]
        self.assertEqual([step["uses"] for step in cli if "uses" in step],
                         ["actions/checkout@v5", "actions/setup-go@v6"])
        build = next(step for step in cli if step.get("run") == "./test/cross-compile-check.sh")
        self.assertNotIn("if", build)
        console = jobs["console-e2e-pr"]["steps"]
        actions = {step["uses"]: step for step in console if "uses" in step}
        pnpm = next(action for action in actions if action.startswith("pnpm/action-setup@"))
        self.assertRegex(pnpm, r"^pnpm/action-setup@[0-9a-f]{40}$")
        self.assertEqual(set(actions) - {pnpm}, {
            "actions/checkout@v5", "actions/setup-go@v6",
            "actions/setup-node@v6", "actions/setup-python@v6", "actions/upload-artifact@v4",
        })
        python = actions["actions/setup-python@v6"]
        install = next(step for step in console if step.get("run") == "python3 -m pip install PyYAML==6.0.3")
        self.assertEqual(python["with"]["python-version"], "3.12")
        self.assertEqual(python["if"], "steps.changes.outputs.run_e2e == 'true'")
        self.assertLess(console.index(python), console.index(install))
        self.assertEqual(actions["actions/checkout@v5"]["with"]["fetch-depth"], "0")
        steps = {step["id"]: step for step in console if "id" in step}
        self.assertEqual(steps["changes"]["env"]["BASE_SHA"], "${{ github.event.pull_request.base.sha }}")
        self.assertEqual(steps["changes"]["shell"], "bash")
        self.assertEqual(steps["e2e"]["run"], "make e2e")
        self.assertEqual(steps["e2e"]["if"], "steps.changes.outputs.run_e2e == 'true'")
        upload = actions["actions/upload-artifact@v4"]
        self.assertEqual(upload["with"]["path"], "/tmp/allowops-p10b-evidence.*")
        self.assertEqual(upload["if"], "always() && steps.e2e.outcome != '' && steps.e2e.outcome != 'skipped'")

    def test_path_filter(self):
        steps = WORKFLOW["jobs"]["console-e2e-pr"]["steps"]
        selector = next(step["run"] for step in steps if step.get("id") == "changes")
        with tempfile.TemporaryDirectory(prefix="allowops git ") as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            output = Path(tmp) / "step output"
            # Git hooks can export GIT_DIR and GIT_INDEX_FILE for the caller's repository.
            env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
            env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")

            def git(*args):
                result = run(["git", *args], repo, env)
                self.assertEqual(result.returncode, 0, result.stdout)
                return result.stdout.strip()

            def select(event, base):
                output.write_text("", encoding="utf-8")
                return run(
                    ["bash", "-eo", "pipefail", "-c", selector], repo,
                    {**env, "GITHUB_EVENT_NAME": event, "BASE_SHA": base, "GITHUB_OUTPUT": str(output)},
                )

            git("init", "-q")
            git("config", "user.name", "CI fixture")
            git("config", "user.email", "ci@example.invalid")
            git("commit", "--allow-empty", "-qm", "base")
            for path, expected in (
                ("web/src/App.tsx", "true"),
                ("internal/gateway/console/handler.go", "true"),
                ("api/proto changes/v1.proto", "true"),
                ("deploy/compose/compose.yaml", "true"),
                ("test/e2e/console.spec.ts", "true"),
                ("docs/README.md", "false"),
                ("web-old/src/App.tsx", "false"),
                ("docs/web/src/App.tsx", "false"),
            ):
                with self.subTest(path=path):
                    base = git("rev-parse", "HEAD")
                    file = repo / path
                    file.parent.mkdir(parents=True, exist_ok=True)
                    file.write_text(path, encoding="utf-8")
                    git("add", "--", path)
                    git("commit", "-qm", "change one path")
                    result = select("pull_request", base)
                    self.assertEqual(result.returncode, 0, result.stdout)
                    self.assertEqual(output.read_text(), f"run_e2e={expected}\n")

            base = git("rev-parse", "HEAD")
            git("mv", "web/src/App.tsx", "docs/former-app.tsx")
            git("commit", "-qm", "move out of web")
            result = select("pull_request", base)
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertEqual(output.read_text(), "run_e2e=true\n")

            result = select("workflow_dispatch", "")
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertEqual(output.read_text(), "run_e2e=true\n")
            result = select("pull_request", "missing-base-commit")
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(output.read_text(), "")

            event_base = git("rev-parse", "HEAD")
            git("switch", "-c", "docs-pr")
            (repo / "docs/README.md").write_text("PR documentation\n", encoding="utf-8")
            git("commit", "-qm", "PR changes docs", "--", "docs/README.md")
            git("switch", "-c", "target", event_base)
            (repo / "web").mkdir(exist_ok=True)
            (repo / "web/base.ts").write_text("export const version = 2;\n", encoding="utf-8")
            git("add", "--", "web/base.ts")
            git("commit", "-qm", "target changes web after event")
            # Only the web change on the PR side of a merge should trigger E2E.
            for first_parent, pr, expected in (("target", "docs-pr", "false"), ("docs-pr", "target", "true")):
                git("switch", "--detach", first_parent)
                git("merge", "--no-ff", "-qm", "PR merge", pr)
                for recorded_base in (event_base, "f" * 40):
                    with self.subTest(pr=pr, recorded_base=recorded_base):
                        result = select("pull_request", recorded_base)
                        self.assertEqual(result.returncode, 0, result.stdout)
                        self.assertEqual(output.read_text(), f"run_e2e={expected}\n")


class CrossCompileTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="allowops build ")
        self.addCleanup(tmp.cleanup)
        self.module = Path(tmp.name) / "go module"
        self.module.mkdir()
        (self.module / "go.mod").write_text("module example.invalid/fixture\n\ngo 1.20\n")
        self.scratch = Path(tmp.name) / "temp outputs"
        self.scratch.mkdir()

    def build(self, *args):
        files = set(self.module.rglob("*"))
        result = run(
            [CHECK, "--module-dir", self.module, *args], self.module.parent,
            {**os.environ, "GOWORK": "off", "CGO_ENABLED": "1", "TMPDIR": str(self.scratch)},
        )
        self.assertEqual(set(self.module.rglob("*")), files)
        self.assertEqual(list(self.scratch.iterdir()), [])
        return result

    def test_portable_module(self):
        # Go's automatic VCS stamping finds this marker but git cannot read its metadata.
        (self.module.parent / ".git").mkdir()
        package = self.module / "cmd/allowops"
        package.mkdir(parents=True)
        (package / "main.go").write_text("//go:build !cgo\n\npackage main\nfunc main() {}\n")
        result = self.build()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(result.stdout.splitlines(), [
            *(f"PASS {target}" for target in TARGETS), "Summary: 4 passed, 0 failed",
        ])

    def test_linux_only_symbol(self):
        (self.module / "main.go").write_text("package main\nfunc main() { linuxOnly() }\n")
        (self.module / "platform.go").write_text("//go:build linux\n\npackage main\nfunc linuxOnly() {}\n")
        result = self.build("--pkg", ".")
        self.assertEqual(result.returncode, 1, result.stdout)
        statuses = [line for line in result.stdout.splitlines() if line.startswith(("PASS ", "FAIL "))]
        self.assertEqual(statuses, ["PASS linux/amd64", *(f"FAIL {target}" for target in TARGETS[1:])])
        self.assertEqual(result.stdout.count("undefined: linuxOnly"), 3, result.stdout)
        self.assertIn("Summary: 1 passed, 3 failed", result.stdout)

        result = self.build("--pkg", ".", "--targets", "linux/amd64")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(result.stdout.splitlines(), ["PASS linux/amd64", "Summary: 1 passed, 0 failed"])

    def test_invalid_targets(self):
        for targets in ("", "linux", "/amd64", "linux/", "linux//amd64", "linux/amd64,", "linux/amd64,,darwin/arm64"):
            with self.subTest(targets=targets):
                result = self.build("--targets", targets)
                self.assertEqual(result.returncode, 2, result.stdout)
                self.assertIn("Invalid --targets", result.stdout)

    def test_option_errors(self):
        for args, diagnostic in (
            (("--unknown",), "Unknown option: --unknown"),
            (("--targets",), "Usage:"),
            (("--module-dir", ""), "Usage:"),
            (("--pkg", ""), "Usage:"),
        ):
            with self.subTest(args=args):
                result = self.build(*args)
                self.assertEqual(result.returncode, 2, result.stdout)
                self.assertIn(diagnostic, result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
