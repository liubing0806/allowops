#!/usr/bin/env python3
"""Exercise the hygiene CLI against disposable Git repositories."""

import base64
import json
import os
import secrets
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHECK = ROOT / "test/repo-hygiene-check.py"
ROADMAP_HEADER = (
    "| 编号 | 原级别 | 后续事项 | 当前去向 |\n"
    "| --- | --- | --- | --- |\n"
)


def private_key():
    # PKCS #8 Ed25519 PrivateKeyInfo with a fresh 32-byte seed per fixture.
    der = bytes.fromhex("302e020100300506032b657004220420") + secrets.token_bytes(32)
    body = base64.b64encode(der).decode("ascii")
    return f"-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----\n"


class HygieneTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="allowops-hygiene-")
        self.addCleanup(temp.cleanup)
        self.repo = Path(temp.name)
        self.git("init", "-q", "--template=")
        self.git("config", "core.excludesFile", os.devnull)

    def git(self, *args):
        return subprocess.run(
            ["git", *args], cwd=self.repo, check=True, capture_output=True, text=True
        )

    def write(self, name, text, *, stage=True):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        if stage:
            self.git("add", "-f", "--", name)

    def check(self, *options, expected=0):
        result = subprocess.run(
            [sys.executable, CHECK, "--repo", self.repo, *options],
            capture_output=True, text=True, timeout=20,
        )
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, expected, output)
        return output

    def test_clean_repository(self):
        self.write("README.md", "Example paths: `server.key`, `credentials.json`.\n")
        self.write("deploy/credentials.json.example", "{}\n")
        self.write("demo.local.env.example", "export AWS_SECRET_ACCESS_KEY=${AWS_SECRET}\n")
        self.check()
        self.check("--include-untracked")

    def test_tracked_sensitive_names(self):
        names = (
            "test/foo/.state/credentials.json", ".state/session", "ops/credentials.json",
            "demo.local.env", "deploy/server.key", "client.p12", "backup/client.pfx",
        )
        self.write(".gitignore", ".state/\n*.local.env\n")
        for name in names:
            self.write(name, "fixture\n")
        output = self.check(expected=1)
        for name in names:
            self.assertIn(name, output)

    def test_untracked_requires_opt_in(self):
        self.write("local/credentials.json", "{}\n", stage=False)
        self.check()
        self.assertIn("local/credentials.json", self.check("--include-untracked", expected=1))

    def test_repository_ignore_rules(self):
        self.write(".gitignore", (ROOT / ".gitignore").read_text(encoding="utf-8"))
        for name in (
            "test/starrocks-dremio/.state/credentials.json",
            ".claude/worktrees/experiment/server.key",
            "deploy/demo.local.env",
        ):
            self.write(name, "fixture\n", stage=False)
            self.git("check-ignore", "-q", "--", name)
        self.check("--include-untracked")

    def test_private_keys_including_examples_and_tests(self):
        key = private_key()
        self.write("notes.txt", key)
        self.write("deploy/service.json.example", json.dumps({"key": key}))
        self.write("internal/local_test.go", "package local\nconst key = `" + key + "`\n")
        output = self.check(expected=1)
        for name in ("notes.txt", "deploy/service.json.example", "internal/local_test.go"):
            self.assertIn(name, output)
        self.assertNotIn(key.splitlines()[1], output)

    def test_symlink_does_not_import_external_file(self):
        with tempfile.TemporaryDirectory() as outside:
            target = Path(outside) / "local.pem"
            target.write_text(private_key(), encoding="utf-8")
            (self.repo / "reference").symlink_to(target)
            self.git("add", "--", "reference")
            self.check()

    def test_worktree_and_index_contents(self):
        self.write("local.conf", "clean\n")
        self.write("local.conf", private_key(), stage=False)
        self.assertIn("local.conf", self.check(expected=1))
        self.git("add", "--", "local.conf")
        self.write("local.conf", "clean\n", stage=False)
        self.assertIn("local.conf", self.check(expected=1))

    def test_hardcoded_assignment(self):
        value = secrets.token_hex(20)
        self.write("deploy/environment", f'export AWS_SECRET_ACCESS_KEY="{value}"\n')
        self.write("run.sh", f"env AWS_SECRET_ACCESS_KEY={value} program\n")
        self.write("test/environment_test.go", f'const env = "AWS_SECRET_ACCESS_KEY={value}"\n')
        (self.repo / "windows.env").write_text(f"GITHUB_TOKEN={value}", encoding="utf-16")
        self.git("add", "--", "windows.env")
        output = self.check(expected=1)
        for name in ("deploy/environment", "run.sh", "test/environment_test.go", "windows.env"):
            self.assertIn(name, output)
        self.assertIn("AWS_SECRET_ACCESS_KEY", output)
        self.assertNotIn(value, output)

    def test_safe_examples_and_runtime_references(self):
        self.write(
            "internal/redact/example_test.go",
            'package redact\nconst sample = "-----BEGIN RSA PRIVATE KEY-----\\n'
            'abcdef\\n-----END RSA PRIVATE KEY-----"\n',
        )
        self.write("test/test_repo_hygiene_check.py", 'header = "-----BEGIN EC PRIVATE KEY-----"\n')
        variable = "GITHUB_TOKEN"
        self.write("settings.py", f"{variable} = config.github_token\n")
        self.write(
            "sample.env.example",
            "AWS_SECRET_ACCESS_KEY=<your-key>\nAWS_SECRET_ACCESS_KEY=changeme\n"
            'AWS_SECRET_ACCESS_KEY="$FROM_ENV"\nAWS_SECRET_ACCESS_KEY=\n',
        )
        self.check()

    def test_source_strings_containing_assignments(self):
        github = "GITHUB_TOKEN"
        aws = "AWS_SECRET_ACCESS_KEY"
        pat = "ghp_" + secrets.token_hex(18)
        aws_value = "A1" + secrets.token_hex(19)
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0." + secrets.token_hex(16)
        files = {
            "go.go": f'package local\nconst env = `\n{github}={pat}\n`\n',
            "python.py": f'env = """\n{aws}={aws_value}\n"""\n',
            "single.py": f's = "{github}={jwt}"\n',
            # Short identifier-shaped values exercise quote context independently of entropy.
            "template.ts": f'const env = `\n{github}=service.token\n`;\n',
            "template.js": f'const env = `\n{aws}=localCredential\n`;\n',
            "nested.js": f'const env = `outer ${{format(`\n{github}=service.token\n`)}} end`;\n',
            "pattern.js": f'const quote = /"/;\nconst env = "{github}=service.token";\n',
            "docstring.py": f"env = '''\n{github}=service.token\n'''\n",
        }
        if sys.version_info >= (3, 12):
            files["interpolation.py"] = f'text = f"{{format("{github}=service.token")}}"\n'
        for name, source in files.items():
            self.write(name, source)
        output = self.check(expected=1)
        for name in files:
            with self.subTest(name=name):
                self.assertIn(f"{name}: hardcoded", output)
        for value in (pat, aws_value, jwt):
            self.assertNotIn(value, output)

    def test_unquoted_token_shapes(self):
        github = "GITHUB_TOKEN"
        suffix = secrets.token_hex(4)
        values = [prefix + suffix for prefix in (
            "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "eyJ", "AKIA", "ASIA",
        )]
        values.extend(("A1" + secrets.token_hex(16), "QaZxSwEdCvFrTgByHnUjMiKoLp"))
        for index, value in enumerate(values):
            self.write(f"config{index}.py", f"{github} = {value}\n")
        output = self.check(expected=1)
        for index, value in enumerate(values):
            self.assertIn(f"config{index}.py: hardcoded", output)
            self.assertNotIn(value, output)

    def test_references_in_code_after_strings_and_comments(self):
        variable = "GITHUB_TOKEN"
        self.write("settings.py", f'# """ in a comment\n{variable} = config.github_token\n')
        self.write("config.go", f'package local\nconst slash = `\\`\nvar {variable} = token\n')
        self.write("settings.ts", f'/* " */ const config = {{\n  {variable}: settings.token,\n}};\n')
        self.write("config.js", f'const quote = "\\\"";\nconst {variable} = settings.token;\n')
        self.write(
            "block-regex.js",
            f'function check(s) {{\n  /`/.test(s);\n  const cfg = {{ {variable}: settings.token }};\n  return cfg;\n}}\n',
        )
        self.check()

    def test_string_secret_after_block_start_regexp(self):
        variable = "GITHUB_TOKEN"
        self.write(
            "block-secret.js",
            f'if (enabled) {{ /"/.test(s); const t = "{variable}=service.token"; }}\n',
        )
        output = self.check(expected=1)
        self.assertIn("block-secret.js: hardcoded", output)
        self.assertNotIn("service.token", output)

    def test_assignment_in_parentheses(self):
        github = "GITHUB_TOKEN"
        aws = "AWS_SECRET_ACCESS_KEY"
        value = secrets.token_hex(20)
        self.write("args.py", f'options = dict({github}="{value}")\n')
        self.write("subshell.sh", f"result=$({aws}={value})\n")
        self.write("command.sh", f"result=$({aws}={value} program)\n")
        output = self.check(expected=1)
        for name in ("args.py", "subshell.sh", "command.sh"):
            self.assertIn(f"{name}: hardcoded", output)
        self.assertNotIn(value, output)

    def test_short_pem_body_in_raw_string(self):
        self.write(
            "sample_test.go",
            "package sample\nconst marker = `-----BEGIN RSA PRIVATE KEY-----\n"
            "abcdef\n-----END RSA PRIVATE KEY-----\n`\n",
        )
        self.check()

    def test_release_requires_security_acceptance(self):
        statuses = (
            "后续安全改进；已提交待验收。",
            "安全风险；已修复，未在本轮验收。",
            "安全项；已修复（待验收）。",
            "安全问题；已提交；历史状态为本轮未修复；当前待验收。",
            "安全改进；上轮未修复，本轮未验收。",
            "安全问题；此前未修复，当前待验收。",
            "安全问题；历史状态为本轮未修复。当前待验收。",
        )
        rows = [f"| SEC/{i} | minor | 检查 | {status} |\n" for i, status in enumerate(statuses)]
        self.write("docs/roadmap.md", ROADMAP_HEADER + "".join(rows))
        output = self.check("--release-gate", expected=1)
        for i in range(len(rows)):
            self.assertIn(f"SEC/{i} ", output)

    def test_release_ignores_historical_status_and_logging_category(self):
        self.write(
            "docs/roadmap.md",
            ROADMAP_HEADER
            + "| SEC/1 | minor | 检查 | 安全改进；已修复（原状态为本轮未修复）。 |\n"
            + "| SEC/2 | minor | 检查 | 安全风险；已解决并已验收; 历史备注：待验收。 |\n"
            + "| SEC/3 | minor | 检查 | 安全问题；已修复并验收 (此前未修复)。 |\n"
            + "| SEC/4 | minor | 检查 | 安全项；已修复并已验收（上轮未修复）。 |\n"
            + "| SEC/5 | minor | 检查 | 安全项；已验收；历史状态（未修复；待验收）。 |\n"
            + "| SEC/6 | minor | 检查 | 安全改进；已修复，原状态为本轮未修复。 |\n"
            + "| ORD/1 | minor | 日志 | 补安全错误类别观测；未修复、未在本轮验收。 |\n",
        )
        self.check("--release-gate")

    def test_release_reports_open_security_rows(self):
        self.write(
            "docs/roadmap.md",
            ROADMAP_HEADER
            + "| SEC/1 | minor | 检查甲\\|乙 | 后续安全改进；本轮未修复。 |\n"
            + "| SEC/2 | minor | 检查丙 | 安全改进，待修复。 |\n"
            + "| ORD/1 | minor | 安全问题已修复 | 后续计划；本轮未修复。 |\n"
            + "| OLD/1 | minor | 原记录为未修复 | 安全改进；已修复。 |\n"
            + "\n```md\n" + ROADMAP_HEADER
            + "| DOC/1 | minor | 演示 | 后续安全改进；本轮未修复。 |\n```\n",
        )
        self.check()
        output = self.check("--release-gate", expected=1)
        self.assertIn("SEC/1", output)
        self.assertIn("检查甲|乙", output)
        self.assertIn("SEC/2", output)
        self.assertIn("检查丙", output)
        for identifier in ("ORD/1", "OLD/1", "DOC/1"):
            self.assertNotIn(identifier, output)

    def test_release_after_resolution_or_removal(self):
        for rows in ("| SEC/1 | minor | 检查甲 | 安全改进；已修复。 |\n", ""):
            with self.subTest(rows=rows):
                self.write("docs/roadmap.md", ROADMAP_HEADER + rows)
                self.check("--release-gate")
        self.write("ops/credentials.json", "{}")
        self.assertIn("ops/credentials.json", self.check("--release-gate", expected=1))

    def test_release_requires_a_readable_status_table(self):
        self.assertIn("docs/roadmap.md", self.check("--release-gate", expected=2))
        self.write("docs/roadmap.md", "# Roadmap\n")
        self.assertIn("docs/roadmap.md", self.check("--release-gate", expected=2))

    def test_release_summary_does_not_print_credentials(self):
        value = secrets.token_hex(20)
        self.write(
            "docs/roadmap.md", ROADMAP_HEADER
            + f"| SEC/1 | minor | 轮换 `AWS_SECRET_ACCESS_KEY={value}` | 安全改进；未修复。 |\n",
        )
        output = self.check("--release-gate", expected=1)
        self.assertIn("SEC/1", output)
        self.assertIn("轮换", output)
        self.assertNotIn(value, output)

    def test_default_repo_from_unrelated_directory(self):
        self.write("credentials.json", "{}")
        result = subprocess.run(
            [sys.executable, CHECK], cwd=self.repo, capture_output=True, text=True, timeout=20
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
