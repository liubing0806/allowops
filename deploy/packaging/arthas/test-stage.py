#!/usr/bin/env python3
"""Offline checks of stage.py with a synthetic archive laid out like the Arthas release."""
import hashlib
import importlib.util
import os
import pathlib
import re
import stat
import sys
import tempfile
import unittest
import zipfile

sys.dont_write_bytecode = True
HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("arthas_stage", HERE / "stage.py")
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)

PROPERTIES = (
    b"#arthas.agentId=abc\r\n"
    b"arthas.outputPath=arthas-output\n"
    b"# MCP (Model Context Protocol) configuration\n"
    b"arthas.mcpEndpoint=/mcp\n"
    b"arthas.mcpProtocol=STREAMABLE\n"
)
WITHOUT_MCP = (
    b"#arthas.agentId=abc\r\n"
    b"arthas.outputPath=arthas-output\n"
    b"# MCP (Model Context Protocol) configuration\n"
)
RELEASE_MEMBERS = {
    "arthas-agent.jar": b"agent",
    "arthas-core.jar": b"core",
    "arthas-spy.jar": b"spy",
    "logback.xml": b"<configuration/>",
    "arthas.properties": PROPERTIES,
    "arthas-boot.jar": b"boot",
    "arthas-client.jar": b"client",
    "as.sh": b"#!/bin/sh\n",
    "async-profiler/libasyncProfiler-linux-x64.so": b"native",
    "lib/libArthasJniLibrary-x64.so": b"native",
}


def write_zip(path, members, symlinks=()):
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)
        for name, target in symlinks:
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(info, target)
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


class StageTest(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="allowops-arthas-stage-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))
        self.legal = self.tmp / "legal"
        self.legal.mkdir()
        for name in stage.LEGAL:
            (self.legal / name).write_bytes(f"{name} text\n".encode())
        self.archive = self.tmp / "arthas.zip"
        self.out = self.tmp / "out"

    def stage(self, members=None, **kwargs):
        digest = write_zip(self.archive, RELEASE_MEMBERS if members is None else members, **kwargs)
        return stage.stage(self.archive, digest, self.legal, self.out)

    def test_stages_only_the_package_files(self):
        manifest = self.stage()
        self.assertEqual(sorted(p.name for p in self.out.iterdir()), sorted(stage.STAGED_FILES + (stage.MANIFEST,)))
        for path in self.out.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644, path.name)
        self.assertEqual((self.out / stage.MANIFEST).read_text(), manifest)

    def test_manifest_matches_the_staged_files(self):
        self.stage()
        lines = (self.out / stage.MANIFEST).read_text().splitlines()
        self.assertEqual([line.split("  ", 1)[1] for line in lines], list(stage.STAGED_FILES))
        for line in lines:
            digest, name = line.split("  ", 1)
            self.assertEqual(digest, hashlib.sha256((self.out / name).read_bytes()).hexdigest(), name)

    def test_properties_lose_only_the_two_mcp_lines(self):
        self.stage()
        self.assertEqual((self.out / "arthas.properties").read_bytes(), WITHOUT_MCP)

    def test_jars_and_logback_are_copied_unchanged(self):
        self.stage()
        for name in stage.JARS + stage.CONFIG:
            self.assertEqual((self.out / name).read_bytes(), RELEASE_MEMBERS[name], name)

    def test_digest_mismatch_fails_before_anything_is_written(self):
        write_zip(self.archive, RELEASE_MEMBERS)
        with self.assertRaises(SystemExit) as caught:
            stage.stage(self.archive, "0" * 64, self.legal, self.out)
        self.assertIn("does not match the pinned", str(caught.exception))
        self.assertFalse(self.out.exists())

    def test_digest_comparison_ignores_case(self):
        digest = write_zip(self.archive, RELEASE_MEMBERS)
        stage.stage(self.archive, digest.upper(), self.legal, self.out)

    def test_missing_member_fails(self):
        for name in stage.JARS + stage.CONFIG + (stage.PROPERTIES,):
            members = {k: v for k, v in RELEASE_MEMBERS.items() if k != name}
            with self.subTest(name):
                with self.assertRaises(SystemExit):
                    self.stage(members)
                self.assertFalse((self.out / stage.MANIFEST).exists())

    def test_properties_without_the_expected_keys_fail(self):
        for data in (b"arthas.mcpEndpoint=/mcp\n", b"arthas.outputPath=x\n"):
            with self.subTest(data):
                with self.assertRaises(SystemExit):
                    self.stage(dict(RELEASE_MEMBERS, **{"arthas.properties": data}))

    def test_other_mcp_setting_fails(self):
        data = PROPERTIES + b"arthas.mcpTimeout=10\n"
        with self.assertRaises(SystemExit) as caught:
            self.stage(dict(RELEASE_MEMBERS, **{"arthas.properties": data}))
        self.assertIn("arthas.mcpTimeout", str(caught.exception))

    def test_key_forms_with_colon_and_spaces_are_removed(self):
        data = b"arthas.mcpEndpoint : /mcp\n  arthas.mcpProtocol:STREAMABLE\nkeep=1\n"
        self.stage(dict(RELEASE_MEMBERS, **{"arthas.properties": data}))
        self.assertEqual((self.out / "arthas.properties").read_bytes(), b"keep=1\n")

    def test_symlink_member_fails(self):
        members = {k: v for k, v in RELEASE_MEMBERS.items() if k != "arthas-core.jar"}
        with self.assertRaises(SystemExit) as caught:
            self.stage(members, symlinks=[("arthas-core.jar", "/etc/passwd")])
        self.assertIn("not a regular file", str(caught.exception))

    def test_non_empty_output_directory_fails(self):
        self.out.mkdir()
        (self.out / "stale").write_text("x")
        with self.assertRaises(SystemExit):
            self.stage()

    def test_missing_legal_file_fails(self):
        (self.legal / "NOTICE").unlink()
        with self.assertRaises(FileNotFoundError):
            self.stage()

    def test_pinned_source_has_a_sha256(self):
        values = dict(
            line.split("=", 1) for line in (HERE / "source.env").read_text().splitlines() if line and not line.startswith("#")
        )
        self.assertRegex(values["ARTHAS_ZIP_SHA256"], r"^[0-9a-f]{64}$")
        self.assertIn(values["ARTHAS_VERSION"], values["ARTHAS_ZIP_URL"])
        self.assertTrue(values["ARTHAS_ZIP_URL"].startswith("https://repo.maven.apache.org/maven2/"))
        self.assertEqual(os.path.basename(values["ARTHAS_ZIP_URL"]), f"arthas-packaging-{values['ARTHAS_VERSION']}-bin.zip")


EPL_SHA256 = "f3d8dc494be2e7ea9cd31ac2fb902e35dce7ff8181b9b30d05861b47c339cb25"
EPL_MARKER = "===== Eclipse Public License - v 1.0 (logback) =====\n\n"


class NoticesTest(unittest.TestCase):
    def setUp(self):
        self.notices = (HERE / "THIRD_PARTY_NOTICES").read_text(encoding="utf-8")

    def test_epl_text_is_unchanged(self):
        text = self.notices.split(EPL_MARKER, 1)[1]
        self.assertEqual(hashlib.sha256(text.encode("ascii")).hexdigest(), EPL_SHA256)

    def test_every_license_choice_is_resolved(self):
        self.assertNotIn("not determined", self.notices)
        for line in self.notices.splitlines():
            if line.startswith("| ") and not line.startswith("| Component") and not line.startswith("| Dependency"):
                license_column = line.split(" | ")[2]
                outside_parentheses = re.sub(r"\([^)]*\)", "", license_column)
                self.assertNotIn(" or ", outside_parentheses, line)

    def test_license_expression_equals_the_licenses_in_the_table(self):
        listed = set()
        for line in self.notices.splitlines():
            if line.startswith("| ") and not line.startswith("| Component") and not line.startswith("| Dependency"):
                column = re.sub(r"\([^)]*\)", "", line.split(" | ")[2])
                listed.update(re.findall(r"Apache-2\.0|BSD-3-Clause|EPL-1\.0|MIT|0BSD|MPL-1\.1|LGPL-2\.1", column))
        expression = re.search(r"^license: (.+)$", (HERE / "nfpm.yaml").read_text(), re.M).group(1)
        self.assertEqual(set(expression.split(" AND ")), listed)

    def test_notice_carries_the_arthas_attribution(self):
        notice = (HERE / "NOTICE").read_text(encoding="utf-8")
        for text in ("Copyright 2018 Alibaba Group", "greys-anatomy", "Apache Commons Lang", "Apache Commons Net"):
            self.assertIn(text, notice)


if __name__ == "__main__":
    unittest.main()
