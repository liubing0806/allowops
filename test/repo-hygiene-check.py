#!/usr/bin/env python3
"""Check Git paths and text for credentials. Optionally check release blockers."""

import argparse
import codecs
import io
import math
import os
import re
import subprocess
import sys
import tokenize
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ROADMAP = Path("docs/roadmap.md")
PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[ \t]*"
    r"(?:\r?\n(?:[ \t]*\r?\n)*|\\(?:r\\)?n)[ \t]*"
    r"(?:M[A-Za-z0-9+/]{15}|b3BlbnNzaC1rZXktdjE|Proc-Type:)"
)
SECRET_ASSIGNMENT = re.compile(
    r"""(?<!\w)(?P<key_quote>["']?)(?P<name>AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|GITHUB_TOKEN|GH_TOKEN)"""
    r"""(?P=key_quote)[ \t]*[:=][ \t]*(?P<quote>["']?)(?P<value>[a-z0-9+/_.=-]+)(?P=quote)"""
    r"""(?=[\s#,});\]'"`\\]|$)""",
    re.IGNORECASE,
)
PLACEHOLDER = re.compile(
    r"x+|\.{3}|(?:change|replace)[_-]?me|redacted|placeholder|"
    r"(?:dummy|example|fake|test)(?:[_-](?:key|secret|token|value))?|"
    r"your[_-](?:aws[_-])?(?:secret[_-](?:access[_-])?key|key|secret|token|value)(?:[_-]here)?|"
    r"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    re.IGNORECASE,
)
# This redaction assertion embeds the synthetic value and checks it disappears.
TEST_ASSIGNMENTS = {
    (Path("internal/redact/builtin_credentials_test.go"), "AWS_SECRET_ACCESS_KEY", "envsecret3"),
}
SOURCE_SUFFIXES = {".go", ".py", ".ts", ".tsx", ".js", ".jsx"}
TOKEN_PREFIX = re.compile(r"gh[pousr]_|github_pat_|eyJ|AKIA|ASIA")
QUOTED_STRING = (
    r"""(?P<quote>["'])(?:\\(?:\r\n|.)|(?!(?P=quote))[^\\\r\n])*"""
    r"(?:(?P=quote)|(?=[\r\n]|\Z))"
)
C_COMMENTS = r"//[^\n]*|/\*.*?(?:\*/|\Z)"
GO_NONCODE = re.compile(r"`[^`]*(?:`|\Z)|" + C_COMMENTS + "|" + QUOTED_STRING, re.DOTALL)
# A regexp in expression position may itself contain quotes or backticks.
JS_REGEXP = (
    r"(?:(?<=[=(:,;!?&|\[{}])|(?<=\breturn)|(?<=\bthrow)|^)\s*/(?![*/])"
    r"(?:\\[^\n]|\[(?:\\[^\n]|[^\]\\\n])*\]|[^/\\\[\n])+/[a-z]*"
)
JS_CODE = re.compile("|".join((C_COMMENTS, QUOTED_STRING, JS_REGEXP, r"[`{}]")), re.DOTALL)
JS_TEMPLATE = re.compile(r"\\.|\$\{|`", re.DOTALL)
SECURITY_ITEM = re.compile(r"安全(?:改进|问题|风险|事项|项)")
UNRESOLVED = re.compile(r"(?:待|未(?:在本轮)?)(?:修复|解决|处理|整改|完成|实施|验收)")
HISTORY_LABEL = r"(?:原状态|旧状态|历史|原先|原为|此前|曾经|上(?:一)?轮|上次)"
HISTORICAL_NOTE = re.compile(
    rf"[（(]\s*{HISTORY_LABEL}[^）)]*[）)]"
    rf"|(?:^|[；;，,。])\s*{HISTORY_LABEL}(?:[（(][^）)]*[）)]|[^；;，,。（(])*"
)


def git_paths(repo, *args):
    output = subprocess.check_output(["git", *args, "-z"], cwd=repo)
    return [Path(os.fsdecode(name)) for name in output.split(b"\0") if name]


def reference_candidate(value):
    if TOKEN_PREFIX.match(value) or not re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", value):
        return False
    if len(value) >= 20 and any(c.isdigit() for c in value) and any(c.isalpha() for c in value):
        return False
    # An opaque base64-like identifier can consist entirely of letters.
    for part in value.split("."):
        if len(part) >= 20:
            frequencies = (count / len(part) for count in Counter(part).values())
            entropy = -sum(p * math.log2(p) for p in frequencies)
            if entropy >= 4.25:  # bits per character
                return False
    return True


def noncode_spans(text, suffix):
    if suffix == ".py":
        line_starts = [0] + [newline.end() for newline in re.finditer("\n", text)]
        try:
            for token in tokenize.generate_tokens(io.StringIO(text).readline):
                kind = tokenize.tok_name[token.type]
                if kind in {"STRING", "COMMENT", "FSTRING_MIDDLE", "TSTRING_MIDDLE"}:
                    line, column = token.start
                    end_line, end_column = token.end
                    yield line_starts[line - 1] + column, line_starts[end_line - 1] + end_column
        except (SyntaxError, tokenize.TokenError):
            # An incomplete source file cannot establish a variable reference.
            yield 0, len(text)
        return
    if suffix == ".go":
        for token in GO_NONCODE.finditer(text):
            yield token.span()
        return

    # Template text can contain ${...} expressions that open nested templates.
    closers = []
    offset = 0
    while offset < len(text):
        if closers and closers[-1] == "`":
            token = JS_TEMPLATE.search(text, offset)
            if not token:
                yield offset, len(text)
                return
            yield offset, token.end()
            if token[0] == "${":
                closers.append("}")
            elif token[0] == "`":
                closers.pop()
        else:
            token = JS_CODE.search(text, offset)
            if not token:
                return
            if token[0] == "{":
                if closers:
                    closers.append("}")
            elif token[0] == "}":
                if closers:
                    closers.pop()
            else:
                yield token.span()
                if token[0] == "`":
                    closers.append("`")
        offset = token.end()


def content_findings(name, data):
    if data.startswith((codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE)):
        text = data.decode("utf-32", errors="replace")
    elif data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        text = data.decode("utf-16", errors="replace")
    elif b"\0" in data:
        return
    else:
        text = data.decode("utf-8", errors="replace")
    if PRIVATE_KEY.search(text):
        yield "PEM private key"
    noncode = None
    for match in SECRET_ASSIGNMENT.finditer(text):
        value = match["value"]
        variable = match["name"].upper()
        if PLACEHOLDER.fullmatch(value) or (name, variable, value) in TEST_ASSIGNMENTS:
            continue
        if not match["quote"] and name.suffix in SOURCE_SUFFIXES and reference_candidate(value):
            if noncode is None:
                noncode = list(noncode_spans(text, name.suffix))
            offset = match.start("value")
            if not any(start <= offset < end for start, end in noncode):
                continue
        yield f"hardcoded {variable} assignment"


def hygiene_findings(repo, include_untracked):
    extra = ["--others", "--exclude-standard"] if include_untracked else []
    names = git_paths(repo, "ls-files", "--cached", *extra)
    modified = set(git_paths(repo, "diff-files", "--name-only", "--ignore-submodules=all"))
    for name in names:
        filename = name.name.lower()
        if (
            ".state" in name.parts[:-1]
            or filename == "credentials.json"
            or filename.endswith((".local.env", ".key", ".p12", ".pfx"))
        ):
            yield f"{name}: sensitive path"
            continue
        path = repo / name
        if path.is_file() and path.resolve() == path:
            for finding in content_findings(name, path.read_bytes()):
                yield f"{name}: {finding}"
        # An unstaged replacement or deletion can hide a key still in the index.
        if name in modified:
            staged = subprocess.check_output(["git", "cat-file", "blob", f":{name}"], cwd=repo)
            for finding in content_findings(name, staged):
                yield f"{name} (index): {finding}"


def roadmap_rows(markdown):
    previous = []
    headers = []
    fence = ""
    found_status_table = False
    for line in markdown.splitlines():
        line = line.strip()
        if fence:
            if line.startswith(fence) and not line.strip(fence[0]):
                fence = ""
            continue
        opening = re.match(r"^`{3,}|^~{3,}", line)
        if opening or "|" not in line:
            fence = opening[0] if opening else ""
            headers = previous = []
            continue
        cells = [
            cell.strip().replace(r"\|", "|")
            for cell in re.split(r"(?<!\\)\|", line.removeprefix("|").removesuffix("|"))
        ]
        if len(cells) == len(previous) and all(re.fullmatch(r":?-+:?", cell) for cell in cells):
            headers = []
            if "当前去向" in previous or "状态" in previous:
                headers = previous
                found_status_table = True
        elif headers:
            if len(cells) != len(headers):
                raise ValueError(f"{ROADMAP}: inconsistent number of table columns")
            yield dict(zip(headers, cells))
        previous = cells
    if not found_status_table:
        raise ValueError(f"{ROADMAP}: no table with a 当前去向 or 状态 column")


def report_cell(cell):
    if PRIVATE_KEY.search(cell):
        return "[PEM private key redacted]"
    return SECRET_ASSIGNMENT.sub(r"\g<name>=[redacted]", cell)


def release_findings(repo):
    path = repo / ROADMAP
    if not path.is_file() or path.resolve() != path:
        raise ValueError(f"{ROADMAP}: expected a regular repository file")
    for row in roadmap_rows(path.read_text(encoding="utf-8")):
        status = row.get("当前去向", row.get("状态", ""))
        current_status = HISTORICAL_NOTE.sub("", status)
        if SECURITY_ITEM.search(current_status) and UNRESOLVED.search(current_status):
            identifier = next((row[h] for h in row if h.startswith("编号") or h == "ID"), "")
            summary = row.get("后续事项") or row.get("建议") or row.get("摘要")
            if not identifier or not summary:
                raise ValueError(f"{ROADMAP}: unresolved security row needs an ID and summary")
            yield f"{ROADMAP}: {report_cell(identifier)} {report_cell(summary)}"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=ROOT, help="Git repository root")
    parser.add_argument("--include-untracked", action="store_true", help="include non-ignored new files")
    parser.add_argument("--release-gate", action="store_true", help="also reject unresolved security items")
    args = parser.parse_args()
    try:
        root = subprocess.check_output(["git", "rev-parse", "--show-toplevel"], cwd=args.repo)
        repo = Path(os.fsdecode(root.removesuffix(b"\n"))).resolve()
        findings = list(hygiene_findings(repo, args.include_untracked))
        if args.release_gate:
            findings.extend(release_findings(repo))
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    for finding in findings:
        print(f"FAIL: {finding}", file=sys.stderr)
    if findings:
        return 1
    print("PASS: release gate" if args.release_gate else "PASS: repository hygiene")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
