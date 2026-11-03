#!/usr/bin/env python3
"""Verify the pinned Arthas release archive and stage the allowops-arthas files.

Only the members named below are read from the archive, by name, so no path in
the archive decides where a file is written. The staged directory holds
exactly the files in STAGED_FILES plus the SHA256SUMS manifest.
"""
import argparse
import hashlib
import pathlib
import re
import shutil
import stat
import sys
import zipfile

JARS = ("arthas-agent.jar", "arthas-core.jar", "arthas-spy.jar")
CONFIG = ("logback.xml",)
PROPERTIES = "arthas.properties"
REMOVED_KEYS = ("arthas.mcpEndpoint", "arthas.mcpProtocol")
LEGAL = ("LICENSE", "NOTICE", "THIRD_PARTY_NOTICES")
MANIFEST = "SHA256SUMS"
STAGED_FILES = tuple(sorted(JARS + CONFIG + (PROPERTIES,) + LEGAL))
MAX_MEMBER_BYTES = 64 * 1024 * 1024


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def strip_mcp_keys(data):
    """Drop the lines that set the MCP keys; keep every other byte as it is.

    The result must have lost each key exactly once and must not contain any
    other arthas.mcp* setting, otherwise the archive layout has changed.
    """
    kept = []
    removed = []
    for line in data.splitlines(keepends=True):
        text = line.decode("utf-8", "replace").lstrip()
        key = None if text[:1] in ("#", "!") else re.split(r"[=:\s]", text, maxsplit=1)[0]
        if key in REMOVED_KEYS:
            removed.append(key)
        else:
            kept.append(line)
            if key is not None and key.startswith("arthas.mcp"):
                raise SystemExit(f"{PROPERTIES}: unexpected MCP setting {key!r}")
    if sorted(removed) != sorted(REMOVED_KEYS):
        raise SystemExit(f"{PROPERTIES}: expected one line for each of {REMOVED_KEYS}, removed {removed}")
    return b"".join(kept)


def read_member(archive, name):
    try:
        info = archive.getinfo(name)
    except KeyError:
        raise SystemExit(f"archive has no member {name!r}") from None
    file_type = stat.S_IFMT(info.external_attr >> 16)
    if info.is_dir() or file_type not in (0, stat.S_IFREG):
        raise SystemExit(f"archive member {name!r} is not a regular file")
    if info.file_size > MAX_MEMBER_BYTES:
        raise SystemExit(f"archive member {name!r} is larger than {MAX_MEMBER_BYTES} bytes")
    data = archive.read(info)
    if len(data) != info.file_size:
        raise SystemExit(f"archive member {name!r} has an unexpected size")
    return data


def stage(archive_path, expected_sha256, legal_dir, out_dir):
    archive_path = pathlib.Path(archive_path)
    out_dir = pathlib.Path(out_dir)
    actual = sha256_file(archive_path)
    if actual != expected_sha256.lower():
        raise SystemExit(f"{archive_path}: SHA-256 {actual} does not match the pinned {expected_sha256.lower()}")
    if out_dir.exists() and any(out_dir.iterdir()):
        raise SystemExit(f"{out_dir} exists and is not empty")

    files = {}
    with zipfile.ZipFile(archive_path) as archive:
        for name in JARS + CONFIG:
            files[name] = read_member(archive, name)
        files[PROPERTIES] = strip_mcp_keys(read_member(archive, PROPERTIES))
    for name in LEGAL:
        files[name] = (pathlib.Path(legal_dir) / name).read_bytes()
    assert tuple(sorted(files)) == STAGED_FILES

    out_dir.mkdir(parents=True, exist_ok=True)
    for name, data in files.items():
        target = out_dir / name
        target.write_bytes(data)
        target.chmod(0o644)
    manifest = "".join(f"{sha256_bytes(files[name])}  {name}\n" for name in STAGED_FILES)
    (out_dir / MANIFEST).write_text(manifest, encoding="ascii")
    (out_dir / MANIFEST).chmod(0o644)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, help="arthas-packaging-<version>-bin.zip")
    parser.add_argument("--sha256", required=True, help="pinned SHA-256 of the archive")
    parser.add_argument("--legal", required=True, help="directory with " + ", ".join(LEGAL))
    parser.add_argument("--out", required=True, help="empty or missing directory for the staged files")
    args = parser.parse_args()
    sys.stdout.write(stage(args.archive, args.sha256, args.legal, args.out))


if __name__ == "__main__":
    main()
