#!/usr/bin/env python3
"""Download approved cloud images and verify distribution-owned manifests."""
import hashlib
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

IMAGES = {
    "centos7": ("https://cloud.centos.org/centos/7/images/", "CentOS-7-x86_64-GenericCloud.qcow2", "sha256sum.txt", "sha256"),
    "rocky8": ("https://dl.rockylinux.org/pub/rocky/8/images/x86_64/", "Rocky-8-GenericCloud-Base.latest.x86_64.qcow2", "Rocky-8-GenericCloud-Base.latest.x86_64.qcow2.CHECKSUM", "sha256"),
    "rocky9": ("https://dl.rockylinux.org/pub/rocky/9/images/x86_64/", "Rocky-9-GenericCloud-Base.latest.x86_64.qcow2", "Rocky-9-GenericCloud-Base.latest.x86_64.qcow2.CHECKSUM", "sha256"),
    "ubuntu2004": ("https://cloud-images.ubuntu.com/focal/current/", "focal-server-cloudimg-amd64.img", "SHA256SUMS", "sha256"),
    "ubuntu2404": ("https://cloud-images.ubuntu.com/noble/current/", "noble-server-cloudimg-amd64.img", "SHA256SUMS", "sha256"),
    "debian12": ("https://cloud.debian.org/images/cloud/bookworm/latest/", "debian-12-genericcloud-amd64.qcow2", "SHA512SUMS", "sha512"),
}

# G63 authorizes this exact hosted image; its manifest still comes from cloud.debian.org.
DEBIAN_IMAGE_URL = "https://chuangtzu.ftp.acc.umu.se/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2"


def checksum(text, name, algorithm):
    length = hashlib.new(algorithm).digest_size * 2
    matches = []
    for line in text.splitlines():
        gnu = re.fullmatch(r"([0-9a-fA-F]{%d})\s+\*?(.+)" % length, line.strip())
        bsd = re.fullmatch(r"#?\s*%s\s*\((.+)\)\s*=\s*([0-9a-fA-F]{%d})" % (algorithm.upper(), length), line.strip())
        if gnu and gnu[2].removeprefix("./") == name:
            matches.append(gnu[1].lower())
        if bsd and bsd[1] == name:
            matches.append(bsd[2].lower())
    if len(matches) != 1:
        raise ValueError(f"expected one {algorithm} entry for {name}, got {len(matches)}")
    return matches[0]


def download(url, path):
    # Do not follow redirects to unreviewed mirrors, including cached redirect responses.
    result = subprocess.run(["curl", "--fail", "--silent", "--show-error", "--retry", "2",
                             "--connect-timeout", "15", "--max-time", "900", "--proto", "=https",
                             "--output", str(path), "--write-out", "%{http_code}", url],
                            check=True, text=True, capture_output=True)
    if result.stdout.strip() != "200":
        raise ValueError(f"official image URL returned HTTP {result.stdout.strip()}: {url}")


def fetch(distro, cache):
    base, name, manifest, algorithm = IMAGES[distro]
    image_url = DEBIAN_IMAGE_URL if distro == "debian12" else base + name
    root = cache / distro
    root.mkdir(parents=True, exist_ok=True)
    download(base + manifest, root / "manifest")
    expected = checksum((root / "manifest").read_text(), name, algorithm)
    path = root / name
    if not path.exists():
        partial = path.with_suffix(path.suffix + ".partial")
        download(image_url, partial)
        partial.rename(path)
    with path.open("rb") as stream:
        actual = hashlib.file_digest(stream, algorithm).hexdigest()
    if actual != expected:
        path.unlink()
        raise ValueError(f"{algorithm} mismatch: expected {expected}, actual {actual}; deleted cached image")
    print(f"verified {distro} image_host={urlparse(image_url).hostname} manifest_host={urlparse(base).hostname} {algorithm}={actual}", file=sys.stderr)
    return path.resolve()


if __name__ == "__main__":
    try:
        print(fetch(sys.argv[1], Path(sys.argv[2])))
    except (ValueError, subprocess.CalledProcessError) as error:
        detail = getattr(error, "stderr", None)
        sys.exit(detail or str(error))
