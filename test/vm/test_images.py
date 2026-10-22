import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from images import checksum, fetch


class ChecksumTest(unittest.TestCase):
    def test_gnu_and_bsd(self):
        digest = "a" * 64
        for manifest in (f"{digest} *disk.qcow2", f"{digest}  ./disk.qcow2",
                         f"SHA256 (disk.qcow2) = {digest}"):
            self.assertEqual(checksum(manifest, "disk.qcow2", "sha256"), digest)

    def test_sha512(self):
        digest = "b" * 128
        self.assertEqual(checksum(f"{digest}  disk.qcow2", "disk.qcow2", "sha512"), digest)

    def test_wrong_filename_and_ambiguous_manifest(self):
        digest = "a" * 64
        for manifest in (f"{digest} *other-disk.qcow2", f"{digest} *disk.qcow2\n{digest} *disk.qcow2"):
            with self.assertRaises(ValueError):
                checksum(manifest, "disk.qcow2", "sha256")

    def test_html_and_incorrect_digest(self):
        for manifest in ("<html>redirected</html>", "abc disk.qcow2", "g" * 64 + " disk.qcow2"):
            with self.assertRaises(ValueError):
                checksum(manifest, "disk.qcow2", "sha256")


class DebianDownloadTest(unittest.TestCase):
    manifest_url = "https://cloud.debian.org/images/cloud/bookworm/latest/SHA512SUMS"
    image_url = "https://chuangtzu.ftp.acc.umu.se/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2"
    image_name = "debian-12-genericcloud-amd64.qcow2"

    def test_approved_image_host_and_official_manifest(self):
        data = b"local G63 image fixture"
        digest = hashlib.sha512(data).hexdigest()

        def download_fixture(url, path):
            if url == self.manifest_url:
                path.write_text(f"{digest}  {self.image_name}\n")
            else:
                path.write_bytes(data)

        with tempfile.TemporaryDirectory() as directory, patch("images.download", side_effect=download_fixture) as downloader:
            result = fetch("debian12", Path(directory))
            self.assertEqual([call.args[0] for call in downloader.call_args_list],
                             [self.manifest_url, self.image_url])
            self.assertEqual(result.read_bytes(), data)

    def test_sha512_mismatch_stops_and_removes_image(self):
        expected = hashlib.sha512(b"expected official image").hexdigest()

        def download_fixture(url, path):
            if url == self.manifest_url:
                path.write_text(f"{expected}  {self.image_name}\n")
            else:
                path.write_bytes(b"mismatched image")

        with tempfile.TemporaryDirectory() as directory, patch("images.download", side_effect=download_fixture):
            root = Path(directory)
            with self.assertRaisesRegex(ValueError, "sha512 mismatch"):
                fetch("debian12", root)
            self.assertFalse((root / "debian12" / self.image_name).exists())


if __name__ == "__main__":
    unittest.main()
