import hashlib
import tempfile
from pathlib import Path
from unittest import TestCase

from dlp_agent.file_hashing import hash_file


class FileHashingTests(TestCase):
    def test_generates_sha256_sha1_and_md5(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.txt"
            path.write_bytes(b"synthetic DLP test")
            result = hash_file(path)

        self.assertIsNone(result.error)
        self.assertEqual(result.hashes["sha256"], hashlib.sha256(b"synthetic DLP test").hexdigest())
        self.assertEqual(result.hashes["sha1"], hashlib.sha1(b"synthetic DLP test").hexdigest())
        self.assertEqual(result.hashes["md5"], hashlib.md5(b"synthetic DLP test").hexdigest())

    def test_same_content_has_same_hash_under_different_names(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "payroll.txt"
            second = Path(directory) / "renamed.txt"
            first.write_bytes(b"same restricted content")
            second.write_bytes(b"same restricted content")

            self.assertEqual(hash_file(first).hashes["sha256"], hash_file(second).hashes["sha256"])
