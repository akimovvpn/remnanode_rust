import gzip
import hashlib
import importlib.util
from pathlib import Path
import unittest

script = Path(__file__).resolve().parents[1] / 'fetch_mihomo.py'
spec = importlib.util.spec_from_file_location('fetch_mihomo', script)
fetch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fetch)


class FetchMihomoTests(unittest.TestCase):
    def test_checks_digest_before_decompressing_or_using_binary(self):
        archive = gzip.compress(b'test executable')
        digest = hashlib.sha256(archive).hexdigest()
        self.assertEqual(fetch.verified_binary(archive, digest), b'test executable')
        with self.assertRaisesRegex(ValueError, 'SHA256'):
            fetch.verified_binary(archive + b'corruption', digest)
        with self.assertRaisesRegex(ValueError, 'SHA256'):
            fetch.verified_binary(archive, '')
