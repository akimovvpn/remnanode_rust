import importlib.util
from pathlib import Path
import tempfile
import unittest


class XrayDigestTests(unittest.TestCase):
    def test_verifies_sha256_and_rejects_corruption_and_missing_digest(self):
        script = Path(__file__).resolve().parents[1] / 'verify_xray.py'
        spec = importlib.util.spec_from_file_location('verify_xray', script)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / 'xray.zip'
            digest = Path(directory) / 'xray.zip.dgst'
            archive.write_bytes(b'abc')
            digest.write_text('MD5= irrelevant\nSHA2-256= ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n')
            module.verify(archive, digest)
            archive.write_bytes(b'corrupt')
            with self.assertRaises(ValueError):
                module.verify(archive, digest)
            digest.write_text('MD5= irrelevant\n')
            with self.assertRaises(ValueError):
                module.verify(archive, digest)
