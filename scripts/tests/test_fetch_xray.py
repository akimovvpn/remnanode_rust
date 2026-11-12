import importlib.util
from pathlib import Path
import unittest

script = Path(__file__).resolve().parents[1] / 'fetch_xray.py'
spec = importlib.util.spec_from_file_location('fetch_xray', script)
fetch = importlib.util.module_from_spec(spec)
if script.exists():
    spec.loader.exec_module(fetch)

class FetchXrayTests(unittest.TestCase):
    def test_accepts_exact_version_arg_only(self):
        self.assertEqual(fetch.version('ARG XRAY_VERSION=v26.11.9\n'), 'v26.11.9')
        for source in ['ARG XRAY_VERSION=$(bad)\n', 'ARG XRAY_VERSION=../../bad\n', 'ARG XRAY_VERSION=v26.11.9\nARG XRAY_VERSION=v26.11.10\n']:
            with self.assertRaises(ValueError):
                fetch.version(source)
