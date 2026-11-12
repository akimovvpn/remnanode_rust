import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('compat', Path(__file__).resolve().parents[1] / 'check_compatibility.py')
compat = importlib.util.module_from_spec(spec)
spec.loader.exec_module(compat)

class CompatibilityTests(unittest.TestCase):
    def test_stale_engine_pin_cannot_advance_supported_baseline(self):
        manifest = {'artifacts': {'xray': 'v26.11.9', 'geocheck': '0.3.0'}}
        docker = 'ARG XRAY_VERSION=v26.11.9\nARG GEOCHECK_VERSION=0.3.0\n'
        compat.check(manifest, docker, 'pub const VERSION: &str = "26.11.9";')
        for wrong in [docker.replace('26.11.9', '26.10.31'), docker + 'ARG XRAY_VERSION=v26.11.9\n']:
            with self.assertRaises(ValueError):
                compat.check(manifest, wrong, 'pub const VERSION: &str = "26.11.9";')

    def test_stale_or_duplicate_rust_core_version_cannot_advance(self):
        manifest = {'artifacts': {'xray': 'v26.11.9', 'geocheck': '0.3.0'}}
        docker = 'ARG XRAY_VERSION=v26.11.9\nARG GEOCHECK_VERSION=0.3.0\n'
        for source in ['', 'pub const VERSION: &str = "26.10.31";', 'pub const VERSION: &str = "26.11.9";\npub const VERSION: &str = "26.11.9";']:
            with self.subTest(source=source), self.assertRaisesRegex(ValueError, 'Rust core VERSION'):
                compat.check(manifest, docker, source)
