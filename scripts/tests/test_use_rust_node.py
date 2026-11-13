import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

script = Path(__file__).resolve().parents[1] / 'use_rust_node.py'
spec = importlib.util.spec_from_file_location('use_rust_node', script)
migrate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(migrate)


class RewriteNodeTests(unittest.TestCase):
    def test_list_environment_keeps_secret_comments_and_other_services(self):
        source = '''services:
  remnanode:
    image: "remnawave/node:latest" # node
    environment:
      - SECRET_KEY="keep-$${literal}"
      - NODE_PORT=2222
  other:
    image: busybox
    environment:
      - XRAY_BINARY=do-not-touch
'''
        expected = source.replace('remnawave/node:latest', migrate.IMAGE).replace(
            '      - NODE_PORT=2222\n',
            '      - NODE_PORT=2222\n      - XRAY_BINARY=/usr/local/bin/rcore\n')
        self.assertEqual(migrate.rewrite(source), expected)
        self.assertEqual(migrate.rewrite(expected), expected)

    def test_map_environment_replaces_existing_binary_without_touching_secret(self):
        source = '''services:
    remnanode:
        image: ghcr.io/remnawave/node:latest
        environment:
            SECRET_KEY: 'keep: # literal'
            XRAY_BINARY: /usr/local/bin/xray
'''
        expected = source.replace('ghcr.io/remnawave/node:latest', migrate.IMAGE).replace(
            '/usr/local/bin/xray', migrate.CORE)
        self.assertEqual(migrate.rewrite(source), expected)

    def test_missing_and_empty_environment_and_missing_final_newline(self):
        for suffix in ['', '\n', '\n    environment: {}\n', '\n    environment: []\n']:
            source = 'services:\n  remnanode:\n    image: remnawave/node:latest' + suffix
            updated = migrate.rewrite(source)
            self.assertIn('    environment:\n      - XRAY_BINARY=/usr/local/bin/rcore\n', updated)
            self.assertEqual(migrate.rewrite(updated), updated)

    def test_existing_quoted_list_variable_is_updated_once(self):
        source = '''services:
  remnanode:
    image: ghcr.io/akimovvpn/remnanode_rust:latest
    environment:
      - "XRAY_BINARY=/old"
      - SECRET_KEY=keep
      - XRAY_BINARY=/duplicate
'''
        updated = migrate.rewrite(source)
        self.assertEqual(updated.count('XRAY_BINARY='), 1)
        self.assertIn('      - XRAY_BINARY=/usr/local/bin/rcore\n', updated)

    def test_crlf_and_scalar_secret_are_preserved(self):
        source = 'services:\r\n  remnanode:\r\n    image: remnawave/node:latest\r\n    environment:\r\n      SECRET_KEY: |\r\n        XRAY_BINARY: secret-text\r\n'
        updated = migrate.rewrite(source)
        self.assertIn('        XRAY_BINARY: secret-text\r\n', updated)
        self.assertIn('      XRAY_BINARY: /usr/local/bin/rcore\r\n', updated)
        self.assertNotIn('\n', updated.replace('\r\n', ''))

    def test_refuses_ambiguous_or_unsupported_layout(self):
        for source in [
            'services:\n  other:\n    image: busybox\n',
            'services:\n  a:\n    image: remnawave/node:latest\n  b:\n    image: remnawave/node:latest\n',
            'services:\n  a:\n    image: remnawave/node:latest\n    environment: {SECRET_KEY: keep}\n',
            'x-template:\n  image: remnawave/node:latest\nservices:\n  other:\n    image: busybox\n',
        ]:
            with self.subTest(source=source), self.assertRaises(ValueError):
                migrate.rewrite(source)


@unittest.skipUnless(shutil.which('docker'), 'Docker Compose is required')
class MigrateNodeTests(unittest.TestCase):
    def test_real_compose_missing_or_empty_environment(self):
        for suffix in ['', '    environment: {}\n', '    environment: []\n']:
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory(prefix='node-migration-') as directory:
                path = Path(directory) / 'docker-compose.yml'
                path.write_text('services:\n  remnanode:\n    image: remnawave/node:latest\n' + suffix)
                migrate.migrate(path)
                self.assertEqual(migrate.compose_model(path)['services']['remnanode']['environment']['XRAY_BINARY'], migrate.CORE)

    def test_real_compose_indentless_list_environment(self):
        with tempfile.TemporaryDirectory(prefix='node-migration-') as directory:
            path = Path(directory) / 'docker-compose.yml'
            path.write_text('services:\n  remnanode:\n    image: remnawave/node:latest\n    environment:\n    - SECRET_KEY=keep\n    restart: always\n')
            migrate.migrate(path)
            node = migrate.compose_model(path)['services']['remnanode']
            self.assertEqual(node['environment'], {'SECRET_KEY': 'keep', 'XRAY_BINARY': migrate.CORE})
            self.assertEqual(node['restart'], 'always')

    def test_real_cli_with_list_environment_and_path_with_spaces(self):
        with tempfile.TemporaryDirectory(prefix='node migration ') as directory:
            path = Path(directory) / 'docker compose.yml'
            path.write_text('services:\n  remnanode:\n    image: remnawave/node:latest\n    environment:\n      - SECRET_KEY=private-test-value\n')
            result = subprocess.run(['python3', str(script), str(path)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn('private-test-value', result.stdout + result.stderr)
            self.assertIn("Next: cd '", result.stdout)
            self.assertEqual(migrate.compose_model(path)['services']['remnanode']['image'], migrate.IMAGE)

    def test_real_compose_backup_permissions_semantics_and_idempotence(self):
        with tempfile.TemporaryDirectory(prefix='node-migration-') as directory:
            path = Path(directory) / 'docker-compose.yml'
            source = '''services:
  remnanode:
    image: remnawave/node:latest
    network_mode: host
    environment:
      SECRET_KEY: 'private-test-value'
      NODE_PORT: '2222'
'''
            path.write_text(source)
            path.chmod(0o640)
            backup = migrate.migrate(path)
            self.assertEqual(backup.read_text(), source)
            self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.stat().st_mode & 0o777, 0o640)
            node = migrate.compose_model(path)['services']['remnanode']
            self.assertEqual(node['image'], migrate.IMAGE)
            self.assertEqual(node['environment']['XRAY_BINARY'], migrate.CORE)
            self.assertEqual(node['environment']['SECRET_KEY'], 'private-test-value')
            self.assertIsNone(migrate.migrate(path))
            self.assertEqual(len(list(path.parent.glob('*.bak.*'))), 1)

    def test_invalid_config_is_not_written_and_secret_is_not_printed(self):
        with tempfile.TemporaryDirectory(prefix='node-migration-') as directory:
            path = Path(directory) / 'docker-compose.yml'
            source = 'services:\n  remnanode:\n    image: remnawave/node:latest\n    ports: private-test-value\n'
            path.write_text(source)
            result = subprocess.run(['python3', str(script), str(path)], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn('private-test-value', result.stdout + result.stderr)
            self.assertEqual(path.read_text(), source)
            self.assertEqual(list(path.parent.glob('*.bak.*')), [])

    def test_semantic_guard_rejects_an_unrelated_change_without_backup(self):
        with tempfile.TemporaryDirectory(prefix='node-migration-') as directory:
            path = Path(directory) / 'docker-compose.yml'
            source = 'services:\n  remnanode:\n    image: remnawave/node:latest\n    restart: always\n'
            path.write_text(source)
            changed = migrate.rewrite(source).replace('restart: always', 'restart: "no"')
            with patch.object(migrate, 'rewrite', return_value=changed), self.assertRaisesRegex(ValueError, 'Unexpected Compose changes'):
                migrate.migrate(path)
            self.assertEqual(path.read_text(), source)
            self.assertEqual(list(path.parent.glob('*.bak.*')), [])
