import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

MODULE = Path(__file__).resolve().parents[1] / 'upstream.py'


class UpstreamTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('upstream', MODULE)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)

    def test_complete_deterministic_snapshot_and_dependency_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            subprocess.run(['git', 'init', '-q', directory], check=True)
            for name, value in {'src/main.ts': 'hello', 'package-lock.json': '{"packages":{"node_modules/sdk":{"version":"1"}}}', 'docker/Dockerfile': 'FROM example:1\nARG XRAY_CORE_VERSION=v1.2.3\nARG GEOCHECK_VERSION=0.1.0\n'}.items():
                target = repo / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(value)
            subprocess.run(['git', '-C', directory, 'add', '.'], check=True)
            subprocess.run(['git', '-C', directory, '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-qm', 'fixture'], check=True)
            first = self.module.snapshot(repo, 'HEAD', '1.0')
            self.assertEqual(first, self.module.snapshot(repo, 'HEAD', '1.0'))
            self.assertEqual(set(first['files']), {'src/main.ts', 'package-lock.json', 'docker/Dockerfile'})
            (repo / 'package-lock.json').write_text('{"packages":{"node_modules/sdk":{"version":"2"}}}')
            subprocess.run(['git', '-C', directory, '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-qam', 'upgrade'], check=True)
            second = self.module.snapshot(repo, 'HEAD', '1.1')
            self.assertEqual(self.module.changes(first, second), {'added': [], 'removed': [], 'changed': ['package-lock.json']})

    def test_route_inventory_uses_controller_http_methods(self):
        sources = {
            'libs/contract/api/controllers/xray.ts': "export const XRAY_CONTROLLER = 'xray' as const;\nexport const XRAY_ROUTES = { START: 'start', STOP: 'stop' } as const;",
            'libs/contract/api/routes.ts': "export const ROOT = '/node' as const;\nexport const REST_API = { XRAY: { START: `${ROOT}/${CONTROLLERS.XRAY_CONTROLLER}/${CONTROLLERS.XRAY_ROUTES.START}`, STOP: `${ROOT}/${CONTROLLERS.XRAY_CONTROLLER}/${CONTROLLERS.XRAY_ROUTES.STOP}` } } as const;",
            'src/modules/xray/xray.controller.ts': '@Controller(XRAY_CONTROLLER)\nclass X { @Post(XRAY_ROUTES.START) start() {} @Get(XRAY_ROUTES.STOP) stop() {} }',
            'libs/contract/commands/xray/start.ts': 'export const url = REST_API.XRAY.START;',
            'libs/contract/commands/xray/stop.ts': 'export const url = REST_API.XRAY.STOP;',
        }
        self.assertEqual(self.module.contract(sources)['routes'], [
            {'method': 'POST', 'path': '/node/xray/start', 'source': 'libs/contract/commands/xray/start.ts'},
            {'method': 'GET', 'path': '/node/xray/stop', 'source': 'libs/contract/commands/xray/stop.ts'},
        ])
        sources['src/modules/xray/xray.controller.ts'] = '@Controller(XRAY_CONTROLLER) class X { @Put("surprise") x() {} }'
        with self.assertRaises(ValueError):
            self.module.contract(sources)
        sources['src/modules/new/new.controller.ts'] = '@Controller(NEW_CONTROLLER) class X { @Get(NEW_ROUTE) x() {} }'
        sources['src/modules/xray/xray.controller.ts'] = '@Controller(XRAY_CONTROLLER) class X { @Post(XRAY_ROUTES.START) x() {} @Get(XRAY_ROUTES.STOP) y() {} }'
        with self.assertRaises(ValueError):
            self.module.contract(sources)

    def test_patch_allowlist_rejects_workflows_and_traversal(self):
        self.module.validate_paths(['src/api.rs', 'Cargo.lock', 'tests/api.rs'])
        for path in ['.github/workflows/ci.yml', 'scripts/upstream.py', '../src/api.rs', 'src/../../x', 'src/.hidden', 'upstream/manifest.json', 'build.rs']:
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.module.validate_paths([path])

    def test_patch_application_checks_new_files_and_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            subprocess.run(['git', 'init', '-q', directory], check=True)
            (repo / 'src').mkdir()
            (repo / 'src/main.rs').write_text('before\n')
            subprocess.run(['git', '-C', directory, 'add', '.'], check=True)
            subprocess.run(['git', '-C', directory, '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-qm', 'fixture'], check=True)
            (repo / 'src/main.rs').write_text('after\n')
            (repo / 'src/new.rs').write_text('new\n')
            subprocess.run(['git', '-C', directory, 'add', '-N', '.'], check=True)
            patch = repo / 'port.patch'
            patch.write_bytes(subprocess.check_output(['git', '-C', directory, 'diff', '--binary', 'HEAD']))
            subprocess.run(['git', '-C', directory, 'reset', '--hard', '-q'], check=True)
            self.module.validate_patch(repo, patch)
            self.assertEqual((repo / 'src/main.rs').read_text(), 'after\n')
            self.assertEqual((repo / 'src/new.rs').read_text(), 'new\n')
            subprocess.run(['git', '-C', directory, 'reset', '--hard', '-q'], check=True)
            (repo / 'src/link').symlink_to('/etc/passwd')
            subprocess.run(['git', '-C', directory, 'add', '-N', 'src/link'], check=True)
            patch.write_bytes(subprocess.check_output(['git', '-C', directory, 'diff', '--binary', 'HEAD']))
            subprocess.run(['git', '-C', directory, 'reset', '--hard', '-q'], check=True)
            with self.assertRaises(ValueError):
                self.module.validate_patch(repo, patch)

    def test_prompt_marks_upstream_untrusted_and_requires_tests(self):
        prompt = self.module.prompt({'tag': '3.4.5', 'commit': 'a' * 40}, {'tag': '3.4.6', 'commit': 'b' * 40})
        self.assertIn('untrusted', prompt)
        self.assertIn('cargo test --locked', prompt)
        self.assertIn('Do not change upstream/', prompt)


if __name__ == '__main__':
    unittest.main()
