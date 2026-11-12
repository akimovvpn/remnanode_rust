import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

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
        self.module.validate_paths(['src/api.rs', 'Cargo.lock', 'tests/api.rs', 'rcore/src/config.rs', 'rcore/tests/vision.rs', 'rcore/Cargo.toml', 'rcore/NOTICE.md'])
        for path in ['.github/workflows/ci.yml', 'scripts/upstream.py', '../src/api.rs', 'src/../../x', 'src/.hidden', 'upstream/manifest.json', 'build.rs', 'rcore/build.rs', 'rcore/tools/run.sh', 'rcore/.git/config', 'rcore/src/.github/workflows/ci.yml', 'rcore/Cargo.lock', 'rcore/src', 'rcore/tests']:
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

    def test_core_sources_fetch_only_for_changed_xray_pin(self):
        old = {'tag': '1', 'commit': 'a' * 40, 'files': {}, 'artifacts': {'xray': 'v1.2.3'}}
        new = {**old, 'tag': '2'}
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            with patch.object(self.module, 'snapshot', return_value=new), patch.object(self.module, 'blobs', return_value=('a' * 40, {})), patch.object(self.module, 'core_sources') as fetch:
                self.module.write_candidate(output, 'HEAD', '2', output, old)
                fetch.assert_not_called()
                new['artifacts'] = {'xray': 'v1.2.4'}
                self.module.write_candidate(output, 'HEAD', '2', output, old)
                fetch.assert_called_once_with('v1.2.4', output)
                fetch.side_effect = ValueError('source unavailable')
                with self.assertRaisesRegex(ValueError, 'source unavailable'):
                    self.module.write_candidate(output, 'HEAD', '2', output, old)

    def test_core_sources_fixed_repositories_verified_reality_commit_and_committed_blobs(self):
        reality_sha = 'abcdef123456' + '0' * 28
        xray_files = {'go.mod': ('100644', b'module github.com/xtls/xray-core\nrequire github.com/xtls/reality v0.0.0-20261101010101-abcdef123456\n'), 'main.go': ('100644', b'package main'), 'api.proto': ('100644', b'syntax = "proto3";'), 'LICENSE': ('100644', b'MPL'), '.github/workflows/run.yml': ('100644', b'untrusted'), 'tools/run.sh': ('100755', b'exit 1')}
        reality_files = {'go.mod': ('100644', b'module github.com/xtls/reality'), 'tls.go': ('100644', b'package reality'), 'LICENSE': ('100644', b'BSD')}
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            with patch.object(self.module, 'fetch_sources', side_effect=[('a' * 40, xray_files), (reality_sha, reality_files)]) as fetch, patch.object(self.module, 'reality_commit', return_value=reality_sha) as resolve:
                self.module.core_sources('v26.11.9', output)
                self.assertEqual(fetch.call_args_list[0].args, (self.module.XRAY_UPSTREAM, 'refs/tags/v26.11.9'))
                self.assertEqual(fetch.call_args_list[1].args, (self.module.REALITY_UPSTREAM, reality_sha))
                resolve.assert_called_once_with('abcdef123456')
            self.assertEqual((output / 'xray-source/main.go').read_bytes(), b'package main')
            self.assertTrue((output / 'reality-source/tls.go').is_file())
            self.assertFalse((output / 'xray-source/.github').exists())
            self.assertFalse((output / 'xray-source/tools').exists())
            manifest = json.loads((output / 'reality-source/manifest.json').read_text())
            self.assertEqual(manifest['commit'], reality_sha)
            self.assertEqual(manifest['files']['tls.go']['sha256'], self.module.hashlib.sha256(b'package reality').hexdigest())
            for invalid in ['--upload-pack=evil', '../v1.2.3', 'v1.2.3;evil']:
                with self.assertRaises(ValueError):
                    self.module.core_sources(invalid, output)
            with patch.object(self.module, 'fetch_sources', side_effect=[('a' * 40, xray_files), ('b' * 40, reality_files)]), patch.object(self.module, 'reality_commit', return_value=reality_sha):
                with self.assertRaisesRegex(ValueError, 'REALITY commit'):
                    self.module.core_sources('v26.11.9', output)

    def test_reality_api_requires_full_matching_commit_hash(self):
        sha = 'abcdef123456' + '0' * 28
        with patch.object(self.module.urllib.request, 'urlopen', return_value=io.StringIO(json.dumps({'sha': sha}))) as request:
            self.assertEqual(self.module.reality_commit('abcdef123456'), sha)
            self.assertEqual(request.call_args.args[0].full_url, 'https://api.github.com/repos/XTLS/REALITY/commits/abcdef123456')
        for sha in ['b' * 40, 'abcdef123456', None, 'abcdef123456' + 'z' * 28]:
            with patch.object(self.module.urllib.request, 'urlopen', return_value=io.StringIO(json.dumps({'sha': sha}))):
                with self.assertRaises(ValueError):
                    self.module.reality_commit('abcdef123456')
        with self.assertRaises(ValueError):
            self.module.reality_commit('../evil')

    def test_prompt_marks_upstream_untrusted_and_requires_tests(self):
        prompt = self.module.prompt({'tag': '3.4.5', 'commit': 'a' * 40}, {'tag': '3.4.6', 'commit': 'b' * 40})
        self.assertIn('untrusted', prompt)
        self.assertIn('cargo test --workspace --locked', prompt)
        self.assertIn('rcore/src/', prompt)
        self.assertIn('_update/xray-source/', prompt)
        self.assertIn('reject unported', prompt)
        self.assertIn('Do not change upstream/', prompt)


if __name__ == '__main__':
    unittest.main()
