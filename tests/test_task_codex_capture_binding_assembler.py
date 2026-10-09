import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from co_v4.task import codex_route
from co_v4.task.common import TaskError

INV = {'native_version': codex_route.ROUTE_VERSION,
       'disabled_mcp_servers': (), 'cleared_environment_keys': ()}


class CaptureBindingTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name).resolve()
        self.home = root / 'home'
        codex = self.home / '.codex'
        codex.mkdir(parents=True)
        os.chmod(codex, 0o755)
        self.cwd = root / 'cwd'
        self.cwd.mkdir()
        os.chmod(self.cwd, 0o700)
        self.pkg = root / 'pkg'
        self.auth = codex / 'auth.json'
        self.binary = root / 'codex'
        self.python = root / 'python3'
        for path, mode in ((self.auth, 0o600), (self.binary, 0o755),
                           (self.python, 0o755)):
            path.write_bytes(b'x')
            os.chmod(path, mode)
        for name in codex_route.SOURCE_FILES:
            path = self.pkg / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'src')
        home = codex_route._canonical_path(str(self.home))
        patches = (mock.patch.object(codex_route.pwd, 'getpwuid',
                                     return_value=mock.Mock(pw_dir=home)),
                   mock.patch.object(codex_route, '_package_root',
                                     return_value=str(self.pkg)),
                   mock.patch.dict(os.environ, {'HOME': home}))
        for patcher in patches:
            self.addCleanup(patcher.stop)
            patcher.start()
        os.environ.pop('CODEX_HOME', None)

    def call(self, **kw):
        args = {'binary': self.binary, 'python': self.python, 'cwd': self.cwd,
                'inventory': dict(INV), 'credential_files': (str(self.auth),)}
        args.update(kw)
        return codex_route.capture_binding(**args)

    def test_binding_exact_and_fresh(self):
        inventory = dict(INV, disabled_mcp_servers=('alpha', 'beta'))
        first = self.call(inventory=inventory)
        canon = codex_route._canonical_path
        digest = 'sha256:' + hashlib.sha256(b'x').hexdigest()
        self.assertEqual(set(first), set(codex_route._CONFIG_KEYS))
        self.assertEqual((first['schema'], first['measurement_home']),
                         (codex_route.CONFIG_SCHEMA, canon(str(self.home))))
        self.assertEqual((first['binary'], first['python'],
                          first['binary_digest'], first['python_digest']),
                         (canon(str(self.binary)), canon(str(self.python)),
                          digest, digest))
        self.assertEqual((first['disabled_mcp_servers'],
                          first['cleared_environment_keys']),
                         (['alpha', 'beta'], []))
        self.assertEqual(len(first['sources']), len(codex_route.SOURCE_FILES))
        cred, = first['credential_files']
        self.assertEqual((cred['path'], cred['uid'], cred['mode']),
                         (canon(str(self.auth)), os.geteuid(), 0o100600))
        first['sources']['x'] = 1
        first['credential_files'][0]['uid'] = -1
        second = self.call(inventory=inventory)
        self.assertEqual((inventory['disabled_mcp_servers'],
                          'x' in second['sources'],
                          second['credential_files'][0]['uid']),
                         (('alpha', 'beta'), False, os.geteuid()))
        self.assertIsNot(first['sources'], second['sources'])

    def test_failures_and_hash_contract(self):
        calls = []
        real = codex_route._hash_path
        def spy(path, size, executable=False, forbidden=frozenset()):
            calls.append((str(path), size, executable, forbidden))
            return real(path, size, executable=executable, forbidden=forbidden)
        with mock.patch.object(codex_route, '_hash_path', spy):
            for env in ({'HOME': str(self.cwd)}, {'CODEX_HOME': ''}):
                with mock.patch.dict(os.environ, env):
                    self.assertRaises(TaskError, self.call)
            os.chmod(self.cwd, 0o755)
            self.assertRaises(TaskError, self.call)
            os.chmod(self.cwd, 0o700)
            for bad in (dict(INV, native_version='x'),
                        dict(INV, disabled_mcp_servers=[]),
                        dict(INV, extra=())):
                self.assertRaises(TaskError, self.call, inventory=bad)
            os.chmod(self.auth, 0o644)
            self.assertRaises(TaskError, self.call)
            os.chmod(self.auth, 0o600)
            self.assertRaises(TaskError, self.call, binary=str(self.auth))
            self.assertEqual(calls, [])
            target = self.pkg / codex_route.SOURCE_FILES[0]
            target.unlink()
            self.assertRaises(TaskError, self.call)
            self.assertEqual([c[1] for c in calls if c[2]],
                             [codex_route._MAX_CODE_BYTES] * 2)
            calls.clear()
            target.write_bytes(b'src')
            self.call()
        self.assertEqual([c[1] for c in calls if c[2]],
                         [codex_route._MAX_CODE_BYTES] * 2)
        self.assertEqual(len({c[3] for c in calls}), 1)
        self.assertNotIn(codex_route._canonical_path(str(self.auth)),
                         {c[0] for c in calls})
        with mock.patch.object(codex_route, '_capture_sources',
                               side_effect=KeyboardInterrupt):
            self.assertRaises(KeyboardInterrupt, self.call)
