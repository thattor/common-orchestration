import copy
import json
import os
import pwd
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from co_v4.task import codex_route as route
from co_v4.task import infer
from co_v4.task.common import TaskError, canonical, digest


class CodexRouteBindingTests(unittest.TestCase):
    MODEL = 'gpt-5-codex'

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(os.path.realpath(self.temp.name))
        self.native = self.base / 'native-cwd'
        self.config_dir = self.base / 'private-config'
        self.binary_dir = self.base / 'installed'
        fixture_home = self.base / 'measurement-home'
        self.credential_dir = fixture_home / '.codex'
        self.package_root = self.base / 'co_v4'
        for path in (self.native, self.config_dir, self.binary_dir,
                     fixture_home,
                     self.credential_dir, self.package_root,
                     self.package_root / 'task',
                     self.package_root / 'adapters'):
            path.mkdir()
        os.chmod(self.native, 0o700)
        os.chmod(self.config_dir, 0o700)

        for relative in route.SOURCE_FILES:
            path = self.package_root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(f'fixture source {relative}\n'.encode('utf-8'))

        self.binary = self.binary_dir / 'codex'
        self.binary.write_bytes(b'codex executable fixture')
        os.chmod(self.binary, 0o755)
        self.python = self.binary_dir / 'python'
        self.python.write_bytes(b'python executable fixture')
        os.chmod(self.python, 0o755)

        self.credential = self.credential_dir / 'auth.json'
        self.credential.write_bytes(b'fixture-only credential')
        os.chmod(self.credential, 0o600)

        self.home = self._canonical(fixture_home)
        self.config_path = self.config_dir / 'binding.json'
        self.config_obj = {
            'schema': 'co.codex-text-binding/1',
            'binary': self._canonical(self.binary),
            'binary_digest': digest(self.binary.read_bytes()),
            'python': self._canonical(self.python),
            'python_digest': digest(self.python.read_bytes()),
            'measurement_home': self.home,
            'credential_files': [
                self._credential_descriptor(self.credential),
            ],
            'disabled_mcp_servers': ['fixture-server'],
            'cleared_environment_keys': ['CODEX_FIXTURE'],
            'sources': {
                relative: digest(
                    (self.package_root / relative).read_bytes())
                for relative in route.SOURCE_FILES
            },
        }
        self.config_bytes = self._config_bytes(self.config_obj)
        self.config_path.write_bytes(self.config_bytes)
        os.chmod(self.config_path, 0o600)

        self.entry = {
            'route': 'codex',
            'version': 'codex-cli 0.160.1',
            'model': self.MODEL,
            'effort': 'high',
            'binary': self._canonical(self.binary),
            'config': self._canonical(self.config_path),
            'native_cwd': self._canonical(self.native),
            'available': True,
            'measured_at': 1760000000,
            'argv_template': list(route.ARGV_TEMPLATE),
            'argv_digest': digest(
                canonical(route.ARGV_TEMPLATE).encode('utf-8')),
            'config_digest': digest(self.config_bytes),
            'probes': [
                {
                    'kind': 'text',
                    'success': True,
                    'input_digest': digest(b'text input'),
                    'output_digest': digest(b'text output'),
                    'nonce_digest': digest(b'text nonce'),
                },
                {
                    'kind': 'json',
                    'success': True,
                    'input_digest': digest(b'json input'),
                    'output_digest': digest(b'json output'),
                    'nonce_digest': digest(b'json nonce'),
                },
            ],
            'known_context': ['fixture context'],
        }
        self._refresh(self.entry)

        self.package_patcher = mock.patch.object(
            route, '_package_root', return_value=self.package_root)
        self.package_patcher.start()
        self.addCleanup(self.package_patcher.stop)
        self.pwd_patcher = mock.patch.object(
            route.pwd, 'getpwuid',
            return_value=SimpleNamespace(pw_dir=self.home))
        self.pwd_patcher.start()
        self.addCleanup(self.pwd_patcher.stop)
        self.env_patcher = mock.patch.dict(
            os.environ, {'HOME': self.home}, clear=True)
        self.env_patcher.start()
        self.addCleanup(self.env_patcher.stop)

    def _canonical(self, path):
        return os.path.realpath(os.fspath(path))

    def _credential_descriptor(self, path):
        st = os.lstat(path)
        return {
            'path': self._canonical(path),
            'dev': st.st_dev,
            'ino': st.st_ino,
            'uid': st.st_uid,
            'mode': st.st_mode,
        }

    def _config_bytes(self, obj):
        return json.dumps(obj, ensure_ascii=False, sort_keys=True,
                          separators=(',', ':'),
                          allow_nan=False).encode('utf-8')

    def _refresh(self, entry):
        entry.pop('measurement_digest', None)
        entry['measurement_digest'] = route.measurement_digest(entry)
        return entry

    def _install_config(self, obj):
        raw = self._config_bytes(obj)
        self.config_path.write_bytes(raw)
        os.chmod(self.config_path, 0o600)
        self.config_bytes = raw
        self.entry['config_digest'] = digest(raw)
        self._refresh(self.entry)
        return raw

    def _entry_for_config_path(self, path, data=None, mode=0o600):
        if data is not None:
            path.write_bytes(data)
            os.chmod(path, mode)
        entry = copy.deepcopy(self.entry)
        entry['config'] = os.fspath(path)
        if data is not None:
            entry['config_digest'] = digest(data)
        try:
            self._refresh(entry)
        except TaskError:
            pass
        return entry

    def assert_unmeasured(self, call):
        with self.assertRaises(TaskError) as raised:
            call()
        self.assertEqual(raised.exception.code, 'route_unmeasured')
        self.assertEqual(raised.exception.detail, '')

    def test_valid_binding_validate_and_read_config_without_subprocess(self):
        with mock.patch.object(subprocess, 'Popen') as popen:
            self.assertIs(
                route.validate_entry(
                    self.entry, self.MODEL, self._canonical(self.native)),
                self.entry)
            loaded = route.read_config(self.entry)
            self.assertIs(route.validate_entry(self.entry, self.MODEL,
                                               self.native), self.entry)
        self.assertEqual(loaded, self.config_obj)
        self.assertIsNot(loaded, self.config_obj)
        popen.assert_not_called()

    def test_effort_changes_route_digest_but_not_legacy_infer_digest(self):
        low = copy.deepcopy(self.entry)
        medium = copy.deepcopy(self.entry)
        for entry in (low, medium):
            entry.pop('measurement_digest')
        low['effort'] = 'low'
        medium['effort'] = 'medium'
        self.assertNotEqual(route.measurement_digest(low),
                            route.measurement_digest(medium))
        self.assertEqual(infer._measurement_digest(low),
                         infer._measurement_digest(medium))

    def test_measurement_digest_performs_no_filesystem_io(self):
        entry = copy.deepcopy(self.entry)
        entry.pop('measurement_digest')
        missing = self.base / 'not-created'
        entry['binary'] = os.fspath(missing / 'codex')
        entry['config'] = os.fspath(missing / 'binding.json')
        entry['native_cwd'] = os.fspath(missing / 'native')
        with mock.patch.object(route.os.path, 'realpath',
                               side_effect=AssertionError), \
                mock.patch.object(route.os, 'open',
                                  side_effect=AssertionError), \
                mock.patch.object(route.os, 'stat',
                                  side_effect=AssertionError), \
                mock.patch.object(route.os, 'lstat',
                                  side_effect=AssertionError):
            result = route.measurement_digest(entry)
        self.assertTrue(result.startswith('sha256:'))

    def test_availability_probe_shape_and_expected_identity_refusals(self):
        cases = []

        def unavailable(entry):
            entry['available'] = False

        def failed_probe(entry):
            entry['probes'][1]['success'] = False

        def reordered_probes(entry):
            entry['probes'] = list(reversed(entry['probes']))

        def extra_field(entry):
            entry['extra'] = None

        cases.extend((unavailable, failed_probe, reordered_probes,
                      extra_field))
        for mutate in cases:
            entry = copy.deepcopy(self.entry)
            mutate(entry)
            self.assert_unmeasured(
                lambda entry=entry: route.validate_entry(
                    entry, self.MODEL, self._canonical(self.native)))

        missing_digest = copy.deepcopy(self.entry)
        missing_digest.pop('measurement_digest')
        self.assertEqual(route.measurement_digest(missing_digest),
                         self.entry['measurement_digest'])
        self.assert_unmeasured(
            lambda: route.read_config(missing_digest))
        self.assert_unmeasured(
            lambda: route.validate_entry(
                self.entry, 'gpt-4.1', self._canonical(self.native)))
        self.assert_unmeasured(
            lambda: route.validate_entry(
                self.entry, self.MODEL,
                self._canonical(self.native) + '/.'))

    def test_config_reader_rejects_unsafe_files_and_non_strict_json(self):
        real = self.config_dir / 'real.json'
        real.write_bytes(self.config_bytes)
        os.chmod(real, 0o600)
        symlink = self.config_dir / 'linked.json'
        os.symlink(real, symlink)

        hard_source = self.config_dir / 'hard-source.json'
        hard_source.write_bytes(self.config_bytes)
        os.chmod(hard_source, 0o600)
        hardlink = self.config_dir / 'hardlink.json'
        os.link(hard_source, hardlink)

        fifo = self.config_dir / 'fifo.json'
        os.mkfifo(fifo, 0o600)

        variants = [
            ('symlink', symlink, None, None),
            ('hardlink', hardlink, None, None),
            ('fifo', fifo, None, None),
            ('mode', self.config_dir / 'mode.json',
             self.config_bytes, 0o644),
            ('oversize', self.config_dir / 'large.json',
             b'0' * 262145, 0o600),
            ('duplicate', self.config_dir / 'duplicate.json',
             b'{"schema":"x","schema":"x"}', 0o600),
            ('fence', self.config_dir / 'fence.json',
             b'```json\n' + self.config_bytes + b'\n```', 0o600),
            ('utf8', self.config_dir / 'utf8.json', b'\xff', 0o600),
            ('nonfinite', self.config_dir / 'nonfinite.json',
             b'{"schema":NaN}', 0o600),
        ]
        for name, path, data, mode in variants:
            with self.subTest(name=name):
                entry = self._entry_for_config_path(
                    path, data=data,
                    mode=0o600 if mode is None else mode)
                self.assert_unmeasured(lambda: route.read_config(entry))

    def test_config_source_and_credential_stat_drift(self):
        original_config = self.config_path.read_bytes()
        self.config_path.write_bytes(b'{}')
        os.chmod(self.config_path, 0o600)
        self.assert_unmeasured(lambda: route.read_config(self.entry))

        self.config_path.write_bytes(original_config)
        os.chmod(self.config_path, 0o600)
        source = self.package_root / 'codex_engine.py'
        original_source = source.read_bytes()
        source.write_bytes(original_source + b'drift')
        self.assert_unmeasured(lambda: route.read_config(self.entry))

        source.write_bytes(original_source)
        os.chmod(self.credential, 0o644)
        self.assert_unmeasured(lambda: route.read_config(self.entry))
        os.chmod(self.credential, 0o600)

    def test_config_and_credentials_must_stay_outside_native_cwd(self):
        inside = self.native / 'inside'
        inside.mkdir()
        os.chmod(inside, 0o700)
        inside_config = inside / 'binding.json'
        entry = self._entry_for_config_path(
            inside_config, data=self.config_bytes)
        self.assert_unmeasured(lambda: route.read_config(entry))

        inside_credential = self.native / 'credential'
        inside_credential.write_bytes(b'credential inside cwd')
        os.chmod(inside_credential, 0o600)
        config = copy.deepcopy(self.config_obj)
        config['credential_files'] = [
            self._credential_descriptor(inside_credential),
        ]
        self._install_config(config)
        self.assert_unmeasured(lambda: route.read_config(self.entry))

    def test_home_is_exact_and_codex_home_must_be_absent(self):
        with mock.patch.dict(os.environ,
                             {'HOME': self.home + '-wrong'}, clear=True):
            self.assert_unmeasured(lambda: route.read_config(self.entry))
        with mock.patch.dict(
                os.environ,
                {'HOME': self.home, 'CODEX_HOME': ''}, clear=True):
            self.assert_unmeasured(lambda: route.read_config(self.entry))
        self.assertEqual(route.read_config(self.entry), self.config_obj)

    def test_pending_probe_prefix_never_qualifies_a_route(self):
        for size in (0, 1, 2):
            with self.subTest(size=size):
                entry = copy.deepcopy(self.entry)
                entry['available'] = False
                entry['probes'] = entry['probes'][:size]
                self._refresh(entry)
                self.assertEqual(route.read_config(entry), self.config_obj)
                self.assert_unmeasured(lambda: route.validate_entry(
                    entry, self.MODEL, self._canonical(self.native)))
                entry['available'] = True
                if size < 2:
                    self.assert_unmeasured(
                        lambda: route.measurement_digest(entry))
        bad = copy.deepcopy(self.entry)
        bad['available'] = False
        bad['probes'] = bad['probes'][1:]
        self.assert_unmeasured(lambda: route.measurement_digest(bad))

    def test_home_mismatch_and_codex_home_refuse_before_any_open(self):
        for changes in ({'HOME': self.home + '-wrong'},
                        {'HOME': self.home, 'CODEX_HOME': ''}):
            with self.subTest(changes=changes), mock.patch.dict(
                    os.environ, changes, clear=True), mock.patch.object(
                        route.os, 'open') as opened:
                self.assert_unmeasured(lambda: route.read_config(self.entry))
                opened.assert_not_called()

    def test_native_auth_cannot_be_replaced_by_an_unrelated_credential(self):
        alternate = self.base / 'unrelated-credential'
        alternate.write_bytes(b'fixture-only unrelated credential')
        os.chmod(alternate, 0o600)
        config = copy.deepcopy(self.config_obj)
        config['credential_files'] = [self._credential_descriptor(alternate)]
        self._install_config(config)
        with mock.patch.object(route, '_hash_path') as hashed:
            self.assert_unmeasured(lambda: route.read_config(self.entry))
            hashed.assert_not_called()

    def test_native_auth_directory_is_refused_before_config_open(self):
        home = self.base / 'fixture-home'
        auth_dir = home / '.codex'
        auth_dir.mkdir(parents=True)
        os.chmod(auth_dir, 0o700)
        auth = auth_dir / 'auth.json'
        auth.write_bytes(b'fixture-only credential, never parse')
        os.chmod(auth, 0o600)
        entry = self._entry_for_config_path(auth)
        with mock.patch.object(route, '_expected_home',
                               return_value=self._canonical(home)), \
                mock.patch.dict(os.environ,
                                {'HOME': self._canonical(home)}, clear=True), \
                mock.patch.object(route.os, 'open') as opened:
            self.assert_unmeasured(lambda: route.read_config(entry))
            opened.assert_not_called()

        alias = self.config_dir / 'auth-alias.json'
        os.link(auth, alias)
        alias_entry = self._entry_for_config_path(alias)
        with mock.patch.object(route, '_expected_home',
                               return_value=self._canonical(home)), \
                mock.patch.dict(os.environ,
                                {'HOME': self._canonical(home)}, clear=True), \
                mock.patch.object(route.os, 'read') as read:
            self.assert_unmeasured(lambda: route.read_config(alias_entry))
            read.assert_not_called()

    def test_unavailable_path_relationship_refuses_before_any_open(self):
        with mock.patch.object(route.os.path, 'commonpath',
                               side_effect=ValueError('fixture only')), \
                mock.patch.object(route.os, 'open') as opened:
            self.assert_unmeasured(lambda: route.read_config(self.entry))
            opened.assert_not_called()

    def test_post_close_error_or_interrupt_does_not_close_fd_twice(self):
        real_close = os.close
        for failure in (OSError('post-close failure'), KeyboardInterrupt(),
                        SystemExit(7)):
            closed = []

            def close_then_fail(fd):
                closed.append(fd)
                real_close(fd)
                raise failure

            with self.subTest(failure=type(failure).__name__), \
                    mock.patch.object(route.os, 'close',
                                      side_effect=close_then_fail):
                if isinstance(failure, OSError):
                    self.assert_unmeasured(lambda: route._read_path(
                        self._canonical(self.config_path), 262144))
                else:
                    with self.assertRaises(type(failure)):
                        route._read_path(self._canonical(self.config_path),
                                         262144)
            self.assertEqual(len(closed), 1)

    def test_read_interrupt_closes_owned_fd_once(self):
        real_close = os.close
        for failure in (KeyboardInterrupt(), SystemExit(7)):
            closed = []

            def close(fd):
                closed.append(fd)
                return real_close(fd)

            with self.subTest(failure=type(failure).__name__), \
                    mock.patch.object(route.os, 'read',
                                      side_effect=failure), \
                    mock.patch.object(route.os, 'close', side_effect=close):
                with self.assertRaises(type(failure)):
                    route._read_path(self._canonical(self.config_path),
                                     262144)
            self.assertEqual(len(closed), 1)

    def test_explicit_empty_inventories_and_missing_or_extra_maps(self):
        empty = copy.deepcopy(self.config_obj)
        empty['disabled_mcp_servers'] = []
        empty['cleared_environment_keys'] = []
        self._install_config(empty)
        self.assertEqual(route.read_config(self.entry), empty)

        for key in ('disabled_mcp_servers', 'cleared_environment_keys',
                    'sources'):
            missing = copy.deepcopy(self.config_obj)
            missing.pop(key)
            self._install_config(missing)
            self.assert_unmeasured(lambda: route.read_config(self.entry))

        extra_source = copy.deepcopy(self.config_obj)
        extra_source['sources']['../outside.py'] = digest(b'outside')
        self._install_config(extra_source)
        self.assert_unmeasured(lambda: route.read_config(self.entry))

    def test_credential_content_is_never_opened(self):
        real_open = os.open
        opened = []

        def tracking_open(path, flags, *args, **kwargs):
            opened.append((self._canonical(path), flags))
            return real_open(path, flags, *args, **kwargs)

        with mock.patch.object(route.os, 'open',
                               side_effect=tracking_open):
            route.read_config(self.entry)
        credential_path = self._canonical(self.credential)
        self.assertFalse(any(path == credential_path for path, _ in opened))
        required = (os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                    | os.O_CLOEXEC)
        self.assertTrue(any(path == self._canonical(self.config_path)
                            and flags == required
                            for path, flags in opened))

        config = copy.deepcopy(self.config_obj)
        config['python'] = credential_path
        config['python_digest'] = digest(b'would otherwise be read')
        self._install_config(config)
        opened.clear()
        with mock.patch.object(route.os, 'open',
                               side_effect=tracking_open):
            self.assert_unmeasured(lambda: route.read_config(self.entry))
        self.assertFalse(any(path == credential_path for path, _ in opened))

    def test_fds_close_after_config_read_and_source_hash_errors(self):
        real_open = os.open
        real_read = os.read
        real_close = os.close
        targets = (
            self._canonical(self.config_path),
            self._canonical(self.package_root / route.SOURCE_FILES[0]),
        )
        for target in targets:
            with self.subTest(target=target):
                opened = {}
                closed = []

                def tracking_open(path, flags, *args, **kwargs):
                    fd = real_open(path, flags, *args, **kwargs)
                    opened[fd] = self._canonical(path)
                    return fd

                def tracking_read(fd, size):
                    if opened.get(fd) == target:
                        raise OSError('injected read failure')
                    return real_read(fd, size)

                def tracking_close(fd):
                    closed.append(fd)
                    return real_close(fd)

                with mock.patch.object(route.os, 'open',
                                       side_effect=tracking_open), \
                        mock.patch.object(route.os, 'read',
                                          side_effect=tracking_read), \
                        mock.patch.object(route.os, 'close',
                                          side_effect=tracking_close):
                    self.assert_unmeasured(
                        lambda: route.read_config(self.entry))
                self.assertTrue(opened)
                self.assertFalse(set(opened) - set(closed))


    def test_auth_identity_returns_dev_ino(self):
        from co_v4.task import codex_route
        expected = os.stat(self.credential)
        self.assertEqual(codex_route._current_auth_identity(self.home), (expected.st_dev, expected.st_ino))

    def test_auth_identity_missing_returns_none(self):
        from co_v4.task import codex_route
        no_auth = self.base / 'home-no-auth-file'
        (no_auth / '.codex').mkdir(parents=True)
        no_codex = self.base / 'home-no-codex-dir'
        no_codex.mkdir()
        absent = self.base / 'home-absent'
        for home in (no_auth, no_codex, absent):
            with self.subTest(home=os.fspath(home)):
                self.assertIsNone(codex_route._current_auth_identity(os.fspath(home)))

    def test_auth_identity_stat_errors_are_fixed(self):
        from co_v4.task import codex_route
        loop_error = OSError('symlink loop')
        loop_error.errno = 62
        for error in (PermissionError('denied'), NotADirectoryError('not a directory'), loop_error):
            with self.subTest(error=type(error).__name__), mock.patch.object(codex_route.os, 'stat', side_effect=error):
                self.assert_unmeasured(lambda : codex_route._current_auth_identity(self.home))

    def test_auth_identity_interrupts_propagate(self):
        from co_v4.task import codex_route
        for exc in (KeyboardInterrupt('stop'), SystemExit('exit')):
            with self.subTest(error=type(exc).__name__), mock.patch.object(codex_route.os, 'stat', side_effect=exc):
                with self.assertRaises(type(exc)) as raised:
                    codex_route._current_auth_identity(self.home)
                self.assertIs(raised.exception, exc)

    def test_private_config_missing_auth_succeeds(self):
        from co_v4.task import codex_route
        no_auth = self.base / 'read-no-auth'
        (no_auth / '.codex').mkdir(parents=True)
        no_codex = self.base / 'read-no-codex'
        no_codex.mkdir()
        for home in (os.fspath(no_auth), os.fspath(no_codex)):
            with self.subTest(home=home):
                (st, raw, config_digest) = codex_route._read_private_config(os.fspath(self.config_path), home)
                self.assertEqual(raw, self.config_bytes)
                self.assertEqual(config_digest, self.entry['config_digest'])
                expected = os.stat(self.config_path)
                self.assertEqual((st.st_dev, st.st_ino), (expected.st_dev, expected.st_ino))

    def test_private_config_unrelated_auth_replacement_succeeds(self):
        from co_v4.task import codex_route
        with mock.patch.object(codex_route, '_current_auth_identity', side_effect=[(11, 22), (33, 44)]):
            (st, raw, config_digest) = codex_route._read_private_config(os.fspath(self.config_path), self.home)
        self.assertEqual(raw, self.config_bytes)
        self.assertEqual(config_digest, self.entry['config_digest'])

    def test_preopen_auth_alias_denies_without_open(self):
        from co_v4.task import codex_route
        auth_stat = os.stat(self.credential)
        config_name = os.fspath(self.config_path)
        real_stat = os.stat

        def fake_stat(path, *args, **kwargs):
            if os.fspath(path) == config_name and kwargs.get('follow_symlinks', True) is False:
                return auth_stat
            return real_stat(path, *args, **kwargs)
        with mock.patch.object(codex_route.os, 'stat', side_effect=fake_stat), mock.patch.object(codex_route.os, 'open') as open_mock, mock.patch.object(codex_route.os, 'read') as read_mock:
            self.assert_unmeasured(lambda : codex_route._read_private_config(config_name, self.home))
        open_mock.assert_not_called()
        read_mock.assert_not_called()

    def test_auth_hardlink_config_denies_before_open(self):
        from co_v4.task import codex_route
        alias = self.config_dir / 'auth-link.json'
        os.link(os.fspath(self.credential), os.fspath(alias))
        with mock.patch.object(codex_route.os, 'open') as open_mock:
            self.assert_unmeasured(lambda : codex_route._read_private_config(os.fspath(alias), self.home))
        open_mock.assert_not_called()

    def test_auth_symlink_target_alias_denies(self):
        from co_v4.task import codex_route
        os.remove(self.credential)
        os.symlink(os.fspath(self.config_path), os.fspath(self.credential))
        with mock.patch.object(codex_route.os, 'open') as open_mock:
            self.assert_unmeasured(lambda : codex_route._read_private_config(os.fspath(self.config_path), self.home))
        open_mock.assert_not_called()

    def test_fd_matching_before_snapshot_denies_without_read(self):
        from co_v4.task import codex_route
        auth_stat = os.stat(self.credential)
        with mock.patch.object(codex_route.os, 'fstat', side_effect=lambda fd: auth_stat), mock.patch.object(codex_route.os, 'read') as read_mock:
            self.assert_unmeasured(lambda : codex_route._read_private_config(os.fspath(self.config_path), self.home))
        read_mock.assert_not_called()

    def test_fd_matching_after_snapshot_denies_without_read(self):
        from co_v4.task import codex_route
        auth_stat = os.stat(self.credential)
        config_stat = os.stat(self.config_path)
        with mock.patch.object(codex_route, '_current_auth_identity', side_effect=[(auth_stat.st_dev, auth_stat.st_ino), (config_stat.st_dev, config_stat.st_ino)]), mock.patch.object(codex_route.os, 'read') as read_mock:
            self.assert_unmeasured(lambda : codex_route._read_private_config(os.fspath(self.config_path), self.home))
        read_mock.assert_not_called()

    def test_config_lstat_errors_are_fixed(self):
        from co_v4.task import codex_route
        loop_error = OSError('symlink loop')
        loop_error.errno = 62
        for error in (PermissionError('denied'), NotADirectoryError('not a directory'), loop_error):
            with self.subTest(error=type(error).__name__), mock.patch.object(codex_route, '_current_auth_identity', return_value=None), mock.patch.object(codex_route.os, 'stat', side_effect=error):
                self.assert_unmeasured(lambda : codex_route._read_private_config(os.fspath(self.config_path), self.home))

    def test_fd_hook_snapshot_errors_are_fixed(self):
        from co_v4.task import codex_route
        loop_error = OSError('symlink loop')
        loop_error.errno = 62
        for error in (PermissionError('denied'), NotADirectoryError('not a directory'), loop_error):
            with self.subTest(error=type(error).__name__), mock.patch.object(codex_route, '_current_auth_identity', side_effect=[None, error]):
                self.assert_unmeasured(lambda : codex_route._read_private_config(os.fspath(self.config_path), self.home))

    def test_config_lstat_interrupts_propagate(self):
        from co_v4.task import codex_route
        for exc in (KeyboardInterrupt('stop'), SystemExit('exit')):
            with self.subTest(error=type(exc).__name__), mock.patch.object(codex_route, '_current_auth_identity', return_value=None), mock.patch.object(codex_route.os, 'stat', side_effect=exc):
                with self.assertRaises(type(exc)) as raised:
                    codex_route._read_private_config(os.fspath(self.config_path), self.home)
                self.assertIs(raised.exception, exc)

    def test_fd_hook_interrupts_propagate_and_close_once(self):
        from co_v4.task import codex_route
        real_close = os.close
        for exc in (KeyboardInterrupt('stop'), SystemExit('exit')):
            closes = []

            def counting_close(fd):
                closes.append(fd)
                real_close(fd)
            with self.subTest(error=type(exc).__name__), mock.patch.object(codex_route, '_current_auth_identity', side_effect=[None, exc]), mock.patch.object(codex_route.os, 'close', side_effect=counting_close):
                with self.assertRaises(type(exc)) as raised:
                    codex_route._read_private_config(os.fspath(self.config_path), self.home)
                self.assertIs(raised.exception, exc)
            self.assertEqual(len(closes), 1)

    def test_fd_hook_denial_closes_once(self):
        from co_v4.task import codex_route
        auth_stat = os.stat(self.credential)
        config_stat = os.stat(self.config_path)
        closes = []
        real_close = os.close

        def counting_close(fd):
            closes.append(fd)
            real_close(fd)
        with mock.patch.object(codex_route, '_current_auth_identity', side_effect=[(auth_stat.st_dev, auth_stat.st_ino), (config_stat.st_dev, config_stat.st_ino)]), mock.patch.object(codex_route.os, 'close', side_effect=counting_close):
            self.assert_unmeasured(lambda : codex_route._read_private_config(os.fspath(self.config_path), self.home))
        self.assertEqual(len(closes), 1)

    def test_private_config_never_opens_auth(self):
        from co_v4.task import codex_route
        opened = []
        real_open = os.open

        def tracking_open(path, *args, **kwargs):
            opened.append(os.fspath(path))
            return real_open(path, *args, **kwargs)
        with mock.patch.object(codex_route.os, 'open', side_effect=tracking_open):
            (st, raw, config_digest) = codex_route._read_private_config(os.fspath(self.config_path), self.home)
        self.assertEqual(opened, [os.fspath(self.config_path)])

    def test_read_config_valid_binding(self):
        from co_v4.task import codex_route
        self.assertEqual(codex_route.read_config(copy.deepcopy(self.entry)), self.config_obj)

    def test_read_config_rejects_mismatched_home(self):
        from co_v4.task import codex_route
        other = os.fspath(self.base / 'other-home')
        with mock.patch.dict(os.environ, {'HOME': other}):
            self.assert_unmeasured(lambda : codex_route.read_config(copy.deepcopy(self.entry)))

    def test_read_config_rejects_codex_home(self):
        from co_v4.task import codex_route
        with mock.patch.dict(os.environ, {'CODEX_HOME': os.fspath(self.base / 'codex-home')}):
            self.assert_unmeasured(lambda : codex_route.read_config(copy.deepcopy(self.entry)))

    def test_read_config_denies_auth_alias_before_read(self):
        from co_v4.task import codex_route
        config_stat = os.stat(self.config_path)
        with mock.patch.object(codex_route, '_current_auth_identity', return_value=(config_stat.st_dev, config_stat.st_ino)), mock.patch.object(codex_route.os, 'read') as read_mock:
            self.assert_unmeasured(lambda : codex_route.read_config(copy.deepcopy(self.entry)))
        read_mock.assert_not_called()


if __name__ == '__main__':
    unittest.main()
