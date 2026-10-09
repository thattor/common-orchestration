import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from co_v4.task import codex_route as route
from co_v4.task.common import TaskError, canonical, digest


class SelectedRegistryReaderTests(unittest.TestCase):
    MODEL = 'gpt-5-codex'

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(os.path.realpath(self.temp.name))
        self.home_dir = self.base / 'measurement-home'
        self.codex_dir = self.home_dir / '.codex'
        self.state = self.base / 'state'
        self.conf = self.state / 'conf'
        self.native = self.base / 'native-cwd'
        self.bin_dir = self.base / 'installed'
        self.pkg = self.base / 'co_v4'
        for path in (self.home_dir, self.codex_dir, self.state, self.conf,
                     self.native, self.bin_dir, self.pkg, self.pkg / 'task',
                     self.pkg / 'adapters'):
            path.mkdir()
        for path in (self.state, self.conf, self.native):
            os.chmod(path, 0o700)

        for relative in route.SOURCE_FILES:
            path = self.pkg / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(
                ('fixture source %s\n' % relative).encode('utf-8'))

        self.binary = self.bin_dir / 'codex'
        self.binary.write_bytes(b'codex executable fixture')
        os.chmod(self.binary, 0o755)
        self.python = self.bin_dir / 'python'
        self.python.write_bytes(b'python executable fixture')
        os.chmod(self.python, 0o755)
        self.auth = self.codex_dir / 'auth.json'
        self.auth.write_bytes(b'fixture-only credential')
        os.chmod(self.auth, 0o600)

        self.home = self._canonical(self.home_dir)
        self.config_path = self.conf / 'binding.json'
        self.config_obj = {
            'schema': 'co.codex-text-binding/1',
            'binary': self._canonical(self.binary),
            'binary_digest': digest(self.binary.read_bytes()),
            'python': self._canonical(self.python),
            'python_digest': digest(self.python.read_bytes()),
            'measurement_home': self.home,
            'credential_files': [self._file_descriptor(self.auth)],
            'disabled_mcp_servers': ['fixture-server'],
            'cleared_environment_keys': ['CODEX_FIXTURE'],
            'sources': {
                relative: digest((self.pkg / relative).read_bytes())
                for relative in route.SOURCE_FILES
            },
        }
        self.config_bytes = self._dump(self.config_obj)
        self.config_path.write_bytes(self.config_bytes)
        os.chmod(self.config_path, 0o600)

        self.key = 'codex/' + self.MODEL
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
                {'kind': 'text', 'success': True,
                 'input_digest': digest(b'text input'),
                 'output_digest': digest(b'text output'),
                 'nonce_digest': digest(b'text nonce')},
                {'kind': 'json', 'success': True,
                 'input_digest': digest(b'json input'),
                 'output_digest': digest(b'json output'),
                 'nonce_digest': digest(b'json nonce')},
            ],
            'known_context': ['fixture context'],
        }
        self._refresh(self.entry)

        self.registry_path = self.state / 'routes2.json'
        self.registry_obj = {
            'schema': 'co.routes/2',
            'created': 1760000100,
            'cwd': self._canonical(self.native),
            'measurements': {self.key: self.entry},
            'candidates': [],
        }
        self.registry_bytes = self._write_registry(self.registry_obj)

        for patcher in (
                mock.patch.object(route, '_package_root',
                                  return_value=self.pkg),
                mock.patch.object(route.pwd, 'getpwuid',
                                  return_value=SimpleNamespace(
                                      pw_dir=self.home)),
                mock.patch.dict(os.environ, {'HOME': self.home},
                                clear=True)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def _canonical(self, path):
        return os.path.realpath(os.fspath(path))

    def _file_descriptor(self, path):
        st = os.lstat(path)
        return {'path': self._canonical(path), 'dev': st.st_dev,
                'ino': st.st_ino, 'uid': st.st_uid, 'mode': st.st_mode}

    def _dump(self, obj):
        return json.dumps(obj, ensure_ascii=False, sort_keys=True,
                          separators=(',', ':'),
                          allow_nan=False).encode('utf-8')

    def _refresh(self, entry):
        entry.pop('measurement_digest', None)
        entry['measurement_digest'] = route.measurement_digest(entry)
        return entry

    def _write_registry(self, obj):
        raw = obj if isinstance(obj, bytes) else self._dump(obj)
        self.registry_path.write_bytes(raw)
        os.chmod(self.registry_path, 0o600)
        return raw

    def _use_entry(self, entry):
        registry = dict(self.registry_obj)
        registry['measurements'] = {self.key: entry}
        return self._write_registry(registry)

    def _read_public(self, **over):
        args = dict(state=os.fspath(self.state), key=self.key,
                    model=self.MODEL, cwd=os.fspath(self.native))
        args.update(over)
        return route.read_measurement(args['state'], args['key'],
                                      args['model'], args['cwd'])

    def _read_pair(self, **over):
        args = dict(state=os.fspath(self.state), key=self.key,
                    model=self.MODEL, cwd=os.fspath(self.native))
        args.update(over)
        return route._read_measured_config(args['state'], args['key'],
                                           args['model'], args['cwd'])

    def _fake_fstat(self, **changes):
        real_fstat = os.fstat
        index = {'st_nlink': 3, 'st_uid': 4, 'st_size': 6}

        def fake(fd):
            values = list(real_fstat(fd))
            for name, value in changes.items():
                values[index[name]] = value
            return os.stat_result(tuple(values))
        return fake

    def assert_unmeasured(self, call):
        with self.assertRaises(TaskError) as raised:
            call()
        exc = raised.exception
        self.assertEqual(exc.code, 'route_unmeasured')
        self.assertEqual(exc.detail, '')
        self.assertEqual(str(exc), 'route_unmeasured')
        self.assertIsNone(exc.__cause__)
        return exc

    def test_public_reader_returns_fresh_entry_after_full_binding(self):
        with mock.patch.object(subprocess, 'Popen') as popen:
            entry = self._read_public()
        popen.assert_not_called()
        self.assertEqual(entry, self.entry)
        self.assertIsNot(entry, self.entry)

        raw = route._read_private_registry(
            self._canonical(self.registry_path), self.home)
        self.assertEqual(raw, self.registry_bytes)

        pair_entry, config = self._read_pair()
        self.assertEqual(pair_entry, self.entry)
        self.assertIsNot(pair_entry, self.entry)
        self.assertEqual(config, self.config_obj)
        self.assertIsNot(config, self.config_obj)

    def test_private_pair_returns_identical_entry_and_config(self):
        captured = {}
        real = route._validated_config

        def capture(entry, model, cwd):
            captured['entry'] = entry
            captured['args'] = (model, cwd)
            captured['config'] = real(entry, model, cwd)
            return captured['config']

        with mock.patch.object(route, '_validated_config',
                               side_effect=capture) as bound:
            entry, config = self._read_pair()
        bound.assert_called_once_with(entry, self.MODEL,
                                      self._canonical(self.native))
        self.assertIs(entry, captured['entry'])
        self.assertIs(config, captured['config'])
        self.assertIsNot(entry, self.entry)

        with mock.patch.object(route, '_validated_config',
                               side_effect=capture) as bound:
            public = self._read_public()
        bound.assert_called_once()
        self.assertIs(public, captured['entry'])

    def test_single_full_binding_and_single_hash_per_bound_object(self):
        real_hash = route._hash_path
        counts = {}

        def counting(path, *args, **kwargs):
            key = self._canonical(path)
            counts[key] = counts.get(key, 0) + 1
            return real_hash(path, *args, **kwargs)

        with mock.patch.object(route, '_hash_path',
                               side_effect=counting), \
                mock.patch.object(route, 'read_config',
                                  wraps=route.read_config) as read, \
                mock.patch.object(route, '_validated_config',
                                  wraps=route._validated_config) as bound:
            entry = self._read_public()
        self.assertEqual(entry, self.entry)
        bound.assert_called_once()
        read.assert_called_once()
        expected = {self._canonical(self.binary),
                    self._canonical(self.python)}
        expected.update(self._canonical(self.pkg / relative)
                        for relative in route.SOURCE_FILES)
        self.assertEqual(set(counts), expected)
        self.assertTrue(all(count == 1 for count in counts.values()))

    def test_tampered_or_missing_bound_objects_refuse_public(self):
        original_config = self.config_path.read_bytes()
        self.config_path.write_bytes(b'{"schema":"x"}')
        os.chmod(self.config_path, 0o600)
        self.assert_unmeasured(self._read_public)
        self.config_path.write_bytes(original_config)
        os.chmod(self.config_path, 0o600)
        self.assertEqual(self._read_public(), self.entry)

        self.config_path.unlink()
        self.assert_unmeasured(self._read_public)
        self.config_path.write_bytes(original_config)
        os.chmod(self.config_path, 0o600)

        original_binary = self.binary.read_bytes()
        self.binary.write_bytes(original_binary + b'drift')
        os.chmod(self.binary, 0o755)
        self.assert_unmeasured(self._read_public)
        self.binary.write_bytes(original_binary)
        os.chmod(self.binary, 0o755)

        source = self.pkg / route.SOURCE_FILES[0]
        original_source = source.read_bytes()
        source.write_bytes(original_source + b'drift')
        self.assert_unmeasured(self._read_public)
        source.unlink()
        self.assert_unmeasured(self._read_public)
        source.write_bytes(original_source)
        self.assertEqual(self._read_public(), self.entry)

    def test_wrong_key_model_cwd_and_entry_state_refuse(self):
        other_cwd = self.base / 'other-cwd'
        other_cwd.mkdir()
        os.chmod(other_cwd, 0o700)
        cases = [
            dict(key='claude/' + self.MODEL),
            dict(key='codex/gpt-4.1'),
            dict(key=7),
            dict(key=None),
            dict(model='gpt-4.1'),
            dict(model='not-a-model'),
            dict(model=5),
            dict(cwd=os.fspath(other_cwd)),
            dict(cwd=self._canonical(self.native) + '/.'),
            dict(cwd=17),
            dict(state=os.fspath(self.config_path)),
        ]
        for over in cases:
            with self.subTest(over=over):
                self.assert_unmeasured(
                    lambda over=over: self._read_public(**over))

        unavailable = dict(self.entry)
        unavailable['available'] = False
        unavailable['probes'] = []
        self._refresh(unavailable)
        self._use_entry(unavailable)
        self.assert_unmeasured(self._read_public)

        self._use_entry('not an entry')
        self.assert_unmeasured(self._read_public)

        registry = dict(self.registry_obj)
        registry['measurements'] = {'codex/gpt-4.1': dict(self.entry)}
        self._write_registry(registry)
        self.assert_unmeasured(self._read_public)
        self._write_registry(self.registry_obj)

    def test_config_location_refusals_precede_config_open(self):
        outside_dir = self.base / 'outside'
        outside_dir.mkdir()
        os.chmod(outside_dir, 0o700)
        outside_config = outside_dir / 'binding.json'
        outside_config.write_bytes(self.config_bytes)
        os.chmod(outside_config, 0o600)
        trapped = self.codex_dir / 'trapped.json'

        real_open = os.open
        opened = []

        def tracking(path, flags, *args, **kwargs):
            opened.append(os.fspath(path))
            return real_open(path, flags, *args, **kwargs)

        with mock.patch.object(route.os, 'open', side_effect=tracking):
            entry = dict(self.entry)
            entry['config'] = self._canonical(outside_config)
            self._refresh(entry)
            self._use_entry(entry)
            self.assert_unmeasured(self._read_public)
            self.assertNotIn(os.fspath(outside_config), opened)

            opened.clear()
            entry = dict(self.entry)
            entry['config'] = self._canonical(self.registry_path)
            self._refresh(entry)
            self._use_entry(entry)
            self.assert_unmeasured(self._read_public)
            self.assertEqual(
                opened.count(os.fspath(self.registry_path)), 1)

            opened.clear()
            entry = dict(self.entry)
            entry['config'] = self._canonical(trapped)
            self._refresh(entry)
            self._use_entry(entry)
            self.assert_unmeasured(self._read_public)
            self.assertNotIn(os.fspath(trapped), opened)
        self._write_registry(self.registry_obj)

    def test_registry_root_shape_and_strict_json(self):
        base = dict(self.registry_obj)
        variants = []
        missing = dict(base)
        missing.pop('candidates')
        variants.append(missing)
        extra = dict(base)
        extra['extra'] = None
        variants.append(extra)
        for field, value in (
                ('schema', 7), ('schema', 'co.routes/1'),
                ('created', True), ('created', 'now'),
                ('cwd', 3), ('cwd', self._canonical(self.base)),
                ('measurements', []), ('candidates', {})):
            variant = dict(base)
            variant[field] = value
            variants.append(variant)
        for obj in variants:
            with self.subTest(variant=repr(obj)[:80]):
                self._write_registry(obj)
                self.assert_unmeasured(self._read_public)
        self._write_registry(base)

        raw = self._dump(base)
        duplicate = raw.replace(b'"candidates":[]',
                                b'"candidates":[],"candidates":[]', 1)
        for blob in (duplicate, raw + b'{}', raw + b' trailing',
                     b'\xff\xfe', b'\xef\xbb\xbf' + raw,
                     b'```json\n' + raw + b'\n```', raw[:-1]):
            with self.subTest(blob=blob[:24]):
                self._write_registry(blob)
                self.assert_unmeasured(self._read_public)
        self._write_registry(base)

        loose = dict(base)
        loose['candidates'] = [{'arbitrary': {'nested': [1, None]}}]
        loose['measurements'] = dict(base['measurements'])
        loose['measurements']['unrelated'] = {'not': 'an entry'}
        self._write_registry(loose)
        self.assertEqual(self._read_public(), self.entry)

    def test_state_dir_requirements_and_codex_home_boundary(self):
        absent = self.base / 'absent-state'
        self.assert_unmeasured(
            lambda: self._read_public(state=os.fspath(absent)))
        self.assertFalse(os.path.lexists(absent))

        os.chmod(self.state, 0o755)
        self.assert_unmeasured(self._read_public)
        os.chmod(self.state, 0o700)

        linked = self.base / 'state-link'
        os.symlink(self.state, linked)
        self.assert_unmeasured(
            lambda: self._read_public(state=os.fspath(linked)))

        regular = self.base / 'state-file'
        regular.write_bytes(b'x')
        self.assert_unmeasured(
            lambda: self._read_public(state=os.fspath(regular)))

        inner_state = self.codex_dir / 'inner-state'
        inner_state.mkdir()
        os.chmod(inner_state, 0o700)
        inner_cwd = self.codex_dir / 'inner-cwd'
        inner_cwd.mkdir()
        os.chmod(inner_cwd, 0o700)

        real_open = os.open
        opened = []

        def tracking(path, flags, *args, **kwargs):
            opened.append(os.fspath(path))
            return real_open(path, flags, *args, **kwargs)

        with mock.patch.object(route.os, 'open', side_effect=tracking):
            self.assert_unmeasured(
                lambda: self._read_public(state=os.fspath(inner_state)))
            self.assert_unmeasured(
                lambda: self._read_public(cwd=os.fspath(inner_cwd)))
            for changes in ({'HOME': self.home + '-wrong'},
                            {'CODEX_HOME': os.fspath(self.base)}):
                with self.subTest(changes=changes), \
                        mock.patch.dict(os.environ, changes):
                    self.assert_unmeasured(self._read_public)
        self.assertEqual(opened, [])

    def test_registry_metadata_and_content_refusals(self):
        copy_path = self.base / 'registry-copy.json'
        copy_path.write_bytes(self.registry_bytes)
        os.chmod(copy_path, 0o600)

        self.registry_path.unlink()
        os.symlink(copy_path, self.registry_path)
        with mock.patch.object(route.os, 'open') as opened:
            self.assert_unmeasured(self._read_public)
            opened.assert_not_called()

        self.registry_path.unlink()
        os.mkfifo(self.registry_path, 0o600)
        with mock.patch.object(route.os, 'open') as opened:
            self.assert_unmeasured(self._read_public)
            opened.assert_not_called()
        self.registry_path.unlink()
        self._write_registry(self.registry_obj)

        extra_link = self.base / 'registry-hardlink'
        os.link(self.registry_path, extra_link)
        with mock.patch.object(route.os, 'read') as read:
            self.assert_unmeasured(self._read_public)
            read.assert_not_called()
        extra_link.unlink()

        self.registry_path.unlink()
        os.link(self.auth, self.registry_path)
        with mock.patch.object(route.os, 'open') as opened:
            self.assert_unmeasured(self._read_public)
            opened.assert_not_called()
        self.registry_path.unlink()
        self._write_registry(self.registry_obj)

        for mode in (0o644, 0o400):
            with self.subTest(mode=oct(mode)):
                os.chmod(self.registry_path, mode)
                with mock.patch.object(route.os, 'read') as read:
                    self.assert_unmeasured(self._read_public)
                    read.assert_not_called()
        os.chmod(self.registry_path, 0o600)

        with mock.patch.object(route.os, 'fstat',
                               side_effect=self._fake_fstat(
                                   st_uid=os.geteuid() + 1)), \
                mock.patch.object(route.os, 'read') as read:
            self.assert_unmeasured(self._read_public)
            read.assert_not_called()

        with self.registry_path.open('wb') as handle:
            handle.truncate(route._MAX_REGISTRY_BYTES + 1)
        os.chmod(self.registry_path, 0o600)
        with mock.patch.object(route.os, 'read') as read:
            self.assert_unmeasured(self._read_public)
            read.assert_not_called()
        self._write_registry(self.registry_obj)

        real_size = os.lstat(self.registry_path).st_size
        for delta in (-1, 8):
            with self.subTest(delta=delta), \
                    mock.patch.object(route.os, 'fstat',
                                      side_effect=self._fake_fstat(
                                          st_size=real_size + delta)):
                self.assert_unmeasured(self._read_public)

    def test_auth_identity_races_missing_auth_and_interrupts(self):
        registry_stat = os.stat(self.registry_path)
        registry_identity = (registry_stat.st_dev, registry_stat.st_ino)

        with mock.patch.object(route, '_current_auth_identity',
                               side_effect=[registry_identity]), \
                mock.patch.object(route.os, 'open') as opened:
            self.assert_unmeasured(self._read_public)
            opened.assert_not_called()

        with mock.patch.object(route, '_current_auth_identity',
                               side_effect=[None, registry_identity]), \
                mock.patch.object(route.os, 'read') as read:
            self.assert_unmeasured(self._read_public)
            read.assert_not_called()

        for exc in (KeyboardInterrupt('stop'), SystemExit(5)):
            with self.subTest(error=type(exc).__name__), \
                    mock.patch.object(route, '_current_auth_identity',
                                      side_effect=exc):
                with self.assertRaises(type(exc)) as raised:
                    self._read_public()
            self.assertIs(raised.exception, exc)

        with mock.patch.object(route, '_current_auth_identity',
                               return_value=None):
            os.chmod(self.registry_path, 0o644)
            self.assert_unmeasured(self._read_public)
            os.chmod(self.registry_path, 0o600)
            self.assertEqual(self._read_public(), self.entry)

        self.auth.unlink()
        self.assertIsNone(route._current_auth_identity(self.home))
        self.assert_unmeasured(self._read_public)

    def test_auth_bytes_never_opened_and_registry_closes_first(self):
        real_open = os.open
        real_close = os.close
        events = []

        def tracking_open(path, flags, *args, **kwargs):
            fd = real_open(path, flags, *args, **kwargs)
            events.append(('open', fd, self._canonical(path)))
            return fd

        def tracking_close(fd):
            events.append(('close', fd, ''))
            return real_close(fd)

        with mock.patch.object(route.os, 'open',
                               side_effect=tracking_open), \
                mock.patch.object(route.os, 'close',
                                  side_effect=tracking_close), \
                mock.patch.object(subprocess, 'Popen',
                                  side_effect=AssertionError) as popen:
            entry = self._read_public()
        self.assertEqual(entry, self.entry)
        popen.assert_not_called()
        auth = self._canonical(self.auth)
        self.assertFalse(any(path == auth
                             for kind, fd, path in events
                             if kind == 'open'))
        reg_fd = conf_fd = None
        for kind, fd, path in events:
            if kind != 'open':
                continue
            if path == self._canonical(self.registry_path):
                reg_fd = fd
            if path == self._canonical(self.config_path):
                conf_fd = fd
        self.assertIsNotNone(reg_fd)
        self.assertIsNotNone(conf_fd)
        reg_close = events.index(('close', reg_fd, ''))
        conf_open = events.index(('open', conf_fd,
                                  self._canonical(self.config_path)))
        self.assertLess(reg_close, conf_open)


if __name__ == '__main__':
    unittest.main()
