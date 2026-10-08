"""#190 M3 host_config Phase A: closed schema, protected fds, canonical paths.

Fresh files in a resolved-owned tempdir only; no existing secret is read
and no token bytes are echoed (subtests label by index). JSON mutation
cases use compact serialization and assert each pattern occurs exactly
once before replacement -- a silent no-op negative is impossible.
"""
import dataclasses
import errno
import json
import os
from pathlib import Path
import secrets
import tempfile
import unittest
from unittest import mock

import co_v4.host_config as hc
from co_v4.host_config import (CredentialSupplier, HostConfigInvalid,
                               load_host_config)
from co_v4.openai_transport import Deadlines


class LoadTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name).resolve()     # canonical /private/...
        self.state = self.dir / 'state'
        self.state.mkdir(mode=0o700)
        self.files = {}
        for name in ('principals', 'registry', 'cred', 'manifest',
                     'launch'):
            p = self.dir / name
            p.write_bytes(b'x')
            p.chmod(0o600)
            self.files[name] = str(p)
        self.path = self.dir / 'host.json'

    def route(self, **kw):
        r = {'model': 'm', 'adapter': 'openai.responses',
             'endpoint': 'http://127.0.0.1:8081/v1', 'auth_ref': 'cred-a',
             'credential_file': self.files['cred'],
             'manifest_file': self.files['manifest'],
             'launch_record': self.files['launch'],
             'profile': {'protocol': 'responses', 'index_mode': 'present',
                         'sequence_mode': 'present', 'inert_fields': {}},
             'profile_digest': 'sha256:' + 'a' * 64,
             'environment_ref': 'env:sha256:' + 'b' * 64,
             'store_param': 'send_false',
             'deadlines': {'connect_s': 5, 'first_byte_s': 10,
                           'idle_s': 30, 'total_s': 60},
             'max_drain_s': 20,
             'verification': {'use_case': 'general', 'official_ref': 'r:o',
                 'implementation_ref': 'r:i', 'measurement_ref': 'r:m',
                 'ac_ref': 'r:a', 'output_mode': 'collect'}}
        r.update(kw)
        return r

    def doc(self, **kw):
        d = {'schema': 'co.service-host/1', 'state_root': str(self.state),
             'ledger_path': str(self.dir / 'capacity.sqlite'),
             'bind': {'host': '127.0.0.1', 'port': 8080},
             'principals_file': self.files['principals'],
             'registry_file': self.files['registry'],
             'max_body_bytes': 65536, 'sync_wait_s': 10,
             'routes': [self.route()]}
        d.update(kw)
        return d

    def raw(self, doc=None):
        return json.dumps(self.doc() if doc is None else doc,
                          separators=(',', ':')).encode()

    def mutate(self, blob, old, new):
        """Exactly-one pattern replacement; a missing pattern fails now."""
        self.assertEqual(blob.count(old), 1)
        out = blob.replace(old, new)
        self.assertNotEqual(out, blob)
        return out

    def write(self, content, mode=0o600, name='host.json'):
        path = self.dir / name
        path.write_bytes(content if type(content) is bytes
                         else self.raw(content))
        path.chmod(mode)
        return path

    def good(self, doc=None):
        return load_host_config(str(self.write(
            self.raw() if doc is None else doc)))

    def bad(self, doc=None, path=None):
        with self.assertRaises(HostConfigInvalid) as e:
            load_host_config(path if path is not None
                             else str(self.write(doc)))
        self.assertEqual(str(e.exception), 'host_config_invalid')

    def test_valid_typed_load(self):
        cfg = self.good()
        self.assertEqual(cfg.state_root, str(self.state))
        self.assertEqual(cfg.ledger_path,
                         str(self.dir / 'capacity.sqlite'))
        self.assertEqual((cfg.bind_host, cfg.bind_port),
                         ('127.0.0.1', 8080))
        self.assertEqual((cfg.max_body_bytes, cfg.sync_wait_s),
                         (65536, 10))
        self.assertEqual((cfg.principals_file, cfg.registry_file),
                         (self.files['principals'], self.files['registry']))
        r = cfg.routes[0]
        self.assertEqual((r.model, r.adapter, r.endpoint, r.auth_ref),
                         ('m', 'openai.responses',
                          'http://127.0.0.1:8081/v1', 'cred-a'))
        self.assertEqual(r.profile_digest, 'sha256:' + 'a' * 64)
        self.assertEqual(r.environment_ref, 'env:sha256:' + 'b' * 64)
        self.assertEqual(r.deadlines,
            Deadlines(connect=5, first_byte=10, idle=30, total=60))
        self.assertEqual((r.max_drain_s, r.store_param), (20, 'send_false'))
        self.assertEqual(r.profile.protocol, 'responses')
        self.assertEqual(r.profile.inert_fields, ())
        self.assertEqual(r.verification,
                         ('general', 'r:o', 'r:i', 'r:m', 'r:a'))
        self.assertIsInstance(cfg.routes, tuple)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            cfg.bind_port = 1

    def test_phase_a_opens_only_config_file(self):
        opened, real = [], os.open
        def spy(*a, **kw):
            opened.append(a)
            return real(*a, **kw)
        with mock.patch.object(hc.os, 'open', spy):
            self.good()
        self.assertEqual([a[0] for a in opened], [str(self.path)])
        flags = opened[0][1]
        self.assertTrue(flags & os.O_NONBLOCK)
        self.assertTrue(flags & os.O_NOFOLLOW)

    def test_config_path_and_fd_protections(self):
        self.write(self.raw())
        self.bad(path='host.json')                      # relative
        self.bad(path=self.path)                        # Path, not str
        self.bad(path=str(self.dir / 'missing.json'))
        self.bad(path=str(self.dir))                    # directory
        self.bad(path=str(self.path) + '\x00')          # NUL
        # Direct FIFO path: refused by canonical lstat, open never runs.
        fifo = self.dir / 'fifo.json'
        os.mkfifo(fifo)
        with mock.patch.object(hc.os, 'open',
                               side_effect=AssertionError('opened')):
            self.bad(path=str(fifo))
        self.write(self.raw(), mode=0o644)
        self.bad(path=str(self.path))
        os.chmod(self.path, 0o600)
        os.link(self.path, self.dir / 'hard.json')
        self.bad(path=str(self.dir / 'hard.json'))
        os.unlink(self.dir / 'hard.json')               # restore nlink 1
        link = self.dir / 'link.json'
        os.symlink(self.path, link)
        self.bad(path=str(link))
        with mock.patch.object(hc.os, 'getuid',
                               return_value=os.getuid() + 1) as fake_uid:
            self.bad(path=str(self.path))
        fake_uid.assert_called()
        with mock.patch.object(hc.os, 'open', side_effect=OSError) as fo:
            self.bad(path=str(self.path))
        fo.assert_called()

    def test_open_race_fifo_nonblocking_fd_closed(self):
        """Regular at lstat, FIFO at open: O_NONBLOCK keeps the seam
        non-hanging, fstat refuses the FIFO, and the fd is closed."""
        self.write(self.raw())
        calls, real = [], os.open

        def spy(path, flags, *a, **kw):
            os.unlink(path)
            os.mkfifo(path)
            fd = real(path, flags, *a, **kw)
            calls.append((path, flags, fd))
            return fd

        with mock.patch.object(hc.os, 'open', spy):
            self.bad(path=str(self.path))
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0][1] & os.O_NONBLOCK)
        with self.assertRaises(OSError) as e:
            os.fstat(calls[0][2])
        self.assertEqual(e.exception.errno, errno.EBADF)

    def test_fstat_failure_normalized_fd_closed(self):
        self.write(self.raw())
        fds, real = [], os.open
        def spy(*a, **kw):
            fd = real(*a, **kw)
            fds.append(fd)
            return fd
        with mock.patch.object(hc.os, 'open', spy), \
                mock.patch.object(hc.os, 'fstat', side_effect=OSError):
            self.bad(path=str(self.path))
        self.assertEqual(len(fds), 1)
        with self.assertRaises(OSError) as e:
            os.fstat(fds[0])
        self.assertEqual(e.exception.errno, errno.EBADF)

    def test_strict_json_rejections(self):
        raw = self.raw()
        cases = (self.mutate(raw, b'8080', b'NaN'),
                 self.mutate(raw, b'8080', b'Infinity'),
                 self.mutate(raw, b'8080', b'8080.5'),
                 self.mutate(raw, b'8080', b'true'),
                 self.mutate(raw, b'"schema":"co.service-host/1"',
                             b'"schema":"co.service-host/1","schema":"x"'),
                 self.mutate(raw, b'"host":"127.0.0.1"',
                             b'"host":"x","host":"127.0.0.1"'),
                 self.mutate(raw, b'"model":"m"',
                             b'"model":"m","model":"m"'),
                 self.mutate(raw, b'"model":"m"',
                             b'"model":"\\ud800"'),
                 self.mutate(raw, b'"inert_fields":{}',
                             b'"inert_fields":{"\\ud800":[]}'),
                 b'\xff' + raw, b'not json', b'[1]', b'5',
                 b' ' * (hc.MAX_CONFIG_BYTES + 1))
        for i, blob in enumerate(cases):
            with self.subTest(i=i):
                self.bad(path=str(self.write(blob)))

    def test_top_and_nested_keys_closed(self):
        for k in self.doc():
            d = self.doc()
            del d[k]
            with self.subTest(missing=k):
                self.bad(d)
        self.bad(self.doc(extra=1))
        self.bad(self.doc(schema='co.service-host/2'))
        self.bad(self.doc(schema=5))
        self.bad(self.doc(bind={'host': '127.0.0.1'}))
        self.bad(self.doc(routes=[dict(self.route(), extra=1)]))
        self.bad(self.doc(routes=[['x']]))
        r = self.route()
        del r['verification']['ac_ref']
        self.bad(self.doc(routes=[r]))

    def test_int_bounds_bool_float_str(self):
        cases = [self.doc(bind={'host': '127.0.0.1', 'port': v})
                 for v in (True, 1.5, '8080', 0, 1023, 65536, None)]
        cases += [self.doc(max_body_bytes=v)
                  for v in (True, 0, 262145, 1.0)]
        cases += [self.doc(sync_wait_s=v) for v in (False, 0, 61)]
        for key in ('connect_s', 'first_byte_s', 'idle_s', 'total_s'):
            for v in (True, 0, 601, 2.5):
                r = self.route()
                r['deadlines'][key] = v
                cases.append(self.doc(routes=[r]))
        r = self.route()
        del r['deadlines']['idle_s']
        cases.append(self.doc(routes=[r]))
        cases.append(self.doc(routes=[self.route(max_drain_s=0)]))
        cases.append(self.doc(routes=[self.route(max_drain_s=False)]))
        for i, d in enumerate(cases):
            with self.subTest(i=i):
                self.bad(d)

    def test_bind_restrictions(self):
        for host in ('::1', 'localhost', '0.0.0.0', '127.0.0.1 ', 5):
            with self.subTest(host=host):
                self.bad(self.doc(bind={'host': host, 'port': 8080}))

    def test_endpoint_literal_loopback_only(self):
        for url in ('http://127.0.0.1:1/v1', 'http://127.0.0.1:65535/v1',
                    'http://[::1]:8080/v1'):
            cfg = self.good(self.doc(routes=[self.route(endpoint=url)]))
            self.assertEqual(cfg.routes[0].endpoint, url)
        bads = ('https://127.0.0.1:8080/v1', 'http://localhost:8080/v1',
                'http://127.0.0.1/v1', 'http://127.0.0.1:8080',
                'http://127.0.0.1:8080/v1/', 'http://127.0.0.1:8080/v2',
                'http://127.0.0.1:8080/v1?q=1', 'http://127.0.0.1:8080/v1#f',
                'http://u:p@127.0.0.1:8080/v1', 'http://[::1:8080/v1',
                'http://127.0.0.1:8080/v1\n', 'http://127.0.0.1:0/v1',
                'http://127.0.0.1:65536/v1', 'http://10.0.0.1:1/v1', 5)
        for i, url in enumerate(bads):
            with self.subTest(i=i):
                self.bad(self.doc(routes=[self.route(endpoint=url)]))

    def test_routes_closed_and_unique(self):
        self.bad(self.doc(routes=[]))
        rt = lambda i: self.route(
            environment_ref='env:sha256:' + ('%064x' % i),
            profile_digest='sha256:' + ('%064x' % i))
        self.bad(self.doc(routes=[rt(i) for i in range(65)]))
        self.bad(self.doc(routes=[self.route(), self.route()]))
        cfg = self.good(self.doc(routes=[self.route(), rt(9)]))
        self.assertEqual(len(cfg.routes), 2)

    def test_route_field_rejections(self):
        cases = [self.route(adapter='openai.other'), self.route(adapter=5),
                 self.route(model=''), self.route(model=5),
                 self.route(auth_ref=''), self.route(auth_ref='a b'),
                 self.route(profile_digest='a' * 64),
                 self.route(profile_digest='sha256:' + 'A' * 64),
                 self.route(profile_digest='sha256:' + 'a' * 63),
                 self.route(environment_ref='sha256:' + 'b' * 64),
                 self.route(environment_ref='env:sha256:' + 'B' * 64),
                 self.route(store_param='send_true'),
                 self.route(store_param=5)]
        for i, r in enumerate(cases):
            with self.subTest(i=i):
                self.bad(self.doc(routes=[r]))

    def test_profile_spec_rules(self):
        def spec(**kw):
            r = self.route()
            r['profile'].update(kw)
            return self.doc(routes=[r])
        self.bad(spec(protocol='chat'))                 # adapter mismatch
        self.bad(spec(protocol=['responses']))          # unhashable-safe
        self.bad(spec(index_mode={'x': 1}))
        self.bad(spec(index_mode='absent_single_part')) # seq still present
        self.bad(spec(inert_fields={'': ['a']}))        # empty event type
        self.bad(spec(inert_fields={'e': ['b', 'a']}))
        self.bad(spec(inert_fields={'e': ['a', 'a']}))
        self.bad(spec(inert_fields={'e': ['a'] * 17}))
        self.bad(spec(inert_fields={'e': 'x'}))
        self.bad(spec(inert_fields={'e' * 129: ['a']}))
        r = self.route()
        r['profile']['x'] = 1
        self.bad(self.doc(routes=[r]))
        r = self.route(adapter='openai.chat')
        r['profile'] = {'protocol': 'chat',
                        'index_mode': 'absent_single_part',
                        'sequence_mode': 'absent', 'inert_fields': {}}
        self.bad(self.doc(routes=[r]))
        cfg = self.good(spec(index_mode='absent_single_part',
                             sequence_mode='absent'))
        self.assertEqual(cfg.routes[0].profile.index_mode,
                         'absent_single_part')
        cfg = self.good(spec(inert_fields={'evt': ['a', 'b']}))
        self.assertEqual(cfg.routes[0].profile.inert_fields,
                         (('evt', ('a', 'b')),))

    def test_verification_closed_shape(self):
        for i, kw in enumerate(({'output_mode': 'none'},
                {'use_case': 'other'}, {'use_case': 'bogus'},
                {'use_case': 5}, {'official_ref': ''},
                {'official_ref': 'a b'}, {'ac_ref': 7})):
            r = self.route()
            r['verification'].update(kw)
            with self.subTest(i=i):
                self.bad(self.doc(routes=[r]))

    def test_path_fields(self):
        self.bad(self.doc(state_root='relative'))
        self.bad(self.doc(state_root=str(self.dir / 'missing')))
        self.bad(self.doc(state_root=self.files['cred']))    # file not dir
        self.good(self.doc(ledger_path=self.files['cred']))  # exists ok
        self.bad(self.doc(ledger_path=str(self.dir / 'x' / 'y')))
        linkdir = self.dir / 'ld'
        os.symlink(self.dir, linkdir)
        self.bad(self.doc(principals_file=str(linkdir / 'principals')))
        self.bad(self.doc(principals_file=str(self.dir / 'none')))
        self.bad(self.doc(principals_file=str(self.dir)))
        self.bad(self.doc(registry_file='registry'))
        for field in ('credential_file', 'manifest_file', 'launch_record'):
            r = self.route()
            r[field] = str(self.dir / 'missing')
            self.bad(self.doc(routes=[r]))
            r = self.route()
            r[field] = str(linkdir / field)
            self.bad(self.doc(routes=[r]))


class SupplierTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name).resolve()
        self.path = self.dir / 'cred.key'
        self.token = secrets.token_urlsafe(24)          # exactly 32 bytes
        self.path.write_bytes(self.token.encode())
        self.path.chmod(0o600)

    def bad(self, blob=None, path=None, ref='cred-a'):
        if blob is not None:
            self.path.write_bytes(blob)
            self.path.chmod(0o600)
        with self.assertRaises(HostConfigInvalid) as e:
            CredentialSupplier(path or str(self.path), ref)
        self.assertEqual(str(e.exception), 'host_config_invalid')
        self.assertNotIn(self.token, str(e.exception))

    def test_exact_bound_tokens_accepted(self):
        for i, size in enumerate((32, 512)):
            token = secrets.token_hex(size // 2)
            self.assertEqual(len(token), size)
            with self.subTest(size=i):
                self.path.write_bytes(token.encode())
                self.path.chmod(0o600)
                s = CredentialSupplier(str(self.path), 'r%d' % i)
                self.assertEqual(s(), {'Authorization': 'Bearer ' + token})
                self.assertEqual(s.credential_ref, 'r%d' % i)

    def test_fresh_dict_and_read_once(self):
        s = CredentialSupplier(str(self.path), 'cred-a')
        one, two = s(), s()
        self.assertEqual(one, {'Authorization': 'Bearer ' + self.token})
        self.assertIsNot(one, two)                      # fresh dict
        for produced in (repr(s), str(s)):
            self.assertNotIn(self.token, produced)
        self.path.write_bytes(secrets.token_urlsafe(48).encode())
        self.assertEqual(s(), one)                      # never re-read

    def test_content_rejections(self):
        tok = self.token.encode()
        for i, blob in enumerate((b'x' * 31, b'x' * 513, tok + b'\n',
                tok[:-2] + b'\r\n', tok[:5] + b' ' + tok[6:],
                tok[:5] + b'\t' + tok[6:], tok[:5] + b'\x80' + tok[6:],
                b'')):
            with self.subTest(i=i):
                self.bad(blob)

    def test_file_rejections(self):
        self.path.chmod(0o644)
        self.bad()
        self.path.chmod(0o600)
        os.link(self.path, self.dir / 'h')
        self.bad(path=str(self.dir / 'h'))
        os.unlink(self.dir / 'h')                       # restore nlink 1
        os.symlink(self.path, self.dir / 'l')
        self.bad(path=str(self.dir / 'l'))
        self.bad(path=str(self.dir / 'missing'))
        self.bad(path=str(self.dir))
        with mock.patch.object(hc.os, 'getuid',
                               return_value=os.getuid() + 1) as fake_uid:
            self.bad()
        fake_uid.assert_called()
        self.path.chmod(0o600)                          # isolated fixture
        with mock.patch.object(hc.os, 'open', side_effect=OSError) as fo:
            self.bad()
        fo.assert_called()
        self.bad(ref='')
        self.bad(ref='has space')
        self.bad(path=5)

    def test_read_failure_normalized_fd_closed(self):
        fds, real_open = [], os.open
        class Handle:
            def __init__(self, fd):
                self._fd = fd
            def __enter__(self):
                return self
            def __exit__(self, *exc):
                os.close(self._fd)
                return False
            def read(self, n):
                raise OSError('fixture')
        def open_spy(*a, **kw):
            fd = real_open(*a, **kw)
            fds.append(fd)
            return fd
        with mock.patch.object(hc.os, 'open', open_spy), \
                mock.patch.object(hc.os, 'fdopen',
                                  lambda fd, mode: Handle(fd)):
            self.bad()
        self.assertEqual(len(fds), 1)
        with self.assertRaises(OSError) as e:
            os.fstat(fds[0])
        self.assertEqual(e.exception.errno, errno.EBADF)


if __name__ == '__main__':
    unittest.main()
