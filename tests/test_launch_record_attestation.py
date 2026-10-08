"""Record/kernel/descriptor discriminator tests for LaunchAttestor.

Reuses the BodyBindingTests fixture (its 4 binding tests re-run here by
inheritance — intentional). These pin that the real protected record
file, its closed schema, the recorded-PID-only kernel read and the
identity-before-hash descriptor path each fail closed. Process identity
is stubbed or fault-injected; no provider is launched, no kernel proof
is claimed."""
import hashlib
import os
import unittest
from dataclasses import asdict
from unittest import mock

from co_v4.launch_attestation import (LaunchAttestor, RouteUnqualified,
                                      load_launch_record)
from co_v4.process_identity import (ProcessIdentity,
                                    ProcessIdentityRejected)
from co_v4.protocol_profile import canonical

try:
    from tests.test_launch_body_binding import (AUTH, ENDPOINT, UID,
                                                BodyBindingTests)
except ImportError:
    from test_launch_body_binding import (AUTH, ENDPOINT, UID,
                                          BodyBindingTests)


class RecordAndDiscriminatorTests(BodyBindingTests):
    def _rec(self, **over):
        rec = {'schema': 'co.provider-launch/1',
               'manifest_sha256': self.sha, 'pid': os.getpid(),
               'start_time': {'sec': 1, 'usec': 2}, 'uid': UID,
               'executable': asdict(self.descs['executable']),
               'argv': self.argv, 'model': asdict(self.descs['model']),
               'template': asdict(self.descs['template']),
               'endpoint': ENDPOINT, 'credential_ref': AUTH}
        rec.update(over)
        return rec

    def _write(self, rec):
        fd = os.open(self.record_path,
                     os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'wb') as f:
            f.write(canonical(rec))

    def _rebind(self, body):
        sha = hashlib.sha256(canonical(body)).hexdigest()
        self._write(self._rec(manifest_sha256=sha))
        return sha

    def _ident(self, **kw):
        base = dict(pid=os.getpid(), uid=UID, start_sec=1, start_usec=2,
                    executable=self.exe, argv=tuple(self.argv))
        base.update(kw)
        return ProcessIdentity(**base)

    def _counting(self, ident=None, exc=None):
        calls = []
        def reader(pid, uid, start_time):
            calls.append(pid)
            if exc is not None:
                raise exc
            return self._ident(**(ident or {}))
        return reader, calls

    def _gate(self, reader=None):
        return LaunchAttestor(self.record_path, self.cred,
                              read_process=reader or self._reader)

    def test_record_schema_and_field_types(self):
        good = self._rec()
        cases = [
            dict(good, schema='other/1'),
            {k: v for k, v in good.items() if k != 'argv'},
            dict(good, extra='x'),
            dict(good, pid='1'), dict(good, pid=0), dict(good, pid=-1),
            dict(good, pid=True),
            dict(good, uid='0'), dict(good, uid=True),
            dict(good, start_time={'sec': 1}),
            dict(good, start_time={'sec': 1, 'usec': 1000000}),
            dict(good, argv=[]), dict(good, argv=['x', 1]),
            dict(good, endpoint=None), dict(good, credential_ref=''),
            dict(good, manifest_sha256='0' * 63),
            dict(good, model=dict(asdict(self.descs['model']),
                                  mtime_ns=-1)),
        ]
        reader, calls = self._counting()
        for rec in cases:
            with self.subTest(case=repr(rec)[:40]):
                self._write(rec)
                with self.assertRaises(RouteUnqualified):
                    self._gate(reader)(dict(self.body), ENDPOINT, AUTH)
                self.assertEqual(calls, [])
        self._write(good)
        self.assertIs(self._gate()(dict(self.body), ENDPOINT, AUTH),
                      True)

    def test_record_file_protections_before_reader(self):
        reader, calls = self._counting()
        att = self._gate(reader)
        os.chmod(self.record_path, 0o644)
        with self.assertRaises(RouteUnqualified):
            att(dict(self.body), ENDPOINT, AUTH)
        os.chmod(self.record_path, 0o600)
        os.link(self.record_path, self.record_path + '.2')
        with self.assertRaises(RouteUnqualified):
            att(dict(self.body), ENDPOINT, AUTH)
        os.unlink(self.record_path + '.2')
        os.rename(self.record_path, self.record_path + '.bak')
        os.symlink(self.record_path + '.bak', self.record_path)
        with self.assertRaises(RouteUnqualified):
            att(dict(self.body), ENDPOINT, AUTH)
        self.assertEqual(calls, [])
        # Wrong-uid record refused before any kernel read of the PID.
        os.remove(self.record_path)
        self._write(self._rec(uid=UID + 1))
        with self.assertRaises(RouteUnqualified):
            att(dict(self.body), ENDPOINT, AUTH)
        self.assertEqual(calls, [])
        self._write(self._rec())
        self.assertIs(att(dict(self.body), ENDPOINT, AUTH), True)

    def test_kernel_identity_discriminators(self):
        for kw in ({'pid': os.getpid() + 1}, {'uid': UID + 1},
                   {'start_sec': 9}, {'start_usec': 7},
                   {'executable': '/other/exe'}, {'argv': ('x',)},
                   {'argv': tuple(self.argv) + ('--timeout', '5')}):
            with self.subTest(kw=kw):
                reader, calls = self._counting(ident=kw)
                with self.assertRaises(RouteUnqualified):
                    self._gate(reader)(dict(self.body), ENDPOINT, AUTH)
                self.assertEqual(calls, [os.getpid()])
        for exc in (ProcessIdentityRejected('dead'),
                    ProcessIdentityRejected('mismatch'),
                    OSError('x'), ValueError('x')):
            reader, calls = self._counting(exc=exc)
            with self.assertRaises(RouteUnqualified):
                self._gate(reader)(dict(self.body), ENDPOINT, AUTH)
            self.assertEqual(calls, [os.getpid()])
        for wrong in (None, 'x', {'pid': 1}):
            reader = lambda pid, uid, st, w=wrong: w
            with self.assertRaises(RouteUnqualified):
                self._gate(reader)(dict(self.body), ENDPOINT, AUTH)
        self.assertIs(self._gate()(dict(self.body), ENDPOINT, AUTH),
                      True)

    def test_inode_replacement_refused_before_hash_read(self):
        for name, data in (('model', b'y'), ('template', b'z'),
                           ('executable', b'x')):
            with self.subTest(name=name):
                self.setUp()              # fresh isolated fixture
                att = self._gate()
                self.assertIs(att(dict(self.body), ENDPOINT, AUTH),
                              True)
                self.assertTrue(att._cache)      # hash cache primed
                path = {'model': self.model, 'template': self.tmpl,
                        'executable': self.exe}[name]
                st = os.stat(path)
                repl = path + '.new'
                with open(repl, 'wb') as f:
                    f.write(data)
                os.utime(repl, ns=(st.st_atime_ns, st.st_mtime_ns))
                os.replace(repl, path)
                new = os.stat(path)
                self.assertEqual((new.st_size, new.st_mtime_ns),
                                 (st.st_size, st.st_mtime_ns))
                self.assertNotEqual(new.st_ino, st.st_ino)
                opened = []
                real_open = os.open
                def spy(p, *a, **k):
                    opened.append(p)
                    return real_open(p, *a, **k)
                with mock.patch('co_v4.launch_attestation.os.open',
                                spy):
                    with self.assertRaises(RouteUnqualified):
                        att(dict(self.body), ENDPOINT, AUTH)
                self.assertNotIn(path, opened)   # never reached hashing

    def test_corrupted_bytes_and_manifest_hash_bindings(self):
        st = os.stat(self.model)
        with open(self.model, 'r+b') as f:
            f.write(b'Y')                         # same size/ino
        os.utime(self.model, ns=(st.st_atime_ns, st.st_mtime_ns))
        self.assertEqual(os.stat(self.model).st_ino, st.st_ino)
        with self.assertRaises(RouteUnqualified):  # digest mismatch
            self._gate()(dict(self.body), ENDPOINT, AUTH)
        with open(self.model, 'r+b') as f:         # restore bytes+mtime
            f.write(b'y')
        os.utime(self.model, ns=(st.st_atime_ns, st.st_mtime_ns))
        self.assertIs(self._gate()(dict(self.body), ENDPOINT, AUTH),
                      True)                          # baseline valid
        body = dict(self.body, model_sha256='0' * 64)
        self._rebind(body)
        with self.assertRaises(RouteUnqualified):
            self._gate()(body, ENDPOINT, AUTH)
        self._write(self._rec())                     # restore record sha
        self.assertIs(self._gate()(dict(self.body), ENDPOINT, AUTH),
                      True)
        body = dict(self.body, launch=dict(
            self.body['launch'], chat_template_sha256='0' * 64))
        self._rebind(body)
        with self.assertRaises(RouteUnqualified):
            self._gate()(body, ENDPOINT, AUTH)
        self._write(self._rec())
        self.assertIs(self._gate()(dict(self.body), ENDPOINT, AUTH),
                      True)

    def test_io_errors_normalized_and_fd_closed(self):
        opened = []
        real_open = os.open
        def spy(p, *a, **k):
            fd = real_open(p, *a, **k)
            opened.append(fd)
            return fd
        for target in ('os.fstat', 'os.read'):
            with self.subTest(target=target):
                opened.clear()
                with mock.patch('co_v4.launch_attestation.os.open',
                                spy), \
                     mock.patch('co_v4.launch_attestation.' + target,
                                side_effect=OSError('x')):
                    with self.assertRaises(RouteUnqualified):
                        load_launch_record(self.record_path)
                self.assertEqual(len(opened), 1)
                with self.assertRaises(OSError):   # EBADF => closed
                    os.fstat(opened[0])

    def test_fifo_record_does_not_block(self):
        os.remove(self.record_path)
        os.mkfifo(self.record_path, 0o600)
        flags, fds = [], []
        real_open = os.open
        def spy(p, *a, **k):
            flags.append(a[0])
            fds.append(real_open(p, *a, **k))
            return fds[-1]
        with mock.patch('co_v4.launch_attestation.os.open', spy):
            with self.assertRaises(RouteUnqualified):
                load_launch_record(self.record_path)
        self.assertEqual(len(flags), 1)
        self.assertTrue(flags[0] & os.O_NONBLOCK)
        with self.assertRaises(OSError):           # EBADF => closed
            os.fstat(fds[0])

    def test_gate_callback_receives_sealed_body(self):
        from co_v4.protocol_profile import (environment_ref,
            issue_profile, verify_manifest)
        from co_v4.qualified_route import QualifiedRouteGate
        try:
            from tests.test_qualified_route import (BLOBS,
                manifest as qmanifest, request)
        except ImportError:
            from test_qualified_route import (BLOBS,
                manifest as qmanifest, request)
        m = qmanifest(
            model_sha256=self.descs['model'].sha256,
            launch={'argv': list(self.argv),
                'chat_template_sha256': self.descs['template'].sha256,
                'slots': 1, 'threads': 2, 'bind': '127.0.0.1:8000'},
            auth={'mode': 'api_key_file', 'credential_ref': AUTH})
        prof = issue_profile(
            verify_manifest(m, BLOBS.__getitem__), 'responses',
            index_mode='absent_single_part', sequence_mode='absent',
            inert_fields={'response.completed': ('timings',)})
        self._write(self._rec(
            manifest_sha256=m['manifest_sha256']))
        seen = []
        def att(fields, endpoint, auth_ref):
            seen.append(dict(fields))
            return self.attest(fields, endpoint, auth_ref)
        gate = QualifiedRouteGate(
            read_evidence=BLOBS.__getitem__,
            probe_identity=lambda: {'model': 'co04-qwen3-06b'},
            launch_attested=att)
        env = environment_ref(ENDPOINT, AUTH, prof.profile_digest)
        binding = gate.qualify(profile=prof, manifest=m,
            endpoint=ENDPOINT, auth_ref=AUTH, request=request(env))
        self.assertEqual(binding.manifest_sha256,
                         m['manifest_sha256'])
        self.assertEqual(len(seen), 1)
        self.assertNotIn('manifest_sha256', seen[0])
        self.assertEqual(hashlib.sha256(canonical(seen[0])).hexdigest(),
                         m['manifest_sha256'])


if __name__ == '__main__':
    unittest.main()
