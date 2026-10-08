"""tests/test_launch_record_build.py — REAL build_launch_record path.

Exercises the actual record builder end-to-end: real file_descriptor
before-identities on owned 0600 files inside a canonical 0700 dir, the
real post-spawn lstat re-checks, the real closed-argv allowlist and the
emitted canonical bytes reparsed by the real load_launch_record. Only
the kernel read seam (read_process) is injected — a typed
ProcessIdentity fixture: never a real provider, never a kernel claim,
never a placeholder dict where a FileDescriptor belongs.
"""
import os
import stat
import tempfile
import unittest
from pathlib import Path

from co_v4.launch_attestation import (LaunchRecordError,
                                      RouteUnqualified,
                                      build_launch_record,
                                      file_descriptor,
                                      load_launch_record)
from co_v4.process_identity import ProcessIdentity

ENDPOINT = 'http://127.0.0.1:8000/v1'
ALIAS = 'co04-qwen3-06b'
SHA = 'a' * 64


def _argv(exe, model, tmpl, cred):
    return (exe, '-m', model, '--chat-template-file', tmpl,
            '--api-key-file', cred, '--host', '127.0.0.1',
            '--port', '8000', '--alias', ALIAS, '--threads', '2',
            '--parallel', '1', '--device', 'none', '--n-gpu-layers',
            '0', '--reasoning', 'off', '--reasoning-budget', '0',
            '--temp', '0',
            '--no-webui', '--no-ui-mcp-proxy')


class _Proc:
    """Bare owned-handle stand-in: only .pid is read."""
    def __init__(self, pid):
        self.pid = pid


class BuildLaunchRecordTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        os.chmod(tmp.name, 0o700)
        root = Path(tmp.name).resolve()          # canonical realpath
        self.paths = {'executable': str(root / 'exe'),
                      'model': str(root / 'm.gguf'),
                      'template': str(root / 't.jinja'),
                      'credential': str(root / 'k')}
        for path in self.paths.values():
            Path(path).write_bytes(b'x')
            os.chmod(path, 0o600)
        self.argv = _argv(self.paths['executable'], self.paths['model'],
                          self.paths['template'],
                          self.paths['credential'])
        self.before = {k: file_descriptor(v)
                       for k, v in self.paths.items()
                       if k != 'credential'}
        self.pid = 4242

    def _ident(self, **kw):
        base = dict(pid=self.pid, uid=os.getuid(), start_sec=10,
                    start_usec=20,
                    executable=self.paths['executable'],
                    argv=tuple(self.argv))
        base.update(kw)
        return ProcessIdentity(**base)

    def _reader(self, ident=None, exc=None):
        def reader(pid, uid):
            if exc is not None:
                raise exc
            return ident if ident is not None else self._ident()
        return reader

    def _build(self, **over):
        kw = dict(proc=self.pid, before=self.before, argv=self.argv,
                  manifest_sha256=SHA, endpoint=ENDPOINT,
                  credential_ref='ref',
                  credential_file=self.paths['credential'],
                  model_id=ALIAS, threads=2, slots=1,
                  read_process=self._reader())
        kw.update(over)
        return build_launch_record(**kw)

    def test_valid_record_bytes_persist_0600_and_reparse(self):
        data = self._build(proc=_Proc(self.pid))   # .pid form accepted
        self.assertIs(type(data), bytes)
        path = str(Path(self.paths['credential']).parent
                   / 'launch.json')
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as handle:
            handle.write(data)
        st = os.lstat(path)
        self.assertEqual((stat.S_IMODE(st.st_mode), st.st_nlink,
                          st.st_uid), (0o600, 1, os.getuid()))
        rec = load_launch_record(path)
        self.assertEqual((rec.manifest_sha256, rec.pid, rec.uid,
                          rec.start_time, rec.argv, rec.endpoint,
                          rec.credential_ref),
                         (SHA, self.pid, os.getuid(), (10, 20),
                          self.argv, ENDPOINT, 'ref'))
        for name in ('executable', 'model', 'template'):
            self.assertEqual(getattr(rec, name), self.before[name])

        # The builder records the kernel-reported birth verbatim; there
        # is no prior timestamp to compare, only the emitted schema.
        data = self._build(read_process=self._reader(
            self._ident(start_sec=9, start_usec=7)))
        path2 = str(Path(self.paths['credential']).parent
                    / 'launch2.json')
        fd = os.open(path2, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as handle:
            handle.write(data)
        self.assertEqual(load_launch_record(path2).start_time, (9, 7))

    def test_file_replacement_and_deletion_refused(self):
        for name in ('executable', 'model', 'template'):
            for kind in ('replace', 'delete'):
                with self.subTest(name=name, kind=kind):
                    self.setUp()                 # fresh owned fixture
                    path = self.paths[name]
                    if kind == 'replace':
                        st = os.stat(path)
                        new = path + '.new'
                        Path(new).write_bytes(b'x')
                        os.utime(new, ns=(st.st_atime_ns,
                                          st.st_mtime_ns))
                        os.replace(new, path)    # new inode, same stat
                        self.assertNotEqual(os.stat(path).st_ino,
                                            st.st_ino)
                    else:
                        os.remove(path)
                    with self.assertRaises(LaunchRecordError) as ctx:
                        self._build()
                    self.assertEqual(ctx.exception.code,
                                     'file changed during launch')

    def test_kernel_identity_and_reader_failures(self):
        for ident in ({'pid': self.pid + 1}, {'uid': os.getuid() + 1},
                      {'argv': tuple(self.argv) + ('--timeout', '5')}):
            with self.subTest(ident=ident):
                with self.assertRaises(LaunchRecordError) as ctx:
                    self._build(read_process=self._reader(
                        self._ident(**ident)))
                self.assertEqual(ctx.exception.code,
                                 'process identity mismatch')
        other = str(Path(self.paths['credential']).parent / 'exe2')
        Path(other).write_bytes(b'x')
        with self.assertRaises(LaunchRecordError) as ctx:
            self._build(read_process=self._reader(
                self._ident(executable=other)))
        self.assertEqual(ctx.exception.code, 'executable path mismatch')
        for exc in (OSError('x'), ValueError('x'), RuntimeError('x')):
            with self.assertRaises(LaunchRecordError) as ctx:
                self._build(read_process=self._reader(exc=exc))
            self.assertEqual(ctx.exception.code,
                             'process identity failed')
        with self.assertRaises(LaunchRecordError) as ctx:
            self._build(read_process=lambda pid, uid: None)
        self.assertEqual(ctx.exception.code, 'process identity mismatch')

    def test_descriptor_and_argument_refusals(self):
        for name in ('executable', 'model', 'template'):
            with self.subTest(missing=name):
                before = {k: v for k, v in self.before.items()
                          if k != name}
                with self.assertRaises(LaunchRecordError) as ctx:
                    self._build(before=before)
                self.assertEqual(ctx.exception.code,
                                 'descriptor missing')
        for before in ('x', {'executable': {'path': self.paths[
                               'executable']},
                             'model': None, 'template': None}):
            with self.assertRaises(LaunchRecordError) as ctx:
                self._build(before=before)
            self.assertEqual(ctx.exception.code, 'descriptor missing')
        for kw in ({'proc': 0}, {'proc': '4242'},
                   {'credential_file': 'relative/key'},
                   {'argv': self.argv + (1,)}, {'read_process': None}):
            with self.subTest(kw=list(kw)):
                with self.assertRaises(LaunchRecordError) as ctx:
                    self._build(**kw)
                self.assertEqual(ctx.exception.code,
                                 'launch arguments invalid')

    def test_closed_argv_endpoint_and_digest_inside_build(self):
        for extra in (('--embedding',), ('--timeout=5',)):
            bad = tuple(self.argv) + extra
            with self.subTest(extra=extra):
                with self.assertRaises(LaunchRecordError) as ctx:
                    self._build(argv=bad, read_process=self._reader(
                        self._ident(argv=bad)))
                self.assertEqual(ctx.exception.code,
                                 'argv flag invalid')
        with self.assertRaises(LaunchRecordError) as ctx:
            self._build(endpoint='http://10.0.0.1:8000/v1')
        self.assertEqual(ctx.exception.code, 'endpoint invalid')
        for digest in ('x', 'g' * 64):
            with self.assertRaises(RouteUnqualified) as ctx:
                self._build(manifest_sha256=digest)
            self.assertEqual(ctx.exception.code,
                             'record fields invalid')
        # An out-of-range reported birth is not rejected as a mismatch —
        # it is emitted, then refused by the closed record schema.
        for over in ({'start_sec': -1}, {'start_usec': 1000000}):
            with self.subTest(over=over):
                with self.assertRaises(RouteUnqualified) as ctx:
                    self._build(read_process=self._reader(
                        self._ident(**over)))
                self.assertEqual(ctx.exception.code,
                                 'record fields invalid')


    def test_temp_flag_required_exact_token_zero(self):
        self.assertIs(type(self._build()), bytes)  # '--temp','0' pinned
        i = self.argv.index('--temp')
        missing = self.argv[:i] + self.argv[i + 2:]
        with self.assertRaises(LaunchRecordError) as ctx:
            self._build(argv=missing, read_process=self._reader(
                self._ident(argv=missing)))
        self.assertEqual(ctx.exception.code,
                         'argv required flag missing')
        for val in ('0.0', '00', '-0', '0.1', '1'):
            bad = self.argv[:i + 1] + (val,) + self.argv[i + 2:]
            with self.subTest(val=val):
                with self.assertRaises(LaunchRecordError) as ctx:
                    self._build(argv=bad, read_process=self._reader(
                        self._ident(argv=bad)))
                self.assertEqual(ctx.exception.code, 'temp flag invalid')
        for extra in (('--temperature', '0'), ('--temp=0',),
                      ('--seed', '42'), ('--temp', '0')):
            bad = self.argv + extra
            with self.subTest(extra=extra):
                with self.assertRaises(LaunchRecordError) as ctx:
                    self._build(argv=bad, read_process=self._reader(
                        self._ident(argv=bad)))
                self.assertEqual(ctx.exception.code, 'argv flag invalid')
        # A flag token as the value is refused by the arity scan.
        bad = self.argv[:i + 1] + ('--host',) + self.argv[i + 2:]
        with self.assertRaises(LaunchRecordError) as ctx:
            self._build(argv=bad, read_process=self._reader(
                self._ident(argv=bad)))
        self.assertEqual(ctx.exception.code, 'argv flag invalid')

if __name__ == '__main__':
    unittest.main()
