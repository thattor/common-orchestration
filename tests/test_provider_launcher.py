"""provider_launcher: env={} contract, helper env count, order, cleanup.

Honest seams only: autospec mocks of the shared attestation APIs prove
call order and refusal — NOT provider qualification, no kernel claim.
The env-count helper is an owned non-platform binary compiled here; it
prints only the integer count of its own environment entries, never
names or values.
"""
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import co_v4.provider_launcher as pl

HELPER_C = (b'#include <stdio.h>\nextern char **environ;\n'
            b'int main(void){int n=0;while(environ[n])n++;'
            b'printf("%d\\n",n);return 0;}\n')
STDIO = dict(stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
             stderr=subprocess.DEVNULL)


class FakeProc:
    def __init__(self):
        self.pid, self.calls, self.alive = 4242, [], True
    def poll(self):
        return None if self.alive else 0
    def terminate(self):
        self.calls.append('terminate'); self.alive = False
    def kill(self):
        self.calls.append('kill'); self.alive = False
    def wait(self, timeout=None):
        self.calls.append('wait'); return 0


class SpawnContractTests(unittest.TestCase):
    def test_boundary_env_shell_argv_constants(self):
        orig = pl._popen
        self.addCleanup(setattr, pl, '_popen', orig)
        seen = []
        pl._popen = lambda argv, **kw: (seen.append((list(argv), kw)),
                                        FakeProc())[1]
        pl.spawn_owned(['/usr/bin/x', '--ok'], **STDIO)
        (argv, kw), = seen
        self.assertEqual((argv, kw['env'], kw['shell'],
                          kw['stdin'], kw['stdout'], kw['stderr']),
                         (['/usr/bin/x', '--ok'], {}, False,
                          subprocess.DEVNULL, subprocess.PIPE,
                          subprocess.DEVNULL))
        self.assertIsNot(kw['env'], os.environ)

    def test_mutated_boundary_variants_fail_the_contract(self):
        # Mocked seam only; nothing spawns and no ambient mapping is
        # read, copied, iterated or compared — identity assertions only.
        orig = pl._popen
        self.addCleanup(setattr, pl, '_popen', orig)
        for bad in (None, os.environ, {'PATH': '/usr/bin'}):
            with self.subTest(bad=type(bad).__name__):
                captured = []
                pl._popen = lambda argv, env=None, **kw: (
                    captured.append(env), FakeProc())[1]

                def mutated(argv, _b=bad, **kw):
                    return pl._popen(list(argv), env=_b, shell=False, **kw)
                mutated(['/usr/bin/x'], **STDIO)
                (env,) = captured
                if bad is os.environ:
                    self.assertIs(env, os.environ)
                    self.assertIsNot(env, None)
                elif bad is None:
                    self.assertIsNone(env)
                else:
                    self.assertEqual(env, {'PATH': '/usr/bin'})
                # Contract predicate; the type() short-circuit never
                # evaluates == on the ambient mapping.
                self.assertFalse(type(env) is dict and env == {})


class EnvCountTests(unittest.TestCase):
    def _compile(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name).resolve()      # canonical, no /private alias
        src, dst = root / 'c.c', root / 'envcount'
        src.write_bytes(HELPER_C)
        subprocess.run(['/usr/bin/cc', '-o', str(dst), str(src)],
                       check=True, capture_output=True, timeout=30)
        return str(dst)

    def _count(self, helper):
        proc = pl.spawn_owned([helper], **STDIO)
        try:
            out, _unused = proc.communicate(timeout=5)
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except Exception:
                    proc.kill()
                    proc.wait(timeout=5)
            if proc.stdout is not None:
                proc.stdout.close()
        return int(out.strip())

    def test_empty_env_zero_and_fresh_path_injection_detected(self):
        helper = self._compile()
        # If the platform injects anything into env={}, that is the real
        # result and this assertion must fail — never adapted.
        self.assertEqual(self._count(helper), 0)
        orig = pl._popen
        self.addCleanup(setattr, pl, '_popen', orig)
        pl._popen = lambda argv, env=None, **kw: orig(
            argv, env={'PATH': '/usr/bin'}, **kw)
        self.assertEqual(self._count(helper), 1)   # exactly detected


class CredentialTests(unittest.TestCase):
    def test_fresh_credential_exact_ascii_0600_no_newline(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        os.chmod(tmp.name, 0o700)
        root = Path(tmp.name).resolve()
        for length in (32, 512):
            path = root / ('key%d' % length)
            self.assertIsNone(pl.provision_credential(str(path),
                                                      length=length))
            blob = path.read_bytes()       # own fresh test file only
            self.assertEqual(len(blob), length)
            self.assertTrue(all(0x21 <= b <= 0x7E for b in blob))
            self.assertNotIn(b'\n', blob)
            st = os.lstat(path)
            self.assertEqual((stat.S_IMODE(st.st_mode), st.st_nlink),
                             (0o600, 1))
        with self.assertRaises(pl.LauncherRejected) as ctx:
            pl.provision_credential(str(root / 'key32'))
        self.assertEqual(ctx.exception.code, 'credential_refused')


class LaunchFlowTests(unittest.TestCase):
    RECORD = b'{"schema":"co.provider-launch/1"}'

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        os.chmod(tmp.name, 0o700)
        self.dir = Path(tmp.name).resolve()
        self.calls = []
        self.proc = FakeProc()
        patchers = [
            mock.patch.object(pl, 'validate_launch_argv', autospec=True),
            mock.patch.object(pl, 'file_descriptor', autospec=True),
            mock.patch.object(pl, 'build_launch_record', autospec=True),
            mock.patch.object(pl, 'read_owned_process', autospec=True),
            mock.patch.object(pl, 'spawn_owned', autospec=True)]
        self.argv_v, self.fd, self.bld, self.reader, self.spawn = (
            p.start() for p in patchers)
        for patcher in patchers:
            self.addCleanup(patcher.stop)
        self.argv_v.side_effect = lambda **kw: self.calls.append('argv')
        self.fd.side_effect = lambda path: (
            self.calls.append('fd'), ('d', path))[1]
        self.bld.side_effect = self._record
        self.spawn.side_effect = lambda argv, **kw: (
            self.calls.append('spawn'), self.proc)[1]

    def _record(self, **kw):
        self.calls.append('record')
        return self.RECORD

    def launch(self, ready=lambda p: True, record_path=None,
               proc=None):
        if proc is not None:
            self.proc = proc
        return pl.launch_provider(
            argv=('/usr/bin/x', '--model', '/m', '--chat-template-file',
                  '/t', '--api-key-file', str(self.dir / 'key')),
            executable_path='/usr/bin/x', model_path='/m',
            template_path='/t', credential_file=str(self.dir / 'key'),
            manifest_sha256='a' * 64, endpoint='http://127.0.0.1:1/v1',
            credential_ref='ref', model_id='m1', threads=4, slots=2,
            host='127.0.0.1', port=1, ready=ready,
            record_path=record_path or str(self.dir / 'launch.json'))

    def test_order_kwargs_and_owned_0600_record(self):
        result = self.launch(
            ready=lambda p: self.calls.append('ready') or True)
        self.assertEqual(self.calls, ['argv', 'fd', 'fd', 'fd', 'spawn',
                                      'ready', 'record'])
        self.argv_v.assert_called_once()
        self.assertEqual(set(self.argv_v.call_args.kwargs),
                         {'argv', 'executable_path', 'model_path',
                          'template_path', 'credential_file', 'model_id',
                          'threads', 'slots', 'host', 'port'})
        kw = self.bld.call_args.kwargs
        self.assertIs(kw['proc'], self.proc)
        self.assertIs(kw['read_process'], self.reader)
        self.assertEqual(kw['argv'][0], '/usr/bin/x')
        self.assertIs(result.process, self.proc)
        st = os.lstat(result.record_path)
        self.assertEqual((stat.S_IMODE(st.st_mode), st.st_uid,
                          st.st_nlink), (0o600, os.getuid(), 1))
        self.assertEqual(Path(result.record_path).read_bytes(),
                         self.RECORD)

    def test_existing_target_and_bad_dir_refused_before_spawn(self):
        target = self.dir / 'launch.json'
        target.write_bytes(b'{}')
        with self.assertRaises(pl.LauncherRejected) as ctx:
            self.launch(record_path=str(target))
        self.assertEqual(ctx.exception.code, 'target_refused')
        self.assertEqual(self.calls, ['argv'])
        target.unlink()
        os.chmod(self.dir, 0o755)
        self.addCleanup(os.chmod, self.dir, 0o700)
        with self.assertRaises(pl.LauncherRejected) as ctx:
            self.launch()
        self.assertEqual(ctx.exception.code, 'target_refused')
        self.assertNotIn('spawn', self.calls)

    def test_failures_clean_only_the_fresh_own_child(self):
        for name, ready, builder in (
                ('ready_failed', lambda p: False, self._record),
                ('ready_failed', lambda p: 1, self._record),   # truthy != True
                ('record_failed', lambda p: True, lambda **kw: 1 / 0)):
            with self.subTest(name=name):
                self.calls.clear()
                proc = FakeProc()                    # fresh owned handle
                self.bld.side_effect = builder
                with self.assertRaises(pl.LauncherRejected) as ctx:
                    self.launch(ready=ready, proc=proc)
                self.assertEqual(ctx.exception.code, name)
                self.assertEqual(proc.calls, ['terminate', 'wait', 'wait'])
                self.assertFalse((self.dir / 'launch.json').exists())
                self.bld.side_effect = self._record

    def test_unconfirmed_stop_retains_handle_without_ended_claim(self):
        proc = FakeProc()
        def hang(timeout=None):
            proc.calls.append('wait')
            raise subprocess.TimeoutExpired('x', 5)
        proc.wait = hang
        with self.assertRaises(pl.LauncherRejected) as ctx:
            self.launch(ready=lambda p: False, proc=proc)
        self.assertEqual(ctx.exception.code, 'cleanup_failed')
        self.assertIs(ctx.exception.child, proc)      # retained, not claimed
        self.assertFalse((self.dir / 'launch.json').exists())


if __name__ == '__main__':
    unittest.main()


class RecordCompletionTests(unittest.TestCase):
    """record_owned_launch: post-capture completion only — the caller
    owns spawn, readiness, captures and manifest verification."""
    RECORD = b'{"schema":"co.provider-launch/1"}'

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        os.chmod(tmp.name, 0o700)
        self.dir = Path(tmp.name).resolve()
        self.proc = FakeProc()
        patchers = [
            mock.patch.object(pl, 'build_launch_record', autospec=True),
            mock.patch.object(pl, 'read_owned_process', autospec=True),
            mock.patch.object(pl, 'spawn_owned', autospec=True)]
        self.bld, self.reader, self.spawn = (p.start() for p in patchers)
        for patcher in patchers:
            self.addCleanup(patcher.stop)
        self.bld.return_value = self.RECORD
        self.before = {'executable': ('d', '/usr/bin/x'),
                       'model': ('d', '/m'), 'template': ('d', '/t')}

    def complete(self, proc=None, record_path=None, **kw):
        args = dict(proc=self.proc if proc is None else proc,
            before=self.before, argv=('/usr/bin/x', '-m', '/m'),
            manifest_sha256='a' * 64,
            endpoint='http://127.0.0.1:1/v1', credential_ref='ref',
            credential_file=str(self.dir / 'key'), model_id='m1',
            threads=4, slots=2,
            record_path=record_path or str(self.dir / 'launch.json'))
        args.update(kw)
        return pl.record_owned_launch(**args)

    def test_keyword_build_atomic_publish_no_spawn(self):
        result = self.complete()
        kw = self.bld.call_args.kwargs
        self.assertIs(kw['proc'], self.proc)
        self.assertIs(kw['read_process'], self.reader)
        self.assertEqual(kw['before'], self.before)
        self.assertEqual(kw['argv'], ('/usr/bin/x', '-m', '/m'))
        self.spawn.assert_not_called()          # never spawns
        self.assertIs(result.process, self.proc)
        self.assertEqual(self.proc.calls, [])   # live child untouched
        st = os.lstat(result.record_path)
        self.assertEqual((stat.S_IMODE(st.st_mode), st.st_nlink),
                         (0o600, 1))
        self.assertEqual(Path(result.record_path).read_bytes(),
                         self.RECORD)

    def test_existing_target_refused_before_build_child_cleaned(self):
        target = self.dir / 'launch.json'
        target.write_bytes(b'{}')
        with self.assertRaises(pl.LauncherRejected) as ctx:
            self.complete(record_path=str(target))
        self.assertEqual(ctx.exception.code, 'target_refused')
        self.bld.assert_not_called()
        self.assertEqual(self.proc.calls, ['terminate', 'wait', 'wait'])
        self.assertEqual(target.read_bytes(), b'{}')   # never overwritten

    def test_build_failure_and_bad_args_clean_only_own_child(self):
        self.bld.side_effect = lambda **kw: 1 / 0
        with self.assertRaises(pl.LauncherRejected) as ctx:
            self.complete()
        self.assertEqual(ctx.exception.code, 'record_failed')
        self.assertEqual(self.proc.calls, ['terminate', 'wait', 'wait'])
        self.assertFalse((self.dir / 'launch.json').exists())
        proc = FakeProc()
        self.bld.return_value = self.RECORD
        self.bld.side_effect = None
        with self.assertRaises(pl.LauncherRejected) as ctx:
            self.complete(proc=proc, manifest_sha256=None)
        self.assertEqual(ctx.exception.code, 'argv_invalid')
        self.assertEqual(proc.calls, ['terminate', 'wait', 'wait'])

    def test_unconfirmed_cleanup_retains_handle(self):
        def hang(timeout=None):
            raise subprocess.TimeoutExpired('x', 5)
        self.proc.wait = hang
        # Force the record stage to fail first: without this the mock
        # returns bytes, the publish succeeds, and cleanup never runs.
        self.bld.side_effect = RuntimeError('fixture record failed')
        with self.assertRaises(pl.LauncherRejected) as ctx:
            self.complete()
        self.assertEqual(ctx.exception.code, 'cleanup_failed')
        self.assertIs(ctx.exception.child, self.proc)
        self.assertFalse((self.dir / 'launch.json').exists())
