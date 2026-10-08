"""process_identity: owned-PID kernel attestation, real + injected faults.

The real-backend case uses one owned fresh Popen child with a public
argv and minimal env; negatives use a narrow fake backend and prove the
argv read is never reached on a pid/uid/birth mismatch.
"""
import os
import select
import subprocess
import unittest

from co_v4.process_identity import (_Fail, ProcessIdentity,
    ProcessIdentityRejected, read_owned_process)

READY_ARG = 'READY'
UID = None                       # bound in setUpModule


def _reap(proc):
    for pipe in (proc.stdin, proc.stdout):
        if pipe is None:
            continue
        try:
            pipe.close()
        except OSError:
            pass
    if proc.poll() is None:
        proc.kill()
    proc.wait()


def spawn():
    # Apple's yes rewrites argv's terminating NUL, which can splice
    # environment bytes into the kernel-reported argv.
    proc = subprocess.Popen(['/bin/cat', '-u'],
                            env={'PATH': '/usr/bin:/bin'},
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE)
    try:
        expected = READY_ARG.encode() + b'\n'
        proc.stdin.write(expected)
        proc.stdin.flush()
        ready, _, _ = select.select([proc.stdout], [], [], 5.0)
        if not ready or proc.stdout.readline() != expected:
            raise AssertionError('owned child did not reach READY')
    except Exception:
        _reap(proc)
        raise
    return proc


def args_blob(argv, path=b'/bin/ls', argc=None,
              env=b'SECRET_ENV=never-decoded\0'):
    body = (len(argv) if argc is None else argc).to_bytes(
        4, 'little', signed=True) + path + b'\0\0'
    for token in argv:
        body += token + b'\0'
    return body + env                   # tail never read


class FakeBackend:
    """Narrow kernel double; call counts prove refusal order."""
    def __init__(self, info=None, path=b'/bin/ls', blob=None):
        # None binds the caller uid by default; explicit info overrides.
        self.info = ((123, os.getuid(), 100, 5) if info is None else info)
        self.queue = []
        self.path = path
        self.blob = (args_blob([b'/bin/ls']) if blob is None else blob)
        self.bsd_calls = self.path_calls = self.args_calls = 0

    def bsd_info(self, pid):
        self.bsd_calls += 1
        info = self.queue.pop(0) if self.queue else self.info
        if isinstance(info, Exception):
            raise info
        return info

    def pid_path(self, pid):
        self.path_calls += 1
        if isinstance(self.path, Exception):
            raise self.path
        return self.path

    def proc_args(self, pid):
        self.args_calls += 1
        if isinstance(self.blob, Exception):
            raise self.blob
        return self.blob


def setUpModule():
    global UID
    UID = os.getuid()


class ValidationTests(unittest.TestCase):
    def test_argument_validation_never_touches_kernel(self):
        fake = FakeBackend()
        cases = [(True, 'bool'), ('x', 'invalid_pid'), (0, 'invalid_pid'),
                 (-3, 'invalid_pid'), (1.5, 'nonfinite'),
                 (2 ** 31, 'invalid_pid')]      # beyond c_int domain
        for pid, reason in cases:
            with self.subTest(pid=pid):
                with self.assertRaises(ProcessIdentityRejected) as ctx:
                    read_owned_process(pid, UID, backend=fake)
                self.assertEqual(ctx.exception.reason, reason)
        self.assertEqual(fake.bsd_calls, 0)
        with self.assertRaises(ProcessIdentityRejected) as ctx:
            read_owned_process(123, UID + 1, backend=fake)
        self.assertEqual(ctx.exception.reason, 'invalid_uid')
        self.assertEqual(fake.bsd_calls, 0)
        for start, reason in ((('a', 0), 'invalid_start'),
                              ((1.0, 0), 'nonfinite'),
                              ((1,), 'invalid_start'),
                              ((-1, 0), 'invalid_start'),
                              ((100, 10 ** 6), 'invalid_start')):
            with self.subTest(start=start):
                with self.assertRaises(ProcessIdentityRejected) as ctx:
                    read_owned_process(123, UID, expected_start=start,
                                       backend=fake)
                self.assertEqual(ctx.exception.reason, reason)

    def test_dead_refusal(self):
        fake = FakeBackend(info=_Fail('dead'))
        with self.assertRaises(ProcessIdentityRejected) as ctx:
            read_owned_process(123, UID, backend=fake)
        self.assertEqual(ctx.exception.reason, 'dead')
        self.assertEqual(fake.args_calls, 0)


class MismatchOrderTests(unittest.TestCase):
    def test_mismatch_refuses_before_argv(self):
        for info in ((999, UID, 100, 5),           # different pid
                     (123, UID + 1, 100, 5),        # foreign uid
                     (123, UID, 101, 5),            # birth drift
                     (123, UID, 100, 7)):           # usec drift
            with self.subTest(info=info):
                fake = FakeBackend(info=info)
                with self.assertRaises(ProcessIdentityRejected) as ctx:
                    # Recorded birth supplied: drift cases are real
                    # mismatches, not legitimate first-birth acquisition.
                    read_owned_process(123, UID,
                                       expected_start=(100, 5),
                                       backend=fake)
                self.assertEqual(ctx.exception.reason, 'mismatch')
                self.assertEqual((fake.path_calls, fake.args_calls), (0, 0))

    def test_expected_start_mismatch_refuses_early(self):
        fake = FakeBackend(info=(123, UID, 100, 5))
        with self.assertRaises(ProcessIdentityRejected) as ctx:
            read_owned_process(123, UID, expected_start=(100, 6),
                               backend=fake)
        self.assertEqual(ctx.exception.reason, 'mismatch')
        self.assertEqual((fake.path_calls, fake.args_calls), (0, 0))

    def test_pid_reuse_race_second_bsd_read(self):
        fake = FakeBackend()
        fake.queue = [(123, UID, 100, 5), (123, UID, 100, 7)]
        with self.assertRaises(ProcessIdentityRejected) as ctx:
            read_owned_process(123, UID, backend=fake)
        self.assertEqual(ctx.exception.reason, 'mismatch')
        self.assertEqual(fake.bsd_calls, 2)
        self.assertEqual(fake.args_calls, 1)   # argv read, then refused

    def test_wrong_typed_backend_data_is_mismatch(self):
        for bad in ('x', (123, UID, 100), (123, UID, 100, True),
                    (123, UID, -1, 5), (123, UID, 100, 10 ** 6)):
            with self.subTest(bad=bad):
                fake = FakeBackend(info=bad)
                with self.assertRaises(ProcessIdentityRejected) as ctx:
                    read_owned_process(123, UID, backend=fake)
                self.assertEqual(ctx.exception.reason, 'mismatch')


class DecodeTests(unittest.TestCase):
    def assert_reason(self, reason, **kw):
        with self.assertRaises(ProcessIdentityRejected) as ctx:
            read_owned_process(123, UID, backend=FakeBackend(**kw))
        self.assertEqual(ctx.exception.reason, reason)

    def test_path_failures(self):
        self.assert_reason('dead', path=_Fail('dead'))
        self.assert_reason('invalid_text', path=b'relative/path')
        self.assert_reason('invalid_text', path=b'/bin/\xff')

    def test_args_blob_failures(self):
        self.assert_reason('short', blob=b'')
        self.assert_reason('short', blob=b'\x01\x00')
        self.assert_reason('truncated', blob=b'x' * (1024 * 1024 + 1))
        self.assert_reason('invalid_args', blob=args_blob([], argc=0))
        self.assert_reason('invalid_args',
                           blob=args_blob([b'/bin/ls'], argc=5000))
        self.assert_reason('unterminated',        # argv[0] NUL removed,
                           blob=args_blob([b'/bin/ls'], env=b'')[:-1])
        self.assert_reason('unterminated', blob=b'\x01\x00\x00\x00no-nul')
        self.assert_reason('invalid_text', blob=args_blob([b'\xff']))

    def test_wrong_typed_backend_bytes_reject_closed(self):
        for kw, reason in (({'path': '/bin/ls'}, 'invalid_text'),
                           ({'blob': 'text'}, 'invalid_args')):
            with self.subTest(**kw):
                with self.assertRaises(ProcessIdentityRejected) as ctx:
                    read_owned_process(123, UID,
                                       backend=FakeBackend(**kw))
                self.assertEqual(ctx.exception.reason, reason)

    def test_happy_decode_ignores_environment(self):
        ident = read_owned_process(123, UID, backend=FakeBackend(
            blob=args_blob([b'/bin/ls', b'-l', b'/tmp'])))
        self.assertEqual(ident.argv, ('/bin/ls', '-l', '/tmp'))
        self.assertNotIn('SECRET_ENV', repr(ident))

    def test_invalid_env_tail_never_decoded(self):
        # Environment tail is byte-invalid AND truncated; still ignored.
        ident = read_owned_process(123, UID, backend=FakeBackend(
            blob=args_blob([b'/bin/ls'], env=b'\xff\xfe-truncated')))
        self.assertEqual(ident.argv, ('/bin/ls',))


class RealKernelTests(unittest.TestCase):
    def test_owned_child_identity_birth_and_dead_pid(self):
        proc = spawn()
        try:
            ident = read_owned_process(proc.pid, UID)
            self.assertIs(type(ident), ProcessIdentity)
            self.assertEqual((ident.pid, ident.uid), (proc.pid, UID))
            self.assertGreater(ident.start_sec, 0)
            self.assertTrue(0 <= ident.start_usec < 1_000_000)
            self.assertEqual(ident.executable,
                             os.path.realpath('/bin/cat'))
            self.assertEqual(ident.argv, ('/bin/cat', '-u'))
            # Recorded-birth path: identical identity, exact start match.
            again = read_owned_process(
                proc.pid, UID,
                expected_start=(ident.start_sec, ident.start_usec))
            self.assertEqual(again, ident)
        finally:
            _reap(proc)
        with self.assertRaises(ProcessIdentityRejected) as ctx:
            read_owned_process(proc.pid, UID)
        self.assertIn(ctx.exception.reason, ('dead', 'mismatch'))


if __name__ == '__main__':
    unittest.main()
