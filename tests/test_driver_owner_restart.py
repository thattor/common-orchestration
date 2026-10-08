"""#190 M3: owner SIGKILL + new-process reopen; lost child stays held.

Worker one (a subprocess this test fully owns) builds the real
DriverPoolFixture root itself — ServiceOwner lock, real ControlStore /
Controller / PooledAdapter on the canonical CapacityLedger — dispatches the
request-bound child, commits the bound 'failed'/'cessation_unconfirmed'
projection plus the stop barrier, then reports pid/argv-marker/AttemptRef/
lock-inode and waits. The parent verifies exact ps identity (pid + lstart
birth + argv marker) before SIGKILL. A DIFFERENT subprocess then reacquires
the same root with a fresh pool (the retained child is lost): across >=3
driver ticks the Attempt stays internally held, the failed row is
byte-identical, attempt/execute counts are unchanged, the physical ledger
holds 1, and no Result/AC/output is fabricated.

Not covered here — the mandatory follow-up chunks still owed:
- same ORIGINAL Native handle reattach (PooledAdapter.reattach) delivering a
  late genuine CONFIRMED Result across this owner kill;
- retry-admission race against the still-held lease after restart.
"""
import json
import os
import platform
import select
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from co_v4 import contracts as c
from co_v4.adapter_capacity import CapacityLedger
from co_v4.catalog import Catalog, CatalogEntry, Verification
from co_v4.controller import JobPlan
from co_v4.output_store import OutputStore
from co_v4.service_owner import OwnerUnavailable, ServiceOwner
from co_v4.state import IngressReceipt, body_digest, create_run_body
import test_service_driver_pool as fix
from test_service_driver_pool import DriverPoolFixture

QUALIFIED = platform.system() == 'Darwin' and platform.machine() == 'arm64'
TESTS = Path(__file__).resolve().parent


def worker_one(root_s, report_s, marker):
    """Own the fixture root, commit the bound decision, report, then wait
    for SIGKILL. No cleanup: this models the owner dying mid-hold."""
    fx = DriverPoolFixture(Path(root_s))
    (queued,) = fx.driver.start()
    assert (queued.status, queued.decided) == ('queued', False)
    ref = fx.dispatch()
    (decided,) = fx.driver.tick()
    assert (decided.status, decided.code, decided.decided) == (
        'failed', 'cessation_unconfirmed', True)
    assert fx.run().stop_requested
    assert fx.state.stop_origin(fx.run_id) == 'projection_decided'
    assert len(fx.child_calls) == 1
    assert fx.ledger.count(fix.ADAPTER) == 1
    Path(report_s).write_text(json.dumps({
        'pid': os.getpid(), 'marker': marker,
        'lock_ino': os.lstat(fx.owner.lock_path).st_ino,
        'ref': [ref.run_id, ref.job_id, ref.attempt_id],
        'row': list(fx.projection_row()),
        'executes': len(fx.child_calls)}))
    print('READY', flush=True)
    sys.stdin.read()


def _open_existing(root):
    """Attach-only reopen: no mkdir, no create_run, no key/profile/gateway
    seed writes. Reuses the fixture's own guarded open/bind/pool methods and
    rebuilds only the immutable plan/catalog inputs."""
    fx = DriverPoolFixture.__new__(DriverPoolFixture)
    fx.root = root
    fx.owner = ServiceOwner.acquire(root)
    fx.receipts, fx.child_calls, fx.children = {}, [], {}
    fx._open()
    fx.output_store = OutputStore(root / 'outputs')
    fx.owner.bind_stores(fx.store, fx.output_store)   # guarded bind pre-tick
    fx.ledger = CapacityLedger(root / 'capacity.sqlite')
    fx.pool = fx._new_pool()                          # fresh pool: child lost
    fx.catalog = Catalog((CatalogEntry(fix.MODEL, fix.ADAPTER, {fix.USE: 2},
        (Verification(fix.MODEL, fix.ADAPTER, fix.USE, fix.ENV,
                      'fixture:official', 'fixture:implementation',
                      'fixture:measurement', 'fixture:ac',
                      output_mode='collect'),)),))
    fx.plan = JobPlan(
        c.Job(fix.RUN_ID, 'job', 'produce the fixture output',
              ('exact content checked',)),
        c.Action('fixture.write', c.Scope(
            (('repository', 'fixture/co'), ('path', '/fixture')), True)),
        'write-output', fix.USE,
        (c.ExecutionConditions(fix.MODEL, fix.ADAPTER, '/fixture', fix.ENV,
                               ('fixture:controls',)),))
    fx.run_id, fx.response_id = fix.RUN_ID, 'resp_fixture'
    fx.receipts['origin'] = IngressReceipt(
        'fixture-principal', 'origin',
        body_digest(create_run_body(fix.RUN_ID, fix.INTENT)), fix.NOW)
    return fx


def worker_two(root_s, prior_s, report_s, marker):
    """Different process, same root: prove the lost child is held, never
    fabricated, never re-executed."""
    prior = json.loads(Path(prior_s).read_text())
    fx = _open_existing(Path(root_s))
    try:
        assert os.lstat(fx.owner.lock_path).st_ino == prior['lock_ino']
        ref = c.AttemptRef(*prior['ref'])
        assert fx.attempt().ref == ref
        view = fx.build_controller().step()       # real Controller recovery
        assert view.state == c.State.RUNNING
        assert not fx.child_calls and not fx.children
        assert fx.ingress_claims() == 1             # no new create-run claim
        row = fx.projection_row()
        assert list(row) == prior['row']          # byte-identical decision
        for _ in range(3):
            (held,) = fx.driver.tick()
            assert (held.status, held.code, held.decided) == (
                'failed', 'cessation_unconfirmed', True)
            run = fx.run()
            assert run.state == c.State.RUNNING and run.stop_requested
            attempt = fx.attempt()
            assert attempt.ref == ref and attempt.result is None
            assert attempt.ac is None and attempt.output is None
            assert attempt.collection_failure is None
            assert len(fx.state.attempts(fx.run_id)) == 1
            assert fx.ledger.count(fix.ADAPTER) == 1
            assert fx.projection_row() == row
            assert not fx.child_calls and not fx.children
        assert prior['executes'] == 1             # one execute, ever
        assert fx.state.history(fx.run_id, 'ac_history') == ()
        assert fx.state.history(fx.run_id, 'driver_audit') == ()
        for sub in ('blobs', 'manifests'):
            assert list((fx.output_store.root / sub).iterdir()) == []
        Path(report_s).write_text(json.dumps({'ok': True}))
        print('READY', flush=True)
        sys.stdin.read()
    finally:
        fx.store.close()
        fx.owner.close()


def _ps(pid):
    """(lstart, state, argv) for pid, or None — same shape as owner tests."""
    try:
        out = subprocess.run(
            ['ps', '-ww', '-o', 'lstart=', '-o', 'stat=', '-o',
             'command=', '-p', str(pid)],
            capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    line = out.stdout.rstrip('\n')
    if out.returncode != 0 or not line.strip():
        return None
    rest = line[24:].split(None, 1)
    return (line[:24].strip(), rest[0] if rest else '',
            rest[1] if len(rest) > 1 else '')


def _guarded_kill(pid, marker, birth):
    """SIGKILL only a pid whose ps birth+argv marker still match. Never a
    broad scan, never an unverified pid."""
    if not pid or not marker or not birth:
        return
    snap = _ps(pid)
    if snap is None or snap[0] != birth or marker not in snap[2]:
        return
    if not snap[1].startswith('Z'):
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def _boot(fn):
    return ('import sys;sys.path[:0]=%r;'
            'import test_driver_owner_restart as m;m.%s(*sys.argv[1:])'
            % ([str(TESTS), str(TESTS.parent)], fn))


class DriverOwnerRestartTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name).resolve()

    def _launch(self, fn, *args):
        marker = 'co04-rst-%d-%d' % (os.getpid(), time.monotonic_ns())
        argv = [sys.executable, '-c', _boot(fn),
                *(str(a) for a in args), marker]
        proc = subprocess.Popen(argv, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
        return proc, marker

    def _ready(self, proc, marker):
        """Bounded READY handshake; then the exec'd marked argv must be
        visible in ps — the worker's reported pid is our child's pid."""
        if (not select.select([proc.stdout], [], [], 90)[0]
                or proc.stdout.readline() != 'READY\n'):
            proc.kill()
            proc.wait(30)
            self.fail('worker never ready: %r'
                      % proc.stderr.read()[:2000])
        deadline = time.monotonic() + 15
        while True:
            snap = _ps(proc.pid)
            if (snap is not None and marker in snap[2]
                    and not snap[1].startswith('Z')):
                return snap[0]                    # verified lstart birth
            self.assertLess(time.monotonic(), deadline,
                            'marked worker argv never appeared: %r' % (snap,))
            time.sleep(0.05)

    def test_owner_kill_new_process_lost_child_stays_held(self):
        root = self.dir / 'root'
        if not QUALIFIED:
            root.mkdir(mode=0o700)
            with self.assertRaises(OwnerUnavailable) as ei:
                ServiceOwner.acquire(root)
            self.assertEqual(ei.exception.code, 'unsupported_platform')
            return
        prior_f, done_f = self.dir / 'w1.json', self.dir / 'w2.json'
        proc1 = proc2 = None
        m1 = b1 = m2 = b2 = None
        try:
            proc1, m1 = self._launch('worker_one', root, prior_f)
            b1 = self._ready(proc1, m1)
            prior = json.loads(prior_f.read_text())
            self.assertEqual(prior['pid'], proc1.pid)
            self.assertEqual(prior['marker'], m1)
            self.assertEqual(prior['executes'], 1)
            ino = os.lstat(root / 'service.lock').st_ino
            self.assertEqual(ino, prior['lock_ino'])
            # Re-verify exact identity immediately before SIGKILL.
            snap = _ps(proc1.pid)
            self.assertIsNotNone(snap)
            self.assertEqual(snap[0], b1)
            self.assertIn(m1, snap[2])
            self.assertFalse(snap[1].startswith('Z'))
            os.kill(proc1.pid, signal.SIGKILL)
            proc1.wait(30)
            self.assertEqual(proc1.returncode, -signal.SIGKILL)
            # No inherited lock fd anywhere: the fresh owner below acquires,
            # and the lock file inode never changes.
            self.assertEqual(
                os.lstat(root / 'service.lock').st_ino, ino)
            proc2, m2 = self._launch('worker_two', root, prior_f, done_f)
            b2 = self._ready(proc2, m2)
            proc2.stdin.close()
            proc2.wait(60)
            self.assertEqual(proc2.returncode, 0,
                             proc2.stderr.read()[:2000])
            self.assertEqual(json.loads(done_f.read_text()), {'ok': True})
            self.assertEqual(
                os.lstat(root / 'service.lock').st_ino, ino)
        finally:
            for proc, m, b in ((proc1, m1, b1), (proc2, m2, b2)):
                if proc is None:
                    continue
                if proc.poll() is None:
                    _guarded_kill(proc.pid, m, b)
                    if proc.poll() is None:
                        proc.kill()              # our own unreaped child
                    proc.wait(30)
                for stream in (proc.stdin, proc.stdout, proc.stderr):
                    try:
                        stream.close()
                    except OSError:
                        pass


if __name__ == '__main__':
    unittest.main()
