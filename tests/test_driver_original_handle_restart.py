# tests/test_driver_original_handle_restart.py
"""#190 M3: owner SIGKILL, ORIGINAL Native handle reattach, held-slot race.

Three real processes, all owned and reaped by this test:

- child_server: an external child process holding the ONE original
  request-bound child object on a local control socket. It outlives the
  owner worker. It is still a synthetic contract fixture — no Native /
  Provider qualification is claimed or credited for it.
- worker_one: builds the real DriverPoolFixture root (ServiceOwner lock,
  real ControlStore / Controller / PooledAdapter on the canonical physical
  CapacityLedger), dispatches once through a ChildProxy handle to that
  original child, commits the bound 'failed'/'cessation_unconfirmed' row
  and the 'projection_decided' stop barrier, reports, then is SIGKILLed.
- worker_two: a DIFFERENT process on the same root. Its fresh pool does
  PooledAdapter.reattach() against the SAME original external handle
  (never a new execute). Until the original child issues a genuine Result
  and CONFIRMED stop, the held executing lease refuses every admission:
  12 physical slots are occupied, a fresh execute is refused by capacity,
  the original request is INVALID_STATE/'already used or rebound'. After
  the genuine evidence: FAILED/'projection_decided', byte-identical row,
  zero AC/output/selection, and admission is atomic again — with the
  original request still un-re-dispatchable.

worker_two also drives two SIMULTANEOUS cross-process admission races on
the physical ledger through poised racer subprocesses (release-byte
barrier): all contenders refuse while the original executes with the other
11 slots reserved, and exactly one contender claims the single slot the
genuine CONFIRMED release frees — losers carry NeverStarted bound to their
own exact requests and never reach a factory or Native call.

NeverStarted proofs are minted only by the real PooledAdapter on
capacity refusal — before any factory call, with no Native contact;
every execute receipt, event, Result and StopReply for the dispatched
Attempt comes from the original external child, never minted by the
host. PID birth (lstart) + argv marker handshake; guarded cleanup; no
network, products, secrets or fees.
"""
from dataclasses import replace
import json
import os
import pickle
import select
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from co_v4 import contracts as c
from co_v4.adapter_capacity import (CapacityError, CapacityLedger,
                                    PooledAdapter)
from co_v4.service_owner import OwnerUnavailable, ServiceOwner
from co_v4.state import body_digest
import test_service_driver_pool as fix
from test_adapter_capacity import Child, request as filler_request
from test_driver_owner_restart import (_guarded_kill, _open_existing, _ps,
                                       QUALIFIED)
from test_service_driver_pool import DriverPoolFixture

TESTS = Path(__file__).resolve().parent


def _send(conn, value):
    payload = pickle.dumps(value)
    conn.sendall(struct.pack('!I', len(payload)) + payload)


_MAX_FRAME = 4 << 20   # trusted-fixture frame cap; never a prod limit


def _recv(conn):
    head = b''
    while len(head) < 4:
        chunk = conn.recv(4 - len(head))
        if not chunk:
            raise RuntimeError('control channel closed')
        head += chunk
    (size,) = struct.unpack('!I', head)
    if size > _MAX_FRAME:
        raise RuntimeError('oversized control frame')
    data = b''
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            raise RuntimeError('control channel closed')
        data += chunk
    return pickle.loads(data)


def ctl(sock_s, op, *args):
    """One-shot control call to the external original child server."""
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    conn.settimeout(30)                # bounded connect/recv/shutdown
    try:
        conn.connect(sock_s)
        _send(conn, (op, args))
        tag, payload = _recv(conn)
    finally:
        conn.close()
    if tag == 'err':
        raise RuntimeError(payload)
    return payload

class ChildProxy:
    """Synthetic-contract proxy bound to the ORIGINAL external child.

    Forwards the real Adapter contract over the local control socket. It
    supplies genuine events/stop/execute replies issued by that child; the
    fixture claims no Native or Provider qualification.
    """
    def __init__(self, sock_s):
        self._sock = sock_s

    def execute(self, request):
        return ctl(self._sock, 'execute', request)

    def events(self, ref, after=None):
        return ctl(self._sock, 'events', ref, after)

    def stop(self, ref):
        return ctl(self._sock, 'stop', ref)

    def status(self, ref):
        return ctl(self._sock, 'status', ref)

    def respond(self, response):
        return ctl(self._sock, 'respond', response)

    def resume(self, state):
        return ctl(self._sock, 'resume', state)

    def usage(self):
        return ()


def child_server(sock_s, marker):
    """Parent-owned external child host; holds the original child objects.

    Synthetic contract fixture only — this is the original handle the test
    reattaches to, never a Native/Provider qualification claim.
    """
    path = Path(sock_s)
    if path.exists():
        path.unlink()
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(sock_s)
    os.chmod(sock_s, 0o600)
    srv.listen(16)
    children = {}

    def handle(op, args):
        if op == 'execute':
            request, = args
            child = children.setdefault(request.ref, Child())
            return child.execute(request)          # real contract receipt
        if op == 'events':
            return children[args[0]].events(args[0], args[1])
        if op == 'stop':
            return children[args[0]].stop(args[0])  # real contract reply
        if op == 'status':
            return children[args[0]].status(args[0])
        if op == 'respond':
            return children[args[0]].respond(args[0])
        if op == 'resume':
            return children[args[0]].resume(args[0])
        if op == 'finish':
            ref, = args
            children[ref].finish(ref)               # genuine Result event
            return True
        if op == 'set_stop':
            ref, name = args
            children[ref].stop_status = getattr(c.StopStatus, name)
            return True
        if op == 'requests':
            child = children.get(args[0])
            return 0 if child is None else len(child.requests)
        if op == 'result':
            return next(e.result for e in children[args[0]].events(args[0])
                        if isinstance(e, c.ResultEvent))
        raise RuntimeError('unknown control op %r' % (op,))

    print('READY', flush=True)
    while True:
        conn, _ = srv.accept()
        conn.settimeout(30)
        try:
            op, args = _recv(conn)
            if op == 'shutdown':
                _send(conn, ('ok', True))
                break
            try:
                _send(conn, ('ok', handle(op, args)))
            except Exception as exc:
                _send(conn, ('err', repr(exc)))
        finally:
            conn.close()
    srv.close()


def worker_one(root_s, sock_s, report_s, marker):
    """Own the root, dispatch via the external child, commit the bound
    decision, report, then wait for SIGKILL. Dies mid-hold."""
    fx = DriverPoolFixture(Path(root_s))

    def factory(request):
        fx.child_calls.append(request)
        fx.children[request.ref] = ChildProxy(sock_s)
        return fx.children[request.ref]

    fx.pool = PooledAdapter(fix.ADAPTER, ledger=fx.ledger,
                            canonical_ledger=fx.ledger.path, factory=factory)
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
    lease = fx.ledger.row(ref, fix.ADAPTER)
    assert lease[2] == 'executing'
    receipt = fx.state.execute_receipt(ref)
    assert (receipt.status, receipt.never_started) == (
        c.OperationStatus.ACCEPTED, None)       # genuine receipt, no proof
    assert ctl(sock_s, 'requests', ref) == 1    # one execute, ever
    Path(report_s).write_text(json.dumps({
        'pid': os.getpid(), 'marker': marker,
        'lock_ino': os.lstat(fx.owner.lock_path).st_ino,
        'ref': [ref.run_id, ref.job_id, ref.attempt_id],
        'digest': lease[0], 'row': list(fx.projection_row()),
        'executes': len(fx.child_calls)}))
    print('READY', flush=True)
    sys.stdin.read()


def racer(ledger_s, sock_s, request_s, report_s, mode, marker):
    """Poised contender on the physical canonical ledger. Prints READY, then
    blocks on the parent's release byte before exactly one admission attempt."""
    ledger = CapacityLedger(Path(ledger_s))
    request = pickle.loads(Path(request_s).read_bytes())
    calls = []

    def factory(req):
        calls.append(req)
        return ChildProxy(sock_s)

    pool = PooledAdapter(fix.ADAPTER, ledger=ledger,
                         canonical_ledger=ledger.path, factory=factory)
    print('READY', flush=True)
    sys.stdin.read(1)                                  # barrier release
    if mode == 'reserve':
        try:
            out = {'status': 'reserved' if pool.reserve(request)
                   else 'full', 'ns': None}
        except CapacityError as exc:
            out = {'status': 'capacity_error', 'ns': str(exc)}
    else:
        reply = pool.execute(request)
        ns = reply.never_started
        out = {'status': reply.status.value,
               'ns': None if ns is None else
               [ns.evidence_ref, ns.request == request]}
    out['factory'] = len(calls)                        # Native calls made
    Path(report_s).write_text(json.dumps(out))


def race_once(ledger_s, sock_s, entries, work, tag):
    """Simultaneous cross-process admission on the same canonical ledger.

    entries: [(mode, request), ...]. Every spawned racer is our own child,
    READY, blocked on its release byte, and verified in ps (pid birth +
    argv marker, not zombie) before ANY release byte is written. Bounded
    readiness and joins; procs/markers/births stay index-aligned even if a
    spawn fails mid-loop; all spawned racers are always reaped and their
    streams closed, success or failure."""
    work.mkdir(exist_ok=True)
    procs, markers, births, reps = [], [], [], []
    try:
        for i, (mode, request) in enumerate(entries):
            req_f = work / ('req-%s-%d' % (tag, i))
            rep_f = work / ('rep-%s-%d' % (tag, i))
            req_f.write_bytes(pickle.dumps(request))
            markers.append('co04-race-%d-%d' % (os.getpid(),
                                                time.monotonic_ns()))
            procs.append(subprocess.Popen(
                [sys.executable, '-c', _boot('racer'), ledger_s, sock_s,
                 str(req_f), str(rep_f), mode, markers[-1]],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True))
            births.append(None)
            reps.append(rep_f)
        for i, proc in enumerate(procs):
            if (not select.select([proc.stdout], [], [], 30)[0]
                    or proc.stdout.readline() != 'READY\n'):
                proc.kill()                  # reap our own child first —
                proc.wait(30)                # stderr.read() on a live,
                # stdin-blocked pipe would hang forever
                raise AssertionError('racer %d never ready: %r'
                                     % (i, proc.stderr.read()[:1000]))
            deadline = time.monotonic() + 15
            while births[i] is None:
                snap = _ps(proc.pid)
                if (snap is not None and markers[i] in snap[2]
                        and not snap[1].startswith('Z')):
                    births[i] = snap[0]
                    continue
                assert time.monotonic() < deadline, (
                    'racer %d marker never visible: %r' % (i, snap))
                time.sleep(0.05)
        for proc in procs:                    # verified identities; release all
            proc.stdin.write('g')
            proc.stdin.flush()
        for i, proc in enumerate(procs):
            proc.wait(60)                     # TimeoutExpired -> finally reaps
            assert proc.returncode == 0, (
                'racer %d exited %r: %r'
                % (i, proc.returncode, proc.stderr.read()[:1000]))
        return [json.loads(rep.read_text()) for rep in reps]
    finally:
        for i, proc in enumerate(procs):
            if proc.poll() is None:
                _guarded_kill(proc.pid, markers[i], births[i])
                if proc.poll() is None:
                    proc.kill()
                proc.wait(30)
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                try:
                    stream.close()
                except OSError:
                    pass

def worker_two(root_s, sock_s, prior_s, report_s, marker):
    """Different process, same root: reattach the ORIGINAL external handle;
    held lease refuses admission until genuine evidence finalizes it."""
    prior = json.loads(Path(prior_s).read_text())
    fx = _open_existing(Path(root_s))
    try:
        assert os.lstat(fx.owner.lock_path).st_ino == prior['lock_ino']
        ref = c.AttemptRef(*prior['ref'])
        attempt = fx.attempt()
        assert attempt.ref == ref
        row = fx.projection_row()
        assert list(row) == prior['row']            # byte-identical decision
        snap, = fx.ledger.unresolved()
        assert (snap.ref, snap.adapter, snap.phase) == (
            ref, fix.ADAPTER, 'executing')
        assert snap.request_digest == prior['digest']
        job = fx.state.get_job(fx.run_id, ref.job_id)
        request = c.ExecuteRequest(ref, job, attempt.conditions)
        assert body_digest(request) == snap.request_digest  # exact binding
        calls = []

        def factory(req):
            calls.append(req)
            return ChildProxy(sock_s)

        fx.pool = PooledAdapter(fix.ADAPTER, ledger=fx.ledger,
                                canonical_ledger=fx.ledger.path,
                                factory=factory)
        # Drifted reattach is refused before the genuine one succeeds.
        wrong = replace(request, conditions=replace(
            request.conditions, model='other'))
        try:
            fx.pool.reattach(wrong, ChildProxy(sock_s))
            raise AssertionError('drifted reattach accepted')
        except CapacityError:
            pass
        fx.pool.reattach(request, ChildProxy(sock_s))   # ORIGINAL handle
        assert ctl(sock_s, 'requests', ref) == 1        # no new execute
        # Held-slot retry race: fill the other 11 real slots, then every
        # admission path against or around the held lease must refuse.
        fillers = [filler_request('held-%d' % i) for i in range(11)]
        for req in fillers:
            assert fx.ledger.reserve(req, 'occupied')
        assert fx.ledger.count(fix.ADAPTER) == 12
        # SIMULTANEOUS refusal: poised cross-process racers on this physical
        # ledger, all released by the barrier byte. Sequential proof above
        # does not claim concurrency; this does.
        racers = [filler_request('race1-%d' % i) for i in range(3)]
        reports = race_once(str(fx.ledger.path), sock_s,
                            [('execute', q) for q in racers]
                            + [('reserve', request)],   # rebind attempt
                            Path(report_s).parent / 'race1', 'held')
        for rep in reports[:3]:
            assert rep['status'] == c.OperationStatus.UNAVAILABLE.value
            assert rep['ns'] == ['capacity:full-before-child-factory', True]
            assert rep['factory'] == 0                  # no factory/Native call
        assert reports[3]['status'] == 'capacity_error'  # held lease rebind refused
        for q in racers:
            assert ctl(sock_s, 'requests', q.ref) == 0  # no child ever ran
        assert fx.ledger.count(fix.ADAPTER) == 12       # still fully held
        fresh = filler_request('fresh')
        reply = fx.pool.execute(fresh)
        assert reply.status == c.OperationStatus.UNAVAILABLE
        assert reply.never_started.evidence_ref == (
            'capacity:full-before-child-factory')
        assert calls == []                            # factory never ran
        assert fx.pool.execute(request).status == (
            c.OperationStatus.INVALID_STATE)          # never re-dispatched
        for attempt_refill in (True,):
            try:
                fx.pool.reserve(request)
                raise AssertionError('held lease rebound')
            except CapacityError:
                pass
        (held,) = fx.driver.tick()
        assert (held.status, held.code, held.decided) == (
            'failed', 'cessation_unconfirmed', True)
        attempt = fx.attempt()
        assert attempt.result is None                 # nothing fabricated
        assert attempt.stop_reply.status == c.StopStatus.UNCONFIRMED
        assert fx.ledger.count(fix.ADAPTER) == 12     # still fully held
        assert fx.projection_row() == row
        # Genuine evidence arrives only from the ORIGINAL external child.
        ctl(sock_s, 'finish', ref)
        ctl(sock_s, 'set_stop', ref, 'CONFIRMED')
        fx.driver.tick()
        run = fx.run()
        assert (run.state, run.final_reason) == (
            c.State.FAILED, 'projection_decided')
        attempt = fx.attempt()
        assert attempt.result == ctl(sock_s, 'result', ref)  # exact identity
        assert attempt.ac is None and attempt.output is None
        assert attempt.collection_failure is None
        assert run.output_selection is None
        assert fx.state.history(fx.run_id, 'ac_history') == ()
        assert fx.state.history(fx.run_id, 'job_goals') == ()
        assert fx.state.execute_receipt(ref).never_started is None
        stops = fx.state.history(fx.run_id, 'stop_history')
        assert [s.status for s in stops] == [
            c.StopStatus.UNCONFIRMED, c.StopStatus.CONFIRMED]
        lease = fx.ledger.row(ref, fix.ADAPTER)
        assert lease[2] == 'released'
        assert lease[3] == stops[-1].evidence_ref     # child's own evidence
        assert fx.projection_row() == row
        assert len(fx.state.attempts(fx.run_id)) == 1
        assert fx.ledger.count(fix.ADAPTER) == 11     # one lease released
        # Exactly one of three simultaneous contenders wins the freed slot.
        contenders = [filler_request('race2-%d' % i) for i in range(3)]
        reports = race_once(str(fx.ledger.path), sock_s,
                            [('execute', q) for q in contenders],
                            Path(report_s).parent / 'race2', 'free')
        wins = [r for r in reports if r['status'] == c.OperationStatus.ACCEPTED.value]
        loses = [r for r in reports if r['status'] == c.OperationStatus.UNAVAILABLE.value]
        assert len(wins) == 1 and len(loses) == 2 and wins[0]['ns'] is None
        winner = contenders[reports.index(wins[0])]
        assert wins[0]['factory'] == 1
        assert ctl(sock_s, 'requests', winner.ref) == 1  # only winner executed
        for rep, q in zip(reports, contenders):
            if rep['status'] == c.OperationStatus.UNAVAILABLE.value:
                assert rep['ns'] == [
                    'capacity:full-before-child-factory', True]  # exact request
                assert rep['factory'] == 0
                assert ctl(sock_s, 'requests', q.ref) == 0
        assert fx.ledger.count(fix.ADAPTER) == 12        # winner claimed it
        for req in fillers:
            assert fx.ledger.release_reserved(req, 'occupied')
        assert fx.ledger.count(fix.ADAPTER) == 1        # race winner executing
        # Safe atomic admission resumes; the original stays undispatchable.
        reply = fx.pool.execute(fresh)
        assert reply.status == c.OperationStatus.ACCEPTED
        assert calls == [fresh]
        assert ctl(sock_s, 'requests', fresh.ref) == 1
        assert fx.ledger.count(fix.ADAPTER) == 2
        assert ctl(sock_s, 'requests', ref) == 1      # still one execute
        assert fx.pool.execute(request).status == (
            c.OperationStatus.INVALID_STATE)
        try:
            fx.pool.reserve(request)
            raise AssertionError('released lease rebound')
        except CapacityError:
            pass
        assert fx.ingress_claims() == 1
        assert fx.state.history(fx.run_id, 'driver_audit') == ()
        for sub in ('blobs', 'manifests'):
            assert list((fx.output_store.root / sub).iterdir()) == []
        Path(report_s).write_text(json.dumps({'ok': True}))
        print('READY', flush=True)
        sys.stdin.read()
    finally:
        fx.store.close()
        fx.owner.close()


def _boot(fn):
    return ('import sys;sys.path[:0]=%r;'
            'import test_driver_original_handle_restart as m;'
            'm.%s(*sys.argv[1:])'
            % ([str(TESTS), str(TESTS.parent)], fn))


class OriginalHandleRestartTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name).resolve()

    def _launch(self, fn, *args):
        marker = 'co04-orig-%d-%d' % (os.getpid(), time.monotonic_ns())
        argv = [sys.executable, '-c', _boot(fn),
                *(str(a) for a in args), marker]
        proc = subprocess.Popen(argv, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
        return proc, marker

    def _ready(self, proc, marker):
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
                return snap[0]
            self.assertLess(time.monotonic(), deadline,
                            'marked worker argv never appeared: %r' % (snap,))
            time.sleep(0.05)

    def test_reattach_original_handle_after_kill_and_held_slot_race(self):
        root, sock = self.dir / 'root', self.dir / 'child.sock'
        if not QUALIFIED:
            root.mkdir(mode=0o700)
            with self.assertRaises(OwnerUnavailable) as ei:
                ServiceOwner.acquire(root)
            self.assertEqual(ei.exception.code, 'unsupported_platform')
            return
        prior_f, done_f = self.dir / 'w1.json', self.dir / 'w2.json'
        server = one = two = None
        ms = mo = mt = bs = bo = bt = None
        try:
            server, ms = self._launch('child_server', sock)
            bs = self._ready(server, ms)
            one, mo = self._launch('worker_one', root, sock, prior_f)
            bo = self._ready(one, mo)
            prior = json.loads(prior_f.read_text())
            self.assertEqual(prior['pid'], one.pid)
            self.assertEqual(prior['marker'], mo)
            self.assertEqual(prior['executes'], 1)
            ino = os.lstat(root / 'service.lock').st_ino
            self.assertEqual(ino, prior['lock_ino'])
            # Verify exact identity immediately before SIGKILL.
            snap = _ps(one.pid)
            self.assertIsNotNone(snap)
            self.assertEqual(snap[0], bo)
            self.assertIn(mo, snap[2])
            self.assertFalse(snap[1].startswith('Z'))
            os.kill(one.pid, signal.SIGKILL)
            one.wait(30)
            self.assertEqual(one.returncode, -signal.SIGKILL)
            # The original external child survives the owner kill.
            alive = _ps(server.pid)
            self.assertIsNotNone(alive)
            self.assertEqual(alive[0], bs)
            self.assertIn(ms, alive[2])
            self.assertFalse(alive[1].startswith('Z'))
            self.assertEqual(
                os.lstat(root / 'service.lock').st_ino, ino)
            two, mt = self._launch('worker_two', root, sock, prior_f, done_f)
            bt = self._ready(two, mt)
            two.stdin.close()
            two.wait(120)
            self.assertEqual(two.returncode, 0,
                             two.stderr.read()[:2000])
            self.assertEqual(json.loads(done_f.read_text()), {'ok': True})
            # Parent-side proof: the ORIGINAL child executed exactly once.
            self.assertEqual(ctl(str(sock), 'requests',
                                 c.AttemptRef(*prior['ref'])), 1)
            self.assertEqual(
                os.lstat(root / 'service.lock').st_ino, ino)
        finally:
            if server is not None and server.poll() is None:
                try:
                    ctl(str(sock), 'shutdown')
                except (OSError, RuntimeError):
                    pass
            for proc, m, b in ((server, ms, bs), (one, mo, bo),
                               (two, mt, bt)):
                if proc is None:
                    continue
                if proc.poll() is None:
                    _guarded_kill(proc.pid, m, b)
                    if proc.poll() is None:
                        proc.kill()
                    proc.wait(30)
                for stream in (proc.stdin, proc.stdout, proc.stderr):
                    try:
                        stream.close()
                    except OSError:
                        pass


if __name__ == '__main__':
    unittest.main()
