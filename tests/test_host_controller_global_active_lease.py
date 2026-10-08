# tests/test_host_controller_global_active_lease.py
"""Active-lease global latch proof on the real host stack (#190 M3).

Complements test_host_controller_global_http (pre-Attempt 503 latch):
here the global failure lands WHILE a durable admitted Attempt holds a
live CapacityLedger lease and a real provider POST is in flight.

A real owned subprocess runs co_v4.cli.main with the PRODUCTION
host_runtime.build -> ServiceHost -> ServiceOwner -> ControlStore /
OutputStore / CapacityLedger / PooledAdapter / OpenAISSEAdapter chain,
the real make_evidence resolver, real Judgment transactions, the real
QualifiedRouteGate verify_manifest/issue_profile path, the REAL
make_models_probe wire GET, the real hr.HttpSseTransport worker
transport and a real loopback HttpService.

Declared fixture boundaries (test-only, never qualification evidence):
- The provider is a parent-owned loopback endpoint that counts POSTs,
  answers the real /models probe and holds the SSE stream open. It is a
  controlled wire fixture, NOT provider or model qualification.
- launch_attested is a fixture callable returning True: an empty
  launch.json can never attest a real native launch, and no real
  endpoint-native attestation exists for an in-process fixture. This
  fault-unit test accepts that seam; it is not stable-provider proof.

Injection seam: the real ControllerState.get_attempt method, armed by a
file flag only after the parent observes the committed ACCEPTED
execute_receipt, the 'executing' ledger lease and exactly one provider
POST. On the FIRST armed read it captures the committed checkpoint's
body_digest (inside the caller, before raising) — the true pre-global
baseline, immune to racing periodic _save — then raises
StoreUnavailable out of Controller._poll -> step() -> driver tick ->
host latch: HTTP 503, ticking stops, owner held, no save, no Native
stop, no ERROR. SIGTERM runs the real ordered bounded close; with no
CONFIRMED cessation ever recorded the lease and Attempt stay held.
"""
import http.client
import json
import os
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from co_v4 import contracts as c
from co_v4 import host_routes as hr
from co_v4.adapter_capacity import CapacityLedger
from co_v4.gateway_store import lookup_body
from co_v4.http_auth import IngressBroker
from co_v4.profile_registry import revision_digest
from co_v4.protocol_profile import (environment_ref, issue_profile,
                                    verify_manifest)
from co_v4.service_owner import OwnerUnavailable, ServiceOwner
from co_v4.state import ControlStore, body_digest
import test_host_routes as thr
import test_profile_registry as tpr

TESTS = Path(__file__).resolve().parent
SRC = TESTS.parent
ADAPTER = 'openai.responses'
ALIAS = 'co-text'
AUTH_REF = 'prov-key'
MODEL = thr.MODEL

CHILD = r'''
import sys
from dataclasses import replace
from pathlib import Path
cfg_s, ready_s, url_s, armed_s, count_s, ckpt_s = sys.argv[1:7]
sys.path[:0] = sys.argv[7:]
import co_v4.cli as cli
import co_v4.host_routes as hr
import co_v4.host_runtime as hrt
from co_v4.service_host import ServiceHost
from co_v4.state import (ControllerState, StoreUnavailable, body_digest)

real_build = hrt.build
real_get = ControllerState.get_attempt
armed_path = Path(armed_s)
count_path = Path(count_s)
ckpt_path = Path(ckpt_s)


def guarded_get_attempt(self, ref):
    # Real ControllerState method seam, armed by the parent only after the
    # committed ACCEPTED receipt + held lease + single POST are observed.
    # The FIRST armed read snapshots the committed checkpoint digest
    # (the true pre-global baseline — the failed step skips _save) and
    # then raises StoreUnavailable out of _poll -> step -> tick -> latch.
    # The count file proves how many armed reads ever ran.
    if armed_path.exists():
        if not ckpt_path.exists():
            ckpt_path.write_text(
                body_digest(self.checkpoint(ref.run_id)))
        seen = int(count_path.read_text()) if count_path.exists() else 0
        count_path.write_text(str(seen + 1))
        raise StoreUnavailable('injected control-store loss')
    return real_get(self, ref)


def build(config):
    builder = real_build(config)

    def wrapped(owner, retain):
        # DECLARED fixture attestation (test-only): the empty launch.json
        # can never attest a real launch, so the gate's launch_attested
        # callback is a constant-True fixture. Real verify_manifest /
        # issue_profile / digest / argv binding / wire /models probe all
        # still run; this is fault-unit acceptance only, never provider
        # qualification.
        hr.LaunchAttestor = (
            lambda record, credential: (
                lambda manifest_fields, endpoint, auth_ref: True))
        comp = builder(owner, retain)
        ControllerState.get_attempt = guarded_get_attempt
        factory = comp.http_factory

        def ready_http(available):
            service = factory(available)
            real_start = service.start

            def start():
                url = real_start()          # real bound listener
                Path(url_s).write_text(url)
                Path(ready_s).write_text('ready')
                print('READY', flush=True)
                return url

            service.start = start
            return service

        return replace(comp, http_factory=ready_http)

    return wrapped


sys.exit(cli.main(['--config', cfg_s], build=build,
                  host_type=ServiceHost))
'''


class FixtureProvider:
    """Owned loopback endpoint: real /models probe answer + held SSE POST.

    Fixture wire evidence only — proves one POST left the transport, the
    real probe ran, and the stream stayed open. No provider or model
    qualification is claimed or established. Every handler thread is
    tracked as an owned handle and joined bounded at close.
    """
    def __init__(self):
        self.posts, self.gets, self.handler_threads = [], [], []
        self.hold = threading.Event()
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def log_message(self, *args):
                pass

            def do_GET(self):
                fixture.handler_threads.append(threading.current_thread())
                fixture.gets.append(self.path)
                body = json.dumps({'object': 'list', 'data': [
                    {'id': MODEL, 'object': 'model',
                     'created': 0, 'owned_by': 'fixture'}]}).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except OSError:
                    pass

            def do_POST(self):
                fixture.handler_threads.append(threading.current_thread())
                length = int(self.headers.get('Content-Length') or 0)
                if length:
                    self.rfile.read(length)
                fixture.posts.append(self.path)
                # 200 + no Content-Length: body is read-until-close, so
                # the real transport sees StreamStarted(200) then blocks
                # on the held stream — a live in-flight Attempt.
                self.send_response(200)
                self.send_header('Content-Type', 'text/event-stream')
                self.end_headers()
                try:
                    self.wfile.flush()
                except OSError:
                    return
                self.close_connection = True
                fixture.hold.wait(90)

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = 'http://127.0.0.1:%d/v1' % self.port
        self.handler_done = False

    def close(self):
        """Owned-handle teardown: release held responses, stop accepts,
        close the listener, then bounded-join every handler thread and
        confirm completion — no daemon-only abandonment."""
        self.hold.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(10)
        pending = list(self.handler_threads)
        for t in pending:
            t.join(10)
        self.handler_done = (
            not self.thread.is_alive()
            and not any(t.is_alive() for t in pending))


def _free_port():
    sock = socket.socket()
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class ActiveLeaseGlobalLatchTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name).resolve()
        root = self.dir / 'root'
        root.mkdir(mode=0o700)
        self.root = root
        self.provider = FixtureProvider()
        self.addCleanup(self.provider.close)
        cred = thr.write(self.dir / 'cred',
                         secrets.token_hex(32).encode())
        mpath = thr.write(self.dir / 'manifest.json',
                          thr.manifest_dict(self.dir, cred))
        launch = thr.write(self.dir / 'launch.json', {})
        doc = json.loads(mpath.read_text())
        prof = issue_profile(verify_manifest(doc, hr.read_evidence),
                             'responses')
        env = environment_ref(self.provider.url, AUTH_REF,
                              prof.profile_digest)
        wire = tpr.wire_entry(
            env=env, routes=[[MODEL, ADAPTER, env]],
            route_bounds=[{'route': [MODEL, ADAPTER, env],
                           'total_s': 120, 'max_drain_s': 30}])
        registry = thr.write(self.dir / 'registry.json',
            tpr.registry_doc([wire], [{
                'alias': ALIAS, 'profile_id': 'co-text',
                'revision_digest': revision_digest(wire)}]))
        self.token = secrets.token_hex(32)
        from hashlib import sha256
        principals = thr.write(self.dir / 'principals.json', [{
            'principal': 'p1',
            'token_sha256': sha256(
                self.token.encode('ascii')).hexdigest()}])
        self.port = _free_port()
        ledger = str(self.dir / 'capacity.sqlite')
        config = {'schema': 'co.service-host/1', 'state_root': str(root),
            'ledger_path': ledger, 'bind': {'host': '127.0.0.1',
            'port': self.port},
            'principals_file': str(principals),
            'registry_file': str(registry),
            'max_body_bytes': 4096, 'sync_wait_s': 5,
            'routes': [{'model': MODEL, 'adapter': ADAPTER,
                'endpoint': self.provider.url, 'auth_ref': AUTH_REF,
                'credential_file': str(cred),
                'manifest_file': str(mpath),
                'launch_record': str(launch),
                'profile': {'protocol': 'responses',
                            'index_mode': 'present',
                            'sequence_mode': 'present',
                            'inert_fields': {}},
                'profile_digest': 'sha256:' + prof.profile_digest,
                'environment_ref': env, 'store_param': 'omit',
                'deadlines': {'connect_s': 5, 'first_byte_s': 10,
                              'idle_s': 60, 'total_s': 60},
                'max_drain_s': 30,
                'verification': {'use_case': 'general',
                    'official_ref': 'r:o', 'implementation_ref': 'r:i',
                    'measurement_ref': 'r:m', 'ac_ref': 'r:a',
                    'output_mode': 'collect'}}]}
        self.ledger_path = Path(ledger)
        self.config = thr.write(self.dir / 'config.json', config)
        self.broker = IngressBroker(
            lambda: datetime.now(timezone.utc).isoformat())

    def _reap(self, proc):
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(5)
        for stream in (proc.stdout, proc.stderr):
            try:
                stream.close()
            except OSError:
                pass

    def wait_ready(self, proc, ready, timeout=30):
        deadline = time.monotonic() + timeout
        while not ready.exists():
            code = proc.poll()
            if code is not None:
                self.fail('child_exit:%s' % code)   # fixed code, never raw
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.02)

    def wait_exit(self, proc, timeout=60):
        try:
            proc.wait(timeout)
        except subprocess.TimeoutExpired:
            self._reap(proc)
            self.fail('child_never_exited')
        return proc.returncode

    def get(self, port, path):
        conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
        try:
            conn.request('GET', path, headers={
                'Authorization': 'Bearer ' + self.token})
            resp = conn.getresponse()
            return resp.status, resp.read()
        finally:
            conn.close()

    def store_handle(self):
        """Observer handle on the child's committed store file. Declared
        read-only intent: _tx still runs BEGIN IMMEDIATE and serializes
        against the owner, but this is NOT a second owner-bound writer —
        only reads and one-shot receipt verification are exercised."""
        return ControlStore(self.root / 'control.sqlite',
            verifier=self.broker.verifier, evidence=lambda *_: None,
            profile_resolver=lambda alias: None)

    def _scenario(self, first_signal, first_exit):
        """Owner process death releases flock, not remote provider capacity."""
        paths = [self.dir / n for n in
                 ('ready', 'url', 'armed', 'count', 'ckpt')]
        proc = subprocess.Popen(
            [sys.executable, '-c', CHILD, str(self.config),
             *(str(p) for p in paths), str(TESTS), str(SRC)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env={'PATH': '/usr/bin:/bin'})
        self.addCleanup(self._reap, proc)
        ready, url_f, armed, count, ckpt = paths
        self.wait_ready(proc, ready)
        port = int(url_f.read_text().rsplit(':', 1)[1])
        conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
        try:
            body = json.dumps({'model': ALIAS, 'input': 'x',
                               'background': True}).encode()
            conn.request('POST', '/v1/responses', body=body, headers={
                'Authorization': 'Bearer ' + self.token,
                'Content-Type': 'application/json'})
            resp = conn.getresponse()
            status, payload = resp.status, json.loads(resp.read())
        finally:
            conn.close()
        self.assertEqual((status, payload.get('status')),
                         (200, 'queued'))
        response_id = payload['id']          # wire resp_*, never run_*

        store = self.store_handle()
        self.addCleanup(store.close)
        state = store.controller()
        ledger = CapacityLedger(self.ledger_path)
        with self.broker.receipt_ref(
                'p1', lookup_body(response_id)) as ref:
            run_id = store.gateway().lookup(response_id, ref).run_id

        # Wait for the REAL committed facts: exactly one provider POST on
        # the declared wire path, the real /models probe served, one
        # durable admitted Attempt, a committed ACCEPTED execute_receipt
        # and a live 'executing' ledger lease.
        deadline, attempt_ref = time.monotonic() + 30, None
        while time.monotonic() < deadline:
            attempts = state.attempts(run_id)
            ref0 = attempts[0].ref if len(attempts) == 1 else None
            row = (ledger.row(ref0, ADAPTER)
                   if ref0 is not None else None)
            receipt = (state.execute_receipt(ref0)
                       if ref0 is not None else None)
            if (self.provider.posts == ['/v1/responses']
                    and self.provider.gets
                    and ref0 is not None
                    and row is not None and row[2] == 'executing'
                    and receipt is not None
                    and receipt.status == c.OperationStatus.ACCEPTED):
                attempt_ref = ref0
                break
            if proc.poll() is not None:
                self.fail('child_exit:%s' % proc.returncode)
            time.sleep(0.02)
        self.assertIsNotNone(attempt_ref)
        self.assertIs(state.get_run(run_id).state, c.State.RUNNING)

        # Arm the real ControllerState.get_attempt seam; the next poll's
        # committed-state read raises StoreUnavailable with the lease
        # live and captures the committed checkpoint digest first.
        armed.write_text('armed')
        deadline, seen = time.monotonic() + 20, None
        while seen != 503 and time.monotonic() < deadline:
            seen, _ = self.get(port, '/v1/models')
            time.sleep(0.02)
        self.assertEqual(seen, 503)              # real listener latch
        self.assertIsNone(proc.poll())           # alive, owner held
        with self.assertRaises(OwnerUnavailable) as ctx:
            ServiceOwner.acquire(self.root)
        self.assertEqual(ctx.exception.code, 'owned_elsewhere')
        deadline = time.monotonic() + 10
        while not count.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertTrue(count.exists())          # seam actually fired
        self.assertEqual(int(count.read_text()), 1)
        self.assertTrue(ckpt.exists())           # pre-global baseline
        time.sleep(0.5)
        self.assertEqual(int(count.read_text()), 1)   # driver stopped
        self.assertEqual(len(self.provider.posts), 1)  # no resend

        run = state.get_run(run_id)
        self.assertIs(run.state, c.State.RUNNING)      # no ERROR/FAILED
        self.assertIsNone(run.final_reason)
        self.assertIsNone(run.output_selection)
        attempt = state.get_attempt(attempt_ref)
        self.assertIsNone(attempt.result)
        self.assertIsNone(attempt.stop_reply)          # no Native auto-stop
        self.assertIsNone(attempt.ac)                  # no AC
        self.assertIsNone(state.attempt_settlement(attempt_ref))
        for kind in ('job_goals', 'run_goals', 'driver_audit',
                     'job_failures', 'ac_history', 'stop_history'):
            self.assertEqual(state.history(run_id, kind), ())
        # No _save ran after the global failure: committed checkpoint
        # digest equals the child-captured first-fault baseline.
        self.assertEqual(body_digest(state.checkpoint(run_id)),
                         ckpt.read_text())
        self.assertEqual(ledger.row(attempt_ref, ADAPTER)[2],
                         'executing')

        # Only signal the original owned Popen after the latched 503,
        # held lease and checkpoint baselines have been verified.
        # Neither ordered close nor kernel death proves remote cessation.
        os.kill(proc.pid, first_signal)
        self.assertEqual(self.wait_exit(proc), first_exit)
        owner = ServiceOwner.acquire(self.root)
        owner.close()

        # Provider cessation was never CONFIRMED: the lease and Attempt
        # stay held — nothing freed, nothing claimed stopped, no resend.
        run = state.get_run(run_id)
        self.assertIs(run.state, c.State.RUNNING)
        self.assertIsNone(run.final_reason)
        self.assertIsNone(run.output_selection)
        attempt = state.get_attempt(attempt_ref)
        self.assertIsNone(attempt.result)
        self.assertIsNone(attempt.stop_reply)
        self.assertIsNone(attempt.ac)
        self.assertIsNone(state.attempt_settlement(attempt_ref))
        self.assertEqual(state.history(run_id, 'stop_history'), ())
        self.assertEqual(state.history(run_id, 'ac_history'), ())
        self.assertEqual(body_digest(state.checkpoint(run_id)),
                         ckpt.read_text())
        self.assertEqual(ledger.row(attempt_ref, ADAPTER)[2],
                         'executing')
        self.assertEqual(len(self.provider.posts), 1)

        # === Recovery phase: fresh owned CLI on the SAME persisted
        # root/ledger/fixture endpoint. Fault disarmed by RENAME (the
        # armed flag is evidence, preserved — never deleted). The old
        # provider stream is STILL held: remote execution is unknown.
        #
        # Expected classification, from the supplied source only:
        # recovery_scan holds the Attempt (committed ACCEPTED receipt —
        # nothing to mint); the fresh PooledAdapter has no child bound
        # to the old ref, so _child -> CapacityError -> pool.stop returns
        # UNCONFIRMED 'child cessation unconfirmed' and events() raises
        # into the controller_error stop path. The contract result is an
        # honest hold: one committed UNCONFIRMED StopReply, RUNNING
        # held, lease 'executing', no resend, no reattach, no
        # finalize — never a fabricated CONFIRMED or NeverStarted.
        armed.rename(self.dir / 'armed.1')
        paths2 = [self.dir / n for n in ('ready2', 'url2')]
        proc2 = subprocess.Popen(
            [sys.executable, '-c', CHILD, str(self.config),
             *(str(p) for p in paths2), str(armed), str(count),
             str(ckpt), str(TESTS), str(SRC)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env={'PATH': '/usr/bin:/bin'})
        self.addCleanup(self._reap, proc2)
        ready2, url2 = paths2
        self.wait_ready(proc2, ready2)
        port2 = int(url2.read_text().rsplit(':', 1)[1])
        self.assertEqual(int(count.read_text()), 1)   # no armed read ran

        # Healthy host: no latched global failure on this process.
        seen, _ = self.get(port2, '/v1/models')
        self.assertEqual(seen, 200)

        # Recovery runs the real Controller/step path: it must commit
        # exactly one genuine UNCONFIRMED StopReply for the SAME Attempt
        # (no Native handle reattached — unsupported recovery stays
        # blocked honestly, not silently).
        deadline, reply = time.monotonic() + 30, None
        while time.monotonic() < deadline:
            hist = state.history(run_id, 'stop_history')
            if hist:
                reply = hist[-1]
                break
            if proc2.poll() is not None:
                self.fail('child_exit:%s' % proc2.returncode)
            time.sleep(0.02)
        self.assertIsNotNone(reply)
        self.assertIs(reply.status, c.StopStatus.UNCONFIRMED)
        self.assertEqual(reply.ref, attempt_ref)
        time.sleep(0.5)                       # several more real ticks

        # No duplicate Attempt, no resend, no fabricated proof: the
        # journal shows the same single admitted Attempt, one
        # ACCEPTED execute_receipt, zero events/AC/goals/failures —
        # and exactly one deduplicated UNCONFIRMED stop record.
        attempts = state.attempts(run_id)
        self.assertEqual(len(attempts), 1)
        self.assertEqual(attempts[0].ref, attempt_ref)
        receipt = state.execute_receipt(attempt_ref)
        self.assertIs(receipt.status, c.OperationStatus.ACCEPTED)
        self.assertIsNone(receipt.never_started)
        self.assertEqual(len(state.history(run_id, 'execute_history')),
                         1)
        stops = state.history(run_id, 'stop_history')
        self.assertEqual(len(stops), 1)        # replay-deduped, not reissued
        self.assertIs(stops[0].status, c.StopStatus.UNCONFIRMED)
        attempt = state.get_attempt(attempt_ref)
        self.assertIsNone(attempt.result)
        self.assertIsNone(attempt.ac)
        self.assertIsNone(attempt.output)
        self.assertIsNone(attempt.collection_failure)
        self.assertIs(attempt.stop_reply.status,
                      c.StopStatus.UNCONFIRMED)  # real reply, not a claim
        self.assertIsNone(state.attempt_settlement(attempt_ref))
        run = state.get_run(run_id)
        self.assertIs(run.state, c.State.RUNNING)  # honest hold, not ERROR
        self.assertIsNone(run.final_reason)
        self.assertIsNone(run.output_selection)
        self.assertFalse(run.stop_requested)   # controller-local stop only
        self.assertIsNone(state.stop_origin(run_id))
        for kind in ('job_goals', 'run_goals', 'job_failures',
                     'ac_history', 'driver_audit'):
            self.assertEqual(state.history(run_id, kind), ())
        self.assertEqual(ledger.row(attempt_ref, ADAPTER)[2],
                         'executing')              # UNCONFIRMED frees nothing
        self.assertEqual(len(self.provider.posts), 1)  # still no resend

        # Northbound truthfulness: same wire response_id, non-decisive
        # in_progress — the gateway never reports a success it cannot prove.
        status, body = self.get(port2, '/v1/responses/' + response_id)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body).get('status'), 'in_progress')

        # SIGTERM on the recovered host: bounded ordered close again —
        # exit 0, owner released; the lease stays held because provider
        # cessation remains UNCONFIRMED, not because shutdown claims stop.
        os.kill(proc2.pid, signal.SIGTERM)
        self.assertEqual(self.wait_exit(proc2), 0)
        owner = ServiceOwner.acquire(self.root)
        owner.close()
        run = state.get_run(run_id)
        self.assertIs(run.state, c.State.RUNNING)
        self.assertIsNone(run.final_reason)
        self.assertIsNone(state.attempt_settlement(attempt_ref))
        self.assertEqual(len(state.attempts(run_id)), 1)
        self.assertEqual(state.history(run_id, 'stop_history'), stops)
        self.assertEqual(ledger.row(attempt_ref, ADAPTER)[2],
                         'executing')
        self.assertEqual(len(self.provider.posts), 1)

        # Owned provider handles completed: held response released and
        # every handler thread joined before the test ends.
        self.provider.close()
        self.assertTrue(self.provider.handler_done)

    def test_active_lease_global_latch_then_sigterm_keeps_lease(self):
        self._scenario(signal.SIGTERM, 0)

    def test_active_lease_global_latch_then_sigkill_keeps_lease(self):
        self._scenario(signal.SIGKILL, -signal.SIGKILL)
