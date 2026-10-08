# tests/test_host_controller_global_http.py
"""Real CLI/host/driver/Controller global latch proof (#190 M3).

A real owned subprocess runs co_v4.cli.main with the PRODUCTION
host_runtime.build -> ServiceHost -> ServiceOwner -> ControlStore /
OutputStore / CapacityLedger / PooledAdapter / ServiceDriver chain, the
real make_evidence resolver, real Judgment transactions and a real
loopback HttpService. Only the provider transport constructor and AC are
fixtures/forbidden seams — this is NOT provider qualification.

Scenario: an authorized HTTP POST background=true submits a real Run.
The trusted resolver's real judgment_view call then raises TypeError (an
observed code-bug class) inside evaluate(), which wraps it as
StoreUnavailable — GLOBAL_FAILURES escapes the real Controller.step(),
the real driver tick propagates, the real Host latches 503 while staying
alive with the owner held. SIGTERM then exits 0, releases the owner, and
a reopened real store/ledger proves: no Attempt, no child Native
execute, no AC/goal, no extra driver audit, no ERROR finalization and no
post-global checkpoint. The live-callback hard_deny path is explicitly
NOT covered here (a separate peer test owns it).
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
import time
import unittest
from datetime import datetime, timezone
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
ENDPOINT = 'http://127.0.0.1:50353/v1'
AUTH_REF = 'prov-key'

CHILD = r'''
import json, sys
from dataclasses import replace
from pathlib import Path
cfg_s, ready_s, url_s, native_s, count_s, ckpt_s = sys.argv[1:7]
sys.path[:0] = sys.argv[7:]
import co_v4.cli as cli
import co_v4.host_routes as hr
import co_v4.host_runtime as hrt
from co_v4.service_host import ServiceHost
from co_v4.state import _unpack, body_digest


class NoNative:
    """Forbidden provider seam: any construction is observed, then refused."""
    def __init__(self, *a, **k):
        Path(native_s).write_text('x')
        raise AssertionError('provider transport forbidden')


hr.HttpSseTransport = NoNative
real_build = hrt.build


def build(config):
    builder = real_build(config)

    def wrapped(owner, retain):
        comp = builder(owner, retain)
        store = comp.store
        counter = Path(count_s)
        ckpt = Path(ckpt_s)

        def faulted(run_id):
            # Observational counter first: every real resolver entry into
            # judgment_view is recorded. On the first call, inside the
            # caller's existing transaction snapshot, capture the REAL
            # pre-global committed checkpoint digest; then the injected
            # TypeError propagates through evaluate() unchanged in class.
            seen = int(counter.read_text()) if counter.exists() else 0
            counter.write_text(str(seen + 1))
            if not ckpt.exists():
                row = store._db.execute(
                    'SELECT body FROM runs WHERE id=?',
                    (run_id,)).fetchone()
                data = _unpack(json.loads(row[0]))
                ckpt.write_text(body_digest(
                    data.get('controller_checkpoint')))
            raise TypeError('injected resolver bug')

        store.judgment_view = faulted
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


def _free_port():
    sock = socket.socket()
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class HostGlobalLatchTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name).resolve()
        root = self.dir / 'root'
        root.mkdir(mode=0o700)
        self.root = root
        cred = thr.write(self.dir / 'cred',
                         secrets.token_hex(32).encode())
        mpath = thr.write(self.dir / 'manifest.json',
                          thr.manifest_dict(self.dir, cred))
        launch = thr.write(self.dir / 'launch.json', {})
        doc = json.loads(mpath.read_text())
        prof = issue_profile(verify_manifest(doc, hr.read_evidence),
                             'responses')
        env = environment_ref(ENDPOINT, AUTH_REF, prof.profile_digest)
        wire = tpr.wire_entry(
            env=env, routes=[[thr.MODEL, ADAPTER, env]],
            route_bounds=[{'route': [thr.MODEL, ADAPTER, env],
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
            'routes': [{'model': thr.MODEL, 'adapter': ADAPTER,
                'endpoint': ENDPOINT, 'auth_ref': AUTH_REF,
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
                              'idle_s': 30, 'total_s': 60},
                'max_drain_s': 30,
                'verification': {'use_case': 'general',
                    'official_ref': 'r:o', 'implementation_ref': 'r:i',
                    'measurement_ref': 'r:m', 'ac_ref': 'r:a',
                    'output_mode': 'collect'}}]}
        self.ledger_path = Path(ledger)
        self.config = thr.write(self.dir / 'config.json',
                                config)

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
            if proc.poll() is not None:
                self.fail('child exited %r: %s'
                          % (proc.returncode, proc.stderr.read()))
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.02)

    def wait_exit(self, proc, timeout=60):
        try:
            proc.wait(timeout)
        except subprocess.TimeoutExpired:
            self._reap(proc)
            self.fail('child never exited')
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

    def test_resolver_typeerror_latches_host_503_owner_held(self):
        paths = [self.dir / n for n in
                 ('ready', 'url', 'native', 'count', 'ckpt')]
        proc = subprocess.Popen(
            [sys.executable, '-c', CHILD, str(self.config),
             *(str(p) for p in paths), str(TESTS), str(SRC)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env={'PATH': '/usr/bin:/bin'})
        self.addCleanup(self._reap, proc)
        ready, url_f, native, count, ckpt = paths
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
        response_id = payload['id']      # wire resp_*, never run_*
        deadline = time.monotonic() + 20
        seen = None
        while seen != 503 and time.monotonic() < deadline:
            seen, _ = self.get(port, '/v1/models')
            time.sleep(0.02)
        self.assertEqual(seen, 503)            # real listener, real latch
        self.assertIsNone(proc.poll())         # alive, owner held
        with self.assertRaises(OwnerUnavailable) as ctx:
            ServiceOwner.acquire(self.root)
        self.assertEqual(ctx.exception.code, 'owned_elsewhere')
        deadline = time.monotonic() + 10       # resolver actually invoked
        while not count.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        first = int(count.read_text())
        self.assertGreaterEqual(first, 1)
        time.sleep(0.5)
        self.assertEqual(int(count.read_text()), first)  # driver stopped
        self.assertFalse(native.exists())     # zero provider transport
        self.assertTrue(ckpt.exists())        # real pre-global baseline
        os.kill(proc.pid, signal.SIGTERM)
        self.assertEqual(self.wait_exit(proc), 0)
        owner = ServiceOwner.acquire(self.root)
        broker = IngressBroker(
            lambda: datetime.now(timezone.utc).isoformat())
        store = ControlStore(self.root / 'control.sqlite',
            verifier=broker.verifier, evidence=lambda *_: None,
            profile_resolver=lambda alias: None, guard=owner.check)
        try:
            # Authenticated principal-scoped lookup maps the wire
            # response id to the internal run_id through the real
            # one-shot IngressBroker verifier and real Gateway.
            with broker.receipt_ref(
                    'p1', lookup_body(response_id)) as ref:
                run_id = store.gateway().lookup(response_id, ref).run_id
            state = store.controller()
            run = state.get_run(run_id)
            self.assertIs(run.state, c.State.PENDING)   # no ERROR/FAILED
            self.assertIsNone(run.final_reason)
            self.assertFalse(run.stop_requested)
            self.assertEqual(run.job_ids, ())
            self.assertEqual(state.attempts(run_id), ())
            for kind in ('job_goals', 'run_goals', 'driver_audit',
                         'events', 'job_failures'):
                self.assertEqual(state.history(run_id, kind), ())
            # Digest equality against the child-captured pre-global
            # baseline: no _save ever ran after the global failure.
            self.assertEqual(body_digest(state.checkpoint(run_id)),
                             ckpt.read_text())
        finally:
            store.close()
            owner.close()
        self.assertEqual(CapacityLedger(self.ledger_path).count(
            ADAPTER), 0)
        self.assertFalse(native.exists())


if __name__ == '__main__':
    unittest.main()
