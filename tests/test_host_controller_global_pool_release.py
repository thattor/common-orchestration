# tests/test_host_controller_global_pool_release.py
"""Pool release()-site global fault -> real host 503 latch (#190 M3 P1).

Same production chain as test_host_controller_global_http, but the
GLOBAL_FAILURES injection sits at the ACTUAL defect site: the real
PooledAdapter.execute() calls ledger.release() after a genuine
request-bound NeverStarted receipt — sqlite3.Error must propagate
through Controller.step() -> driver tick -> host latch (HTTP 503),
never degrade to a per-Attempt ERROR receipt.

Fixture boundaries (controlled, NOT provider/model qualification):
- NoNative forbids any provider transport construction outright.
- Refuse is a side-effect-free fixture child installed on the real
  pool's .factory AFTER the production build composes it: a typed
  OutputCollector whose execute() returns a real request-bound
  NeverStarted before any transport. The child is in-process test code,
  never a provider claim.
- ledger.release is wrapped to snapshot the committed write-ahead
  checkpoint digest INSIDE the fault (the true baseline — the failed
  step skips _save) and then raise one fixed sqlite3.Error instance.
"""
import http.client
import json
import os
import signal
import subprocess
import sys
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path

from co_v4 import contracts as c
from co_v4.adapter_capacity import CapacityLedger
from co_v4.gateway_store import lookup_body
from co_v4.http_auth import IngressBroker
from co_v4.process_identity import (ProcessIdentityRejected,
                                    read_owned_process)
from co_v4.service_owner import OwnerUnavailable, ServiceOwner
from co_v4.state import ControlStore, body_digest
import test_host_controller_global_http as base

TESTS, SRC, ADAPTER = base.TESTS, base.SRC, base.ADAPTER

CHILD = r'''
import sqlite3, sys
from dataclasses import replace
from pathlib import Path
cfg_s, ready_s, url_s, native_s, count_s, ckpt_s, calls_s = sys.argv[1:8]
sys.path[:0] = sys.argv[8:]
import co_v4.cli as cli
import co_v4.host_routes as hr
import co_v4.host_runtime as hrt
from co_v4 import contracts as c
from co_v4.service_host import ServiceHost
from co_v4.state import body_digest


class NoNative:
    """Forbidden provider seam: construction is observed, then refused."""
    def __init__(self, *a, **k):
        Path(native_s).write_text('x')
        raise AssertionError('provider transport forbidden')


hr.HttpSseTransport = NoNative


def bump(i):
    p = Path(calls_s)
    parts = (p.read_text() if p.exists() else '0,0,0').split(',')
    parts[i] = str(int(parts[i]) + 1)
    p.write_text(','.join(parts))


class Refuse:
    """Fixture child on the real pool's .factory: side-effect-free
    construction, a typed OutputCollector, and execute() returns a
    genuine request-bound NeverStarted BEFORE any transport — the exact
    release site under test."""
    def execute(self, request):
        bump(1)
        return c.OperationReply(request.ref,
            c.OperationStatus.UNSUPPORTED, 'preflight refusal',
            never_started=c.NeverStarted(
                request, 'fixture:before-transport'))
    def stop(self, ref):
        bump(2)
        return c.StopReply(ref, c.StopStatus.UNCONFIRMED, 'fixture stop')
    def collect_output(self, ref):
        return ()


real_build = hrt.build
FAULT = sqlite3.Error('injected ledger release loss')


def build(config):
    builder = real_build(config)

    def wrapped(owner, retain):
        comp = builder(owner, retain)
        pool = comp.adapters['openai.responses']
        state = comp.store.controller()

        def factory(request):
            bump(0)
            return Refuse()
        pool.factory = factory

        def release(request, own, evidence):
            # Fault-instant baseline: snapshot the committed write-ahead
            # checkpoint (active=Attempt, pending_io='execute') BEFORE
            # raising — the failed step skips _save, so this digest is
            # the true pre-global record, immune to later _save races.
            counter = Path(count_s)
            seen = int(counter.read_text()) if counter.exists() else 0
            counter.write_text(str(seen + 1))
            ckpt = Path(ckpt_s)
            if not ckpt.exists():
                ckpt.write_text(body_digest(
                    state.checkpoint(request.ref.run_id)))
            raise FAULT                    # one fixed global instance
        pool.ledger.release = release

        factory_http = comp.http_factory

        def ready_http(available):
            service = factory_http(available)
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


class PoolReleaseGlobalLatchTests(base.HostGlobalLatchTests):
    # Composed reuse: base setUp/config/helpers run verbatim. The
    # resolver-fault test lives in the base file; non-callable here so
    # it is never re-collected under this class.
    test_resolver_typeerror_latches_host_503_owner_held = None

    def test_pool_release_sqlite_fault_latches_503_lease_held(self):
        paths = [self.dir / n for n in
                 ('ready', 'url', 'native', 'count', 'ckpt', 'calls')]
        proc = subprocess.Popen(
            [sys.executable, '-c', CHILD, str(self.config),
             *(str(p) for p in paths), str(TESTS), str(SRC)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env={'PATH': '/usr/bin:/bin'})
        self.addCleanup(self._reap, proc)
        ready, url_f, native, count, ckpt, calls = paths
        self.wait_ready(proc, ready)
        port = int(url_f.read_text().rsplit(':', 1)[1])
        # Kernel-attested identity of the owned child before signalling.
        ident = read_owned_process(proc.pid, os.getuid())
        self.assertEqual((ident.pid, ident.uid), (proc.pid, os.getuid()))
        conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
        try:
            body = json.dumps({'model': base.ALIAS, 'input': 'x',
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
        deadline, seen = time.monotonic() + 20, None
        while seen != 503 and time.monotonic() < deadline:
            seen, _ = self.get(port, '/v1/models')
            time.sleep(0.02)
        self.assertEqual(seen, 503)               # real listener latch
        self.assertIsNone(proc.poll())            # alive, owner held
        with self.assertRaises(OwnerUnavailable) as ctx:
            ServiceOwner.acquire(self.root)
        self.assertEqual(ctx.exception.code, 'owned_elsewhere')
        deadline = time.monotonic() + 10
        while not count.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        # The real release() site fired exactly once; the fault-instant
        # checkpoint baseline exists; zero provider transport.
        self.assertEqual(count.read_text(), '1')
        self.assertTrue(ckpt.exists())
        self.assertEqual(calls.read_text(), '1,1,0')  # factory+execute, 0 stop
        self.assertFalse(native.exists())
        time.sleep(0.5)
        self.assertEqual(count.read_text(), '1')   # driver stopped
        os.kill(proc.pid, signal.SIGTERM)
        self.assertEqual(self.wait_exit(proc), 0)
        # Kernel birth/uid checked pre-kill; post-exit read must be dead.
        with self.assertRaises(ProcessIdentityRejected) as dead:
            read_owned_process(proc.pid, os.getuid(),
                               (ident.start_sec, ident.start_usec))
        self.assertEqual(dead.exception.reason, 'dead')
        owner = ServiceOwner.acquire(self.root)    # owner freed by exit
        broker = IngressBroker(
            lambda: datetime.now(timezone.utc).isoformat())
        store = ControlStore(self.root / 'control.sqlite',
            verifier=broker.verifier, evidence=lambda *_: None,
            profile_resolver=lambda alias: None, guard=owner.check)
        try:
            with broker.receipt_ref(
                    'p1', lookup_body(response_id)) as ref:
                run_id = store.gateway().lookup(response_id, ref).run_id
            state = store.controller()
            attempt_ref, = (a.ref for a in state.attempts(run_id))
            # Exactly one admitted Attempt; the execute receipt was
            # NEVER committed — the fault preceded _record_execute_receipt.
            self.assertIsNone(state.execute_receipt(attempt_ref))
            run = state.get_run(run_id)
            self.assertIs(run.state, c.State.RUNNING)  # no ERROR/FAILED
            self.assertIsNone(run.final_reason)
            self.assertIsNone(run.output_selection)
            self.assertFalse(run.stop_requested)
            attempt = state.get_attempt(attempt_ref)
            self.assertIsNone(attempt.result)
            self.assertIsNone(attempt.stop_reply)      # no fake cessation
            self.assertIsNone(attempt.ac)
            self.assertIsNone(state.attempt_settlement(attempt_ref))
            for kind in ('job_goals', 'run_goals', 'driver_audit',
                         'events', 'job_failures', 'ac_history',
                         'stop_history', 'execute_history'):
                self.assertEqual(state.history(run_id, kind), ())
            # The committed checkpoint is exactly the fault-instant
            # write-ahead: active Attempt pinned, pending_io='execute',
            # byte-identical digest — no post-global _save ever ran.
            snapshot = state.checkpoint(run_id)
            self.assertEqual(snapshot.active, attempt_ref)
            self.assertEqual(snapshot.pending_io, 'execute')
            self.assertEqual(body_digest(snapshot), ckpt.read_text())
            # Held, not freed: the durable lease stays 'executing' and
            # the child was never re-invoked — no resend, no Result.
            self.assertEqual(CapacityLedger(self.ledger_path).row(
                attempt_ref, ADAPTER)[2], 'executing')
            self.assertEqual(calls.read_text(), '1,1,0')
        finally:
            store.close()
            owner.close()


if __name__ == '__main__':
    unittest.main()
