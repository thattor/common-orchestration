# tests/test_host_callback_hard_deny.py
"""Profile-Run live Native-callback boundary on the real host stack (#190 M3).

A real owned subprocess runs co_v4.cli.main with the PRODUCTION
host_runtime.build -> ServiceHost -> ServiceOwner -> ControlStore /
OutputStore / CapacityLedger / PooledAdapter / real OpenAI adapter chain,
the real make_evidence resolver, real Judgment transactions, the real
QualifiedRouteGate verify_manifest/issue_profile path, the REAL
make_models_probe wire GET, the real hr.HttpSseTransport worker
transport and a real loopback HttpService — the same composition proof
as test_host_controller_global_active_lease (fixture provider and the
declared launch_attested seam included; this is NOT provider/model
qualification and the OpenAI wire is NOT claimed to support Native
callbacks — protocol-specific tool-call policy lives in the adapter's
own suite).

Under test: a durably admitted pure-profile Attempt whose Adapter emits
ONE valid typed ConfirmationEvent. The test-owned wrapper inserts it
into the REAL child _Attempt event journal under pool._lock, bound to
the exact live AttemptRef — the event then flows through the real
pool.events cursor translation like any genuine Native event (no
synthetic id is ever returned that the journal does not contain, so no
'unknown event cursor' channel fault can masquerade as a held proof).
The real Controller._events / _poll / request_internal_stop / _stop
path must then hold the boundary: committed ConfirmationEvent as
evidence, the durable 'approval_required' stop barrier, a decisive
failed/approval_required projection — and no WaitingHuman, Approval,
Answer, AC, adopted output or fabricated COMPLETED. The stop itself is
the real transport drain: whatever Result/StopReply it genuinely yields
is committed (nothing forced or faked); a CONFIRMED+Result settlement
finalizes FAILED/approval_required with the lease released, otherwise
the Attempt stays honestly held.
"""
import http.client
import json
import os
import secrets
import signal
import subprocess
import sys
import time
import unittest
from pathlib import Path

from co_v4 import contracts as c
from co_v4.adapter_capacity import CapacityLedger
from co_v4.gateway_store import lookup_body
from co_v4.service_owner import ServiceOwner
import test_host_controller_global_active_lease as gal

TESTS = Path(__file__).resolve().parent
SRC = TESTS.parent
ADAPTER = 'openai.responses'

CHILD = r'''
import sys
from dataclasses import replace
from pathlib import Path
cfg_s, ready_s, url_s, armed_s = sys.argv[1:5]
sys.path[:0] = sys.argv[5:]
import co_v4.cli as cli
import co_v4.host_routes as hr
import co_v4.host_runtime as hrt
from co_v4 import contracts as c
from co_v4.service_host import ServiceHost

real_build = hrt.build
armed_path = Path(armed_s)


def build(config):
    builder = real_build(config)

    def wrapped(owner, retain):
        # DECLARED fixture attestation (test-only), identical to the
        # active-lease suite: never provider qualification evidence.
        hr.LaunchAttestor = (
            lambda record, credential: (
                lambda manifest_fields, endpoint, auth_ref: True))
        comp = builder(owner, retain)
        # Test-owned seam: on the first armed events() call, insert ONE
        # valid typed ConfirmationEvent into the real child _Attempt
        # journal, under pool._lock (the same lock pool.events/stop
        # serialize on). The event's id then exists in the journal, so
        # the Controller's persisted cursor always resolves through the
        # real events(ref, after) translation — every subsequent real
        # event drains coherently after it. Bound to the live ref;
        # injected exactly once; no declared effect is executed.
        pool = comp.adapters['openai.responses']
        real_events = pool.events
        injected = []

        def events(ref, after=None):
            with pool._lock:
                if armed_path.exists() and not injected:
                    child = pool._children.get(ref)
                    attempt = (None if child is None
                               else child._attempts.get(ref))
                    if attempt is not None:
                        injected.append(ref)
                        conf = c.Confirmation(
                            ref=ref, request_id='cb-' + ref.attempt_id,
                            decision=c.Decision.CONFIRM,
                            requested_action=c.Action(
                                'native.tool.write',
                                c.Scope((('effect', 'fixture'),),
                                        complete=True)),
                            reason='fixture native confirmation',
                            native_source='fixture:callback',
                            can_respond=True)
                        attempt.events.append(c.ConfirmationEvent(
                            ref, 'cb-' + ref.attempt_id, conf))
            return real_events(ref, after)

        pool.events = events
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


class CallbackHardDenyTests(unittest.TestCase):
    def setUp(self):
        # Composition, not inheritance: reuse the owned fixture stack
        # (provider, config, broker, token, helpers) without re-running
        # its TestCase under discovery.
        self.fx = gal.ActiveLeaseGlobalLatchTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.provider = self.fx.provider

    def _spawn(self):
        paths = [self.fx.dir / n for n in ('ready', 'url', 'armed')]
        proc = subprocess.Popen(
            [sys.executable, '-c', CHILD, str(self.fx.config),
             *(str(p) for p in paths), str(TESTS), str(SRC)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env={'PATH': '/usr/bin:/bin'})
        self.addCleanup(self.fx._reap, proc)
        self.fx.wait_ready(proc, paths[0])
        port = int(paths[1].read_text().rsplit(':', 1)[1])
        return proc, port, paths[2]

    def _post(self, port):
        conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
        try:
            body = json.dumps({'model': gal.ALIAS, 'input': 'x',
                               'background': True}).encode()
            conn.request('POST', '/v1/responses', body=body, headers={
                'Authorization': 'Bearer ' + self.fx.token,
                'Content-Type': 'application/json'})
            resp = conn.getresponse()
            return resp.status, json.loads(resp.read())
        finally:
            conn.close()

    def _run_id(self, store, response_id):
        with self.fx.broker.receipt_ref(
                'p1', lookup_body(response_id)) as ref:
            return store.gateway().lookup(response_id, ref).run_id

    def _wait_admitted(self, proc, store, ledger, run_id):
        """Committed facts only: durable Attempt, ACCEPTED receipt,
        live 'executing' lease."""
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            attempts = store.controller().attempts(run_id)
            ref = attempts[0].ref if len(attempts) == 1 else None
            row = ledger.row(ref, ADAPTER) if ref is not None else None
            receipt = (store.controller().execute_receipt(ref)
                       if ref is not None else None)
            if (ref is not None and row is not None
                    and row[2] == 'executing'
                    and receipt is not None
                    and receipt.status == c.OperationStatus.ACCEPTED):
                return ref
            if proc.poll() is not None:
                self.fail('child_exit:%s' % proc.returncode)
            time.sleep(0.02)
        self.fail('admission_never_observed')

    def test_confirmation_event_hard_deny_approval_barrier(self):
        proc, port, armed = self._spawn()
        status, payload = self._post(port)
        self.assertEqual((status, payload.get('status')),
                         (200, 'queued'))
        response_id = payload['id']

        store = self.fx.store_handle()
        self.addCleanup(store.close)
        state = store.controller()
        ledger = CapacityLedger(self.fx.ledger_path)
        run_id = self._run_id(store, response_id)

        # Arm only after the real wire POST is in flight and the Attempt
        # is durably admitted with an ACCEPTED receipt.
        attempt_ref = self._wait_admitted(proc, store, ledger, run_id)
        self.assertEqual(self.provider.posts, ['/v1/responses'])
        self.assertIs(state.get_run(run_id).state, c.State.RUNNING)

        armed.write_text('armed')
        # Poll a consistent committed pair, not stop_origin alone: the
        # durable approval barrier AND at least one real committed
        # StopReply (the real drain takes up to the route max_drain).
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            if (state.stop_origin(run_id) == 'approval_required'
                    and state.history(run_id, 'stop_history')):
                break
            if proc.poll() is not None:
                self.fail('child_exit:%s' % proc.returncode)
            time.sleep(0.05)
        self.assertEqual(state.stop_origin(run_id), 'approval_required')
        stops = state.history(run_id, 'stop_history')
        self.assertTrue(stops)                          # real stop ran
        self.assertTrue(all(s.ref == attempt_ref for s in stops))

        # === Committed boundary facts ===
        run = state.get_run(run_id)
        self.assertTrue(run.stop_requested)
        self.assertIsNone(run.output_selection)
        self.assertNotEqual(run.state, c.State.COMPLETED)  # never faked
        events = state.history(run_id, 'events')
        # Genuine StatusEvents (pending/running/…) coexist; exactly one
        # ConfirmationEvent, bound to the live Attempt, and no adoption
        # records of any kind.
        confirmations = [e for e in events
                         if isinstance(e, c.ConfirmationEvent)]
        self.assertEqual(len(confirmations), 1)
        event = confirmations[0]
        self.assertEqual(event.ref, attempt_ref)
        self.assertEqual(event.confirmation.request_id,
                         'cb-' + attempt_ref.attempt_id)
        self.assertIs(event.confirmation.decision, c.Decision.CONFIRM)
        self.assertTrue(all(e.ref == attempt_ref for e in events))
        attempt = state.get_attempt(attempt_ref)
        self.assertIsNone(attempt.ac)                  # no AC ran
        self.assertIsNone(attempt.output)              # no adopted output
        self.assertIsNone(attempt.collection_failure)
        # No Human channel artifacts: no wait, approval, answer, relay.
        self.assertEqual(state.waits(run_id), ())
        for kind in ('approvals', 'answers', 'ac_history', 'job_goals',
                     'run_goals', 'job_failures', 'rejections',
                     'timeouts', 'driver_audit'):
            self.assertEqual(state.history(run_id, kind), ())

        # === Settlement-consistent outcome ===
        # The real stop drain decides: a genuine terminal Result plus
        # CONFIRMED cessation settles 'native' and the barrier finalizes
        # the Run FAILED/approval_required with the lease released;
        # anything else stays honestly held — no fabricated proof.
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            settled = state.attempt_settlement(attempt_ref)
            run = state.get_run(run_id)
            if settled == 'native' and run.state in c.TERMINAL:
                break
            if proc.poll() is not None:
                self.fail('child_exit:%s' % proc.returncode)
            time.sleep(0.05)
        settled = state.attempt_settlement(attempt_ref)
        attempt = state.get_attempt(attempt_ref)
        run = state.get_run(run_id)
        if settled == 'native':
            # Real Result + real CONFIRMED stop: terminal FAILED with
            # the approval barrier as final reason; capacity released.
            self.assertIs(run.state, c.State.FAILED)
            self.assertEqual(run.final_reason, 'approval_required')
            self.assertIsNotNone(attempt.result)
            self.assertIs(attempt.stop_reply.status,
                          c.StopStatus.CONFIRMED)
            self.assertEqual(ledger.row(attempt_ref, ADAPTER)[2],
                             'released')
        else:
            # Cessation/settlement unproven: held, never finalized.
            self.assertIs(run.state, c.State.RUNNING)
            self.assertIsNone(run.final_reason)
            self.assertEqual(ledger.row(attempt_ref, ADAPTER)[2],
                             'executing')

        # === Public surface: decisive failed/approval_required ===
        with self.fx.broker.receipt_ref(
                'p1', lookup_body(response_id)) as ref:
            proj = store.gateway().read(response_id, ref)
        self.assertEqual((proj.status, proj.code, proj.decided),
                         ('failed', 'approval_required', True))
        http_status, body = self.fx.get(
            port, '/v1/responses/' + response_id)
        self.assertEqual(http_status, 200)
        self.assertEqual(json.loads(body).get('status'), 'failed')
        self.assertIn('approval_required', body.decode())

        # === A second valid Run still progresses; no global latch ===
        status2, payload2 = self._post(port)
        self.assertEqual((status2, payload2.get('status')),
                         (200, 'queued'))
        response_id2 = payload2['id']
        run_id2 = self._run_id(store, response_id2)
        ref2 = self._wait_admitted(proc, store, ledger, run_id2)
        self.assertNotEqual(ref2, attempt_ref)
        deadline = time.monotonic() + 30
        while len(self.provider.posts) < 2 \
                and time.monotonic() < deadline:
            if proc.poll() is not None:
                self.fail('child_exit:%s' % proc.returncode)
            time.sleep(0.02)
        self.assertEqual(len(self.provider.posts), 2)   # run2 POST only
        run2 = state.get_run(run_id2)
        self.assertIs(run2.state, c.State.RUNNING)
        self.assertFalse(run2.stop_requested)
        self.assertIsNone(state.stop_origin(run_id2))
        self.assertFalse(any(isinstance(e, c.ConfirmationEvent)
                             for e in state.history(run_id2, 'events')))
        with self.fx.broker.receipt_ref(
                'p1', lookup_body(response_id2)) as ref:
            proj2 = store.gateway().read(response_id2, ref)
        self.assertEqual(proj2.status, 'in_progress')
        seen, _ = self.fx.get(port, '/v1/models')
        self.assertEqual(seen, 200)                     # no global 503

        # === Real bounded shutdown; held facts survive ===
        os.kill(proc.pid, signal.SIGTERM)
        self.assertEqual(self.fx.wait_exit(proc), 0)
        owner = ServiceOwner.acquire(self.fx.root)
        owner.close()
        run = state.get_run(run_id)
        self.assertTrue(run.stop_requested)
        self.assertEqual(state.stop_origin(run_id), 'approval_required')
        self.assertEqual(len([e for e in state.history(run_id, 'events')
                              if isinstance(e, c.ConfirmationEvent)]), 1)
        if state.attempt_settlement(attempt_ref) == 'native':
            self.assertIs(run.state, c.State.FAILED)
            self.assertEqual(run.final_reason, 'approval_required')
            self.assertEqual(ledger.row(attempt_ref, ADAPTER)[2],
                             'released')
        else:
            self.assertIs(run.state, c.State.RUNNING)
            self.assertEqual(ledger.row(attempt_ref, ADAPTER)[2],
                             'executing')
        self.assertEqual(len(self.provider.posts), 2)   # no resend

        self.provider.close()
        self.assertTrue(self.provider.handler_done)


if __name__ == '__main__':
    unittest.main()
