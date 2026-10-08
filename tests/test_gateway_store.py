"""M3 Gateway seam: single-transaction submit, replay and principal scope.

Synthetic control-store fixtures only; no provider, network or HTTP.
"""
from dataclasses import replace
from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest

from co_v4 import contracts as c
from co_v4.gateway_store import (GatewayRejected, Submission, lookup_body,
                                 submit_body)
from co_v4.http_auth import IngressBroker
from co_v4.responses_input import TaskIntent, parse
from co_v4.state import (ControlStore, Conflict, IngressReceipt, NotFound,
                         IntegrityViolation, StoreUnavailable, UntrustedInput,
                         body_digest)

NOW = '2026-10-06T00:00:00Z'
DIGEST = 'sha256:' + '0' * 64
PURE = c.TaskProfile('p-pure', DIGEST, 'pure')
EFFECTFUL = c.TaskProfile('p-effect', DIGEST, 'effectful')
TABLES = ('runs', 'ingress', 'gateway_responses', 'gateway_keys',
          'gateway_work', 'gateway_projections')


def intent(model='co-auto', **kw):
    return parse(json.dumps({'model': model, 'input': 'x', **kw}).encode())


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'control.sqlite'
        self.receipts, self.calls = {}, []
        self.profiles = {'co-auto': PURE, 'co-effect': EFFECTFUL}
        self.store = self.connect()
        self.gateway = self.store.gateway()
        self.addCleanup(self._close)

    def _close(self):
        try:
            self.store.close()
        except Exception:
            pass

    def connect(self):
        return ControlStore(self.path, verifier=self.receipts.__getitem__,
            evidence=lambda *_: None, clock=lambda: NOW,
            profile_resolver=self.resolve)

    def resolve(self, alias):
        self.calls.append(alias)
        return self.profiles[alias]

    def auth(self, source, body, principal='p1'):
        self.receipts[source] = IngressReceipt(
            principal, source, body_digest(body), NOW)
        return source

    def submit(self, req, key=None, source='e1', principal='p1'):
        return self.gateway.submit(req, key,
            self.auth(source, submit_body(req.body_hash, key), principal))

    def rows(self, table):
        return self.store._db.execute(
            'SELECT COUNT(*) FROM ' + table).fetchone()[0]

    def counts(self):
        return tuple(self.rows(t) for t in TABLES)

    def test_read_context_broker_oneshot_scope_restart(self):
        # Real IngressBroker: submit consumes the one-shot ref; reads mint
        # fresh receipts and resolve context from the durable row only.
        broker = IngressBroker(lambda: NOW)
        store = ControlStore(self.path, verifier=broker.verifier,
            evidence=lambda *_: None, clock=lambda: NOW,
            profile_resolver=self.resolve)
        self.addCleanup(store.close)
        gateway = store.gateway()
        req = intent()
        with broker.receipt_ref('p1', submit_body(req.body_hash, 'k')) as ref:
            sub = gateway.submit(req, 'k', ref)
        with self.assertRaises(UntrustedInput):      # ref popped at submit
            gateway.read(sub.response_id, ref)
        epoch = int(datetime(2026, 10, 6, tzinfo=timezone.utc).timestamp())
        with broker.receipt_ref('p1', lookup_body(sub.response_id)) as ref:
            ctx = gateway.read_context(sub.response_id, ref)
        self.assertIs(type(ctx.intent), TaskIntent)
        self.assertEqual((ctx.intent, ctx.created_at), (req, epoch))
        before = store._db.total_changes
        with broker.receipt_ref('p2', lookup_body(sub.response_id)) as ref:
            with self.assertRaises(NotFound):
                gateway.read_context(sub.response_id, ref)
        with broker.receipt_ref('p1', lookup_body('missing')) as ref:
            with self.assertRaises(NotFound):
                gateway.read_context('missing', ref)
        self.assertEqual(store._db.total_changes, before)  # write-free
        # Reconnect: a brand-new broker has no pending refs; the context
        # still resolves, proving no replay of the original receipt.
        store.close()
        broker2 = IngressBroker(lambda: NOW)
        store2 = ControlStore(self.path, verifier=broker2.verifier,
            evidence=lambda *_: None, clock=lambda: NOW,
            profile_resolver=self.resolve)
        self.addCleanup(store2.close)
        gateway2 = store2.gateway()
        with broker2.receipt_ref('p1', lookup_body(sub.response_id)) as ref:
            self.assertEqual(gateway2.read_context(sub.response_id, ref), ctx)
        with store2._tx():
            data, prior = store2._load_locked(sub.run_id)
            data['run'] = replace(data['run'], original_intent='{}')
            store2._store_locked(sub.run_id, data, prior)
        with broker2.receipt_ref('p1', lookup_body(sub.response_id)) as ref:
            with self.assertRaises(IntegrityViolation):
                gateway2.read_context(sub.response_id, ref)

    def test_read_context_row_integrity(self):
        # Trusted-SQL tamper fixture: corrupt gateway_responses fields and
        # the Run binding, restore between cases; every read uses a fresh
        # one-shot IngressBroker receipt.
        broker = IngressBroker(lambda: NOW)
        store = ControlStore(self.path, verifier=broker.verifier,
            evidence=lambda *_: None, clock=lambda: NOW,
            profile_resolver=self.resolve)
        self.addCleanup(store.close)
        gateway = store.gateway()
        req = intent()
        with broker.receipt_ref('p1', submit_body(req.body_hash, 'k')) as ref:
            sub = gateway.submit(req, 'k', ref)
        row_sql = ('SELECT request_digest, alias, created_at'
                   ' FROM gateway_responses WHERE response_id=?')
        good = store._db.execute(row_sql, (sub.response_id,)).fetchone()

        def ctx(principal='p1'):
            with broker.receipt_ref(principal,
                                    lookup_body(sub.response_id)) as ref:
                return gateway.read_context(sub.response_id, ref)

        def corrupt(digest=None, alias=None, at=None):
            store._db.execute(
                'UPDATE gateway_responses SET request_digest=?, alias=?,'
                ' created_at=? WHERE response_id=?',
                (good[0] if digest is None else digest,
                 good[1] if alias is None else alias,
                 good[2] if at is None else at, sub.response_id))

        def restore():
            store._db.execute(
                'UPDATE gateway_responses SET request_digest=?, alias=?,'
                ' created_at=? WHERE response_id=?',
                (*good, sub.response_id))

        corrupt(digest='sha256:' + 'f' * 64)
        with self.assertRaises(IntegrityViolation):
            ctx()
        corrupt(alias='co-effect')          # drifted alias binding
        with self.assertRaises(IntegrityViolation):
            ctx()
        # Mandatory bad-time list: malformed, naive, pre-epoch (negative).
        for bad_at in ('not-a-time', '2026-10-06T00:00:00',
                       '1960-01-01T00:00:00Z'):
            corrupt(at=bad_at)
            with self.assertRaises(IntegrityViolation):
                ctx()
        restore()
        # Corrupt the Run binding AND the row: a foreign principal still
        # gets the indistinguishable NotFound before any load/validation.
        with store._tx(sub.run_id) as data:
            data['run'] = replace(data['run'], run_id='other')
        corrupt(at='not-a-time')
        with self.assertRaises(IntegrityViolation):
            ctx()
        with self.assertRaises(NotFound):
            ctx(principal='p2')
        restore()
        with store._tx(sub.run_id) as data:
            data['run'] = replace(data['run'], run_id=sub.run_id)
        self.assertEqual(ctx().intent, req)

    def test_gateway_requires_resolver(self):
        plain = ControlStore(Path(self.tmp.name) / 'plain.sqlite',
            verifier=self.receipts.__getitem__, evidence=lambda *_: None)
        with self.assertRaises(StoreUnavailable):
            plain.gateway()
        plain.close()

    def test_submit_persists_pinned_run_and_exact_resend(self):
        req = intent()
        sub = self.submit(req, 'key-1')
        self.assertTrue(sub.created and sub.response_id.startswith('resp_'))
        self.assertNotIn(sub.run_id, sub.response_id)
        run = self.store.controller().get_run(sub.run_id)
        self.assertEqual(run.original_intent,
                         req.canonical_body.decode('utf-8'))
        self.assertEqual(run.authenticated_origin_ref, 'e1')
        # Persisted profile round-trips through _unpack: structural equality
        # on the frozen TaskProfile is the pin check, never object identity.
        self.assertEqual(run.profile, PURE)
        self.assertEqual(self.calls, ['co-auto'])
        self.assertEqual(self.gateway.pending_work(), (sub.run_id,))
        self.calls.clear()
        replay = self.gateway.submit(req, 'key-1', 'e1')
        self.assertEqual(replay, Submission(sub.response_id, sub.run_id,
                                            'co-auto', False))
        self.assertEqual(self.calls, [])
        self.assertEqual((self.rows('runs'), self.rows('ingress')), (1, 1))

    def test_keyless_pure_resend_and_new_events(self):
        req = intent()
        first = self.submit(req)
        self.assertTrue(first.created)
        self.assertEqual(self.submit(req).response_id, first.response_id)
        other = self.submit(req, source='e2')
        self.assertNotEqual(other.run_id, first.run_id)
        self.assertEqual(self.rows('runs'), 2)

    def test_key_conflict_and_key_replay(self):
        req, other = intent(), intent(input='y')
        sub = self.submit(req, 'k')
        self.auth('e1', submit_body(other.body_hash, 'k'))
        with self.assertRaises(Conflict):
            self.gateway.submit(other, 'k', 'e1')     # same event, new digest
        self.auth('e1', submit_body(req.body_hash, 'k2'))
        with self.assertRaises(Conflict):
            self.gateway.submit(req, 'k2', 'e1')      # same event, new key
        self.assertEqual(self.rows('runs'), 1)
        self.calls.clear()
        replay = self.submit(req, 'k', source='e2')
        self.assertEqual((replay.response_id, replay.created),
                         (sub.response_id, False))
        self.assertEqual(self.calls, [])
        self.assertEqual(self.rows('ingress'), 2)
        self.auth('e3', submit_body(other.body_hash, 'k'))
        with self.assertRaises(Conflict):
            self.gateway.submit(other, 'k', 'e3')     # same key, new digest
        self.assertEqual(self.rows('runs'), 1)

    def test_alias_rebind_does_not_move_pinned_run(self):
        req = intent()
        sub = self.submit(req, 'k')
        self.profiles['co-auto'] = EFFECTFUL
        self.calls.clear()
        self.assertEqual(self.submit(req, 'k', source='e2').response_id,
                         sub.response_id)
        self.assertEqual(self.calls, [])
        # Alias rebind does not move the pinned Run profile; all fields equal.
        self.assertEqual(self.store.controller().get_run(sub.run_id).profile,
                         PURE)

    def test_principal_isolation_and_read_only_lookup(self):
        req = intent()
        sub = self.submit(req, 'k', principal='p1')
        foreign = self.submit(req, 'k', source='e2', principal='p2')
        self.assertNotEqual(foreign.run_id, sub.run_id)
        before = self.store._db.total_changes
        self.auth('e3', lookup_body('missing'))
        with self.assertRaises(NotFound):
            self.gateway.lookup('missing', 'e3')
        self.auth('e4', lookup_body(sub.response_id), principal='p2')
        with self.assertRaises(NotFound):             # identical to missing
            self.gateway.lookup(sub.response_id, 'e4')
        self.auth('e5', lookup_body(sub.response_id))
        seen = self.gateway.lookup(sub.response_id, 'e5')
        self.assertEqual((seen.response_id, seen.run_id, seen.created),
                         (sub.response_id, sub.run_id, False))
        self.assertEqual(self.store._db.total_changes, before)

    def test_forged_intent_and_auth_fail_before_any_write(self):
        req = intent()
        before = self.counts()
        for bad in ({'forged': True}, replace(req, body_hash='0' * 64),
                    replace(req, canonical_body=b'{}')):
            with self.assertRaises(UntrustedInput):
                self.gateway.submit(bad, None, 'e9')
        with self.assertRaises(UntrustedInput):
            self.gateway.submit(req, None, 'no-such-receipt')
        for bad in ('', 'has space', 'k' * 256, 7):
            self.auth('bad', submit_body(req.body_hash, bad))
            with self.assertRaises(GatewayRejected):
                self.gateway.submit(req, bad, 'bad')
        self.assertEqual(self.counts(), before)

    def test_effectful_requires_key_and_background(self):
        req = intent(model='co-effect')
        self.auth('e1', submit_body(req.body_hash, None))
        with self.assertRaises(GatewayRejected):
            self.gateway.submit(req, None, 'e1')
        self.auth('e2', submit_body(req.body_hash, 'k'))
        with self.assertRaises(GatewayRejected):
            self.gateway.submit(req, 'k', 'e2')
        sub = self.submit(intent(model='co-effect', background=True),
                          'k', source='e3')
        self.assertTrue(sub.created)

    def test_resolver_failure_rolls_back_everything(self):
        req = intent(model='co-missing')
        self.auth('e1', submit_body(req.body_hash, 'k'))
        with self.assertRaises(GatewayRejected):
            self.gateway.submit(req, 'k', 'e1')
        self.assertEqual(self.counts(), (0,) * len(TABLES))

    def test_reopen_preserves_ids_and_pending_work(self):
        req = intent()
        sub = self.submit(req, 'k')
        self.store.close()
        self.store = self.connect()
        self.gateway = self.store.gateway()
        self.calls.clear()
        self.assertEqual(self.submit(req, 'k', source='e2').response_id,
                         sub.response_id)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.gateway.pending_work(), (sub.run_id,))


if __name__ == '__main__':
    unittest.main()
