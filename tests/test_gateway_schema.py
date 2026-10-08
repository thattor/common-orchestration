"""M3 gateway schema + shared Run-creation seam; synthetic fixtures only."""
from dataclasses import replace
from pathlib import Path
import sqlite3
import tempfile
import unittest

from co_v4.state import (CONTRACT_MARKER, GATEWAY_TABLES, Conflict,
                         ControlStore, IngressReceipt, Limits,
                         StoreUnavailable, UntrustedInput,
                         body_digest, create_run_body)

NOW = '2026-10-06T00:00:00Z'


class GatewaySchemaTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'control.sqlite'
        self.receipts = {}

    def connect(self, path=None):
        return ControlStore(path or self.path,
                            verifier=self.receipts.__getitem__,
                            evidence=lambda *_: None, clock=lambda: NOW)

    def receipt(self, source, body, limits=None):
        self.receipts[source] = IngressReceipt(
            'fixture-principal', source, body_digest(body), NOW, limits)

    def test_fresh_schema_has_gateway_tables_and_reopens(self):
        store = self.connect()
        tables = {r[0] for r in store._db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertEqual({'meta', 'runs', 'ingress', 'resumes'} | GATEWAY_TABLES,
                         tables)
        self.assertEqual(store._db.execute(
            'SELECT contract FROM meta WHERE id=1').fetchone(),
            (CONTRACT_MARKER,))
        store.close()
        self.connect().close()  # a marked full schema reopens

    def test_refused_stores_remain_byte_identical(self):
        cases = {}
        foreign = Path(self.tmp.name) / 'foreign.sqlite'
        db = sqlite3.connect(foreign)
        db.execute('CREATE TABLE data (v TEXT)'); db.commit(); db.close()
        cases['foreign-unmarked'] = foreign
        legacy = Path(self.tmp.name) / 'legacy.sqlite'
        db = sqlite3.connect(legacy)
        db.execute('CREATE TABLE meta (id INTEGER PRIMARY KEY CHECK(id=1), contract TEXT NOT NULL)')
        db.execute("INSERT INTO meta VALUES (1, 'co.controller/3')")
        db.execute('CREATE TABLE runs (id TEXT PRIMARY KEY, body TEXT NOT NULL)')
        db.commit(); db.close()
        cases['legacy-contract'] = legacy
        # A valid co.controller/4 marker missing any gateway table refuses
        # without migration, deletion or partial creation.
        for missing in sorted(GATEWAY_TABLES):
            path = Path(self.tmp.name) / ('incomplete-' + missing + '.sqlite')
            self.connect(path).close()
            db = sqlite3.connect(path)
            db.execute('DROP TABLE ' + missing); db.commit(); db.close()
            cases['missing-' + missing] = path
        for name, path in cases.items():
            before = path.read_bytes()
            with self.subTest(name=name), self.assertRaises(StoreUnavailable):
                self.connect(path)
            self.assertEqual(path.read_bytes(), before)

    def test_create_run_replay_limits_and_single_claim_unchanged(self):
        store = self.connect(); intake = store.intake()
        self.receipt('origin:r', create_run_body('r', 'intent'), Limits(2, 2, 2))
        run = intake.create_run('r', 'intent', 'origin:r')
        self.assertEqual(run.limits, Limits(2, 2, 2))
        self.assertEqual(store._claimed(self.receipts['origin:r']),
                         ('create', 'r', 'intent'))
        self.assertEqual(intake.create_run('r', 'intent', 'origin:r'), run)
        # Identical replay does not claim; the journal still holds one row.
        self.assertEqual(store._db.execute(
            'SELECT COUNT(*) FROM ingress').fetchone(), (1,))
        with self.assertRaises(UntrustedInput):
            intake.create_run('r', 'different', 'origin:r')
        # A verified receipt reusing the consumed source event conflicts and
        # rolls back the pending Run row in the same transaction.
        self.receipts['origin:r'] = replace(
            self.receipts['origin:r'],
            body_digest=body_digest(create_run_body('other', 'other intent')))
        with self.assertRaises(Conflict):
            intake.create_run('other', 'other intent', 'origin:r')
        self.assertIsNone(store._db.execute(
            "SELECT 1 FROM runs WHERE id='other'").fetchone())
        self.assertIsNone(store._claimed(IngressReceipt(
            'fixture-principal', 'unseen-event', body_digest('x'), NOW)))
        self.assertEqual(store._db.execute(
            'SELECT COUNT(*) FROM ingress').fetchone(), (1,))
        store.close()


if __name__ == '__main__':
    unittest.main()
