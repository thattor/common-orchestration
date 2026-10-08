"""OutputStore and Contract-marker unit checks; synthetic bytes only."""
import hashlib
import os
import sqlite3
import stat
import threading
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from co_v4 import contracts as c
from co_v4.output_store import DOMAIN, IntegrityError, OutputRejected, OutputStore
from co_v4.state import (ControlStore, IngressReceipt, StoreUnavailable,
                         body_digest, create_run_body)


REF = c.AttemptRef('r', 'j', 'a')
# sha256(b'hello') — fixed golden value, independent of implementation.
HELLO = 'sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.store = OutputStore(Path(self.tmp.name) / 'outputs')

    def put(self, text='hello'):
        return self.store.put(REF, (c.OutputItem(0, 'text/plain', text),))

    def test_golden_blob_manifest_and_domain_digest(self):
        out = self.put()
        meta, = out.items
        self.assertEqual(meta.blob_digest, HELLO)
        self.assertEqual((meta.index, meta.media_type, meta.size), (0, 'text/plain', 5))
        expected = (b'[{"blob_digest":"' + HELLO.encode() +
                    b'","index":0,"media_type":"text/plain","size":5}]')
        manifest = self.store.root / 'manifests' / out.digest[7:]
        self.assertEqual(manifest.read_bytes(), expected)
        self.assertEqual(out.digest,
                         'sha256:' + hashlib.sha256(DOMAIN + expected).hexdigest())
        self.assertIsNone(out.created_at)  # control state stamps it, not the store

    def test_exact_utf8_no_normalization_and_idempotent_content(self):
        text = 'café 日本語 \n'
        out = self.put(text)
        blob = self.store.root / 'blobs' / out.items[0].blob_digest[7:]
        self.assertEqual(blob.read_bytes(), text.encode('utf-8'))
        self.assertEqual(out.items[0].size, len(text.encode('utf-8')))
        replay = self.put(text)
        self.assertEqual((replay.digest, replay.items), (out.digest, out.items))
        ref = c.OutputRef(REF, out.digest)
        self.assertEqual(self.store.get(ref, out), (text,))

    def test_get_rejects_wrong_attempt_digest_and_corrupt_objects(self):
        out = self.put()
        other = c.OutputRef(c.AttemptRef('r', 'j', 'b'), out.digest)
        with self.assertRaises(IntegrityError):
            self.store.get(other, out)
        wrong = c.OutputRef(REF, 'sha256:' + '0' * 64)
        with self.assertRaises(IntegrityError):
            self.store.get(wrong, out)
        blob = self.store.root / 'blobs' / HELLO[7:]
        blob.write_bytes(b'tampered')
        with self.assertRaises(IntegrityError):
            self.put()
        blob.write_bytes(b'hello')
        manifest = self.store.root / 'manifests' / out.digest[7:]
        manifest.write_bytes(b'{"not":"the manifest"}')
        with self.assertRaises(IntegrityError):
            self.store.get(c.OutputRef(REF, out.digest), out)

    def test_schema_and_index_rejection_is_policy_not_storage(self):
        with self.assertRaises(OutputRejected):
            self.store.put(REF, ({'text': 'x'},))
        with self.assertRaises(OutputRejected):
            self.store.put(REF, (c.OutputItem(1, 'text/plain', 'x'),))
        with self.assertRaises(ValueError):
            c.OutputItem(0, 'application/json', 'x')
        # The canonical contract permits exact empty text: it persists as a
        # zero-byte blob and round-trips verbatim. A non-empty accepted
        # candidate is a Controller-side gate, never the store's.
        empty = self.put('')
        self.assertEqual(empty.items[0].size, 0)
        self.assertEqual(self.store.get(c.OutputRef(REF, empty.digest), empty),
                         ('',))

    def test_identical_existing_entry_still_dir_fsyncs(self):
        """Same-bytes replay still fsyncs each object directory itself; the
        winner's earlier fsync does not cover this call's promise.

        Fsync targets are classified live with fstat at call time — a closed
        directory fd number later reused by a regular tmp-file fsync must
        never be miscounted as directory durability."""
        out = self.put()
        dir_fsyncs = []
        real_fsync = os.fsync

        def tracked_fsync(fd):
            try:
                if stat.S_ISDIR(os.fstat(fd).st_mode):
                    dir_fsyncs.append(fd)
            except OSError:
                pass
            return real_fsync(fd)

        with mock.patch.object(os, 'fsync', tracked_fsync):
            replay = self.put()
        self.assertEqual((replay.digest, replay.items), (out.digest, out.items))
        # Blob and manifest commits each hit EEXIST on identical bytes; each
        # must still fsync its own directory before returning success.
        self.assertEqual(len(dir_fsyncs), 2)

    def test_same_bytes_replay_cannot_return_before_dir_fsync(self):
        """Failure injection: hold the directory fsync and prove a same-bytes
        put() does not report success while its own fsync is still pending —
        the window where the link winner crashed before its dir fsync.

        On the unfixed path the EEXIST return opens no directory at all, so
        the gate is never reached and gate.wait itself fails the test.
        """
        out = self.put()
        gate, release = threading.Event(), threading.Event()
        real_fsync = os.fsync

        def gated_fsync(fd):
            try:
                if stat.S_ISDIR(os.fstat(fd).st_mode):
                    gate.set()          # this put reached its own dir fsync
                    release.wait(10)    # hold durability until released
            except OSError:
                pass
            return real_fsync(fd)

        done, failures = [], []

        def work():
            try:
                done.append(self.put())
            except Exception as exc:    # surfaced and asserted below
                failures.append(exc)

        with mock.patch.object(os, 'fsync', gated_fsync):
            worker = threading.Thread(target=work)
            try:
                worker.start()
                self.assertTrue(gate.wait(10))
                # The event itself proves the put is inside its fsync; it must
                # not have already reported success.
                self.assertEqual(done, [])
                self.assertEqual(failures, [])
            finally:
                release.set()
                worker.join(10)
        self.assertFalse(worker.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(len(done), 1)
        self.assertEqual(done[0].digest, out.digest)


class ContractMarkerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'control.sqlite'

    def connect(self):
        return ControlStore(self.path,
            verifier=lambda ref: IngressReceipt('p', ref, body_digest(
                create_run_body('r', 'i')), '2026-09-28T00:00:00Z'),
            evidence=lambda *_: None)

    def tables(self, path):
        db = sqlite3.connect(path)
        try:
            return {r[0] for r in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
        finally:
            db.close()

    def test_fresh_marker_and_refusal_without_modifying_old_state(self):
        store = self.connect()
        row = store._db.execute('SELECT contract FROM meta WHERE id=1').fetchone()
        self.assertEqual(row, ('co.controller/4',))
        store.close()
        self.connect().close()  # marked store reopens

        foreign = Path(self.tmp.name) / 'foreign.sqlite'
        db = sqlite3.connect(foreign)
        db.execute('CREATE TABLE data (v TEXT)'); db.commit(); db.close()
        self.path = foreign
        with self.assertRaises(StoreUnavailable):
            self.connect()
        self.assertNotIn('meta', self.tables(foreign))  # untouched

        v3 = Path(self.tmp.name) / 'v3.sqlite'
        db = sqlite3.connect(v3)
        db.execute('CREATE TABLE runs (id TEXT PRIMARY KEY, body TEXT NOT NULL)')
        db.commit(); db.close()
        self.path = v3
        with self.assertRaises(StoreUnavailable):
            self.connect()
        self.assertNotIn('meta', self.tables(v3))

        mismatched = Path(self.tmp.name) / 'old.sqlite'
        db = sqlite3.connect(mismatched)
        db.execute("CREATE TABLE meta (id INTEGER PRIMARY KEY CHECK(id=1), contract TEXT NOT NULL)")
        db.execute("INSERT INTO meta VALUES (1, 'co.controller/3')")
        db.execute('CREATE TABLE runs (id TEXT PRIMARY KEY, body TEXT NOT NULL)')
        db.execute('CREATE TABLE ingress (event TEXT PRIMARY KEY, binding TEXT NOT NULL)')
        db.execute('''CREATE TABLE resumes (
            id TEXT PRIMARY KEY, run TEXT NOT NULL, attempt TEXT NOT NULL,
            adapter TEXT NOT NULL, revision INTEGER NOT NULL, opaque BLOB NOT NULL)''')
        db.commit(); db.close()
        self.path = mismatched
        with self.assertRaises(StoreUnavailable):
            self.connect()


if __name__ == '__main__': unittest.main()
