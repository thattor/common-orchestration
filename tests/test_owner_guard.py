"""Owner-guard integration: a real ServiceOwner guard wired into
ControlStore and OutputStore. Qualified Darwin arm64/APFS hosts run the
real paths; elsewhere every acquire asserts unsupported_platform. No
new processes, no fake platform/filesystem qualification."""
import json
import os
import platform
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import co_v4.service_owner as so
from co_v4 import contracts as c
from co_v4.output_store import OutputStore
from co_v4.service_owner import OwnerUnavailable, ServiceOwner
from co_v4.state import (ControlStore, IngressReceipt, body_digest,
                       create_run_body)

_QUALIFIED = platform.system() == "Darwin" \
    and platform.machine() == "arm64"
_NOW = "2026-10-07T00:00:00Z"


def _mutate(st, index, value):
    """Re-seal one field; os.stat_result has no _replace."""
    vals = list(st)
    vals[index] = value
    return os.stat_result(vals)


def _as_dir(st):
    return _mutate(st, stat.ST_MODE,
                   (st.st_mode & ~stat.S_IFMT(st.st_mode)) | stat.S_IFDIR)


def _as_reg(st):
    return _mutate(st, stat.ST_MODE,
                   (st.st_mode & ~stat.S_IFMT(st.st_mode)) | stat.S_IFREG)


def _bump_dev(st):
    return _mutate(st, stat.ST_DEV, st.st_dev + 1)


def _bump_uid(st):
    return _mutate(st, stat.ST_UID, st.st_uid + 1)


def _bump_nlink(st):
    return _mutate(st, stat.ST_NLINK, st.st_nlink + 1)


class OwnerGuardTest(unittest.TestCase):
    def make_root(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        root = Path(os.path.realpath(td.name)) / "state"
        root.mkdir()
        root.chmod(0o700)
        return root

    def acquire(self, root):
        if _QUALIFIED:
            return ServiceOwner.acquire(root)
        with self.assertRaises(OwnerUnavailable) as ei:
            ServiceOwner.acquire(root)
        self.assertEqual(ei.exception.code, "unsupported_platform")
        return None

    def acquire_fails(self, root, code):
        with self.assertRaises(OwnerUnavailable) as ei:
            ServiceOwner.acquire(root)
        exc = ei.exception
        self.assertEqual(exc.code,
                         code if _QUALIFIED else "unsupported_platform")
        self.assertEqual(str(exc), exc.code)

    def stores(self, root, owner):
        """Real guarded stores plus a task-owned receipt fixture."""
        receipts = {}

        def auth(source, body):
            receipts[source] = IngressReceipt(
                "fixture-human", source, body_digest(body), _NOW)

        store = ControlStore(
            root / "control.sqlite", verifier=receipts.__getitem__,
            evidence=lambda *a: None, clock=lambda: _NOW,
            guard=owner.check)
        self.addCleanup(store.close)
        out = OutputStore(root / "outputs", guard=owner.check)
        return store, out, auth

    def _rev(self, store):
        body = store._db.execute(
            "SELECT body FROM runs WHERE id='r'").fetchone()[0]
        return json.loads(body)["run"]["fields"]["revision"]

    def _tree(self, base):
        return sorted(str(p.relative_to(base)) for p in base.rglob("*"))

    def _stat_spy(self, target, mutate):
        """os.stat baseline everywhere except one lstat-style dirfd
        lookup under the held root, which sees mutate(st)."""
        real_stat = os.stat

        def fake_stat(path, *a, **kw):
            st = real_stat(path, *a, **kw)
            if (kw.get("dir_fd") is not None
                    and kw.get("follow_symlinks") is False
                    and path == target):
                return mutate(st)
            return st

        return mock.patch.object(so.os, "stat", fake_stat)

    def _fstat_spy(self, target, mutate):
        """os.open/os.fstat baseline except the fd opened for `target`,
        which gets one changed stat_result."""
        opened = {}
        real_open, real_fstat = os.open, os.fstat

        def fake_open(path, flags, mode=0o777, *, dir_fd=None):
            fd = real_open(path, flags, mode, dir_fd=dir_fd)
            opened[fd] = os.fspath(path)
            return fd

        def fake_fstat(fd):
            st = real_fstat(fd)
            return mutate(st) if opened.get(fd) == target else st

        return mock.patch.multiple(so.os, open=fake_open,
                                   fstat=fake_fstat)

    def test_unsupported_platform_fixed_code(self):
        root = self.make_root()
        with mock.patch.object(so.platform, "system",
                               return_value="Linux"):
            self.acquire_fails(root, "unsupported_platform")

    def test_lost_guard_blocks_connect_and_dirs(self):
        root = self.make_root()
        owner = self.acquire(root)
        if owner is None:
            return
        owner.close()  # guard now raises real owner_lost
        db = root / "control.sqlite"
        with self.assertRaises(OwnerUnavailable) as ei:
            ControlStore(db, verifier=lambda ref: None,
                         evidence=lambda *a: None, guard=owner.check)
        self.assertEqual(ei.exception.code, "owner_lost")
        self.assertFalse(db.exists())  # no database left behind
        with self.assertRaises(OwnerUnavailable) as ei:
            OutputStore(root / "outputs", guard=owner.check)
        self.assertEqual(ei.exception.code, "owner_lost")
        self.assertFalse((root / "outputs").exists())  # no dirs made

    def test_guarded_stores_bind_actual_paths(self):
        root = self.make_root()
        owner = self.acquire(root)
        if owner is None:
            return
        try:
            store, out, _ = self.stores(root, owner)
            owner.bind_stores(store, out)
            self.assertEqual(store.controller().storage_path,
                             root / "control.sqlite")
            self.assertEqual(out.root, root / "outputs")
        finally:
            owner.close()

    def test_lock_swap_lost_guard_public_tx(self):
        root = self.make_root()
        owner = self.acquire(root)
        if owner is None:
            return
        try:
            store, out, auth = self.stores(root, owner)
            auth("origin:r", create_run_body("r", "real intent"))
            store.intake().create_run("r", "real intent", "origin:r")
            auth("stop:r", {"operation": "stop_run", "run_id": "r"})
            owner.bind_stores(store, out)
            db = root / "control.sqlite"

            def snap():
                return (db.read_bytes(), store._db.total_changes,
                        store._db.execute(
                            "SELECT count(*) FROM ingress").fetchone()[0],
                        self._rev(store), self._tree(root / "outputs"))

            before = snap()
            os.rename(owner.lock_path, root / "held.aside")
            new = root / "service.lock"
            new.write_bytes(b"")  # different inode at the same path
            new.chmod(0o600)
            calls = (owner.check,
                     lambda: store.intake().record_stop_request(
                         "r", "stop:r"),
                     lambda: store.controller().get_run("r"),
                     lambda: out.put(c.AttemptRef("r", "j", "a"),
                                     (c.OutputItem(0, "text/plain", "x"),)))
            for call in calls:
                with self.assertRaises(OwnerUnavailable) as ei:
                    call()
                self.assertIs(type(ei.exception), OwnerUnavailable)
                self.assertEqual(ei.exception.code, "owner_lost")
            self.assertEqual(snap(), before)
        finally:
            owner.close()

    def test_root_swap_lost_guard_public_tx(self):
        root = self.make_root()
        owner = self.acquire(root)
        if owner is None:
            return
        aside = root.with_name(root.name + ".aside")
        fresh = None
        try:
            store, out, auth = self.stores(root, owner)
            auth("origin:r", create_run_body("r", "real intent"))
            store.intake().create_run("r", "real intent", "origin:r")
            auth("stop:r", {"operation": "stop_run", "run_id": "r"})
            owner.bind_stores(store, out)
            before = (root / "control.sqlite").read_bytes()
            os.rename(root, aside)
            fresh = Path(str(root))
            fresh.mkdir()
            fresh.chmod(0o700)
            calls = (owner.check,
                     lambda: store.intake().record_stop_request(
                         "r", "stop:r"),
                     lambda: out.put(c.AttemptRef("r", "j", "a"),
                                     (c.OutputItem(0, "text/plain", "x"),)))
            for call in calls:
                with self.assertRaises(OwnerUnavailable) as ei:
                    call()
                self.assertIs(type(ei.exception), OwnerUnavailable)
                self.assertEqual(ei.exception.code, "owner_lost")
            self.assertEqual((aside / "control.sqlite").read_bytes(),
                             before)
            self.assertEqual(self._rev(store), 0)
            os.rmdir(fresh)
            fresh = None
        finally:
            if fresh is not None and fresh.exists():
                os.rmdir(fresh)
            if aside.exists() and not root.exists():
                os.rename(aside, root)
            owner.close()

    def test_invalid_inputs_rejected_without_authority(self):
        root = self.make_root()
        owner = self.acquire(root)
        if owner is None:
            return
        try:
            with self.assertRaises(ValueError):
                OutputStore(Path("relative/outputs"))
            store, out, _ = self.stores(root, owner)
            with self.assertRaises(ValueError):
                out.put("not-an-attempt-ref", ())
            with self.assertRaises(ValueError):
                out.put(c.AttemptRef("r", "j", "a"), "not-a-tuple")
            with self.assertRaises(ValueError):
                store.controller().history("r", "bogus")
        finally:
            owner.close()

    def test_lock_uid_and_nlink_rejected(self):
        cases = (("uid", _bump_uid), ("nlink", _bump_nlink))
        for name, mutate in cases:
            with self.subTest(name=name):
                root = self.make_root()
                with self._fstat_spy("service.lock", mutate):
                    self.acquire_fails(root, "lock_unverified")

    def test_entry_kind_uid_dev_rejected(self):
        cases = (("control.sqlite", _as_dir, "root_unverified"),
                 ("control.sqlite-wal", _bump_uid, "root_unverified"),
                 ("outputs/blobs", _as_reg, "root_unverified"),
                 ("outputs", _bump_dev, "fs_mismatch"))
        for target, mutate, code in cases:
            with self.subTest(target=target):
                root = self.make_root()
                p = root / target
                if target.startswith("outputs"):
                    p.mkdir(parents=True)
                else:
                    p.write_bytes(b"x")
                with self._stat_spy(target, mutate):
                    self.acquire_fails(root, code)

    def test_bind_dev_mismatch_post_create(self):
        root = self.make_root()
        owner = self.acquire(root)
        if owner is None:
            return
        try:
            store, out, _ = self.stores(root, owner)
            # Post-create entry lstat, then dirfd fstat of an opened dir.
            for spy in (self._stat_spy("outputs/blobs", _bump_dev),
                        self._fstat_spy("outputs/tmp", _bump_dev)):
                with spy:
                    with self.assertRaises(OwnerUnavailable) as ei:
                        owner.bind_stores(store, out)
                self.assertEqual(ei.exception.code, "fs_mismatch")
        finally:
            owner.close()


if __name__ == "__main__":
    unittest.main()
