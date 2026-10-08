import multiprocessing as mp
import os
import platform
import select
import signal
import stat
import subprocess
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock

import co_v4.service_owner as so
from co_v4.service_owner import OwnerUnavailable, ServiceOwner

_QUALIFIED = platform.system() == "Darwin" \
    and platform.machine() == "arm64"


def _race_worker(root, barrier, release, q):
    diag = []
    real_open = so.os.open

    def spy_open(path, flags, mode=0o777, *, dir_fd=None):
        try:
            fd = real_open(path, flags, mode, dir_fd=dir_fd)
        except OSError as exc:
            diag.append((repr(path), oct(flags),
                         "errno=%r" % exc.errno))
            raise
        try:
            st = os.fstat(fd)
            diag.append((repr(path), oct(flags), "ok",
                         "mode=%s" % oct(stat.S_IMODE(st.st_mode)),
                         "nlink=%d" % st.st_nlink,
                         "inheritable=%r" % os.get_inheritable(fd)))
        except OSError:
            pass
        return fd

    try:
        barrier.wait(timeout=30)
        so.os.open = spy_open  # child-local capture around real acquire
        try:
            owner = ServiceOwner.acquire(root)
        finally:
            so.os.open = real_open
    except OwnerUnavailable as exc:
        q.put(("loser", exc.code, diag))
        return
    except Exception as exc:
        q.put(("error", type(exc).__name__, diag))
        return
    q.put(("winner", os.getpid()))
    release.wait(30)  # winner holds until parent saw both replies
    owner.close()


def _orphan_owner(root, inherit, marker, ready):
    owner = None
    child = None
    rfd = wfd = None
    try:
        owner = ServiceOwner.acquire(root)
        rfd, wfd = os.pipe()  # child byte proves exec+argv are live
        fds = [wfd] + ([owner._lock_fd] if inherit else [])
        argv = [sys.executable, "-c",
                "import os,sys,time;"
                "os.write(%d,b'R');time.sleep(60)" % wfd, marker]
        child = subprocess.Popen(argv, pass_fds=fds)  # close_fds default
        os.close(wfd)
        wfd = None
        if not (select.select([rfd], [], [], 30)[0]
                and os.read(rfd, 1) == b"R"):
            raise RuntimeError("child startup handshake timed out")
        os.close(rfd)
        rfd = None
        ready.put((child.pid, os.lstat(owner.lock_path).st_ino))
        time.sleep(120)  # bounded wait; SIGKILL lands here, never notify a dead waiter
    except Exception as exc:
        ready.put(("error", type(exc).__name__))
    finally:
        for fd in (rfd, wfd):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
        if child is not None:
            try:
                child.terminate()
            except OSError:
                pass
        if owner is not None:
            owner.close()


def _mk_layout(root):
    (root / "control.sqlite").write_bytes(b"")
    for d in ("outputs/blobs", "outputs/manifests", "outputs/tmp"):
        (root / d).mkdir(parents=True)


def _fake_stores(root):
    state = types.SimpleNamespace(storage_path=root / "control.sqlite")
    store = types.SimpleNamespace(controller=lambda: state)
    out = types.SimpleNamespace(root=root / "outputs")
    return store, out


class ServiceOwnerTest(unittest.TestCase):
    def make_root(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        root = Path(os.path.realpath(td.name)) / "state"
        root.mkdir()
        root.chmod(0o700)
        return root

    def acquire(self, root):
        """Return a ServiceOwner on qualified hosts; elsewhere assert
        the fixed unsupported_platform code and return None."""
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
        self.assertEqual(str(exc), exc.code)  # fixed code only

    def _child_ps(self, pid):
        """(lstart, state, argv) snapshot for pid, or None if gone."""
        try:
            out = subprocess.run(
                ["ps", "-ww", "-o", "lstart=", "-o", "stat=", "-o",
                 "command=", "-p", str(pid)],
                capture_output=True, text=True, timeout=10)
        except (OSError, subprocess.SubprocessError):
            return None
        line = out.stdout.rstrip("\n")
        if out.returncode != 0 or not line.strip():
            return None
        rest = line[24:].split(None, 1)  # lstart is fixed 24 chars
        return (line[:24].strip(),
                rest[0] if rest else "",
                rest[1] if len(rest) > 1 else "")

    def _child_birth(self, pid, marker):
        """Verified start identity (lstart) of our marked child."""
        snap = self._child_ps(pid)
        self.assertIsNotNone(snap, "child pid absent from ps")
        lstart, state, argv = snap
        self.assertIn(marker, argv)
        self.assertFalse(state.startswith("Z"))
        return lstart

    def _kill_child(self, pid, marker, birth):
        """SIGKILL only the verified task-owned child: pid + argv
        marker + exact lstart birth. Never pkill, never broad scan."""
        if not pid or not marker or not birth:
            return
        snap = self._child_ps(pid)
        if snap is None:
            return
        lstart, state, argv = snap
        if lstart != birth or marker not in argv:
            return  # identity mismatch: never kill unverified pids
        if not state.startswith("Z"):
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                return
        for _ in range(200):  # bounded; zombies are reaped by launchd
            snap = self._child_ps(pid)
            if snap is None or snap[1].startswith("Z"):
                return
            time.sleep(0.05)

    def _start_orphan(self, root, inherit, cleanup):
        """Fork an owner that spawns a marked child, snapshot its
        birth identity, then SIGKILL the owner."""
        ctx = mp.get_context("fork")
        ready = ctx.Queue()
        marker = "co04-own-%d-%d" % (os.getpid(), time.monotonic_ns())
        proc = ctx.Process(target=_orphan_owner,
                           args=(root, inherit, marker, ready))
        proc.start()
        try:
            report = ready.get(timeout=60)
            if isinstance(report[0], str):
                self.fail("owner worker failed: %r" % (report,))
            child_pid, lock_ino = report
            deadline = time.monotonic() + 15
            while True:  # bounded: ps must show the exec'd marked argv
                snap = self._child_ps(child_pid)
                if (snap is not None and marker in snap[2]
                        and not snap[1].startswith("Z")):
                    break
                self.assertLess(time.monotonic(), deadline,
                                "marked child argv never appeared: %r"
                                % (snap,))
                time.sleep(0.05)
            birth = self._child_birth(child_pid, marker)
            cleanup.append((child_pid, marker, birth))
            os.kill(proc.pid, signal.SIGKILL)
            proc.join(30)
            self.assertEqual(proc.exitcode, -signal.SIGKILL)
            snap = self._child_ps(child_pid)
            self.assertIsNotNone(snap)
            self.assertEqual(snap[0], birth)
            self.assertIn(marker, snap[2])
            self.assertFalse(snap[1].startswith("Z"))
        except Exception:
            if proc.is_alive():
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
            proc.join(30)
            ready.close()
            ready.join_thread()
            raise
        ready.close()
        ready.join_thread()
        return proc, lock_ino

    def test_unsupported_platform_fixed_code(self):
        root = self.make_root()
        with mock.patch.object(so.platform, "system",
                               return_value="Linux"):
            self.acquire_fails(root, "unsupported_platform")

    def test_properties_and_double_acquire(self):
        root = self.make_root()
        owner = self.acquire(root)
        if owner is None:
            return
        self.assertEqual(owner.root, root)
        self.assertEqual(owner.lock_path, root / "service.lock")
        st = os.lstat(owner.lock_path)
        self.assertTrue(stat.S_ISREG(st.st_mode))
        self.assertEqual(stat.S_IMODE(st.st_mode), 0o600)
        self.assertFalse(os.get_inheritable(owner._lock_fd))
        self.assertFalse(os.get_inheritable(owner._root_fd))
        owner.check()
        self.acquire_fails(root, "owned_elsewhere")
        owner.close()
        self.assertTrue(owner.lock_path.exists())

    def test_root_rejected(self):
        for case in ("mode", "symlink", "noncanonical", "file"):
            with self.subTest(case=case):
                root = self.make_root()
                if case == "mode":
                    root.chmod(0o755)
                elif case == "symlink":
                    link = root.parent / "link"
                    link.symlink_to(root)
                    root = link
                elif case == "noncanonical":
                    root = root / ".." / root.name
                elif case == "file":
                    root = root / "plain"
                    root.write_bytes(b"x")
                self.acquire_fails(root, "root_unverified")

    def test_root_uid_rejected(self):
        root = self.make_root()
        real_uid = os.getuid()  # cache before patching so.os.getuid
        with mock.patch.object(so.os, "getuid",
                               return_value=real_uid + 1):
            self.acquire_fails(root, "root_unverified")

    def test_lock_rejected(self):
        for case in ("symlink", "dir", "nlink", "mode"):
            with self.subTest(case=case):
                root = self.make_root()
                p = root / "service.lock"
                if case == "symlink":
                    (root / "target").write_bytes(b"x")
                    p.symlink_to("target")
                elif case == "dir":
                    p.mkdir()
                elif case == "nlink":
                    p.write_bytes(b"x")
                    p.chmod(0o600)
                    os.link(p, root / "alias")
                elif case == "mode":
                    p.write_bytes(b"x")
                    p.chmod(0o644)
                self.acquire_fails(root, "lock_unverified")

    def test_foreign_filesystem_rejected(self):
        cases = (("nfs", so.MNT_LOCAL), ("smbfs", so.MNT_LOCAL),
                 ("msdos", so.MNT_LOCAL), ("weirdfs", so.MNT_LOCAL),
                 ("apfs", 0))
        for name, flags in cases:
            with self.subTest(name=name):
                root = self.make_root()
                fake = lambda fd, n=name, f=flags: (
                    (1, 2), n.encode(), f)
                with mock.patch.object(so, "_fsinfo", fake):
                    self.acquire_fails(root, "unsupported_filesystem")

    def test_fs_layout_selfcheck(self):
        root = self.make_root()
        with mock.patch.object(so, "_fstatfs_buf",
                               lambda fd: so._Statfs()):
            self.acquire_fails(root, "fs_unverified")

    def test_inheritable_lock_fd_rejected(self):
        root = self.make_root()
        with mock.patch.object(so.os, "get_inheritable",
                               return_value=True):
            self.acquire_fails(root, "lock_unverified")

    def test_os_open_failure_fixed_code(self):
        root = self.make_root()
        with mock.patch.object(
                so.os, "open",
                side_effect=OSError("secret-path-detail")):
            self.acquire_fails(root, "root_unverified")

    def test_prestore_symlink_rejected(self):
        names = ("control.sqlite", "control.sqlite-wal",
                 "control.sqlite-shm", "control.sqlite-journal",
                 "outputs", "outputs/blobs",
                 "outputs/manifests", "outputs/tmp")
        for name in names:
            with self.subTest(name=name):
                root = self.make_root()
                p = root / name
                if p.parent != root:
                    p.parent.mkdir(parents=True)
                p.symlink_to(".")
                self.acquire_fails(root, "root_unverified")

    def test_prestore_hardlink_rejected(self):
        root = self.make_root()
        p = root / "control.sqlite"
        p.write_bytes(b"x")
        os.link(p, root / "control.sqlite-wal")
        self.acquire_fails(root, "root_unverified")

    def test_lock_identity_swap(self):
        root = self.make_root()
        owner = self.acquire(root)
        if owner is None:
            return
        os.rename(owner.lock_path, root / "held.aside")
        new = root / "service.lock"
        new.write_bytes(b"")  # different inode at the same path
        new.chmod(0o600)
        with self.assertRaises(OwnerUnavailable) as ei:
            owner.check()
        self.assertEqual(ei.exception.code, "owner_lost")
        owner.close()
        self.assertTrue(new.exists())  # close never unlinks

    def test_root_identity_swap(self):
        root = self.make_root()
        owner = self.acquire(root)
        if owner is None:
            return
        aside = root.with_name(root.name + ".aside")
        os.rename(root, aside)
        try:
            fresh = Path(str(root))
            fresh.mkdir()
            fresh.chmod(0o700)
            with self.assertRaises(OwnerUnavailable) as ei:
                owner.check()
            self.assertEqual(ei.exception.code, "owner_lost")
            owner.close()
            os.rmdir(fresh)
        finally:
            os.rename(aside, root)

    def test_check_fsid_change(self):
        root = self.make_root()
        owner = self.acquire(root)
        if owner is None:
            return
        fake = lambda fd: ((9, 9), b"apfs", so.MNT_LOCAL)
        with mock.patch.object(so, "_fsinfo", fake):
            with self.assertRaises(OwnerUnavailable) as ei:
                owner.check()
        self.assertEqual(ei.exception.code, "owner_lost")
        owner.close()

    def test_after_close_and_stale_fd(self):
        root = self.make_root()
        owner = self.acquire(root)
        if owner is None:
            return
        owner.close()
        owner.close()
        with self.assertRaises(OwnerUnavailable) as ei:
            owner.check()
        self.assertEqual(ei.exception.code, "owner_lost")
        owner2 = ServiceOwner.acquire(root)
        os.close(owner2._lock_fd)
        with self.assertRaises(OwnerUnavailable) as ei:
            owner2.check()
        self.assertEqual(ei.exception.code, "owner_lost")
        owner2.close()

    def test_bind_stores_ok_and_wrong_paths(self):
        root = self.make_root()
        owner = self.acquire(root)
        if owner is None:
            return
        try:
            _mk_layout(root)
            store, out = _fake_stores(root)
            owner.bind_stores(store, out)
            bad = types.SimpleNamespace(
                storage_path=root / "elsewhere.sqlite")
            bad_store = types.SimpleNamespace(controller=lambda: bad)
            with self.assertRaises(OwnerUnavailable) as ei:
                owner.bind_stores(bad_store, out)
            self.assertEqual(ei.exception.code, "root_unverified")
            bad_out = types.SimpleNamespace(root=root / "elsewhere")
            with self.assertRaises(OwnerUnavailable) as ei:
                owner.bind_stores(store, bad_out)
            self.assertEqual(ei.exception.code, "root_unverified")
        finally:
            owner.close()

    def test_bind_output_dir_fsid_mismatch(self):
        root = self.make_root()
        owner = self.acquire(root)
        if owner is None:
            return
        try:
            _mk_layout(root)
            store, out = _fake_stores(root)
            real = so._fsinfo

            def fake(fd):
                fsid, name, flags = real(fd)
                if fd != owner._root_fd:
                    return (9, 9), name, flags
                return fsid, name, flags

            with mock.patch.object(so, "_fsinfo", fake):
                with self.assertRaises(OwnerUnavailable) as ei:
                    owner.bind_stores(store, out)
            self.assertEqual(ei.exception.code, "fs_mismatch")
        finally:
            owner.close()

    def test_bind_missing_output_dir(self):
        root = self.make_root()
        owner = self.acquire(root)
        if owner is None:
            return
        try:
            (root / "control.sqlite").write_bytes(b"")
            store, out = _fake_stores(root)
            with self.assertRaises(OwnerUnavailable) as ei:
                owner.bind_stores(store, out)
            self.assertEqual(ei.exception.code, "root_unverified")
        finally:
            owner.close()

    def test_two_process_race_single_winner(self):
        root = self.make_root()
        if not _QUALIFIED:
            self.acquire_fails(root, "unsupported_platform")
            return
        ctx = mp.get_context("fork")
        for _ in range(20):
            barrier = ctx.Barrier(2)
            release = ctx.Event()
            q = ctx.Queue()
            procs = [ctx.Process(
                target=_race_worker,
                args=(root, barrier, release, q)) for _ in range(2)]
            for p in procs:
                p.start()
            try:
                results = [q.get(timeout=60) for _ in range(2)]
            finally:
                release.set()
                for p in procs:
                    p.join(30)
                    if p.is_alive():
                        p.terminate()
                        p.join(10)
                q.close()
                q.join_thread()
            self.assertEqual([p.exitcode for p in procs], [0, 0])
            kinds = sorted(r[0] for r in results)
            self.assertEqual(kinds, ["loser", "winner"])
            loser = next(r for r in results if r[0] == "loser")
            self.assertEqual(loser[1], "owned_elsewhere", loser)

    def test_kill9_default_child_reacquire_permitted(self):
        root = self.make_root()
        if not _QUALIFIED:
            self.acquire_fails(root, "unsupported_platform")
            return
        cleanup = []
        proc = None
        try:
            proc, ino = self._start_orphan(root, False, cleanup)
            # Child alive with default close_fds=True holds no lock fd:
            # the SIGKILLed owner's lock is fully released.
            new_owner = ServiceOwner.acquire(root)
            new_owner.close()
            self.assertEqual(
                os.lstat(root / "service.lock").st_ino, ino)
        finally:
            for pid, m, birth in cleanup:
                self._kill_child(pid, m, birth)
            if proc is not None:
                proc.join(30)

    def test_kill9_inherited_fd_blocks_reacquire(self):
        root = self.make_root()
        if not _QUALIFIED:
            self.acquire_fails(root, "unsupported_platform")
            return
        cleanup = []
        proc = None
        try:
            proc, ino = self._start_orphan(root, True, cleanup)
            child_pid, marker, birth = cleanup[-1]
            # Child inherited the actual locked fd: acquire must fail
            # while it is alive.
            with self.assertRaises(OwnerUnavailable) as ei:
                ServiceOwner.acquire(root)
            self.assertEqual(ei.exception.code, "owned_elsewhere")
            snap = self._child_ps(child_pid)
            self.assertIsNotNone(snap)
            self.assertEqual(snap[0], birth)
            self.assertIn(marker, snap[2])
            self.assertFalse(snap[1].startswith("Z"))
        finally:
            for pid, m, birth in cleanup:
                self._kill_child(pid, m, birth)
            if proc is not None:
                proc.join(30)
        deadline = time.monotonic() + 15
        while True:
            try:
                freed = ServiceOwner.acquire(root)
                freed.close()
                break
            except OwnerUnavailable:
                if time.monotonic() > deadline:
                    self.fail("lock still held after child exit")
                time.sleep(0.05)
        self.assertEqual(os.lstat(root / "service.lock").st_ino, ino)


if __name__ == "__main__":
    unittest.main()
