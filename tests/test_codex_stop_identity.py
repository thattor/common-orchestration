"""Stop-case interpreter identity and binding boundaries; NOT Native acceptance."""
import io
import os
import subprocess
import sys
import tempfile
import time
import unittest
from collections import deque
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from probes import codex_live_control as p


class FakeWire:
    """In-memory wire double: records rpc/send, serves canned results. No process."""

    def __init__(self, cwd, pid=900001):
        self.cwd = cwd
        self.proc = SimpleNamespace(pid=pid)
        self.calls = []
        self.events = deque()
        self.received_at = {}

    def queue(self, msg):
        self.received_at[id(msg)] = time.monotonic()
        self.events.append(msg)

    def rpc(self, method, params, timeout=10):
        self.calls.append(("rpc", method))
        if method == "thread/start":
            return {**p.config(self.cwd), "sandbox": {"type": "readOnly"},
                    "thread": {"id": "fake-thread"}}
        if method == "turn/start":
            return {"turn": {"id": "fake-turn", "status": "inProgress"}}
        if method == "turn/interrupt":
            self.queue({"id": "req-1", "method": "item/unknown/request",
                        "params": {"threadId": "fake-thread"}})
            return {}
        raise AssertionError(method)

    def send(self, message):
        self.calls.append(("send", message))

    def read(self, end):
        return self.events.popleft() if self.events else None


class StopIdentityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.cwd = self.root / "workspace"
        self.cwd.mkdir()
        self.helper = self.root / "bounded_action.py"
        self.helper.write_bytes(p.HELPER)
        self.exec_path = ("/verified/Python.framework/Versions/3.12/Resources/"
                          "Python.app/Contents/MacOS/Python")
        self.command = self.exec_path + " -I " + str(self.helper)

    def watch(self, server_pid=900001):
        return p.ProcessWatch(server_pid, self.command, self.helper, io.BytesIO())

    @staticmethod
    def rows(*entries):
        return {pid: (ppid, lstart, stat, cmd) for pid, ppid, lstart, stat, cmd in entries}

    def framework_tree(self, name="cellar"):
        prefix = self.root / name / "python@3.12" / "3.12.14" / "Frameworks"
        exe = (prefix / "Python.framework" / "Versions" / "3.12" / "Resources"
               / "Python.app" / "Contents" / "MacOS" / "Python")
        return prefix, exe

    def make_framework(self, name="cellar", file=True, executable=True):
        prefix, exe = self.framework_tree(name)
        if file:
            exe.parent.mkdir(parents=True)
            exe.write_bytes(b"#!/fake-framework-python\n")
            exe.chmod(0o755 if executable else 0o644)
        alias = self.root / (name + "-opt") / "python@3.12" / "Frameworks"
        alias.parent.mkdir(parents=True)
        alias.symlink_to(prefix, target_is_directory=True)
        return alias, exe

    def framework_config(self, alias, **overrides):
        real = p.sysconfig.get_config_var
        values = {"PYTHONFRAMEWORK": "Python",
                  "PYTHONFRAMEWORKPREFIX": str(alias), "VERSION": "3.12"}
        values.update(overrides)
        return patch.object(p.sysconfig, "get_config_var",
                            side_effect=lambda key: values.get(key, real(key)))

    # --- Ruling 1 section 3: binding and watch negatives ---

    def test_bin_spelling_descendant_is_not_bound(self):
        rows = self.rows(
            (900001, 1, "boot", "Ss", "fixture-server"),
            (900010, 900001, "t-a", "S",
             "/cellar/bin/python3.12 -I " + str(self.helper)))
        watch = self.watch()
        with patch.object(p, "process_table", return_value=rows):
            self.assertEqual(watch.sample(), (False, False))
        self.assertIsNone(watch.operation)

    def test_exact_command_non_descendant_is_not_bound(self):
        rows = self.rows(
            (900001, 1, "boot", "Ss", "fixture-server"),
            (900020, 1, "t-a", "S", self.command))
        watch = self.watch()
        with patch.object(p, "process_table", return_value=rows):
            self.assertEqual(watch.sample(), (False, False))
        self.assertIsNone(watch.operation)

    def test_helper_bytes_changed_is_integrity_boundary(self):
        self.helper.write_bytes(p.HELPER + b"#tampered")
        with patch.object(p, "process_table", return_value={}):
            with self.assertRaisesRegex(p.Boundary, "helper_integrity_changed"):
                self.watch().sample()

    def test_two_exact_descendants_is_multiple_boundary(self):
        rows = self.rows(
            (900001, 1, "boot", "Ss", "fixture-server"),
            (900010, 900001, "t-a", "S", self.command),
            (900011, 900001, "t-b", "S", self.command))
        with patch.object(p, "process_table", return_value=rows):
            with self.assertRaisesRegex(p.Boundary, "multiple_target_operations"):
                self.watch().sample()

    def test_truncating_ps_row_is_not_bound_by_prefix(self):
        truncated = self.command[:60]
        self.assertTrue(self.command.startswith(truncated))
        self.assertNotEqual(truncated, self.command)
        rows = self.rows(
            (900001, 1, "boot", "Ss", "fixture-server"),
            (900010, 900001, "t-a", "S", truncated))
        watch = self.watch()
        with patch.object(p, "process_table", return_value=rows):
            self.assertEqual(watch.sample(), (False, False))
        self.assertIsNone(watch.operation)

    def test_reused_pid_identity_gone_and_never_signaled(self):
        alive = self.rows(
            (900001, 1, "boot", "Ss", "fixture-server"),
            (900010, 900001, "t-a", "S", self.command))
        reused = self.rows(
            (900001, 1, "boot", "Ss", "fixture-server"),
            (900010, 900001, "t-b", "S", self.command))
        watch = self.watch()
        with patch.object(p, "process_table", return_value=alive):
            self.assertEqual(watch.sample(), (False, False))
        self.assertIsNotNone(watch.operation)
        with patch.object(p, "process_table", return_value=reused), \
                patch.object(p.os, "kill") as kill:
            gone, _ = watch.sample()
            self.assertTrue(gone)
            watch.cleanup()
        kill.assert_not_called()

    # --- Identity verification: both rulings ---

    def test_config_kernel_agreement_returns_kernel_path(self):
        alias, exe = self.make_framework()
        kernel = os.path.realpath(str(exe))
        with self.framework_config(alias), \
                patch.object(p, "kernel_executable", return_value=kernel):
            self.assertEqual(p.verified_interpreter(), kernel)

    def test_config_symlink_to_other_interpreter_is_boundary(self):
        alias_a, _ = self.make_framework("cellar-a")
        _, exe_b = self.make_framework("cellar-b")
        with self.framework_config(alias_a), \
                patch.object(p, "kernel_executable",
                             return_value=os.path.realpath(str(exe_b))):
            with self.assertRaisesRegex(p.Boundary, "interpreter_identity_unverified"):
                p.verified_interpreter()

    def test_missing_or_empty_config_var_is_boundary(self):
        alias, _ = self.make_framework()
        for override in ({"PYTHONFRAMEWORKPREFIX": None}, {"PYTHONFRAMEWORKPREFIX": ""},
                         {"VERSION": None}, {"VERSION": ""}):
            with self.subTest(override=override):
                with self.framework_config(alias, **override), \
                        patch.object(p, "kernel_executable") as kernel:
                    with self.assertRaisesRegex(p.Boundary, "interpreter_identity_unverified"):
                        p.verified_interpreter()
                kernel.assert_not_called()

    def test_missing_config_target_is_boundary_from_strict_resolution(self):
        alias, _ = self.framework_tree("cellar-missing")
        alias.parent.mkdir(parents=True)
        alias.symlink_to(self.root / "cellar-missing" / "python@3.12" / "3.12.14"
                         / "Frameworks", target_is_directory=True)
        with self.framework_config(alias), \
                patch.object(p, "kernel_executable") as kernel:
            with self.assertRaisesRegex(p.Boundary, "interpreter_identity_unverified"):
                p.verified_interpreter()
        kernel.assert_not_called()

    def test_kernel_symlinked_spelling_is_never_resolved(self):
        alias, exe = self.make_framework()
        spelling = str(alias / "Python.framework" / "Versions" / "3.12" / "Resources"
                       / "Python.app" / "Contents" / "MacOS" / "Python")
        self.assertNotEqual(spelling, os.path.realpath(spelling))
        with self.framework_config(alias), \
                patch.object(p, "kernel_executable", return_value=spelling):
            with self.assertRaisesRegex(p.Boundary, "interpreter_identity_unverified"):
                p.verified_interpreter()

    def test_unavailable_kernel_probe_is_boundary(self):
        alias, _ = self.make_framework()
        with self.framework_config(alias), \
                patch.object(p, "kernel_executable",
                             side_effect=p.Boundary("kernel_executable_observation_unavailable")):
            with self.assertRaisesRegex(p.Boundary, "interpreter_identity_unverified"):
                p.verified_interpreter()

    def test_exec_must_be_regular_executable_file(self):
        alias, exe = self.framework_tree("cellar-dir")
        exe.mkdir(parents=True)
        alias_dir = self.root / "cellar-dir-opt" / "python@3.12" / "Frameworks"
        alias_dir.parent.mkdir(parents=True)
        alias_dir.symlink_to(self.root / "cellar-dir" / "python@3.12" / "3.12.14"
                             / "Frameworks", target_is_directory=True)
        directory = os.path.realpath(str(exe))
        with self.framework_config(alias_dir), \
                patch.object(p, "kernel_executable", return_value=directory):
            with self.assertRaisesRegex(p.Boundary, "interpreter_identity_unverified"):
                p.verified_interpreter()
        alias, exe = self.make_framework("cellar-noexec", executable=False)
        plain = os.path.realpath(str(exe))
        with self.framework_config(alias), \
                patch.object(p, "kernel_executable", return_value=plain):
            with self.assertRaisesRegex(p.Boundary, "interpreter_identity_unverified"):
                p.verified_interpreter()

    def test_non_framework_keeps_resolved_sys_executable(self):
        real = p.sysconfig.get_config_var
        with patch.object(p.sysconfig, "get_config_var",
                          side_effect=lambda k: None if k == "PYTHONFRAMEWORK" else real(k)), \
                patch.object(p, "kernel_executable") as kernel:
            self.assertEqual(p.verified_interpreter(),
                             str(Path(sys.executable).resolve()))
        kernel.assert_not_called()

    def test_identity_failure_is_boundary_before_thread_start_zero_rpcs(self):
        alias_a, _ = self.make_framework("cellar-a")
        _, exe_b = self.make_framework("cellar-b")
        wire = FakeWire(self.cwd)
        facts = {}
        scratch = self.root / "case-identity"
        scratch.mkdir()
        with self.framework_config(alias_a), \
                patch.object(p, "kernel_executable",
                             return_value=os.path.realpath(str(exe_b))), \
                patch.object(p, "process_table", return_value={}):
            with self.assertRaisesRegex(p.Boundary, "interpreter_identity_unverified"):
                p.run_case(wire, self.cwd, scratch, "stop", 1, facts)
        self.assertEqual(wire.calls, [])
        self.assertNotIn("thread_configuration_matches", facts)

    # --- run_case outcomes ---

    def test_interrupt_ack_while_process_alive_stays_unconfirmed(self):
        scratch = self.root / "case-ack"
        scratch.mkdir()
        command = self.exec_path + " -I " + str(scratch / "bounded_action.py")
        rows = self.rows(
            (900001, 1, "boot", "Ss", "fixture-server"),
            (900010, 900001, "t-a", "S", command),
            (900011, 900010, "t-c", "S", "/bin/sleep 40"))
        wire = FakeWire(self.cwd, pid=900001)
        facts = {}
        with patch.object(p, "verified_interpreter", return_value=self.exec_path), \
                patch.object(p, "process_table", return_value=rows), \
                patch.object(p.os, "kill") as kill:
            with self.assertRaisesRegex(p.Boundary, "unexpected_request"):
                p.run_case(wire, self.cwd, scratch, "stop", 2, facts)
        self.assertTrue(facts["operation_started"])
        self.assertTrue(facts["child_started"])
        self.assertTrue(facts["interrupt_sent"])
        self.assertTrue(facts["interrupt_receipt"])
        self.assertFalse(facts["operation_gone_before_cleanup"])
        self.assertFalse(facts["children_gone_before_cleanup"])
        verdict = p.classify({"stop": facts}, {})
        self.assertEqual(verdict["interrupt_receipt"]["status"], "pass")
        self.assertEqual(verdict["operation_cessation"]["status"], "unsupported")
        self.assertEqual(verdict["child_cessation"]["status"], "unsupported")
        self.assertEqual({c.args[0] for c in kill.call_args_list}, {900010, 900011})

    def test_no_observations_unconfirmed_and_no_cleanup_signal(self):
        scratch = self.root / "case-quiet"
        scratch.mkdir()
        wire = FakeWire(self.cwd)
        facts = {}
        with patch.object(p, "verified_interpreter", return_value=self.exec_path), \
                patch.object(p, "process_table", return_value={}), \
                patch.object(p.os, "kill") as kill:
            p.run_case(wire, self.cwd, scratch, "stop", .2, facts)
        self.assertFalse(facts["operation_started"])
        self.assertFalse(facts["interrupt_sent"])
        verdict = p.classify({"stop": facts}, {})
        for feature in ("interrupt_receipt", "operation_cessation", "child_cessation"):
            self.assertEqual(verdict[feature]["status"], "unsupported")
        kill.assert_not_called()

    # --- locale pinning, decode policy and command hygiene ---

    def test_ps_child_env_differs_only_by_lc_all(self):
        parent = {"LANG": "ja_JP.UTF-8", "LC_ALL": "ja_JP.UTF-8",
                  "LC_TIME": "ja_JP.UTF-8", "CO_UNRELATED_MARKER": "keep"}
        captured = {}

        def fake_run(argv, **kwargs):
            captured["argv"], captured["kwargs"] = argv, kwargs
            return subprocess.CompletedProcess(
                argv, 0, b"900001 1 Mon Oct  5 10:00:00 2026 Ss fixture-server\n", b"")

        with patch.dict(os.environ, parent, clear=True), \
                patch.object(p.subprocess, "run", side_effect=fake_run):
            rows = p.process_table()
            self.assertEqual(os.environ["LC_ALL"], "ja_JP.UTF-8")
        kwargs = captured["kwargs"]
        self.assertEqual(captured["argv"],
                         ["/bin/ps", "-axww", "-o", "pid=,ppid=,lstart=,stat=,command="])
        self.assertTrue(kwargs["capture_output"])
        self.assertEqual(kwargs["timeout"], 2)
        self.assertFalse(kwargs["check"])
        child = kwargs["env"]
        self.assertIsNot(child, os.environ)
        self.assertEqual(set(child), set(parent))
        self.assertEqual({key for key in child if child[key] != parent[key]},
                         {"LC_ALL"})
        self.assertEqual(child["LC_ALL"], "C")
        self.assertEqual(child["LANG"], "ja_JP.UTF-8")
        self.assertEqual(child["LC_TIME"], "ja_JP.UTF-8")
        self.assertEqual(child["CO_UNRELATED_MARKER"], "keep")
        self.assertEqual(rows[900001],
                         (1, "Mon Oct 5 10:00:00 2026", "Ss", "fixture-server"))

    def test_eight_field_row_still_boundary(self):
        out = (b"900001 1 Mon Oct  5 10:00:00 2026 Ss fixture-server\n"
               b"900010 900001 Oct 5 10:00:00 2026 S short-date\n")
        with patch.object(p.subprocess, "run",
                          return_value=subprocess.CompletedProcess([], 0, out, b"")):
            with self.assertRaisesRegex(p.Boundary, "host_process_format_unavailable"):
                p.process_table()

    def test_non_ascii_command_is_boundary_before_thread_start(self):
        wire = FakeWire(self.cwd)
        for index, spelling in enumerate(("/verified/Pyth\u00f6n",
                                          "/verified/Py\thon",
                                          "/verified/Py\x7fthon")):
            scratch = self.root / ("case-nonascii-" + str(index))
            scratch.mkdir()
            with self.subTest(spelling=ascii(spelling)):
                facts = {}
                with patch.object(p, "verified_interpreter", return_value=spelling), \
                        patch.object(p, "process_table", return_value={}):
                    with self.assertRaisesRegex(p.Boundary, "process_command_not_ascii"):
                        p.run_case(wire, self.cwd, scratch, "stop", 1, facts)
        self.assertEqual(wire.calls, [])

    def test_undecodable_and_escaped_rows_retained_never_bound(self):
        out = (b"900001 1 Mon Oct  5 10:00:00 2026 Ss fixture-server\n"
               b"900010 900001 Mon Oct  5 10:00:00 2026 S undecodable\xff\xfecmd\n"
               b"900012 900001 Mon Oct  5 10:00:00 2026 S escapedM-bM-^TM-^Xcmd\n"
               b"900011 900001 Mon Oct  5 10:00:00 2026 S " + self.command.encode() + b"\n")

        def fake_run(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 0, out, b"")

        watch = self.watch()
        with patch.object(p.subprocess, "run", side_effect=fake_run):
            rows = p.process_table()
            self.assertEqual(len(rows), 4)
            self.assertIn("\ufffd", rows[900010][3])
            watch.sample()
        self.assertEqual(watch.operation[0], 900011)

    def test_c_locale_lstart_identity_stable_across_cleanup(self):
        def table(raw):
            return lambda argv, **kwargs: subprocess.CompletedProcess(argv, 0, raw, b"")

        first = (b"900001 1 Mon Oct  5 10:00:00 2026 Ss fixture-server\n"
                 b"900010 900001 Mon Oct  5 10:00:00 2026 S " + self.command.encode() + b"\n")
        reused = (b"900001 1 Mon Oct  5 10:00:00 2026 Ss fixture-server\n"
                  b"900010 900001 Tue Oct  6 11:11:11 2026 S " + self.command.encode() + b"\n")
        watch = self.watch()
        with patch.object(p.subprocess, "run", side_effect=table(first)):
            self.assertEqual(watch.sample(), (False, False))
            self.assertEqual(watch.sample(), (False, False))
        self.assertEqual(watch.operation[1][1], "Mon Oct 5 10:00:00 2026")
        with patch.object(p.subprocess, "run", side_effect=table(first)), \
                patch.object(p.os, "kill") as kill:
            watch.cleanup()
        self.assertEqual({call.args[0] for call in kill.call_args_list}, {900010})
        with patch.object(p.subprocess, "run", side_effect=table(reused)), \
                patch.object(p.os, "kill") as kill_reused:
            gone, _ = watch.sample()
            self.assertTrue(gone)
            watch.cleanup()
        kill_reused.assert_not_called()


if __name__ == "__main__":
    unittest.main()
