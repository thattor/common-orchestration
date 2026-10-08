from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest

from co_v4.contracts import AttemptRef, ExecuteRequest, ExecutionConditions, Job
from co_v4.delegation import (DelegatedScope, DelegatedTransport, ScopeDenied,
                              WorkerWorkspace, job_payload)
from co_v4.state import ControlStore


class WorkerWorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.workspace = self.root / "worker-a"
        self.workspace.mkdir()
        self.other = self.root / "worker-b"
        self.other.mkdir()
        self.control = self.root / "co"
        self.control.mkdir()
        self.state = self.control / "control.db"
        def refuse(*args): raise RuntimeError("no Human ingress")
        store = ControlStore(self.state, verifier=refuse, evidence=refuse)
        store.close()
        self.before = self.state.read_bytes()
        self.ref = AttemptRef("run", "job", "attempt-a")
        self.delegation = DelegatedScope("human:fixture", self.ref, str(self.workspace))
        self.writer = WorkerWorkspace(self.delegation, protected_state=(self.state,))
        self.addCleanup(self.writer.close)

    def test_owned_workspace_write_and_readback(self):
        self.writer.create_artifact(self.ref, "result.txt", b"bounded artifact")
        self.assertEqual((self.workspace / "result.txt").read_bytes(), b"bounded artifact")
        self.assertEqual(self.state.read_bytes(), self.before)

    def test_outside_other_attempt_other_repo_and_protected_state_denied(self):
        for path in ("../worker-b/artifact", "../unrelated-repo/file", "../co/control.db",
                     str(self.state), str(self.other / "artifact"), "a/../../escape"):
            with self.subTest(path=path), self.assertRaises(ScopeDenied):
                self.writer.create_artifact(self.ref, path, b"forbidden")
        with self.assertRaises(ScopeDenied):
            self.writer.create_artifact(replace(self.ref, attempt_id="attempt-b"), "x", b"no")
        self.assertEqual(self.state.read_bytes(), self.before)
        self.assertEqual(list(self.other.iterdir()), [])
        self.assertEqual(list(self.workspace.iterdir()), [])

    def test_symlinks_and_existing_hardlinks_cannot_redirect_writes(self):
        (self.workspace / "alias").symlink_to(self.control, target_is_directory=True)
        (self.workspace / "direct").symlink_to(self.state)
        (self.workspace / "hardlink").hardlink_to(self.state)
        for path in ("alias/control.db", "direct", "hardlink"):
            with self.subTest(path=path), self.assertRaises(ScopeDenied):
                self.writer.create_artifact(self.ref, path, b"forbidden")
        self.assertEqual(self.state.read_bytes(), self.before)

    def test_write_cannot_overwrite_an_artifact(self):
        self.writer.create_artifact(self.ref, "result", b"first")
        with self.assertRaises(ScopeDenied):
            self.writer.create_artifact(self.ref, "result", b"second")
        self.assertEqual((self.workspace / "result").read_bytes(), b"first")

    def test_protected_state_overlap_refused(self):
        for workspace in (self.root, self.control):
            with self.assertRaises(ScopeDenied):
                WorkerWorkspace(replace(self.delegation, workspace=str(workspace)),
                                protected_state=(self.state,))


class DelegationTransportTests(unittest.TestCase):
    def setUp(self):
        self.request = ExecuteRequest(AttemptRef("r", "j", "a"), Job("r", "j", "respond", ()),
                                     ExecutionConditions("model", "devin.acp", "/worker", "env"))
        self.scope = DelegatedScope("intent", self.request.ref, "/worker", "devin.text.only")
        self.sent = []
        class Inner:
            def send(inner, message): self.sent.append(message)
        self.transport = DelegatedTransport(Inner(), self.request, self.scope, admitted=lambda: True)
        self.message = {"method": "session/prompt", "params": {"sessionId": "s", "prompt": [
            {"type": "text", "text": json.dumps(job_payload(self.request))}]}}

    def test_changed_context_cannot_reach_native(self):
        payload = job_payload(self.request)
        payload["context"] = {"out_of_scope": "request"}
        self.message["params"]["prompt"][0]["text"] = json.dumps(payload)
        with self.assertRaises(ScopeDenied): self.transport.send(self.message)
        self.assertEqual(self.sent, [])

    def test_native_submission_requires_preflight_and_is_single_use(self):
        self.transport.admitted = lambda: False
        with self.assertRaises(ScopeDenied): self.transport.send(self.message)
        self.transport.admitted = lambda: True
        self.transport.send(self.message)
        with self.assertRaises(ScopeDenied): self.transport.send(self.message)
        payload = json.loads(self.sent[0]["params"]["prompt"][0]["text"])
        self.assertEqual(payload["delegation"], self.scope.envelope())
        self.assertEqual(len(self.sent), 1)
