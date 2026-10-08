"""Trusted CO -> Native delegation and the Worker artifact command boundary.

These objects belong to host composition. Worker input cannot construct grants.
Native prompt adherence is the 0.3 trust assumption, not OS containment proof.
"""
from dataclasses import dataclass
import json
import os
from pathlib import Path

from .contracts import AttemptRef
from .devin_workspace import DevinWorkspaceBinding


class ScopeDenied(RuntimeError):
    """Fixed diagnostics only; never include Worker paths or content."""


@dataclass(frozen=True)
class DelegatedScope:
    human_intent_ref: str
    attempt: AttemptRef
    workspace: str
    capability: str = "codex.readonly.local"

    def validate(self, request, capability):
        if (not self.human_intent_ref or self.attempt != request.ref
                or self.workspace != request.conditions.workspace
                or self.capability != capability):
            raise ScopeDenied("delegated_scope_mismatch")

    def envelope(self):
        return {"human_intent_ref": self.human_intent_ref,
                "run_id": self.attempt.run_id, "job_id": self.attempt.job_id,
                "attempt_id": self.attempt.attempt_id, "workspace": self.workspace,
                "capability": self.capability,
                "write_authority": "none; artifacts must use the CO Worker command boundary",
                "constraints": ["Only carry out the bound Job and its supplied context.",
                    "Do not inspect credentials, modify other Attempts or repositories, or change CO state.",
                    "Do not request expanded permissions. Return out-of-scope needs to Controller.",
                    ("Use no tools; produce only the requested text response."
                     if self.capability == "devin.text.only" else
                     "Only local read-only operations in the assigned workspace; no network or writes.")]}


def job_payload(request):
    job = request.job
    return {"instructions": job.instructions, "context": json.loads(job.context_json),
            "acceptance_criteria": list(job.acceptance_criteria)}


class DelegatedTransport:
    """Bind the actual model submission, including context, before Native sees it.

    Adapter control messages retain their existing validation. Exactly one model
    submission is accepted and it must equal the immutable ExecuteRequest. No
    new tool or session-wide approval capability is granted by this wrapper.
    """
    def __init__(self, inner, request, delegation, *, admitted, workspace_binding=None):
        self.inner, self.request, self.delegation = inner, request, delegation
        self.admitted = admitted
        self.workspace_binding = workspace_binding
        if workspace_binding is not None:
            if type(workspace_binding) is not DevinWorkspaceBinding or delegation.capability != "devin.text.only":
                raise ScopeDenied("workspace_binding_mismatch")
            workspace_binding.validate(request)
        self.submitted = False
        self.tool_events = 0

    def send(self, message):
        method = message.get("method")
        if method in {"turn/start", "session/prompt"}:
            expected_method = ("turn/start" if self.request.conditions.adapter == "codex.app-server"
                               else "session/prompt")
            key = "input" if method == "turn/start" else "prompt"
            pieces = message.get("params", {}).get(key)
            if (method != expected_method or self.submitted or not self.admitted()
                    or not isinstance(pieces, list) or len(pieces) != 1
                    or set(pieces[0]) != {"type", "text"} or pieces[0]["type"] != "text"):
                raise ScopeDenied("unbound_native_submission")
            try:
                payload = json.loads(pieces[0]["text"])
            except (ValueError, TypeError):
                raise ScopeDenied("unbound_native_submission") from None
            if payload != job_payload(self.request):
                raise ScopeDenied("unbound_native_submission")
            payload["delegation"] = self.delegation.envelope()
            if self.workspace_binding is not None:
                payload["delegation"].update(
                    resolved_workspace=self.workspace_binding.validate(self.request),
                    workspace_binding_ref=self.workspace_binding.binding_ref)
            message = {**message, "params": {**message["params"], key: [
                {"type": "text", "text": json.dumps(payload, ensure_ascii=False)}]}}
            self.submitted = True
        self.inner.send(message)

    def poll(self):
        messages = self.inner.poll()
        if self.delegation.capability == "devin.text.only":
            for message in messages:
                update = message.get("params", {}).get("update", {})
                if (message.get("method") == "session/update"
                        and update.get("sessionUpdate") in {"tool_call", "tool_call_update"}):
                    # This is detection, not proof of pre-action interception.
                    # A text-only route must never report success after it.
                    self.tool_events += 1
                    raise ScopeDenied("text_only_native_tool_observed")
        return messages
    def alive(self): return self.inner.alive()
    def close(self): self.inner.close()


class WorkerWorkspace:
    """Controller-owned per-Attempt artifact writer; no generic filesystem handle.

    create_artifact is the public Command. It creates a new file exclusively;
    overwrite, symlink, hard-link, parent traversal and cross-Attempt writes are
    denied. Caller cannot select a workspace or protected-state inventory. The
    root is held open and each existing directory is opened relative to it with
    O_NOFOLLOW. The host must keep directory rename authority in trusted code.
    No claim is made that this Python object contains arbitrary Native tools.
    """
    def __init__(self, delegation, *, protected_state):
        root = Path(delegation.workspace)
        if (not delegation.human_intent_ref or not root.is_absolute()
                or root.resolve(strict=True) != root or not root.is_dir()
                or not protected_state):
            raise ScopeDenied("invalid_worker_workspace")
        protected = tuple(Path(p).resolve(strict=True) for p in protected_state)
        # Whole CO-state parent directories are excluded, including future DB
        # sidecars, rather than protecting only today's file names.
        if any(root.is_relative_to(p.parent) or p.parent.is_relative_to(root) for p in protected):
            raise ScopeDenied("protected_state_overlaps_workspace")
        self.delegation = delegation
        self._fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)

    def create_artifact(self, attempt, relative_path, content):
        if attempt != self.delegation.attempt or self._fd is None:
            raise ScopeDenied("worker_attempt_mismatch")
        if not isinstance(relative_path, str) or not isinstance(content, bytes):
            raise ScopeDenied("invalid_artifact_command")
        parts = relative_path.split("/")
        if not parts or any(p in ("", ".", "..") or "\x00" in p for p in parts):
            raise ScopeDenied("artifact_scope_denied")
        directory = os.dup(self._fd)
        try:
            for component in parts[:-1]:
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=directory)
                os.close(directory)
                directory = child
            fd = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=directory)
            with os.fdopen(fd, "wb") as output:
                output.write(content)
                output.flush()
                os.fsync(output.fileno())
        except OSError:
            raise ScopeDenied("artifact_scope_denied") from None
        finally:
            os.close(directory)

    def close(self):
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None
