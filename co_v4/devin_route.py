"""Trusted, launch-bound composition for Controller -> DevinTextHost.

Dispatch admission attests the actual checked host and mandatory gate wiring.
It is not Native session admission, Human authentication or OS isolation. The
resolver must separately verify Human intent/policy and role-owned state. A
model prompt remains impossible until the existing exact-session gate passes.
No Native process is started by bind; assess only runs the bounded version
command. All methods and receipts belong outside Worker reach.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import fcntl
import os
import stat
import json
from pathlib import Path
import subprocess

from . import contracts as c
from . import delegation, devin_host, devin_workspace, devin_selection
from .adapters import devin
from .codex_host import HostUnverified
from .delegation import DelegatedScope
from .devin_host import (DevinHostConfig, DevinLaunchTemplate, DevinTextHost,
                         check_launch_template, launch_environment)
from .state import NotFound, body_digest
from .trace import PublicationPolicy, canonical


def environment_definition(template: DevinLaunchTemplate, *, policy_ref: str):
    """Immutable configuration identity, separately checked per launch instance.

    Actual workspace/state/credential identities remain in each admission.
    This identity never aliases a previous environment or verifies a use by
    itself. Catalog qualification must measure this configuration and use first.
    """
    if not policy_ref.strip(): raise ValueError('reviewed policy reference required')
    fingerprint = check_launch_template(template)
    workspace = (template.workspace_binding.physical_workspace if template.workspace_binding is not None
                 else Path(template.conditions.workspace))
    info = workspace.stat(follow_symlinks=False)
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700 or any(workspace.iterdir()):
        raise HostUnverified('environment_definition_requires_fresh_private_workspace')
    sources = tuple((module.__name__, hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest())
                    for module in (devin_host, devin, delegation, devin_workspace, devin_selection))
    descriptor = {
        'schema': 'devin-text-launch-template-v1', 'model': template.conditions.model,
        'adapter': 'devin.acp', 'capability': 'devin.text.only',
        'selection': devin_selection.selection(template.conditions.model, template.effort),
        'native_version_required': template.expected_version, 'executable_sha256': fingerprint[1],
        'implementation_sha256': sources,
        'route_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'platform': 'Darwin-arm64', 'policy_ref': policy_ref,
        'native_mode_required': 'plan', 'client_filesystem': False, 'client_terminal': False,
        'session_mcp': [], 'inherited_environment_names': sorted(launch_environment()),
        'workspace_rule': 'fresh canonical private workspace; separate canonical protected state',
        'protected_target_count': len(template.protected_state),
        'auth_metadata_target_count': len(template.credential_files),
        'guarantee_model': 'native_handoff_v1', 'native_internal_isolation_claimed': False}
    if template.workspace_binding is not None:
        # This instance needs new evidence; never alias an absolute-workspace qualification.
        descriptor['workspace_resolution'] = 'devin-exact-request-binding-v1'
    PublicationPolicy.check_content(descriptor)
    return 'devin-text-template:' + hashlib.sha256(canonical(descriptor).encode()).hexdigest(), descriptor


@dataclass(frozen=True)
class DispatchAdmission:
    """Immutable evidence for one Job/conditions/revision, optionally one Attempt.

    The host must retain this readable receipt wherever evidence_ref resolves.
    It grants no authority by itself; execute also requires the exact reserved
    Attempt in ControllerState and a fresh binding check.
    """
    evidence_ref: str
    ref: c.QuestionRef
    job_digest: str
    conditions_digest: str
    state_revision: int
    observed_at: str
    native_version: str
    executable_sha256: str
    implementation_sha256: tuple[tuple[str, str], ...]
    environment_names: tuple[str, ...]
    protected_target_count: int
    auth_metadata_target_count: int
    binding_digest: str
    phase: str = 'dispatch_admission'
    native_handoff_verified: bool = False
    workspace_binding_ref: str | None = None
    workspace_environment_evidence_ref: str | None = None


class DevinTextRoute:
    """One fixed Job, immutable launch template, and direct trusted gate wiring.

    assess(job, conditions, revision) checks routing readiness. bind(request,
    revision) repeats those checks for the Controller-generated Attempt before
    final Judgment. Repeated bound Judgment reads are idempotent. execute only
    dispatches that same request after ControllerState reserves it. The actual
    Adapter Contract is unchanged; retries need new admissions/Attempt refs.
    """
    def __init__(self, template: DevinLaunchTemplate, job: c.Job, *,
                 human_intent_ref: str, state, expected_response: str | None = None):
        if (type(template) is not DevinLaunchTemplate or type(job) is not c.Job
                or not human_intent_ref.strip()):
            raise ValueError('trusted launch template, fixed Job and intent reference required')
        if devin_selection.resolve_model(template.conditions.model, template.effort) != template.conditions.model:
            raise HostUnverified("exact_devin_model_required")
        if template.workspace_binding is not None and template.workspace_binding.request.job != job:
            raise HostUnverified("dispatch_workspace_job_mismatch")
        self.template, self.job = template, job
        self.human_intent_ref, self.state = human_intent_ref, state
        self._expected_response = expected_response
        self._closed, self._owner_fd = False, None
        self._receipts, self._bound, self._submitted = {}, {}, set()
        self._baseline = None
        self._version = None
        # Capture the concrete gate implementations, not a caller-selected factory.
        self._wiring = self._gate_wiring()
        # The launch template's first protected target is its actual ControlStore.
        # Lock ownership serializes all route instances before they can bind,
        # including instances prepared before an Attempt is reserved.
        primary = template.protected_state[0] if template.protected_state else None
        if (primary is None or primary.resolve(strict=True) != primary
                or primary != state.storage_path):
            raise HostUnverified('dispatch_owner_target_unverified')
        lock = primary.with_name(primary.name + '.devin-owner.lock')
        fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid():
                raise HostUnverified('dispatch_owner_target_unverified')
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except Exception:
            os.close(fd)
            raise HostUnverified('dispatch_owner_unavailable') from None
        self._owner_fd = fd
        self._owner_path = lock
        try:
            # Read only after ownership acquisition. A prior owner may have
            # reserved/dispatched while this constructor was awaiting the lock.
            self._preexisting_attempts = frozenset(a.ref for a in state.attempts(job.run_id))
        except NotFound:
            self._preexisting_attempts = frozenset()
        except Exception:
            self.close()
            raise

    @staticmethod
    def _gate_wiring():
        return (devin_host.DevinTextHost, devin_host.DevinTextHost.make_adapter,
                devin_host.DevinTextHost.verify, devin_host.DevinTextHost.transport,
                devin_host.DevinTextHost.observed_transport, devin_host.check_launch_template,
                devin_host.launch_environment,
                devin.DevinAdapter, devin.DevinAdapter.execute,
                devin.DevinAdapter._start_prompt, delegation.DelegatedTransport,
                delegation.DelegatedTransport.send, delegation.DelegatedTransport.poll,
                devin_workspace.DevinWorkspaceBinding, devin_workspace.DevinWorkspaceBinding.validate,
                devin_workspace.DevinWorkspaceBinding._inspect, devin_workspace.execution_workspace,
                devin_workspace._identity, devin_workspace._request_digest,
                devin_host.execution_workspace, devin.execution_workspace,
                devin_selection.resolve_model, devin_selection.selection,
                devin_host.resolve_model, devin_host.selection, devin_selection.ModelObservation.observe,
                devin.DevinAdapter._observe_models, devin_host.DevinTextHost.observe_model)

    def _check(self):
        if self._closed or self._owner_fd is None:
            raise HostUnverified('dispatch_owner_closed')
        owned, current = os.fstat(self._owner_fd), self._owner_path.stat(follow_symlinks=False)
        if ((owned.st_dev, owned.st_ino) != (current.st_dev, current.st_ino)
                or self.template.protected_state[0] != self.state.storage_path):
            raise HostUnverified('dispatch_owner_target_changed')
        if self._gate_wiring() != self._wiring:
            raise HostUnverified('dispatch_gate_changed')
        fingerprint = check_launch_template(self.template)
        env = launch_environment()
        implementations = tuple((module.__name__, hashlib.sha256(
            Path(module.__file__).read_bytes()).hexdigest())
            for module in (devin_host, devin, delegation, devin_workspace, devin_selection))
        binding = (fingerprint, tuple(sorted(env.items())), implementations,
                   body_digest(self.template.conditions), body_digest(self.job),
                   self.template.expected_version, self.template.effort, self.human_intent_ref, self._expected_response,
                   self.template.workspace_binding.binding_ref if self.template.workspace_binding is not None else None)
        if self._baseline is not None and binding != self._baseline:
            raise HostUnverified('dispatch_template_changed')
        if self._version is None:
            observed = subprocess.run([str(self.template.executable), 'version'],
                capture_output=True, timeout=5, check=False, env=env)
            if observed.returncode or observed.stdout.strip() != self.template.expected_version.encode():
                raise HostUnverified('dispatch_native_version_mismatch')
            # Detect target/config replacement during the external version command.
            if fingerprint != check_launch_template(self.template) or env != launch_environment():
                raise HostUnverified('dispatch_template_changed')
            self._version = self.template.expected_version
        self._baseline = binding
        return fingerprint, env, implementations, hashlib.sha256(canonical(binding).encode()).hexdigest()

    def _admit(self, job, conditions, revision, ref):
        if (job != self.job or conditions != self.template.conditions
                or type(revision) is not int or revision < 0
                or (ref.run_id, ref.job_id) != (job.run_id, job.job_id)):
            raise HostUnverified('dispatch_request_mismatch')
        fingerprint, env, implementations, binding_digest = self._check()
        key = (ref, revision)
        previous = self._receipts.get(key)
        if previous is not None:
            return previous
        identity = {'ref': {'run_id': ref.run_id, 'job_id': ref.job_id, 'attempt_id': ref.attempt_id},
                    'job_digest': body_digest(job), 'conditions_digest': body_digest(conditions),
                    'revision': revision, 'binding_digest': binding_digest}
        receipt = DispatchAdmission('devin-dispatch:' + hashlib.sha256(canonical(identity).encode()).hexdigest(),
            ref, identity['job_digest'], identity['conditions_digest'], revision,
            datetime.now(timezone.utc).isoformat(), self._version, fingerprint[1], implementations,
            tuple(sorted(env)), len(self.template.protected_state), len(self.template.credential_files), binding_digest,
            workspace_binding_ref=(self.template.workspace_binding.binding_ref
                                   if self.template.workspace_binding is not None else None),
            workspace_environment_evidence_ref=(self.template.workspace_binding.environment_evidence_ref
                                   if self.template.workspace_binding is not None else None))
        # Receipt fields are selected host observations, not Native output.
        PublicationPolicy.check_content(json.loads(canonical({
            'evidence_ref': receipt.evidence_ref, 'native_version': receipt.native_version,
            'run_id': ref.run_id, 'job_id': ref.job_id, 'attempt_id': ref.attempt_id})))
        self._receipts[key] = receipt
        return receipt

    def assess(self, job, conditions, state_revision):
        return self._admit(job, conditions, state_revision, c.QuestionRef(job.run_id, job.job_id))

    def bind(self, request: c.ExecuteRequest, state_revision: int):
        ref = request.ref
        if self.template.workspace_binding is not None:
            self.template.workspace_binding.validate(request, self.template.protected_state)
        if type(request) is not c.ExecuteRequest or ref in self._preexisting_attempts:
            raise HostUnverified('dispatch_request_mismatch')
        receipt = self._admit(request.job, request.conditions, state_revision,
                             c.QuestionRef(ref.run_id, ref.job_id, ref.attempt_id))
        previous = self._bound.get(ref)
        if previous is not None:
            if previous[0] != request or previous[1] != receipt:
                raise HostUnverified('dispatch_attempt_rebound')
            return receipt
        if ref in self._submitted:
            raise HostUnverified('dispatch_attempt_already_submitted')
        template = self.template
        host = DevinTextHost(DevinHostConfig(template.conditions, template.executable,
            template.expected_version, template.protected_state, template.credential_files,
            DelegatedScope(self.human_intent_ref, ref, template.conditions.workspace, 'devin.text.only'),
            workspace_binding=template.workspace_binding, effort=template.effort),
            expected_response=self._expected_response)
        adapter = host.make_adapter()
        self._bound[ref] = request, receipt, host, adapter
        return receipt

    @property
    def admissions(self):
        return tuple(self._receipts.values())

    def observation(self, ref):
        return dict(self._bound[ref][2].observation)

    def execute(self, request):
        ref = request.ref
        if ref in self._submitted or ref in self._preexisting_attempts:
            return c.OperationReply(ref, c.OperationStatus.INVALID_STATE, 'Attempt already used')
        fresh = False
        try:
            registered, receipt, host, adapter = self._bound[ref]
            if registered != request:
                raise HostUnverified('dispatch_request_mismatch')
            run = self.state.get_run(ref.run_id)
            attempt = self.state.get_attempt(ref)
            fresh = (attempt.state == c.State.PENDING and attempt.started_at is None
                     and attempt.result is None and attempt.stop_reply is None
                     and self.state.execute_receipt(ref) is None)
            if not fresh:
                raise HostUnverified('dispatch_attempt_already_started')
            self._check()
            if (run.stop_requested or run.state in c.TERMINAL or run.revision != attempt.revision
                    or attempt.revision != receipt.state_revision + 1
                    or attempt.conditions != request.conditions
                    or self.state.get_job(ref.run_id, ref.job_id) != request.job):
                raise HostUnverified('dispatch_reservation_changed')
        except Exception:
            return c.OperationReply(ref, c.OperationStatus.UNSUPPORTED, 'dispatch admission unverified',
                never_started=(c.NeverStarted(request, 'devin:before-transport:dispatch-admission-unverified')
                               if fresh else None))
        self._submitted.add(ref)
        return adapter.execute(request)

    def _adapter(self, ref):
        if ref not in self._submitted:
            raise HostUnverified('dispatch_not_submitted')
        return self._bound[ref][3]

    def events(self, ref, after=None): return self._adapter(ref).events(ref, after)
    def status(self, ref): return self._adapter(ref).status(ref)
    def stop(self, ref): return self._adapter(ref).stop(ref)
    def respond(self, response): return self._adapter(response.ref).respond(response)
    def resume(self, state): return self._adapter(state.ref).resume(state)
    def usage(self): return ()

    def close(self):
        if self._closed: return
        self._closed = True
        failed = False
        try:
            for _, _, _, adapter in self._bound.values():
                try:
                    adapter.close()
                except Exception:
                    failed = True
        finally:
            if self._owner_fd is not None:
                fcntl.flock(self._owner_fd, fcntl.LOCK_UN)
                os.close(self._owner_fd)
                self._owner_fd = None

        if failed:
            raise HostUnverified('dispatch_cleanup_unconfirmed')
