"""Single-Attempt, text-only Devin host under the 0.3 Native handoff guarantee.

Plan mode, no ACP client filesystem/terminal capabilities, no session MCPs,
minimal inherited environment and the bound delegation prompt are mandatory.
Native auth remains in place. This is not an OS sandbox or proof that Native
cannot ignore its prompt. Text cessation requires the original prompt response,
owned CLI wait and validated EOF. Unknown scope, ALLOW and Resume stay unsupported.
"""
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import platform
import re

from .adapters.devin import AcpTransport, DevinAdapter
from .codex_host import HostUnverified, _identity
from .contracts import ExecutionConditions
from .delegation import DelegatedScope, DelegatedTransport
from .devin_selection import ModelObservation, resolve_model, selection
from .devin_workspace import DevinWorkspaceBinding, execution_workspace


@dataclass(frozen=True)
class DevinLaunchTemplate:
    conditions: ExecutionConditions
    executable: Path
    expected_version: str
    protected_state: tuple[Path, ...]
    credential_files: tuple[Path, ...]
    effort: str | None = field(default=None, kw_only=True)
    workspace_binding: DevinWorkspaceBinding | None = field(default=None, kw_only=True)


@dataclass(frozen=True)
class DevinHostConfig(DevinLaunchTemplate):
    delegation: DelegatedScope


def launch_environment():
    """The exact minimal inherited environment of this trusted route."""
    return {key: os.environ[key] for key in ("HOME", "PATH", "TMPDIR", "USER", "LOGNAME", "LANG")
            if key in os.environ}


def check_launch_template(config):
    """Check current local targets without starting Native or asserting admission.

    The returned private fingerprint contains target identities and executable
    digest, not credential values. It is one input to dispatch admission; only
    verify(session) may attest actual Native handoff.
    """
    c = config
    if (type(c) not in {DevinLaunchTemplate, DevinHostConfig}
            or c.conditions.adapter != "devin.acp"
            or not c.conditions.environment_ref or not c.conditions.control_evidence_refs
            or platform.system() != "Darwin" or platform.machine() != "arm64"
            or not c.expected_version or not 1 <= len(c.protected_state) <= 8
            or not 1 <= len(c.credential_files) <= 8):
        raise HostUnverified("environment_not_supported")
    try:
        if resolve_model(c.conditions.model, c.effort) != c.conditions.model:
            raise ValueError("exact model required in ExecutionConditions")
    except ValueError:
        raise HostUnverified("unsupported_devin_selection") from None
    binding = c.workspace_binding
    if binding is not None:
        if type(binding) is not DevinWorkspaceBinding or binding.request.conditions != c.conditions:
            raise HostUnverified("workspace_binding_mismatch")
        root = Path(binding.validate(binding.request, c.protected_state))
    else:
        root = Path(c.conditions.workspace)
    if not root.is_dir() or any(p.is_relative_to(root) for p in c.protected_state):
        raise HostUnverified("protected_state_inside_worker_workspace")
    if any(not p.is_file() for p in (*c.protected_state, *c.credential_files)):
        raise HostUnverified("required_target_missing")
    targets = (c.executable, root, *c.protected_state,
               *(p.parent for p in c.protected_state), *c.credential_files)
    return (tuple(_identity(p) for p in targets),
            hashlib.sha256(c.executable.read_bytes()).hexdigest(),
            tuple(selection(c.conditions.model, c.effort).items()))


class DevinTextHost:
    """Trusted composition only; never construct from Worker JSON."""
    def __init__(self, config, *, expected_response=None):
        if expected_response is not None and (type(expected_response) is not str or
                not re.fullmatch(r'[A-Z0-9_]{1,128}', expected_response)):
            raise ValueError('fixed allowlisted response required')
        if resolve_model(config.conditions.model, config.effort) != config.conditions.model:
            raise HostUnverified("exact_devin_model_required")
        self._models = ModelObservation(config.conditions.model)
        self._expected_response = expected_response
        self._response_text, self._response_overflow, self._response_chunks = '', False, 0
        self.config = config
        self._request = self._transport = self._binding = None
        self._admitted = False
        self._session = None
        self.observation = {"status": "not_run", "native_handoff_verified": False,
                            "installed_production": False, "credential_isolation_verified": False,
                            "credential_inventory_complete": False,
                            "selection": selection(config.conditions.model, config.effort),
                            **self._models.evidence()}

    def make_adapter(self):
        return DevinAdapter(verify_host=self.verify, transport_factory=(self.transport if
                            self._expected_response is None else self.observed_transport),
                            desired_mode="plan", verify_text_cessation=self.verify_text_cessation,
                            workspace_binding=self.config.workspace_binding,
                            observe_model=self.observe_model)

    def observe_model(self, fields, *, current_update=False):
        try:
            self._models.observe(fields, current_update=current_update)
            self.observation.update(self._models.evidence())
        except ValueError:
            self._admitted = False
            self.observation.update(status="native_model_mismatch", native_handoff_verified=False,
                                    effective_model_verified=False, effective_model=None,
                                    model_binding="native_model_mismatch")
            raise HostUnverified("native_model_mismatch") from None

    def _check(self, request):
        c = self.config
        try:
            c.delegation.validate(request, "devin.text.only")
        except Exception:
            raise HostUnverified("delegated_scope_mismatch") from None
        if request.conditions != c.conditions:
            raise HostUnverified("execution_conditions_mismatch")
        if c.workspace_binding is not None:
            c.workspace_binding.validate(request, c.protected_state)
        binding = check_launch_template(c)
        if self._binding is not None and self._binding != binding:
            raise HostUnverified("host_target_changed")
        self._binding = binding

    def verify(self, request, phase, native):
        try:
            self._check(request)
            if phase == "launch":
                if self._request is not None:
                    raise HostUnverified("host_already_used")
                self._request = request
                self.observation["status"] = "awaiting_native_preflight"
                return
            if phase != "session" or request != self._request or self._transport is None:
                raise HostUnverified("unbound_native_transport")
            if not isinstance(native, dict) or not native.get("sessionId"):
                raise HostUnverified("native_configuration_mismatch")
            modes = []
            if "modes" in native:
                modes.append(native["modes"].get("currentModeId"))
            if "configOptions" in native:
                modes.extend(option.get("currentValue") for option in native["configOptions"]
                             if (option.get("id") or option.get("configId")) == "mode")
            if not modes or any(mode != "plan" for mode in modes):
                raise HostUnverified("native_configuration_mismatch")
            self.observe_model(native)
            self._admitted = True
            self._session = native["sessionId"]
            self.observation.update(status="delegated_native_preflight_passed",
                native_handoff_verified=True, guarantee_model="native_handoff_v1",
                delegated_capability="devin.text.only", native_mode="plan",
                environment_ref=self.config.conditions.environment_ref,
                human_intent_ref=self.config.delegation.human_intent_ref,
                attempt_ref={"run_id": request.ref.run_id, "job_id": request.ref.job_id,
                             "attempt_id": request.ref.attempt_id},
                credential_values_read=False, native_internal_isolation_claimed=False)
            if self.config.workspace_binding is not None:
                self.observation.update(
                    workspace_binding_ref=self.config.workspace_binding.binding_ref,
                    workspace_environment_evidence_ref=self.config.workspace_binding.environment_evidence_ref)
        except HostUnverified as exc:
            self._admitted = False
            self.observation.update(status=str(exc), native_handoff_verified=False)
            raise
        except Exception:
            self._admitted = False
            self.observation.update(status="host_preflight_unavailable", native_handoff_verified=False)
            raise HostUnverified("host_preflight_unavailable") from None

    def transport(self, request):
        if request != self._request or self._transport is not None:
            raise HostUnverified("unbound_native_transport")
        self._check(request)
        env = launch_environment()
        inner = AcpTransport(str(self.config.executable), execution_workspace(request, self.config.workspace_binding),
            request.conditions.model, expected_version=self.config.expected_version, environ=env)
        self._transport = DelegatedTransport(inner, request, self.config.delegation,
            admitted=lambda: self._admitted, workspace_binding=self.config.workspace_binding)
        return self._transport

    def observed_transport(self, request):
        """Fixed-response observation only; no arbitrary transport or callback hook."""
        inner = self.transport(request)
        host = self
        class Observe:
            def send(self, message): inner.send(message)
            def poll(self):
                messages = inner.poll()
                for message in messages:
                    if message.get('method') != 'session/update': continue
                    params = message.get('params', {})
                    update = params.get('update', {})
                    if update.get('sessionUpdate') != 'agent_message_chunk': continue
                    content = update.get('content', {})
                    if (not inner.submitted or params.get('sessionId') != host._session
                            or content.get('type') != 'text' or type(content.get('text')) is not str):
                        host._response_overflow = True
                        host._response_text = ''
                        continue
                    host._response_chunks += 1
                    if host._response_overflow or len(host._response_text) + len(content['text']) > 128:
                        host._response_overflow = True
                        host._response_text = ''
                    else:
                        host._response_text += content['text']
                return messages
            def alive(self): return inner.alive()
            def close(self): inner.close()
        return Observe()

    def verify_text_cessation(self, request, session, prompt_rpc, stop_reason, drain):
        """Attest only this host's bound text turn and owned CLI, not descendants.

        The Adapter supplies the correlated original prompt completion and
        validates the remaining frames. Native fields and arbitrary transports
        cannot manufacture process-wait evidence. A hash binds private IDs;
        raw session/RPC identifiers and Native text never enter CO records.
        """
        self._check(request)
        transport = self._transport
        if (not self._admitted or request != self._request or session != self._session
                or type(transport) is not DelegatedTransport
                or transport.request != request or transport.delegation != self.config.delegation
                or not transport.submitted or transport.tool_events
                or stop_reason not in {"end_turn", "cancelled"}):
            raise HostUnverified("text_cessation_binding_unverified")
        inner = transport.inner
        if type(inner) is not AcpTransport:
            # Synthetic/custom transports can exercise Result mapping, but do
            # not acquire production cessation authority from lookalike fields.
            return None
        if (inner.prompt_binding != (session, prompt_rpc)
                or inner._outgoing or inner._closed):
            raise HostUnverified("owned_cli_binding_unverified")
        inner.reap_owned()
        drain(inner.drained)
        if (not inner.drained() or inner._waited_exit is None
                or inner._process.poll() != inner._waited_exit or transport.tool_events):
            raise HostUnverified("owned_cli_completion_unverified")
        observation = {
            "guarantee_model": "native_handoff_v1", "capability": "devin.text.only",
            "attempt_ref": {"run_id": request.ref.run_id, "job_id": request.ref.job_id,
                            "attempt_id": request.ref.attempt_id},
            "environment_ref": request.conditions.environment_ref,
            "native_version": self.config.expected_version,
            "selection": selection(request.conditions.model, self.config.effort),
            **self._models.evidence(),
            "session_sha256": hashlib.sha256(session.encode()).hexdigest(),
            "prompt_rpc_sha256": hashlib.sha256(prompt_rpc.encode()).hexdigest(),
            "native_stop_reason": stop_reason, "native_mode": "plan",
            "owned_pid": inner._process.pid, "owned_exit_code": inner._waited_exit,
            "owned_cleanup_action": inner._cleanup_action, "stdout_eof_validated": True,
            "tool_events": 0, "pending_permissions": 0,
            "native_internal_isolation_claimed": False,
        }
        proof = "devin.acp:text-only:" + stop_reason + ":" + hashlib.sha256(
            json.dumps(observation, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self.observation["cessation"] = {**observation, "evidence_ref": proof}
        if self._expected_response is not None:
            self.observation['fixed_response'] = {
                'expected_sha256': hashlib.sha256(self._expected_response.encode()).hexdigest(),
                'observed_sha256': (None if self._response_overflow else
                                    hashlib.sha256(self._response_text.encode()).hexdigest()),
                'observed_utf8_bytes': (None if self._response_overflow else len(self._response_text.encode())),
                'matched': not self._response_overflow and self._response_text == self._expected_response,
                'overflow_or_unbound': self._response_overflow, 'chunks': self._response_chunks,
                'validated_eof': True}
            self._response_text = ''
        return proof
