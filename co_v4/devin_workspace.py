"""Exact-request host binding; see ../DEVIN-WORKSPACE-BINDING.md."""
from dataclasses import asdict, dataclass, field
import hashlib
import json
import os
from pathlib import Path
import stat

from .contracts import AttemptRef, ExecuteRequest, ExecutionConditions, Job


class WorkspaceBindingError(RuntimeError):
    """Fixed diagnostics; no private paths or request contents."""


def _identity(path, *, directory):
    if type(path) is not type(Path()) or not path.is_absolute() or path.resolve(strict=True) != path:
        raise WorkspaceBindingError('workspace_binding_noncanonical_target')
    info = path.stat(follow_symlinks=False)
    if (info.st_uid != os.getuid()
            or (directory and not stat.S_ISDIR(info.st_mode))
            or (not directory and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1))):
        raise WorkspaceBindingError('workspace_binding_unowned_target')
    return (str(path), info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode)


def _request_digest(request):
    if (type(request) is not ExecuteRequest or type(request.ref) is not AttemptRef
            or type(request.job) is not Job or type(request.conditions) is not ExecutionConditions
            or type(request.job.acceptance_criteria) is not tuple
            or type(request.conditions.control_evidence_refs) is not tuple):
        raise WorkspaceBindingError('workspace_binding_mutable_request')
    values = (request.ref.run_id, request.ref.job_id, request.ref.attempt_id,
        request.job.run_id, request.job.job_id, request.job.instructions, request.job.context_json,
        *request.job.acceptance_criteria, request.conditions.model, request.conditions.adapter,
        request.conditions.workspace, request.conditions.environment_ref, *request.conditions.control_evidence_refs)
    if any(type(value) is not str for value in values):
        raise WorkspaceBindingError('workspace_binding_mutable_request')
    return hashlib.sha256(json.dumps(asdict(request), sort_keys=True, separators=(',', ':')).encode()).hexdigest()


@dataclass(frozen=True)
class DevinWorkspaceBinding:
    """Host-owned resolution, not authority, Approval or Catalog qualification.

    No arbitrary resolver callback: one logical request maps to one pinned local
    target. The caller must retain actual scope/config evidence before dispatch.
    """
    request: ExecuteRequest
    physical_workspace: Path
    protected_state: tuple[Path, ...]
    environment_evidence_ref: str
    _targets: tuple = field(init=False, repr=False)
    _request_digest: str = field(init=False, repr=False)
    binding_ref: str = field(init=False)

    def __post_init__(self):
        request_digest = _request_digest(self.request)
        if (type(self.request) is not ExecuteRequest
                or self.request.conditions.adapter != 'devin.acp'
                or not self.request.conditions.workspace.startswith('candidate-workspace:')
                or not self.request.conditions.workspace.removeprefix('candidate-workspace:').strip()
                or type(self.protected_state) is not tuple or not 1 <= len(self.protected_state) <= 8
                or not isinstance(self.environment_evidence_ref, str)
                or not self.environment_evidence_ref.strip()):
            raise WorkspaceBindingError('workspace_binding_invalid_contract')
        targets = self._inspect()
        object.__setattr__(self, '_targets', targets)
        object.__setattr__(self, '_request_digest', request_digest)
        content = {'request': asdict(self.request), 'targets': targets,
                   'environment_evidence_ref': self.environment_evidence_ref}
        digest = hashlib.sha256(json.dumps(content, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        object.__setattr__(self, 'binding_ref', 'devin-workspace:' + digest)

    def _inspect(self):
        try:
            root = self.physical_workspace
            identity = _identity(root, directory=True)
            if stat.S_IMODE(identity[-1]) != 0o700:
                raise WorkspaceBindingError('workspace_binding_nonprivate_target')
            targets = []
            for target in self.protected_state:
                if root.is_relative_to(target.parent) or target.parent.is_relative_to(root):
                    raise WorkspaceBindingError('workspace_binding_protected_overlap')
                targets.append((_identity(target, directory=False), _identity(target.parent, directory=True)))
            return identity, tuple(targets)
        except WorkspaceBindingError:
            raise
        except Exception:
            raise WorkspaceBindingError('workspace_binding_target_unavailable') from None

    def validate(self, request, protected_state=None):
        if (_request_digest(request) != self._request_digest or request != self.request
                or (protected_state is not None and protected_state != self.protected_state)):
            raise WorkspaceBindingError('workspace_binding_request_mismatch')
        if self._inspect() != self._targets:
            raise WorkspaceBindingError('workspace_binding_target_changed')
        return str(self.physical_workspace)


def execution_workspace(request, binding=None):
    """Return physical cwd without replacing the logical ExecuteRequest."""
    if binding is None:
        return request.conditions.workspace
    if type(binding) is not DevinWorkspaceBinding:
        raise WorkspaceBindingError('workspace_binding_invalid_contract')
    return binding.validate(request)
