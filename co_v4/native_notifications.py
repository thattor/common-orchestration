"""Conservative translation seam for Codex app-server 0.156.1.

Schema-derived, NOT evidence of interception or a production Codex Adapter.
No shell parsing: commandActions is best-effort display data, not authorization.
"""
from .contracts import Action, AttemptRef, Confirmation, Decision, Scope


COMMAND_APPROVAL = "item/commandExecution/requestApproval"


def codex_confirmation(ref: AttemptRef, request_id: str, method: str,
                       params: dict) -> Confirmation:
    # request_id is allocated for each JSON-RPC callback, including callbacks
    # sharing itemId but differing in approvalId (stdin/subcommands).
    if not request_id:
        raise ValueError("CO confirmation ID required")
    if method != COMMAND_APPROVAL:
        return Confirmation(ref, request_id, Decision.UNDETERMINED,
                            Action("native.unknown", Scope((("method", method),))),
                            "unmapped Native notification", "codex.app-server", False)
    dimensions = tuple((key, params.get(key) if isinstance(params.get(key), str)
                        and params.get(key) else None)
                       for key in ("command", "cwd", "environmentId"))
    # Even a known command+cwd does not prove repository/branch/effect, environment,
    # shell expansion, stdin or network target. Trusted resolution is #158 work.
    action = Action("process.execute", Scope(dimensions, complete=False))
    return Confirmation(ref, request_id, Decision.UNDETERMINED, action,
                        "Native approval requested; semantic target unresolved",
                        "codex.app-server", True)
