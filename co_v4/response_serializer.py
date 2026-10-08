"""Allowlist-only northbound Responses serializer (#190 M3).

Maps a trusted Gateway Projection plus the canonical TaskIntent to the
plain closed dict the HTTP layer returns. Never emits run/attempt/job
IDs, provider model names, routes, adapter errors, diagnostics, input
items or context. Fixed codes/messages only; no exception text. The
OutputStore is touched only for a decided completed projection, via
get(), which rehashes stored bytes before any text is serialized.
"""
from . import contracts as c
from .gateway_store import PROJECTION_CODES, Projection
from .output_store import IntegrityError
from .responses_input import TaskIntent

_STATUSES = frozenset(
    {'queued', 'in_progress', 'completed', 'failed', 'cancelled'})

_MESSAGES = {
    'provider_refusal':
        'provider_refusal: the model provider refused the request',
    'content_filter':
        'content_filter: the response was blocked by a content filter',
    'protocol_violation':
        'protocol_violation: the provider reply violated the protocol',
    'output_unavailable':
        'output_unavailable: the run completed without a usable output',
    'approval_required': 'approval_required: the request requires approval',
    'integrity_violation':
        'integrity_violation: stored state failed an integrity check',
    'cessation_unconfirmed':
        'cessation_unconfirmed: execution cessation was not confirmed',
    'cancellation_unconfirmed':
        'cancellation_unconfirmed: the cancellation was not confirmed',
    'run_failed': 'run_failed: the run failed',
}
assert frozenset(_MESSAGES) == PROJECTION_CODES


def serialize_response(projection, intent, created_at, output_store):
    """Closed Responses-subset dict; raises ValueError/IntegrityError."""
    if type(projection) is not Projection:
        raise ValueError('typed Projection required')
    if type(intent) is not TaskIntent:
        raise ValueError('typed TaskIntent required')
    if type(created_at) is not int or created_at < 0:
        raise ValueError('integer epoch created_at required')
    if (type(projection.status) is not str
            or projection.status not in _STATUSES
            or type(projection.decided) is not bool
            or type(projection.response_id) is not str):
        raise ValueError('invalid projection')
    error = None
    if projection.status == 'failed':
        if type(projection.code) is not str \
                or projection.code not in _MESSAGES:
            raise IntegrityError('failed projection lacks closed code')
        error = {'code': 'server_error',
                 'message': _MESSAGES[projection.code]}
    elif projection.code is not None:
        raise IntegrityError('non-failed projection carries code')
    output = []
    if projection.status == 'completed':
        sel = projection.output
        if (not projection.decided
                or type(sel) is not tuple or len(sel) != 2
                or type(sel[0]) is not c.OutputRef
                or type(sel[1]) is not c.AttemptOutput):
            raise IntegrityError('completed projection lacks output')
        texts = output_store.get(sel[0], sel[1])  # rehashed; may raise
        output = [{
            'id': 'msg_' + sel[0].digest[7:],
            'type': 'message',
            'role': 'assistant',
            'status': 'completed',
            'content': [{'type': 'output_text', 'text': text,
                         'annotations': []} for text in texts],
        }]
    elif projection.output is not None:
        raise IntegrityError('non-completed projection carries output')
    return {
        'id': projection.response_id,
        'object': 'response',
        'created_at': created_at,
        'status': projection.status,
        'model': intent.model,
        'output': output,
        'error': error,
        'incomplete_details': None,
        'instructions': intent.instructions,
        'metadata': dict(intent.metadata),
        'background': intent.background,
        'tools': [],
        'tool_choice': 'none',
        'parallel_tool_calls': False,
        'text': {'format': {'type': 'text'}},
        'usage': None,
    }
