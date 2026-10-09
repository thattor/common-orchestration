"""Pure in-memory JSON-RPC correlation tracker for the Codex Native route.

This leaf only correlates pending request ids to their methods. It performs
no IO, no send/launch claims, no sequencing, and retains no params, payloads,
while keeping ids only in bounded private accounting. Refusal is sticky.
"""

from co_v4.adapters.codex import NativeError
from co_v4.codex_text_validation import frame_kind, rpc_key

INVALID = 'codex_rpc_tracker_invalid'

_METHODS = frozenset({
    'initialize', 'thread/start', 'model/list', 'config/read',
    'account/read', 'account/rateLimits/read', 'command/exec', 'turn/start',
})
_REQUEST_KEYS = frozenset({'id', 'method', 'params', 'jsonrpc'})
_MAX_USED = 256
_MAX_PENDING = 128


class RPCTracker:
    """Bounded typed-ID to method correlation; never carries payloads."""

    def __init__(self):
        self.error = None
        self._used = set()
        self._pending = {}

    @property
    def pending_rpc_count(self):
        return len(self._pending)

    def _open(self):
        if self.error is not None:
            raise NativeError(INVALID) from None

    def _refuse(self):
        self.error = INVALID
        raise NativeError(INVALID) from None

    def record_request(self, message):
        """Validate a request frame and record its id-to-method correlation."""
        self._open()
        if type(message) is not dict:
            self._refuse()
        if not {'id', 'method', 'params'} <= message.keys() <= _REQUEST_KEYS:
            self._refuse()
        version = message.get('jsonrpc', '2.0')
        method = message['method']
        if (type(version) is not str or version != '2.0'
                or type(method) is not str or method not in _METHODS
                or type(message['params']) is not dict):
            self._refuse()
        try:
            key = rpc_key(message['id'])
        except NativeError:
            self._refuse()
        if (key in self._used or len(self._used) >= _MAX_USED
                or len(self._pending) >= _MAX_PENDING):
            self._refuse()
        self._used.add(key)
        self._pending[key] = method

    def consume_response(self, frame):
        """Match one response frame; return (method, fresh result copy)."""
        self._open()
        try:
            kind = frame_kind(frame)
        except NativeError:
            self._refuse()
        version = frame.get('jsonrpc', '2.0')
        if (kind != 'response' or type(version) is not str
                or version != '2.0' or type(frame['result']) is not dict):
            self._refuse()
        try:
            key = rpc_key(frame['id'])
        except NativeError:
            self._refuse()
        if key not in self._pending:
            self._refuse()
        method = self._pending[key]
        result = dict(frame['result'])
        del self._pending[key]
        return method, result
