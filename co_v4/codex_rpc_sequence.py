"""Pure Codex Native RPC stage gate over a single RPCTracker leaf.

Orders initialize -> initialized -> thread/start and admits the metadata
probe family only while ready or thread_ready; never admits turn/start.
No IO, no payload retention; sticky refusal under INVALID.
"""

from co_v4.adapters.codex import NativeError
from co_v4.codex_rpc_tracker import RPCTracker

INVALID = 'codex_rpc_sequence_invalid'

_PROBE_METHODS = frozenset({
    'model/list', 'config/read', 'account/read',
    'account/rateLimits/read', 'command/exec',
})
_INITIALIZED_KEYS = (frozenset({'method'}), frozenset({'method', 'jsonrpc'}))


class CodexRPCSequence:
    """Sticky stage gate; the Tracker alone owns shape, ids, and limits."""

    def __init__(self):
        self._tracker = RPCTracker()
        self._stage = 'new'
        self.error = None
        self.thread_id = None

    @property
    def stage(self):
        return self._stage

    @property
    def pending_rpc_count(self):
        return self._tracker.pending_rpc_count

    def _open(self):
        if self.error is not None:
            raise NativeError(INVALID) from None

    def _refuse(self):
        self.error = INVALID
        raise NativeError(INVALID) from None

    def record_outgoing(self, message):
        """Gate one outgoing frame by exact method/stage; no turn/start."""
        self._open()
        try:
            method = message.get('method') if type(message) is dict else None
            if type(method) is not str:
                self._refuse()
            if method == 'initialize':
                if self._stage != 'new':
                    self._refuse()
                self._tracker.record_request(message)
                self._stage = 'initialize_pending'
            elif method == 'initialized':
                version = message.get('jsonrpc', '2.0')
                if (self._stage != 'initialize_replied'
                        or self._tracker.pending_rpc_count != 0
                        or frozenset(message) not in _INITIALIZED_KEYS
                        or type(version) is not str or version != '2.0'):
                    self._refuse()
                self._stage = 'ready'
            elif method == 'thread/start':
                if (self._stage != 'ready'
                        or self._tracker.pending_rpc_count != 0):
                    self._refuse()
                self._tracker.record_request(message)
                self._stage = 'thread_pending'
            elif (method in _PROBE_METHODS
                    and self._stage in ('ready', 'thread_ready')):
                self._tracker.record_request(message)
            else:
                self._refuse()
        except Exception:
            self._refuse()

    def consume_response(self, frame):
        """Consume one Tracker-matched reply; bind thread id only if valid."""
        self._open()
        try:
            method, result = self._tracker.consume_response(frame)
            if method == 'initialize':
                if (self._stage != 'initialize_pending'
                        or type(result.get('userAgent')) is not str):
                    self._refuse()
                self._stage = 'initialize_replied'
            elif method == 'thread/start':
                thread = result.get('thread')
                tid = thread.get('id') if type(thread) is dict else None
                if (self._stage != 'thread_pending' or type(tid) is not str
                        or not tid or len(tid.encode('utf-8')) > 1024):
                    self._refuse()
                self.thread_id = tid
                self._stage = 'thread_ready'
            return method, result
        except Exception:
            self._refuse()
