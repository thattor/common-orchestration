"""Pure Codex Native RPC stage gate over a single RPCTracker leaf.

Orders initialize -> initialized -> thread/start -> turn/start and admits
the metadata probe family only while ready or thread_ready. One turn/start
submission is admitted while thread_ready with no request pending.
No IO, no payload retention; sticky refusal under INVALID.
"""

import math

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

    def __init__(self, *, clock=None):
        if clock is not None and not callable(clock):
            raise NativeError(INVALID) from None
        self._tracker = RPCTracker()
        self._clock = clock
        self._stage = 'new'
        self.error = None
        self.thread_id = None
        self.turn_submissions = 0
        self.turn_write_attempt_at = None
        self.turn_rpc_confirmed = False
        self.turn_id = None

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
        """Gate one outgoing frame by exact method and stage."""
        method = message.get('method') if type(message) is dict else None
        if type(method) is str and method == 'turn/start':
            self._record_turn_attempt(message)
            return
        self._open()
        try:
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

    def _record_turn_attempt(self, message):
        """Count then stamp one turn/start submission before gating it."""
        self.turn_submissions += 1
        self._open()
        if self.turn_submissions != 1:
            self._refuse()
        self._stamp_turn_attempt()
        try:
            params = message.get('params')
            tid = params.get('threadId') if type(params) is dict else None
            if (self._stage != 'thread_ready'
                    or self._tracker.pending_rpc_count != 0
                    or type(params) is not dict
                    or type(tid) is not str
                    or not tid
                    or len(tid.encode('utf-8')) > 1024
                    or tid != self.thread_id):
                self._refuse()
            self._tracker.record_request(message)
            self._stage = 'turn_pending'
        except Exception:
            self._refuse()

    def _stamp_turn_attempt(self):
        """Store one valid write-attempt observation from the clock hook."""
        if self._clock is None:
            self._refuse()
        try:
            sample = self._clock()
        except (KeyboardInterrupt, SystemExit):
            self.error = INVALID
            raise
        except Exception:
            self._refuse()
        if type(sample) is bool or type(sample) not in (int, float):
            self._refuse()
        try:
            value = float(sample)
        except Exception:
            self._refuse()
        if not math.isfinite(value) or value < 0:
            self._refuse()
        self.turn_write_attempt_at = value

    def consume_response(self, frame):
        """Consume one Tracker-matched reply; bind ids only if valid."""
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
            elif method == 'turn/start':
                turn = result.get('turn')
                if type(turn) is not dict:
                    self._refuse()
                tid = turn.get('id')
                status = turn.get('status')
                items = turn.get('items')
                if (self._stage != 'turn_pending'
                        or self.turn_submissions != 1
                        or self.turn_rpc_confirmed
                        or type(tid) is not str or not tid
                        or len(tid.encode('utf-8')) > 1024
                        or type(status) is not str or status != 'inProgress'
                        or type(items) is not list or len(items) > 128
                        or turn.get('error') is not None
                        or result.get('error') is not None):
                    self._refuse()
                self.turn_id = tid
                self.turn_rpc_confirmed = True
                self._stage = 'turn_replied'
            return method, result
        except Exception:
            self._refuse()
