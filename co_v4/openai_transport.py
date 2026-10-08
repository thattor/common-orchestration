"""Stdlib HTTP/SSE transport and per-Attempt plumbing for OpenAI-compatible edges.

One CO Attempt maps to exactly one provider POST: no transport or SDK retry,
redirect following, cookies, or auth discovery. Endpoint, model and store policy
are host-frozen route data; the auth supplier is injected by host composition
and is never callable from Job, northbound or Worker content.

sent_state records what is provable: 'not_sent' means the explicit connect
never returned, 'unknown' means the connection was established or the send
faulted partway, and 'sent' means the whole request body was written.
No response bytes is never evidence of non-execution, and
close() releases only the local socket; neither attests remote cessation.
"""
from dataclasses import dataclass, field
import codecs
import hashlib
import http.client
import json
import math
import queue
import re
import socket
import threading
import time
import urllib.parse
from uuid import uuid4

from .contracts import (CollectionError, NeverStarted, OperationReply,
    OperationStatus, OutputItem, State, StatusEvent, ResultEvent, Result,
    StopReply, StopStatus)
from .delegation import job_payload

MAX_STREAM = 8 * 1024 * 1024
# MAX_EVENT must fit the largest legal terminal frame or in-limit outputs
# lose their cessation proof: the independent size vector shows 262144
# in-limit decoded bytes serialize to 1573097 JSON bytes in a completed
# envelope; 2 MiB covers that plus 64x64 part metadata and envelope fields.
MAX_EVENT = 2 * 1024 * 1024
MAX_LINE = MAX_EVENT + 1024   # one data: line may carry a whole legal event
MAX_REQUEST = 1024 * 1024
MAX_OBSERVATIONS = 256
MAX_QUEUE = 256
MAX_HEADERS = 32
LOOPBACK_HOSTS = frozenset({'127.0.0.1', '::1', 'localhost'})
SENT_STATES = frozenset({'not_sent', 'unknown', 'sent'})
POLICY_REASONS = frozenset({'provider_refusal', 'content_filter',
    'protocol_violation'})
# sequence_number/output_index/content_index are ignored for terminal
# proof on every route: they mark semantically through _seq or the
# strict checker, never through shape.
STRUCTURAL_KEYS = frozenset({'sequence_number', 'output_index',
                             'content_index'})
RESPONSE_TERMINALS = frozenset({'response.completed', 'response.incomplete',
                                'response.failed'})
RESERVED_HEADERS = frozenset({'host', 'content-length', 'connection',
    'transfer-encoding', 'te', 'upgrade', 'expect'})
_HEADER_NAME = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,128}\Z")
_HEADER_VALUE = re.compile('[\t\x20-\x7e\x80-\uffff]{0,8192}\\Z')


def _refuse(*args):
    raise ValueError('unverified host')


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result


def strict_json(data):
    """Reject duplicate keys and non-JSON constants; returns any JSON value."""
    return json.loads(data, object_pairs_hook=_object,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))


def payload_digest(request):
    """Canonical digest of the exact delegated payload; binds route to request."""
    return hashlib.sha256(json.dumps(job_payload(request), sort_keys=True,
        ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


@dataclass(frozen=True)
class Deadlines:
    """Bounded per-Attempt clocks enforced by the transport, not the provider."""
    connect: float = 10.0
    first_byte: float = 30.0
    idle: float = 60.0
    total: float = 120.0

    def __post_init__(self):
        for name in ('connect', 'first_byte', 'idle', 'total'):
            value = getattr(self, name)
            if (type(value) not in (int, float) or not math.isfinite(value)
                    or not 0 < value <= 600):
                raise ValueError('bounded deadline required')


@dataclass(frozen=True)
class OpenAIRoute:
    """Host-frozen per-request route binding; not authorization evidence.

    The route pins the exact ExecuteRequest it serves. Worker, northbound or
    model content cannot select endpoint, credentials or storage policy.
    """
    request: object
    endpoint: str
    model: str
    store_param: str           # 'send_false' | 'omit'; verified per route
    payload_sha256: str
    # HTTP statuses the route's verification evidence records as
    # pre-generation rejections; only these may confirm cessation.
    confirmed_statuses: tuple = ()
    # Responses sequence_number handling: 'required' unless route evidence
    # records the field is never emitted on this route ('absent').
    sequence: str = 'required'
    # True only where route evidence records a post-terminal [DONE] on the
    # Responses wire; Chat does not consult it (one [DONE] allowed globally).
    allow_terminal_done: bool = False
    # Host-configured qualified-route binding: a co.route-protocol/2 profile
    # plus its non-secret credential reference name. Neither field is
    # authority — only a QualifiedRouteGate binding enables dispatch.
    profile: object = None
    auth_ref: object = None

    def __post_init__(self):
        parsed = urllib.parse.urlsplit(self.endpoint)
        try:
            bad_port = parsed.port is not None and not 0 < parsed.port < 65536
        except ValueError:
            bad_port = True
        if (self.store_param not in ('send_false', 'omit')
                or type(self.model) is not str or not self.model
                or re.fullmatch('[0-9a-f]{64}', self.payload_sha256 or '') is None
                or parsed.username is not None or parsed.password is not None
                or not parsed.hostname or bad_port
                or (parsed.scheme != 'https' and not (
                    parsed.scheme == 'http'
                    and parsed.hostname.lower() in LOOPBACK_HOSTS))):
            raise ValueError('invalid frozen route')
        if (type(self.confirmed_statuses) is not tuple
                or len(self.confirmed_statuses) > 32
                or any(type(status) is not int or not 100 <= status <= 599
                       for status in self.confirmed_statuses)):
            raise ValueError('invalid confirmed status set')
        if (self.sequence not in ('required', 'absent')
                or type(self.allow_terminal_done) is not bool):
            raise ValueError('invalid route evidence flags')
        if self.profile is not None:
            # Lazy: protocol_profile imports this module for strict_json.
            from .protocol_profile import RouteProtocolProfile
            if (type(self.profile) is not RouteProtocolProfile
                    or type(self.auth_ref) is not str or not self.auth_ref
                    or self.sequence
                    != ('absent' if self.profile.sequence_mode == 'absent'
                        else 'required')
                    or self.allow_terminal_done):
                raise ValueError('invalid route profile binding')
        conditions = getattr(self.request, 'conditions', None)
        if conditions is None or conditions.model != self.model:
            raise ValueError('route does not bind the exact request model')


@dataclass(frozen=True)
class StreamStarted:
    status: int


@dataclass(frozen=True)
class SseMessage:
    event: str
    data: str

    def __post_init__(self):
        if (type(self.event) is not str or len(self.event) > 256
                or type(self.data) is not str
                or len(self.data.encode('utf-8')) > MAX_EVENT):
            raise ValueError('invalid SSE message')


@dataclass(frozen=True)
class StreamEnded:
    """Clean HTTP EOF after all complete frames were delivered."""


@dataclass(frozen=True)
class StreamFailed:
    """Terminal transport observation; category is fixed vocabulary only."""
    category: str
    sent_state: str

    def __post_init__(self):
        if self.sent_state not in SENT_STATES:
            raise ValueError('invalid transmit proof state')


@dataclass(frozen=True)
class StreamCapped:
    """A host resource cap was reached; fixed vocabulary, never a policy
    verdict. The transport discards the untrusted frame to a resync point
    and keeps reading until the real protocol terminal or the deadline."""
    category: str


class TransportOpenError(Exception):
    """Fixed open-stage category plus transmit proof; never raw exception text."""

    def __init__(self, category, sent_state):
        super().__init__(category)
        self.category, self.sent_state = category, sent_state


class _StreamFault(Exception):
    def __init__(self, category):
        super().__init__(category)
        self.category = category


class _ProtocolError(ValueError):
    """Fixed protocol-violation category; never carries provider content."""


class _CapHit(ValueError):
    """Parser resource cap; never a policy or protocol verdict.

    events are the valid frames already emitted by the current feed() call;
    rest is the unconsumed buffer tail; discard is True when that tail begins
    inside the offending frame (skip to its blank-line boundary) and False
    when the offending line itself ended the frame (resume immediately).
    """
    def __init__(self, events, rest, discard):
        super().__init__('sse resource limit')
        self.events, self.rest, self.discard = events, rest, discard


def sse_object(data):
    """Strict JSON object for one SSE data payload; duplicate keys rejected."""
    try:
        obj = strict_json(data)
    except Exception:
        raise _ProtocolError('protocol_violation') from None
    if type(obj) is not dict:
        raise _ProtocolError('protocol_violation')
    return obj


class SseDecoder:
    """Incremental SSE parser; strict UTF-8 across arbitrary chunk splits.

    Handles CRLF, CR and LF line endings, comment lines, multiline data fields
    and events split at any byte boundary. An undispatched event and an
    unterminated final line are discarded at stream end per SSE semantics.
    """
    def __init__(self, max_event=MAX_EVENT, max_line=MAX_LINE):
        self._decoder = codecs.getincrementaldecoder('utf-8')('strict')
        self._max_event, self._max_line = max_event, max_line
        self._buf, self._data, self._name = '', [], ''
        self._size, self._bom = 0, True

    def _eol(self, final=False):
        buf = self._buf
        newline, cr = buf.find('\n'), buf.find('\r')
        if newline == -1 and cr == -1:
            return None
        if cr != -1 and (newline == -1 or cr < newline):
            if cr == len(buf) - 1 and not final:
                return None   # possible '\r\n' split across chunks
            if cr + 1 < len(buf) and buf[cr + 1] == '\n':
                return buf[:cr], 2
            return buf[:cr], 1
        return buf[:newline], 1

    def _line(self, line):
        if line == '':
            if not self._data:
                self._name = ''
                return None
            event = SseMessage(self._name or 'message', '\n'.join(self._data))
            self._data, self._name, self._size = [], '', 0
            return event
        if line.startswith(':'):
            return None
        name, sep, value = line.partition(':')
        if sep and value.startswith(' '):
            value = value[1:]
        if name == 'data':
            self._size += len(value.encode('utf-8')) + 1
            if self._size > self._max_event:
                raise ValueError('sse event limit')
            self._data.append(value)
        elif name == 'event':
            self._name = value
        return None   # id/retry/unknown fields are ignored per SSE spec

    def feed(self, chunk):
        if type(chunk) is not bytes:
            raise ValueError('sse chunk must be bytes')
        self._buf += self._decoder.decode(chunk)
        if self._bom and self._buf:
            self._bom = False
            if self._buf.startswith('\ufeff'):
                self._buf = self._buf[1:]
        events = []
        while True:
            found = self._eol()
            if found is None:
                break
            line, width = found
            if len(line.encode('utf-8')) > self._max_line:
                raise _CapHit(events, self._buf, True)
            self._buf = self._buf[len(line) + width:]
            try:
                event = self._line(line)
            except ValueError:
                # A dispatch-time limit means the offending frame is already
                # fully consumed; a mid-frame data limit leaves its tail in
                # _buf so the resync skips that frame only.
                raise _CapHit(events, self._buf, line != '') from None
            if event is not None:
                events.append(event)
        if (len(self._buf) > self._max_line // 4
                and len(self._buf.encode('utf-8')) > self._max_line):
            raise _CapHit(events, self._buf, True)
        return events

    def finish(self):
        self._buf += self._decoder.decode(b'', final=True)
        if self._buf.endswith('\r'):
            line, self._buf = self._buf[:-1], ''
            event = self._line(line)
            return (event,) if event is not None else ()
        return ()


class _Discard:
    """Bounded resync scanner for an untrusted oversized frame.

    Bytes are skipped until the blank line that ends the discarded event; no
    frame content is buffered, so a runaway frame cannot grow memory. The
    skipped bytes are never trusted as a terminal frame.
    """
    def __init__(self):
        # Resync always begins at a line boundary: _CapHit.rest starts either
        # with the unconsumed offending line or with the blank line ending
        # the offending frame, which this flag correctly closes.
        self._line_end, self._cr = True, False

    def feed(self, chunk):
        """Return the offset where normal decoding resumes, or None."""
        i, n = 0, len(chunk)
        while i < n:
            b = chunk[i]
            i += 1
            if b == 13 or b == 10:
                ended = self._line_end and not (self._cr and b == 10)
                self._line_end, self._cr = True, b == 13
                if ended:
                    if b == 13 and i < n and chunk[i] == 10:
                        i += 1   # consume the rest of the CRLF terminator
                    return i
            else:
                self._line_end = self._cr = False
        return None


class HttpSseTransport:
    """One POST on a worker thread, then a bounded SSE read. Never retried.

    A buffered http.client response cannot be reused after a socket timeout
    (socket.makefile state is inconsistent), so nothing here retries a
    timed-out read: the worker gives each blocking call the full remaining
    real deadline once, and a timeout is terminal. open() validates, resolves
    the injected auth supplier and starts the worker; abort() is the
    admission seam honoured before conn.connect(), the only call whose
    failure provably means no request byte left this process. Observations
    ride a bounded queue: the worker blocks on put with deadline-bounded
    waits, so TCP applies backpressure and no frame is dropped while a
    consumer may still drain; poll() returns at most MAX_OBSERVATIONS per
    call. Resource caps surface as output_limit_exceeded, a host limit and
    not a policy violation. Errors surface only as fixed categories
    with the transmit proof; exception text, headers, bodies and
    credentials never propagate.
    """
    def __init__(self, *, url, body, auth_supplier=None, deadlines=Deadlines(),
                 connection_factory=None, clock=time.monotonic,
                 max_stream=MAX_STREAM, max_event=MAX_EVENT):
        parsed = urllib.parse.urlsplit(url)
        try:
            bad_port = parsed.port is not None and not 0 < parsed.port < 65536
        except ValueError:
            bad_port = True
        if (parsed.username is not None or parsed.password is not None
                or not parsed.hostname or bad_port
                or (parsed.scheme != 'https' and not (
                    parsed.scheme == 'http'
                    and parsed.hostname.lower() in LOOPBACK_HOSTS))):
            raise ValueError('endpoint must be https or authorized loopback')
        if (type(body) is not bytes or not 0 < len(body) <= MAX_REQUEST
                or type(deadlines) is not Deadlines
                or (auth_supplier is not None and not callable(auth_supplier))
                or type(max_stream) is not int or not 0 < max_stream <= MAX_STREAM):
            raise ValueError('invalid transport request')
        self._body, self._auth = body, auth_supplier
        self._deadlines, self._clock = deadlines, clock
        self._factory, self._max_stream = connection_factory, max_stream
        self._max_event = max_event
        self._decoder = SseDecoder(max_event)
        self._path = parsed.path or '/'
        if parsed.query:
            self._path += '?' + parsed.query
        self._host, self._port, self._secure = (parsed.hostname, parsed.port,
                                                parsed.scheme == 'https')
        self._conn = self._resp = self._sock = None
        self.sent_state, self.responded, self.closed = 'not_sent', False, False
        self.error_class = None
        self._opened = self._done = False
        self.dropped_terminal = False   # worker ended with its terminal obs
                                        # undelivered: consumer abandoned or
                                        # deadline passed; settles upstream
        self._started = self._last = 0.0
        self._received = 0
        self._queue = queue.Queue(maxsize=MAX_QUEUE)
        self._aborted = threading.Event()
        self._gate = threading.Lock()   # atomic pre-connect admission decision
        self._connect_started = False
        self._sent_at = 0.0
        self._capped = False         # resource cap announced; output untrusted
        self._discard = None         # resync scanner inside an oversized frame
        self._headers = {}
        self.deadline = 0.0

    @property
    def done(self):
        return self._done

    @property
    def auth_supplier(self):
        """The injected host auth supplier; read-only identity evidence."""
        return self._auth

    def _total_left(self):
        return self._deadlines.total - (self._clock() - self._started)

    def _idle_left(self):
        return self._deadlines.idle - (self._clock() - self._last)

    def open(self):
        """Validate, resolve injected auth once, then hand the POST to a worker."""
        if self._opened or self.closed:
            raise TransportOpenError('transport_reuse', 'unknown')
        self._opened = True
        self._started = self._last = self._clock()
        self.deadline = self._started + self._deadlines.total
        try:
            supplied = self._auth() if self._auth is not None else {}
            if (type(supplied) is not dict or len(supplied) > MAX_HEADERS
                    or any(not self._header(name, value)
                           for name, value in supplied.items())):
                raise TransportOpenError('auth_unavailable', 'not_sent')
            headers = {str(name).lower(): value for name, value in supplied.items()}
            headers.update({'content-type': 'application/json',
                            'accept': 'text/event-stream',
                            'content-length': str(len(self._body)),
                            'connection': 'close'})
        except TransportOpenError:
            raise
        except Exception as exc:
            self.error_class = type(exc).__name__
            raise TransportOpenError('auth_unavailable', 'not_sent') from None
        # The auth supplier may have consumed the budget: never start the wire
        # once the total deadline has already passed.
        if self._total_left() <= 0:
            raise TransportOpenError('total_timeout', 'not_sent')
        self._headers = headers
        threading.Thread(target=self._run, daemon=True,
                         name='co-openai-sse').start()

    def cancel(self):
        """Pre-connect admission cancellation; True only if connect never began.

        Atomic with the worker's gated connect decision. The gate is held
        only for the flag decision, so cancel() never blocks on a connect
        timeout or a socket operation. A True return means
        the worker will emit 'aborted'/'not_sent' and zero connections were or
        will be made. Never touches a live wire; close() owns forced local
        release after a drain deadline.
        """
        with self._gate:
            if self._connect_started or self._done:
                return False
            self._aborted.set()
            return True

    @staticmethod
    def _header(name, value):
        return (type(name) is str and type(value) is str
                and _HEADER_NAME.fullmatch(name) is not None
                and _HEADER_VALUE.fullmatch(value) is not None
                and name.lower() not in RESERVED_HEADERS)

    def _close_conn(self):
        conn, self._conn = self._conn, None
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass

    def _push(self, obs):
        if not self._deliver(obs):
            raise _StreamFault('aborted' if self._aborted.is_set()
                               else 'queue_deadline')

    def _deliver(self, obs):
        """Bounded blocking enqueue; True only when the observation queued.

        The worker never drops a frame while a consumer may still drain:
        queue-full applies TCP backpressure. Waits are sliced so close() or
        the total deadline release a blocked put without a thread leak.

        Only close() — the consumer abandoning the stream — ends delivery.
        cancel() marks _aborted before connect and the resulting
        'aborted'/'not_sent' terminal must still be delivered as proof.
        """
        while not self.closed:
            left = self._total_left()
            if left <= 0:
                return False
            try:
                self._queue.put(obs, timeout=min(1.0, left))
                return True
            except queue.Full:
                continue
        return False

    def _cap(self):
        if not self._capped:
            self._capped = True
            self._push(StreamCapped('output_limit_exceeded'))

    def _terminal(self, obs):
        with self._gate:
            self._done = True
        self._close_conn()
        # Terminals are delivered while a consumer may drain; only close() or
        # an expired deadline ends the delivery attempt, and then the missing
        # observation is reported via dropped_terminal upstream — never faked.
        if not self._deliver(obs):
            self.dropped_terminal = True

    def _end_stream(self):
        try:
            for event in self._decoder.finish():
                self._push(event)
        except UnicodeDecodeError:
            return self._terminal(StreamFailed('utf8_decode', self.sent_state))
        except ValueError:
            self._cap()   # undeliverable tail at EOF: discarded, never trusted
        self._terminal(StreamEnded())

    def _run(self):
        """Worker: explicit connect, one send, then the response read.

        sent_state stays 'not_sent' through conn.connect() (the only call
        whose failure means no byte left), becomes 'unknown' once connected,
        and 'sent' only after the whole body was written.
        """
        phase = 'connect'
        try:
            if self._total_left() <= 0:
                return self._terminal(StreamFailed('total_timeout', 'not_sent'))
            factory = self._factory or (http.client.HTTPSConnection if self._secure
                                      else http.client.HTTPConnection)
            conn = factory(self._host, self._port, timeout=min(
                self._deadlines.connect, self._total_left()))
            self._conn = conn
            with self._gate:
                # Atomic with cancel(): once the marker is set connect() runs,
                # and once abort is seen connect() never runs. The terminal
                # observation is emitted only after the gate is released:
                # _terminal takes this same lock to publish _done, so calling
                # it here would self-deadlock the worker.
                if self._aborted.is_set():
                    pre_connect = StreamFailed('aborted', 'not_sent')
                elif self._total_left() <= 0:
                    pre_connect = StreamFailed('total_timeout', 'not_sent')
                else:
                    pre_connect = None
                    self._connect_started = True
            if pre_connect is not None:
                return self._terminal(pre_connect)
            conn.connect()
            self._sock = conn.sock
            self.sent_state = 'unknown'
            phase = 'send'
            if self._aborted.is_set():
                return self._terminal(StreamFailed('aborted', 'unknown'))
            budget = self._total_left()
            if budget <= 0:
                return self._terminal(StreamFailed('total_timeout', 'unknown'))
            self._sock.settimeout(budget)
            conn.putrequest('POST', self._path, skip_accept_encoding=True)
            for name, value in self._headers.items():
                conn.putheader(name, value)
            conn.endheaders(self._body)
            self.sent_state = 'sent'
            self._sent_at = self._clock()
            phase = 'first_byte'
            # first_byte measures provider response time from the completed
            # request; auth/connect/send work is not charged to it.
            budget = min(self._deadlines.first_byte - (self._clock() - self._sent_at),
                         self._total_left())
            if budget <= 0:
                return self._terminal(StreamFailed(
                    'total_timeout' if self._total_left() <= 0
                    else 'first_byte_timeout', 'sent'))
            self._sock.settimeout(budget)
            self._resp = conn.getresponse()
            self.responded = True
            self._last = self._clock()
            self._push(StreamStarted(self._resp.status))
            if not 200 <= self._resp.status <= 299:
                return self._terminal(StreamFailed('http_status', self.sent_state))
            phase = 'body'
            while not self._done:
                if self._total_left() <= 0:
                    return self._terminal(StreamFailed('total_timeout', self.sent_state))
                if self._idle_left() <= 0:
                    return self._terminal(StreamFailed('idle_timeout', self.sent_state))
                if self._aborted.is_set():
                    return self._terminal(StreamFailed('aborted', self.sent_state))
                self._sock.settimeout(min(self._idle_left(), self._total_left()))
                try:
                    chunk = self._resp.read1(65536)
                except (socket.timeout, TimeoutError):
                    category = ('total_timeout' if self._total_left() <= 0
                                else 'idle_timeout')
                    return self._terminal(StreamFailed(category, self.sent_state))
                except http.client.IncompleteRead as exc:
                    if exc.partial:
                        for event in self._feed(exc.partial):
                            self._push(event)
                    return self._end_stream()
                if chunk == b'':
                    return self._end_stream()
                for event in self._feed(chunk):
                    self._push(event)
        except (socket.timeout, TimeoutError):
            category = {'connect': 'connect_failed', 'send': 'send_failed',
                        'first_byte': 'first_byte_timeout'}.get(phase)
            if category is None or (phase == 'first_byte'
                                    and self._total_left() <= 0):
                category = 'total_timeout'
            self._terminal(StreamFailed(category, self.sent_state))
        except _StreamFault as exc:
            self._terminal(StreamFailed(exc.category, self.sent_state))
        except Exception as exc:
            self.error_class = type(exc).__name__
            if self._aborted.is_set():
                category = 'aborted'
            elif phase == 'connect':
                category = 'connect_failed'
            elif phase == 'send':
                category = 'send_failed'
            else:
                category = 'eof' if self._is_eof(exc) else 'read_failed'
            self._terminal(StreamFailed(category, self.sent_state))

    @staticmethod
    def _is_eof(exc):
        return isinstance(exc, (http.client.BadStatusLine,
                                http.client.RemoteDisconnected, ConnectionError))

    def _feed(self, chunk):
        self._received += len(chunk)
        self._last = self._clock()
        if self._received > self._max_stream:
            self._cap()
        if self._discard is not None:
            offset = self._discard.feed(chunk)
            if offset is None:
                return ()
            chunk, self._discard = chunk[offset:], None
            if not chunk:
                return ()
        return self._decode(chunk)

    def _decode(self, data):
        """Decode bytes; a capped frame discards only its own span.

        Valid frames emitted before the breach are kept, the decoder resyncs
        on a clean instance, and skipped bytes are never trusted as a
        terminal frame."""
        out = []
        while data:
            try:
                return out + self._decoder.feed(data)
            except UnicodeDecodeError:
                raise _StreamFault('utf8_decode') from None
            except _CapHit as hit:
                # Oversized frame or line: a host resource cap, not a
                # protocol verdict.
                out += hit.events
                self._cap()
                tail = hit.rest.encode('utf-8')
                self._decoder = SseDecoder(self._max_event)
                if hit.discard:
                    discard = _Discard()
                    offset = discard.feed(tail)
                    if offset is None:
                        self._discard = discard
                        return out
                    tail = tail[offset:]
                data = tail
        return out

    def poll(self):
        """Nonblocking bounded drain of decoded observations.

        One wire chunk may decode to more frames than MAX_OBSERVATIONS; the
        remainder stays queued for the next call instead of being an error.
        Frame content limits live in the decoder, not in the batch size.
        """
        if not self._opened:
            return ()
        out = []
        while len(out) < MAX_OBSERVATIONS:
            try:
                out.append(self._queue.get_nowait())
            except queue.Empty:
                break
        return tuple(out)

    def close(self):
        """Local socket release only; never evidence of remote cessation."""
        self.closed = True
        self._aborted.set()
        self._close_conn()


def _http_outcome(status):
    """HTTP error statuses map to one fixed reason; the status stays private.

    Cessation is UNCONFIRMED by default; only statuses recorded in route
    evidence as pre-generation rejections confirm it (handled by the caller).
    """
    if type(status) is int and 400 <= status < 500:
        return State.FAILED, 'http_status'
    return State.ERROR, 'http_status'


@dataclass
class _Attempt:
    request: object
    started: float
    transport: object = None
    events: list = field(default_factory=list)
    proto: dict = field(default_factory=dict)
    outcome: object = None        # (State, reason) at protocol terminal
    parts: object = None          # ordered exact output pieces, success only
    terminal_seen: bool = False
    stop_requested: bool = False
    terminal: bool = False
    closed: bool = False
    sent_state: str = 'unknown'  # only processed observations prove 'not_sent'
    http_status: object = None
    binding: object = None      # QualifiedBinding issued this dispatch
    running: bool = False
    result_state: object = None
    error_class: object = None
    fault: object = None         # private fixed diagnostic detail


class OpenAISSEAdapter:
    """Shared Attempt plumbing for the two OpenAI-compatible text Adapters.

    This is not a unified adapter identity: each subclass owns its request body
    (_body) and its protocol terminal mapping (_sse). Defaults refuse; fixture
    callbacks never qualify a real host. Calls are serialized per Attempt by
    the trusted host/pool.
    """
    ADAPTER_ID = ''

    def __init__(self, *, verify_host=_refuse, transport_factory=None, route=None,
                 clock=time.monotonic, max_drain=120, qualification_gate=None,
                 manifest_loader=None, auth_supplier=None):
        if type(max_drain) not in (int, float) or not 0 < max_drain <= 600:
            raise ValueError('bounded drain required')
        if (qualification_gate is None) != (manifest_loader is None):
            raise ValueError('qualification gate and loader are paired')
        if qualification_gate is not None:
            from .qualified_route import QualifiedRouteGate
            if (type(qualification_gate) is not QualifiedRouteGate
                    or not callable(manifest_loader)):
                raise ValueError('invalid qualification wiring')
        self._gate, self._loader = qualification_gate, manifest_loader
        self._auth_supplier = auth_supplier
        self._verify, self._factory, self._route = verify_host, transport_factory, route
        self._clock, self._max_drain = clock, float(max_drain)
        self._attempts, self._closed = {}, False

    def _credential_ref(self):
        """Non-secret reference name on the injected auth supplier object —
        attribute or zero-arg accessor. Fixed failure vocabulary only."""
        from .protocol_profile import ProfileError
        try:
            cred = self._auth_supplier.credential_ref
            if callable(cred):
                cred = cred()
        except Exception:
            raise ProfileError('credential_ref unavailable') from None
        if type(cred) is not str or not cred:
            raise ProfileError('credential_ref unavailable')
        return cred

    def _preflight(self, request):
        """Qualified-route gate check before any socket or POST.

        Returns (binding, None) on success, (None, fixed evidence) on
        failure. Failures outside qualify() — loader, supplier accessor,
        every binding check — latch the shared gate via exclude(); failures
        inside qualify() are already latched by the gate itself."""
        route, gate, loader = self._route, self._gate, self._loader
        if gate is None or loader is None or self._auth_supplier is None:
            return None, 'route:unqualified'
        env = getattr(request.conditions, 'environment_ref', None)
        try:
            manifest = loader(route.profile.provider_manifest_sha256)
        except Exception:
            gate.exclude(env)
            return None, 'route:qualification_failed'
        try:
            binding = gate.qualify(profile=route.profile, manifest=manifest,
                endpoint=route.endpoint, auth_ref=route.auth_ref,
                request=request)
        except Exception:
            return None, 'route:qualification_failed'
        try:
            from .qualified_route import QualifiedBinding
            cred = self._credential_ref()
            ok = (type(binding) is QualifiedBinding
                  and binding.endpoint == route.endpoint
                  and binding.model == route.model
                  and binding.environment_ref == env
                  and binding.auth_ref == cred
                  and route.sequence
                  == ('absent' if binding.profile.sequence_mode == 'absent'
                      else 'required'))
        except Exception:
            ok = False
        if not ok:
            gate.exclude(env)
            return None, 'route:qualification_failed'
        return binding, None

    def execute(self, request):
        ref = request.ref
        if self._closed or ref in self._attempts:
            return OperationReply(ref, OperationStatus.INVALID_STATE,
                                  'Adapter closed or Attempt used')
        try:
            if (request.conditions.adapter != self.ADAPTER_ID
                    or self._factory is None or type(self._route) is not OpenAIRoute
                    or self._route.request != request
                    or self._route.payload_sha256 != payload_digest(request)):
                raise ValueError('route unavailable')
            body = self._body(request, self._route)
            if len(body) > MAX_REQUEST:
                raise ValueError('request too large')
            if self._verify(request, self._route) is not None:
                raise ValueError('host verifier must attest or raise, not return a flag')
        except Exception:
            return OperationReply(ref, OperationStatus.UNSUPPORTED,
                self.ADAPTER_ID + ' host preflight refused',
                never_started=NeverStarted(request,
                    self.ADAPTER_ID + ':never-started:' + uuid4().hex))
        binding = None
        if self._route.profile is not None:
            # Fresh qualify before any socket or POST; failure is a fixed
            # NeverStarted and the shared gate latch keeps later dispatches
            # on this route out as well.
            binding, evidence = self._preflight(request)
            if binding is None:
                return OperationReply(ref, OperationStatus.UNSUPPORTED,
                    'route qualification refused',
                    never_started=NeverStarted(request, evidence))
        attempt = _Attempt(request, self._clock())
        attempt.binding = binding
        # Reservation precedes factory: ambiguous creation/submission cannot retry.
        self._attempts[ref] = attempt
        self._status(attempt, State.PENDING)
        try:
            attempt.transport = self._factory(request, body, self._route)
            if attempt.transport is None:
                raise ValueError('missing transport')
            if (binding is not None
                    and getattr(attempt.transport, 'auth_supplier', None)
                    is not self._auth_supplier):
                # The constructed transport does not carry the attested
                # supplier object. sent_state is snapshotted BEFORE close():
                # a close implementation must never rewrite the transmit
                # proof and mint a NeverStarted. Reservation removed, object
                # closed, route excluded either way.
                unopened = (getattr(attempt.transport, 'sent_state', None)
                            == 'not_sent')
                try:
                    attempt.transport.close()
                except Exception:
                    pass
                self._gate.exclude(
                    getattr(request.conditions, 'environment_ref', None))
                if unopened:
                    del self._attempts[ref]
                    return OperationReply(ref, OperationStatus.UNSUPPORTED,
                        'route qualification refused',
                        never_started=NeverStarted(request,
                            'route:qualification_failed'))
                self._finish(attempt, State.ERROR,
                             'provider_submission_unknown')
                return OperationReply(ref, OperationStatus.ERROR,
                                      'provider submission outcome unknown')
            if attempt.stop_requested:
                # Stop honored before open(): zero connections were or will be
                # made. Per ruling this is a NeverStarted receipt only — no
                # ResultEvent, so the Attempt cannot carry both proofs. The
                # settled marker keeps later evidence calls inert.
                attempt.terminal = True
                attempt.sent_state = 'not_sent'
                return OperationReply(ref, OperationStatus.UNSUPPORTED,
                    'stop honored before wire',
                    never_started=NeverStarted(request,
                        self.ADAPTER_ID + ':transport:stopped-before-connect:'
                        + uuid4().hex))
            attempt.transport.open()
        except TransportOpenError as exc:
            attempt.sent_state = (exc.sent_state if exc.sent_state in SENT_STATES
                                  else 'unknown')
            self._finish(attempt, State.ERROR,
                exc.category if exc.category.startswith('transport_')
                else 'transport_' + exc.category)
            return OperationReply(ref, OperationStatus.ERROR,
                                  'provider submission outcome unknown')
        except Exception as exc:
            attempt.error_class = type(exc).__name__
            attempt.sent_state = 'unknown'
            self._finish(attempt, State.ERROR, 'provider_submission_unknown')
            return OperationReply(ref, OperationStatus.ERROR,
                                  'provider submission outcome unknown')
        return OperationReply(ref, OperationStatus.ACCEPTED,
                              'submission in flight; one request; outcome unverified')

    def _status(self, attempt, state):
        attempt.events.append(StatusEvent(attempt.request.ref, uuid4().hex, state))

    def _finish(self, attempt, state, reason=None):
        if attempt.terminal:
            return
        attempt.terminal = True
        attempt.result_state = state
        if state != State.COMPLETED:
            attempt.parts = None
        self._status(attempt, state)
        attempt.events.append(ResultEvent(attempt.request.ref, uuid4().hex,
            Result(attempt.request.ref, state, reason)))
        if not attempt.closed:
            attempt.closed = True
            if attempt.transport is not None:
                try:
                    attempt.transport.close()
                except Exception:
                    pass

    def _settle(self, attempt):
        """Finalize at stream end: first policy signal wins, then a host
        resource cap, then the observed natural terminal outcome."""
        state, reason = self._outcome(attempt,
            attempt.outcome if attempt.outcome is not None
            else (State.ERROR, 'transport_eof'))
        if attempt.stop_requested and state == State.COMPLETED:
            state, reason = State.FAILED, 'stopped_midrequest'
        self._finish(attempt, state, reason)

    def _policy(self, attempt, reason):
        """First valid policy signal in stream order wins; never overwritten."""
        if reason not in POLICY_REASONS:
            raise ValueError('unknown policy reason')
        if attempt.proto.get('policy') is None:
            attempt.proto['policy'] = reason

    def _outcome(self, attempt, natural):
        """Settled (State, reason): the first-observed policy signal wins
        over every non-policy terminal, cap or EOF; a proof-invalidation
        yields protocol_violation only when no earlier policy exists; a host
        resource cap outranks the natural terminal outcome."""
        policy = attempt.proto.get('policy')
        if policy is not None:
            return (State.FAILED, policy)
        if attempt.proto.get('violation') is not None:
            return (State.FAILED, 'protocol_violation')
        if attempt.proto.get('limited'):
            return (State.FAILED, 'output_limit_exceeded')
        return natural

    def _inert_keys(self, attempt, etype):
        """The issued binding's per-event inert allowlist; empty on generic
        routes. Host-configured route data, never wire content."""
        binding = attempt.binding
        if binding is None:
            return frozenset()
        fields = getattr(binding.profile, 'inert_fields', None)
        get = getattr(fields, 'get', None)
        return set(get(etype, ())) if callable(get) else frozenset()

    def _terminal_shape(self, attempt, event, etype, obj):
        """Core-proof-vs-semantic gate shared by generic and profile
        routes; terminal_seen may be set only when this returns True.

        Core keys are required and typed; sequence/index keys are ignored
        for proof; only the issued binding's inert allowlist adds keys —
        any other top-level key fails the shape. Identity is shape: a
        contradictory SSE event name, a malformed/over-long/invalid-UTF8
        id, a known-rid or route-model mismatch, a wrong status, and
        malformed details/error/output fields — none is a terminal. An
        unknown rid is adopted (a dropped created frame invents no
        mismatch). Failure content strings are NOT shape: _failure_text
        marks them semantically after recognition.
        """
        if event not in ('', 'message') and event != etype:
            return False              # SSE name contradicts data.type
        inert = self._inert_keys(attempt, etype) | STRUCTURAL_KEYS
        if etype == 'error':
            core = {'type', 'code', 'message', 'param'}
            return (core <= set(obj) <= core | inert
                    and type(obj['message']) is str
                    and (obj['code'] is None or type(obj['code']) is str)
                    and (obj['param'] is None
                         or type(obj['param']) is str))
        if etype not in RESPONSE_TERMINALS:
            return False
        if not {'type', 'response'} <= set(obj) <= (
                {'type', 'response'} | inert):
            return False
        resp = obj['response']
        if (type(resp) is not dict
                or ('object' in resp and resp['object'] != 'response')
                or type(resp.get('id')) is not str or not resp['id']):
            return False
        try:
            if len(resp['id'].encode('utf-8')) > 256:
                return False
        except UnicodeEncodeError:
            return False
        model = resp.get('model')
        if type(model) is str:
            try:
                model.encode('utf-8')
            except UnicodeEncodeError:
                return False
        elif model is not None:
            return False
        if resp.get('status') != {'response.completed': 'completed',
                                  'response.incomplete': 'incomplete',
                                  'response.failed': 'failed'}[etype]:
            return False
        rid = attempt.proto.get('rid')
        if rid is not None and resp['id'] != rid:
            return False
        if (model is not None and model != self._route.model
                or (model is None and attempt.binding is not None
                    and etype == 'response.completed')):
            return False        # profile routes require model on completed
        details = resp.get('incomplete_details')
        if (details is not None
                and (type(details) is not dict
                     or not (details.get('reason') is None
                             or type(details.get('reason')) is str))):
            return False
        if etype == 'response.failed':
            err = resp.get('error')
            if (err is not None
                    and (type(err) is not dict
                         or not set(err) <= {'code', 'message'}
                         or type(err.get('message')) is not str
                         or not (err.get('code') is None
                                 or type(err.get('code')) is str))):
                return False
        if type(resp.get('output')) is not list:
            return False
        if rid is None:
            attempt.proto['rid'] = resp['id']   # adopt first observed id
        return True

    def _failure_text(self, obj):
        """Strict UTF-8 on failure content strings — semantic, never
        shape: False when any code/param/message/reason string fails to
        encode. Covers the top-level error event fields, response.error
        and incomplete_details, identically on generic and profile
        routes. Identity fields are not consulted here."""
        resp = obj.get('response')
        resp = resp if type(resp) is dict else {}
        details = resp.get('incomplete_details')
        details = details if type(details) is dict else {}
        err = resp.get('error')
        err = err if type(err) is dict else {}
        for value in (obj.get('code'), obj.get('param'), obj.get('message'),
                      details.get('reason'), err.get('code'),
                      err.get('message')):
            try:
                if value is not None:
                    value.encode('utf-8')
            except (AttributeError, UnicodeEncodeError):
                return False
        return True

    def _strict_checker(self, attempt):
        """Create or locate the strict single-part checker for this
        Attempt. Its only authority is the QualifiedBinding the gate
        issued during this dispatch — never route.profile or a
        caller-constructed object; generic routes return None.
        responses_profile is imported lazily (protocol_profile cycle).
        """
        checker = attempt.proto.get('checker')
        if checker is not None:
            return checker
        profile = getattr(attempt.binding, 'profile', None)
        if getattr(profile, 'index_mode', None) != 'absent_single_part':
            return None
        from .responses_profile import SinglePartChecker
        checker = SinglePartChecker(profile)
        if attempt.proto.get('unverifiable'):
            checker.mark_unverifiable()
        attempt.proto['checker'] = checker
        return checker

    def _strict_feed(self, attempt, obj):
        """Feed one parsed envelope to the strict checker.

        Returns the checker's result — a text tuple only on a fully
        verified response.completed. ProfileCap is atomic (raised before
        any state change), so the frame is refed exactly once under the
        permanent discard latch; a semantic ProfileError is a first-wins
        policy mark, never fatal. Frames after a policy signal or cap
        still run every structural check with accumulation disabled."""
        proto = attempt.proto
        checker = proto['checker']
        from .protocol_profile import ProfileError
        from .responses_profile import ProfileCap
        discard = (proto.get('policy') is not None
                   or proto.get('limited'))
        try:
            return checker.feed(obj, discard=discard)
        except ProfileCap:
            proto['limited'] = True       # non-policy host cap
            proto.pop('strict_parts', None)
            attempt.parts = None
            try:
                checker.feed(obj, discard=True)
            except ProfileError:
                self._policy(attempt, 'protocol_violation')
            return None
        except ProfileError:
            self._policy(attempt, 'protocol_violation')
            return None

    def _transport_fail(self, attempt, obs):
        attempt.sent_state = obs.sent_state
        if obs.category == 'http_status':
            confirmed = getattr(self._route, 'confirmed_statuses', ())
            if type(confirmed) is tuple and attempt.http_status in confirmed:
                # Route evidence records this status as a pre-generation
                # rejection; only then is cessation CONFIRMED.
                attempt.terminal_seen = True
            state, reason = _http_outcome(attempt.http_status)
            self._finish(attempt, state, reason)
        elif obs.category == 'aborted' and obs.sent_state == 'not_sent':
            self._finish(attempt, State.FAILED, 'stopped_before_transmit')
        elif (attempt.outcome is not None
                or attempt.proto.get('policy') is not None
                or attempt.proto.get('limited')):
            # Permitted frames only: a later local transport failure cannot
            # retract observed protocol facts, nor mint a success.
            self._settle(attempt)
        elif obs.category == 'eof':
            self._finish(attempt, State.ERROR, 'transport_eof')
        elif obs.category == 'aborted':
            self._finish(attempt, State.ERROR, 'stop_cessation_unconfirmed')
        else:
            self._finish(attempt, State.ERROR, 'transport_' + obs.category)

    def _violate(self, attempt, detail):
        """Proof-invalidating protocol activity (e.g. post-terminal traffic).

        Clears the cessation proof and closes the stream; the Result reason
        keeps the first-observed policy signal if one exists, otherwise it
        is protocol_violation.
        """
        attempt.terminal_seen = False
        attempt.proto['violation'] = detail
        self._policy(attempt, 'protocol_violation')
        raise _ProtocolError(detail)

    def _pump(self, attempt):
        if attempt.terminal or attempt.transport is None:
            return 0
        try:
            batch = attempt.transport.poll()
            if type(batch) is not tuple or len(batch) > MAX_OBSERVATIONS:
                raise _ProtocolError('invalid_bounded_poll')
            if (not batch and getattr(attempt.transport, 'done', False)
                    and getattr(attempt.transport, 'dropped_terminal', False)):
                # Worker ended with its terminal undelivered (consumer gone or
                # deadline passed): settle by whatever protocol facts exist.
                if (attempt.proto.get('violation') is not None
                        or attempt.proto.get('policy') is not None
                        or attempt.proto.get('limited')
                        or attempt.outcome is not None):
                    self._settle(attempt)
                else:
                    self._finish(attempt, State.ERROR, 'transport_queue_deadline')
                return 0
            for obs in batch:
                if attempt.terminal:
                    break
                if type(obs) is StreamStarted:
                    attempt.http_status = obs.status
                    if 200 <= obs.status <= 299 and not attempt.running:
                        attempt.running = True
                        self._status(attempt, State.RUNNING)
                elif type(obs) is SseMessage:
                    self._sse(attempt, obs.event, obs.data)
                elif type(obs) is StreamCapped:
                    # Output suppression is protocol-side; transport keeps
                    # delivering so the real terminal can still be observed.
                    attempt.proto['limited'] = True
                    # The capped frame was dropped unparsed: a strict
                    # checker — now or lazily created later — can no
                    # longer prove missing phases or byte equality.
                    attempt.proto['unverifiable'] = True
                    checker = attempt.proto.get('checker')
                    if checker is not None:
                        checker.mark_unverifiable()
                elif type(obs) is StreamEnded:
                    self._settle(attempt)
                elif type(obs) is StreamFailed:
                    self._transport_fail(attempt, obs)
                else:
                    raise _ProtocolError('unknown_observation')
            return len(batch)
        except _ProtocolError as exc:
            attempt.fault = str(exc)
            self._finish(attempt, *self._outcome(attempt,
                (State.FAILED, 'protocol_violation')))
        except Exception as exc:
            attempt.error_class = type(exc).__name__
            self._finish(attempt, State.ERROR, 'openai_stream_error')
        return 0

    def _get(self, ref):
        if ref not in self._attempts:
            raise ValueError('unknown Attempt')
        return self._attempts[ref]

    def events(self, ref, after=None):
        attempt, start = self._get(ref), 0
        if after is not None:
            ids = [event.event_id for event in attempt.events]
            if after not in ids:
                raise ValueError('unknown event cursor')
            start = ids.index(after) + 1
        self._pump(attempt)
        return tuple(attempt.events[start:])

    def status(self, ref):
        attempt = self._get(ref)
        self._pump(attempt)
        return next(event for event in reversed(attempt.events)
                    if isinstance(event, StatusEvent))

    def stop(self, ref):
        if ref not in self._attempts:
            # Unknown Attempt: no acknowledgement, queue or reservation is
            # created; pre-dispatch stop belongs to the admission/ledger seam.
            return StopReply(ref, StopStatus.UNCONFIRMED, 'unknown Attempt')
        attempt = self._attempts[ref]
        if not attempt.terminal:
            attempt.stop_requested = True
            transport = attempt.transport
            if transport is not None:
                cancel = getattr(transport, 'cancel', None)
                if callable(cancel):
                    try:
                        cancel()   # admission seam: wins only before connect
                    except Exception:
                        pass
            # A live wire is never closed for a normal stop: output stays
            # suppressed while draining for the provider protocol terminal,
            # bounded by the smaller of max_drain and the remaining total
            # deadline. Forced local close after the deadline is not proof.
            deadline = self._clock() + self._max_drain
            total_end = getattr(transport, 'deadline', None)
            if type(total_end) in (int, float) and math.isfinite(total_end):
                deadline = min(deadline, total_end)
            while not attempt.terminal and self._clock() < deadline:
                if self._pump(attempt) == 0:
                    time.sleep(0.01)
            if not attempt.terminal:
                if transport is not None:
                    try:
                        transport.close()
                    except Exception:
                        pass
                # Linearize the race: absorb anything the worker delivered
                # before close so a real terminal is honored, then give up.
                self._pump(attempt)
                if not attempt.terminal:
                    self._finish(attempt, State.ERROR, 'stop_cessation_unconfirmed')
        if attempt.sent_state == 'not_sent':
            return StopReply(ref, StopStatus.CONFIRMED,
                'attempt never transmitted', self.ADAPTER_ID + ':never-transmitted')
        if attempt.terminal_seen:
            return StopReply(ref, StopStatus.CONFIRMED,
                'provider protocol terminal observed', self.ADAPTER_ID + ':terminal')
        return StopReply(ref, StopStatus.UNCONFIRMED,
            'no protocol terminal observed; remote execution unknown')

    def resume(self, state):
        if (state.adapter != self.ADAPTER_ID or state.ref not in self._attempts
                or self._attempts[state.ref].terminal):
            return OperationReply(state.ref, OperationStatus.INVALID_STATE,
                                  'unknown or terminal resume identity')
        return OperationReply(state.ref, OperationStatus.UNSUPPORTED,
                              'stateless HTTP resume unsupported')

    def respond(self, response):
        if (response.ref not in self._attempts
                or self._attempts[response.ref].terminal):
            return OperationReply(response.ref, OperationStatus.INVALID_STATE,
                                  'unknown or terminal Attempt')
        return OperationReply(response.ref, OperationStatus.UNSUPPORTED,
                              'permission relay unsupported on text role')

    def usage(self):
        return ()

    def diagnostic(self, ref):
        """Private fixed-vocabulary observation; no provider text or errors."""
        attempt = self._get(ref)
        return {'sent_state': attempt.sent_state,
                'violation': attempt.proto.get('violation'),
                'policy': attempt.proto.get('policy'),
                'limited': bool(attempt.proto.get('limited')),
                'fault': attempt.fault,
                'responded': attempt.transport is not None
                    and getattr(attempt.transport, 'responded', False),
                'http_status': attempt.http_status,
                'terminal_seen': attempt.terminal_seen,
                'stop_requested': attempt.stop_requested,
                'result_state': (attempt.result_state.value
                                 if attempt.result_state is not None else None),
                'error_class': attempt.error_class}

    def collect_output(self, ref):
        """Optional M1 OutputCollector: exact ordered items of one success.

        Durable storage, digest binding and AC are Controller-owned; this
        Adapter never persists output and refuses non-successful Attempts
        with a declared CollectionError, not a misclassified bug.
        """
        attempt = self._get(ref)
        if (attempt.result_state is not State.COMPLETED or attempt.parts is None
                or attempt.stop_requested):
            raise CollectionError('successful text output unavailable')
        return tuple(OutputItem(index, 'text/plain', part)
                     for index, part in enumerate(attempt.parts))

    def close(self):
        self._closed = True
        for attempt in self._attempts.values():
            self._finish(attempt, State.ERROR, 'adapter_closed')
