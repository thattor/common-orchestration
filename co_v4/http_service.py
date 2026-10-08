"""Loopback Responses-subset HTTP service (#190 M3).

Host-composed northbound listener: stdlib ThreadingHTTPServer bound to
127.0.0.1 only, bounded handler concurrency, per-socket timeouts, fixed
error envelopes and allowlist-only serialization. No streaming, no
provider or endpoint configuration is admitted here, and no client field
carries authority; the mutable Native pool/driver lifecycle remains the
later ServiceHost chunk. Every gateway call mints a fresh one-shot
IngressBroker receipt — including each synchronous poll — so a consumed
ref can never be replayed. Foreign and absent response ids are the same
404; nothing echoes exception text, tokens, routes or internal ids.
close() never blocks unboundedly: handlers are daemon threads tracked
under a Condition, marked closing so in-flight polls end as a fixed
503, and a bounded wait yields 'stopped' or 'host_stop_unconfirmed'.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import math
import socket
import threading
import time

from .gateway_store import (Gateway, GatewayRejected, cancel_body,
                            lookup_body, submit_body)
from .http_auth import AuthRejected, IngressBroker, TokenAuth
from .openai_transport import strict_json
from .output_store import IntegrityError, OutputStore
from .profile_registry import ProfileRegistry
from .response_serializer import serialize_response
from .responses_input import MAX_BODY_BYTES, RequestRejected, parse
from .service_owner import OwnerUnavailable
from .state import (Conflict, IntegrityViolation, NotFound,
                    StoreUnavailable, UntrustedInput)

HOST = '127.0.0.1'
MAX_HANDLERS = 32
SOCKET_TIMEOUT = 10.0
STOP_WAIT = SOCKET_TIMEOUT + 1.0
POLL_SECONDS = 0.1
PREFIX = '/v1/responses/'
_ERRORS = {
    400: ('invalid_request_error', 'invalid_request',
          'the request is not valid for this endpoint'),
    401: ('authentication_error', 'unauthorized',
          'authentication failed'),
    404: ('invalid_request_error', 'not_found',
          'the requested resource was not found'),
    405: ('invalid_request_error', 'method_not_allowed',
          'the method is not allowed'),
    409: ('invalid_request_error', 'conflict',
          'the request conflicts with committed state'),
    413: ('invalid_request_error', 'request_too_large',
          'the request body exceeds the host byte limit'),
    500: ('server_error', 'server_error',
          'the request failed an internal check'),
    503: ('server_error', 'service_unavailable',
          'the service is unavailable'),
}


class _Reject(Exception):
    """Internal fixed-status rejection; the status text is never echoed."""
    def __init__(self, status):
        self.status = status
        super().__init__(status)


def _status(exc):
    """Exception -> fixed HTTP status. No detail crosses the boundary."""
    if isinstance(exc, _Reject):
        return exc.status
    # IntegrityViolation subclasses Conflict: integrity is checked first.
    if isinstance(exc, (IntegrityViolation, IntegrityError)):
        return 500
    if isinstance(exc, (AuthRejected, UntrustedInput)):
        return 401
    if isinstance(exc, OwnerUnavailable):
        return 503
    if isinstance(exc, RequestRejected):
        return 413 if exc.code == 'body_too_large' else 400
    if isinstance(exc, GatewayRejected):
        return 400
    if isinstance(exc, Conflict):
        return 409
    if isinstance(exc, NotFound):
        return 404
    if isinstance(exc, StoreUnavailable):
        return 503
    return 500


def _envelope(status):
    kind, code, message = _ERRORS[status]
    return json.dumps({'error': {'message': message, 'type': kind,
        'param': None, 'code': code}}, separators=(',', ':'),
        ensure_ascii=False).encode('utf-8')


class _Server(ThreadingHTTPServer):
    daemon_threads = True             # close() joins, never the mixin
    block_on_close = False            # unbounded ThreadingMixIn join off
    request_queue_size = 128          # accept backlog covers slot bursts

    def __init__(self, address, handler, service):
        self.service = service
        self.slots = threading.BoundedSemaphore(MAX_HANDLERS)
        self.active = 0
        self.active_cond = threading.Condition()
        super().__init__(address, handler)

    def handle_error(self, request, client_address):
        pass                          # silent: no traceback, no client bytes

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            blob = _envelope(503)
            try:
                request.settimeout(SOCKET_TIMEOUT)
                request.sendall(
                    b'HTTP/1.1 503 Service Unavailable\r\n'
                    b'Content-Type: application/json\r\n'
                    b'Content-Length: ' + str(len(blob)).encode('ascii')
                    + b'\r\nConnection: close\r\n\r\n' + blob)
                # Drain only already-queued request bytes: nonblocking and
                # capped, so the accept loop never stalls on a stalled or
                # streaming client. FIN before close keeps the fixed 503
                # readable; close() with an unread receive queue would
                # reset instead.
                request.setblocking(False)
                drained = 0
                while drained <= MAX_BODY_BYTES:
                    try:
                        chunk = request.recv(65536)
                    except BlockingIOError:
                        break
                    if not chunk:
                        break
                    drained += len(chunk)
                request.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            request.close()
            return
        # Count in the parent before the worker is started: a close() that
        # races thread scheduling can never observe a pending handler as 0.
        with self.active_cond:
            self.active += 1
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            with self.active_cond:
                self.active -= 1
                self.active_cond.notify_all()
            request.close()

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()
            with self.active_cond:
                self.active -= 1
                self.active_cond.notify_all()


class _Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def setup(self):
        # StreamRequestHandler.setup assigns self.connection; the socket
        # timeout must be applied after it, not on an unset attribute.
        super().setup()
        self.connection.settimeout(SOCKET_TIMEOUT)

    def __getattr__(self, name):
        # Every do_* without an explicit handler routes through _run so
        # unknown methods get the fixed 405 envelope, never send_error 501.
        if name.startswith('do_'):
            return self._run
        raise AttributeError(name)

    def log_message(self, *args):
        pass                          # silent log: nothing client-derived

    def send_error(self, code, message=None, explain=None):
        # BaseHTTPRequestHandler parser errors (bad request line, 414,
        # 431) get the fixed envelope too; a down service answers 503.
        # Parser failures arrive with request_version 'HTTP/0.9', under
        # which send_response() would emit a bare body with no status
        # line; force a versioned response so the fixed envelope is a
        # real HTTP/1.1 rejection.
        if self.request_version not in ('HTTP/1.0', 'HTTP/1.1'):
            self.request_version = 'HTTP/1.1'
        service = getattr(self.server, 'service', None)
        if service is not None and not service._up():
            code = 503
        self._error(code if code in _ERRORS else 400)

    def _send(self, status, body):
        try:
            blob = (body if type(body) is bytes else
                    json.dumps(body, ensure_ascii=False, allow_nan=False,
                               separators=(',', ':')).encode('utf-8'))
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(blob)))
            self.send_header('Connection', 'close')
            self.end_headers()
            if self.command != 'HEAD':     # honest length, no body
                self.wfile.write(blob)
        except (OSError, ValueError):
            pass
        self.close_connection = True

    def _error(self, status):
        self._send(status, _envelope(status))

    def _body(self):
        """Bounded POST body: strict ASCII-decimal Content-Length,
        no encodings, application/json when nonempty, exact byte count."""
        if self.headers.get_all('Transfer-Encoding'):
            raise _Reject(400)
        if self.headers.get_all('Content-Encoding'):
            raise _Reject(400)
        lengths = self.headers.get_all('Content-Length')
        if lengths is None or len(lengths) != 1:
            raise _Reject(400)
        text = lengths[0].strip()
        if not text or any(ch < '0' or ch > '9' for ch in text):
            raise _Reject(400)
        # Bound before int(): an absurd digit count is 413, never a parse
        # ValueError reaching the 500 fallback.
        digits = text.lstrip('0') or '0'
        service = self.server.service
        if len(digits) > service._max_length_digits:
            raise _Reject(413)
        length = int(digits)
        if length > service._max_body_bytes:
            raise _Reject(413)
        types = self.headers.get_all('Content-Type')
        # At most one Content-Type is enforced before the length-0 exit;
        # an empty body still does not require the header.
        if types is not None and len(types) != 1:
            raise _Reject(400)
        if not length:
            return b''
        if (types is None
                or types[0].split(';')[0].strip().lower()
                != 'application/json'):
            raise _Reject(400)
        blob = self.rfile.read(length)
        if len(blob) != length:
            raise _Reject(400)
        return blob

    def _principal(self):
        """availability -> auth, before any parse or store touch."""
        service = self.server.service
        if not service._up():
            raise _Reject(503)
        headers = self.headers.get_all('Authorization')
        if headers is None or len(headers) != 1:
            raise _Reject(401)
        try:
            return service._auth.authenticate(headers[0])
        except AuthRejected:
            raise _Reject(401) from None

    def _emit(self, service, principal, response_id, projection):
        context = service._context(principal, response_id)
        self._send(200, serialize_response(
            projection, context.intent, context.created_at,
            service._store))

    def _route(self):
        service = self.server.service
        principal = self._principal()
        path = self.path
        if self.command == 'GET':
            if path == '/v1/models':
                return self._send(200, {'object': 'list', 'data': [
                    {'id': alias, 'object': 'model', 'created': 0,
                     'owned_by': 'co'}
                    for alias in service._registry.aliases]})
            if path.startswith(PREFIX):
                response_id = path[len(PREFIX):]
                if response_id and '/' not in response_id:
                    return self._emit(service, principal, response_id,
                        service._read(principal, response_id))
            raise _Reject(404)
        if self.command == 'POST':
            if path == '/v1/responses':
                return self._create(service, principal)
            if path.startswith(PREFIX) and path.endswith('/cancel'):
                response_id = path[len(PREFIX):-len('/cancel')]
                if response_id and '/' not in response_id:
                    return self._cancel(service, principal, response_id)
            raise _Reject(404)
        raise _Reject(405)

    def _create(self, service, principal):
        intent = parse(self._body(), limit=service._max_body_bytes)
        keys = self.headers.get_all('Idempotency-Key')
        if keys is not None and len(keys) != 1:
            raise _Reject(400)
        sub = service._submit(principal, intent,
                              keys[0] if keys else None)
        projection = service._read(principal, sub.response_id)
        if not intent.background:
            deadline = time.monotonic() + service._sync_timeout
            while not projection.decided:
                if not service._up():       # shutdown marks closing
                    raise _Reject(503)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                time.sleep(min(POLL_SECONDS, remaining))
                projection = service._read(principal, sub.response_id)
        self._emit(service, principal, sub.response_id, projection)

    def _cancel(self, service, principal, response_id):
        body = self._body()
        if body:
            try:
                value = strict_json(body.decode('utf-8', 'strict'))
            except (UnicodeDecodeError, ValueError):
                raise _Reject(400) from None
            if value != {}:
                raise _Reject(400)
        self._emit(service, principal, response_id,
                   service._cancel_run(principal, response_id))

    def _run(self):
        try:
            self._route()
        except Exception as exc:
            self._error(_status(exc))

    do_GET = do_POST = do_HEAD = _run


class HttpService:
    """Host composition only; owns the socket, serve thread and slots.

    gateway is ControlStore.gateway(); broker/auth are http_auth types;
    registry supplies /v1/models aliases (tuple property) and, via the
    store's profile_resolver, submission resolution; available() is the
    host health hook — when it returns False or raises, every endpoint is
    a fixed 503. close() is single-shot and bounded: it marks closing so
    in-flight sync polls fail fast as 503, then waits at most STOP_WAIT
    for active handlers, returning 'stopped' or 'host_stop_unconfirmed'
    (references retained so the host can retry close()).
    max_body_bytes is one configured wire+parse cap; the default only
    serves existing callers — the host CLI passes the configured value.
    """

    def __init__(self, *, gateway, broker, auth, registry, output_store,
                 available, port=0, sync_timeout=30.0,
                 max_body_bytes=MAX_BODY_BYTES):
        if (type(gateway) is not Gateway
                or type(broker) is not IngressBroker
                or type(auth) is not TokenAuth
                or type(registry) is not ProfileRegistry
                or type(output_store) is not OutputStore
                or not callable(available)
                or type(port) is not int or not 0 <= port <= 65535
                or type(sync_timeout) not in (int, float)
                or not math.isfinite(sync_timeout)
                or not 0 < sync_timeout <= 600
                or type(max_body_bytes) is not int
                or not 1 <= max_body_bytes <= 262144):
            raise ValueError('invalid HTTP service composition')
        self._gateway, self._broker, self._auth = gateway, broker, auth
        self._registry, self._store = registry, output_store
        self._available = available
        self._port, self._sync_timeout = port, float(sync_timeout)
        self._max_body_bytes = max_body_bytes
        self._max_length_digits = len(str(max_body_bytes))
        self._server = self._thread = None
        self._started = self._closing = False

    @property
    def base_url(self):
        return (None if self._server is None else
                'http://%s:%d' % self._server.server_address[:2])

    def start(self):
        """Single-shot: a closed or running service cannot restart."""
        if self._started or self._server is not None or self._closing:
            raise ValueError('service already started or closed')
        # The bound socket is owned the moment _Server returns; a failure
        # below then retries server_close() and, on cleanup failure, keeps
        # the reference for a later close().
        server = self._server = _Server((HOST, self._port), _Handler, self)
        # The serve Thread is owned BEFORE it can exist: a start() that
        # raises AFTER the real thread spawned must never orphan a live
        # serve_forever under a released owner.
        thread = self._thread = threading.Thread(
            target=server.serve_forever,
            kwargs={'poll_interval': 0.1}, daemon=True)
        try:
            thread.start()
        except BaseException:
            # The owned close() contract: a never-started Thread (ident is
            # None) skips shutdown entirely, a started one gets the bounded
            # shutdown/drain/join. Unconfirmed keeps _server/_thread for
            # the host's retry; any cleanup error is swallowed so the
            # ORIGINAL start failure is what propagates.
            try:
                self.close()
            except Exception:
                pass                    # refs kept; close() retries
            raise
        self._started = True
        return self.base_url

    def close(self):
        """'stopped' | 'host_stop_unconfirmed'; idempotent, bounded."""
        self._closing = True
        server, thread = self._server, self._thread
        if server is None:
            return 'stopped'
        if thread is None or getattr(thread, 'ident', None) is None:
            # serve_forever never ran: shutdown() would block forever,
            # join() would raise on an unstarted Thread, and no handler
            # can exist without the serve thread, so the only remaining
            # step is the retryable socket close. ident is the public
            # spawn proof; it is None iff start() never ran the thread.
            try:
                server.server_close()
            except Exception:
                return 'host_stop_unconfirmed'
            self._server = self._thread = None
            return 'stopped'
        # One shared deadline: shutdown/close cannot consume the whole
        # budget and leave nothing for the handler join.
        deadline = time.monotonic() + STOP_WAIT
        try:
            server.shutdown()         # bounded by serve poll interval
            server.server_close()     # socket only; no thread join here
        except Exception:
            # A failed stop or socket close must not report 'stopped':
            # keep refs so a retry close() can finish the sequence.
            return 'host_stop_unconfirmed'
        with server.active_cond:
            done = server.active_cond.wait_for(
                lambda: not server.active,
                timeout=max(0.0, deadline - time.monotonic()))
        if done:
            thread.join(timeout=max(0.0, deadline - time.monotonic()))
            done = not thread.is_alive()
        if not done:
            return 'host_stop_unconfirmed'   # refs kept for retry close()
        self._server = self._thread = None
        return 'stopped'

    def _up(self):
        if self._closing:
            return False
        try:
            return bool(self._available())
        except Exception:
            return False

    def _submit(self, principal, intent, key):
        with self._broker.receipt_ref(
                principal, submit_body(intent.body_hash, key)) as ref:
            return self._gateway.submit(intent, key, ref)

    def _context(self, principal, response_id):
        with self._broker.receipt_ref(
                principal, lookup_body(response_id)) as ref:
            return self._gateway.read_context(response_id, ref)

    def _read(self, principal, response_id):
        with self._broker.receipt_ref(
                principal, lookup_body(response_id)) as ref:
            return self._gateway.read(response_id, ref)

    def _cancel_run(self, principal, response_id):
        with self._broker.receipt_ref(
                principal, cancel_body(response_id)) as ref:
            return self._gateway.cancel(response_id, ref)
