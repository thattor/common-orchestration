"""#190 M3 HTTP start ownership: real HttpService inside real ServiceHost.

Real _Server loopback socket and the real owner/store/driver stack via the
test_service_host fixture, used by COMPOSITION only: this class is a plain
unittest.TestCase so the base host tests are not re-run against a real
listener, and the fake HttpFixture stays theirs. No Native/AC proof is
fabricated; threading.Thread is patched ONLY around host.start() -- the
driver thread is created through service_host's already-bound Thread name
and is running before HttpService.start is reached, so the injected
failure lands solely on the serve thread. Every bound socket is released
by close() on the happy path and by fixture/registered cleanups on
failure; no thread is ever killed.
"""
import socket
import threading
import time
import unittest
from unittest import mock

from co_v4.gateway_store import Gateway
from co_v4.http_auth import IngressBroker, TokenAuth
import co_v4.http_service as hs
from co_v4.http_service import HttpService
from co_v4.output_store import OutputStore
from co_v4.state import ControlStore
import test_service_host as fx


class DeadThread:
    """threading.Thread seam injection: start() fails deterministically."""
    def __init__(self, *a, **kw):
        pass

    def start(self):
        raise OSError('thread refused')


class StartedThenFailThread(threading.Thread):
    """start() REALLY spawns the thread, then reports failure — the
    actual-started failure class that must not orphan serve_forever."""
    def start(self):
        super().start()
        raise OSError('thread reported failed')

class HttpStartOwnershipTests(unittest.TestCase):
    """Owns a ServiceHostTests fixture instance; delegates seed/host/
    held/released and comp/broker/http state to it (all set dynamically
    during build, so no stale references are kept here)."""

    def setUp(self):
        self.fx = fx.ServiceHostTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        # Entries are (principal, sha256-hex) fixture pairs, never tokens.
        self.fx.auth = TokenAuth((('p', 'ab' * 32),))
        self.fx.http_factory = self.http_factory

    def http_factory(self, available):
        """Unstarted real HttpService; the host owns it before start()."""
        self.fx.order.append('http')
        self.fx.avail = available
        self.fx.http = HttpService(
            gateway=self.fx.comp.gateway, broker=self.fx.broker,
            auth=self.fx.auth, registry=self.fx.registry,
            output_store=self.fx.comp.output_store, available=available,
            sync_timeout=0.5)
        return self.fx.http

    def standalone(self, tag):
        root = self.fx.tmp / tag
        root.mkdir(mode=0o700)
        store = ControlStore(root / 'control.sqlite',
            verifier=lambda ref: None, evidence=self.fx._evidence,
            clock=lambda: fx.NOW, profile_resolver=self.fx.registry.resolve)
        self.addCleanup(store.close)
        return HttpService(
            gateway=Gateway(store, bound_resolver=lambda *_: None),
            broker=IngressBroker(lambda: fx.NOW), auth=self.fx.auth,
            registry=self.fx.registry,
            output_store=OutputStore(root / 'outputs'),
            available=lambda: True, sync_timeout=0.5)

    def refused(self, port):
        with self.assertRaises(OSError):
            socket.create_connection(('127.0.0.1', port), timeout=2)

    def bound(self, port):
        """A second bind on the same loopback port is refused: proof the
        socket is still held, without consuming accept backlog."""
        probe = socket.socket()
        try:
            with self.assertRaises(OSError):
                probe.bind(('127.0.0.1', port))
        finally:
            probe.close()

    def test_normal_start_binds_and_close_releases(self):
        fx = self.fx
        fx.seed([])
        host = fx.host()
        # Short handler socket timeout keeps the close join bounded: the
        # probe connection never sends a request.
        with mock.patch.object(hs, 'SOCKET_TIMEOUT', 0.5):
            host.start()
            port = int(fx.http.base_url.rsplit(':', 1)[1])
            conn = socket.create_connection(('127.0.0.1', port),
                                            timeout=5)
            conn.close()
            self.assertEqual(host.close(), 'stopped')
        self.refused(port)                             # socket released
        self.assertIsNone(fx.http._server)
        fx.released()

    def test_thread_start_failure_clean_close_releases(self):
        # thread.start() raises; server_close() succeeds inside start():
        # _server is cleared, the host unwinds, the port refuses, owner
        # released.
        fx = self.fx
        fx.seed([])
        host = fx.host()
        ports = []
        real_srv = hs._Server

        def srv(*a, **kw):
            s = real_srv(*a, **kw)
            ports.append(s.server_address[1])
            return s

        with mock.patch.object(hs, '_Server', srv), \
                mock.patch.object(threading, 'Thread', DeadThread):
            with self.assertRaises(OSError) as e:
                host.start()
        self.assertEqual(str(e.exception), 'thread refused')
        self.assertEqual(len(ports), 1)
        self.assertIsNone(fx.http._server)             # cleared
        self.assertIsNone(fx.http._thread)
        self.refused(ports[0])                         # socket released
        self.assertEqual(host.close(), 'stopped')
        fx.released()

    def test_thread_start_failure_close_fault_retains_then_recovers(self):
        # server_close() raises during start cleanup AND the host's own
        # teardown close(): _server kept, original error propagates,
        # 'host_stop_unconfirmed', owner held. Removing the fault first,
        # a bind-probe proves the socket is still live, then the retry
        # close() is the real socket release.
        fx = self.fx
        fx.seed([])
        host = fx.host()
        servers = []
        real_srv = hs._Server

        def srv(*a, **kw):
            s = real_srv(*a, **kw)
            servers.append(s)
            s.server_close = lambda: (_ for _ in ()).throw(
                OSError('close refused'))
            return s

        calls = []
        try:
            with mock.patch.object(hs, '_Server', srv), \
                    mock.patch.object(threading, 'Thread', DeadThread):
                with self.assertRaises(OSError) as e:
                    host.start()
            self.assertEqual(str(e.exception), 'thread refused')
            # Ref retention BEFORE any successful close: the service and
            # its still-bound _server are reachable through the host.
            self.assertIs(host._http, fx.http)
            self.assertIs(fx.http._server, servers[0])
            fx.held()                                  # owner retained
            # No serve thread -> shutdown() must never run: a spy proves
            # the no-thread close() cannot hang and cannot call it.
            servers[0].shutdown = lambda *a, **kw: calls.append(1)
            self.assertEqual(host.close(), 'host_stop_unconfirmed')
            self.assertEqual(calls, [])
            fx.held()
        finally:
            # Restore the real method only; on a mid-test failure the
            # fixture's registered host.close() cleanup still runs the
            # real release sequence.
            for s in servers:
                s.__dict__.pop('server_close', None)
        # Still bound: the retained socket refuses a fresh bind before
        # the confirmed retry.
        self.bound(servers[0].server_address[1])
        self.assertEqual(host.close(), 'stopped')      # real close
        self.assertIsNone(fx.http._server)
        self.refused(servers[0].server_address[1])
        self.assertEqual(calls, [])
        fx.released()

    def test_close_without_thread_never_shutdown(self):
        svc = self.standalone('bare1')
        self.assertEqual(svc.close(), 'stopped')       # nothing bound
        svc = self.standalone('bare2')
        self.addCleanup(svc.close)
        servers = []
        real_srv = hs._Server

        def srv(*a, **kw):
            s = real_srv(*a, **kw)
            servers.append(s)
            s.server_close = lambda: (_ for _ in ()).throw(OSError('x'))
            return s

        calls = []
        try:
            with mock.patch.object(hs, '_Server', srv), \
                    mock.patch.object(threading, 'Thread', DeadThread):
                with self.assertRaises(OSError):
                    svc.start()
            server = svc._server
            self.assertIs(server, servers[0])
            server.shutdown = lambda *a, **kw: calls.append(1)
            deadline = time.monotonic() + 5
            self.assertEqual(svc.close(), 'host_stop_unconfirmed')
            self.assertLess(time.monotonic(), deadline)
            self.assertEqual(calls, [])
            self.assertIs(svc._server, server)         # retained
        finally:
            for s in servers:
                s.__dict__.pop('server_close', None)
        # Happy-path retry: the restored real server_close is what closes
        # the still-bound socket, on the confirmed close() call.
        self.assertEqual(svc.close(), 'stopped')
        self.assertEqual(calls, [])
        self.assertIsNone(svc._server)

    def test_started_then_failed_thread_drains_live_server(self):
        # Thread.start() spawned serve_forever THEN raised: the owned
        # _thread reference lets the start-failure path run the bounded
        # shutdown/drain/join instead of orphaning a live writer. Only
        # the Http thread is patched — the driver thread is created via
        # service_host's already-bound Thread name.
        fx = self.fx
        fx.seed([])
        host = fx.host()
        ports, made, shutdowns = [], [], []
        real_srv = hs._Server

        def srv(*a, **kw):
            s = real_srv(*a, **kw)
            ports.append(s.server_address[1])
            real_sd = s.shutdown
            s.shutdown = lambda *a2, **k2: (shutdowns.append(1),
                                            real_sd(*a2, **k2))[1]
            return s

        def thread_factory(*a, **kw):
            t = StartedThenFailThread(*a, **kw)
            made.append(t)
            return t

        with mock.patch.object(hs, '_Server', srv), \
                mock.patch.object(threading, 'Thread', thread_factory):
            with self.assertRaises(OSError) as e:
                host.start()
        self.assertEqual(str(e.exception), 'thread reported failed')
        self.assertEqual(len(ports), 1)
        self.assertEqual(made[0].ident is not None, True)  # really ran
        self.assertGreaterEqual(len(shutdowns), 1)         # real drain
        self.assertIsNone(fx.http._server)
        self.assertIsNone(fx.http._thread)
        self.refused(ports[0])              # socket actually released
        self.assertEqual(host.close(), 'stopped')
        fx.released()

    def test_started_thread_close_fault_retains_then_recovers(self):
        # Same actually-started failure, but the FIRST cleanup close()
        # cannot confirm (server_close raises): _server/_thread stay
        # retained, the owner is held, the bound port proves the socket
        # is live — and the ORIGINAL start error is what propagates.
        fx = self.fx
        fx.seed([])
        host = fx.host()
        servers, made = [], []
        real_srv = hs._Server
        fault = {'on': True}

        def srv(*a, **kw):
            s = real_srv(*a, **kw)
            servers.append(s)
            real_close = s.server_close
            def flaky_close():
                if fault['on']:
                    raise OSError('close refused')
                return real_close()
            s.server_close = flaky_close
            return s

        def thread_factory(*a, **kw):
            t = StartedThenFailThread(*a, **kw)
            made.append(t)
            return t

        try:
            with mock.patch.object(hs, '_Server', srv), \
                    mock.patch.object(threading, 'Thread', thread_factory):
                with self.assertRaises(OSError) as e:
                    host.start()
            self.assertEqual(str(e.exception),
                             'thread reported failed')
            self.assertIs(host._http, fx.http)         # retained
            self.assertIs(fx.http._server, servers[0])
            self.assertIs(fx.http._thread, made[0])
            fx.held()                                # owner held
            self.assertEqual(host.close(),
                             'host_stop_unconfirmed')
            fx.held()
        finally:
            # Clearing the fault before the fixture's registered
            # host.close() cleanup keeps teardown honest on mid-test
            # failure too.
            fault['on'] = False
        # shutdown ran while serve_forever was live -> it exited for real.
        self.assertFalse(made[0].is_alive())
        self.bound(servers[0].server_address[1])       # socket held
        self.assertEqual(host.close(), 'stopped')
        self.assertIsNone(fx.http._server)
        self.refused(servers[0].server_address[1])
        fx.released()


if __name__ == '__main__':
    unittest.main()
