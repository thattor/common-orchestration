"""Tests for the owned-transport metadata RPC side of codex_inventory."""

import os
import sys
import time
import unittest
from unittest import mock

import co_v4.codex_permissions as codex_permissions
import co_v4.codex_text_transport as text_transport
import co_v4.codex_text_validation as text_validation
from co_v4 import codex_inventory as ci
from co_v4.adapters.codex import NativeError
from co_v4.codex_host import FEATURES_01601

INVENTORY_POLL = ci._InventoryTransport.poll


def _config():
    return {
        "features": {name: False for name in FEATURES_01601},
        "web_search": "disabled",
        "shell_environment_policy": {
            "inherit": "none",
            "include_only": [],
            "set": {"B_KEY": "x", "A_KEY": "x"},
        },
        "mcp_servers": {"zeta": {}, "alpha": {}},
    }


def _response(request_id, result):
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _notification(method, params=None):
    return {"jsonrpc": "2.0", "method": method,
            "params": {} if params is None else params}


def _success_queue():
    return [[_response(ci._ID_INITIALIZE,
                      {"userAgent": "codex-cli/0.160.1"})],
            [_response(ci._ID_CONFIG_READ, {"config": _config()})]]


class FakeTransport(ci._InventoryTransport):
    queue = ()
    drain = ()
    poll_error = None
    send_error = None
    close_error = None
    stop_on_close = True
    native_version = "codex-cli 0.160.1"
    instances = []

    def __init__(self, *args, **kwargs):
        self._received = 0
        self._pending = {}
        self._answers = {}
        self._protocol_invalid = False
        self.args = args
        self.kwargs = kwargs
        self.sent = []
        self.closes = 0
        self.stopped = False
        self.native_version = type(self).native_version
        self._queue = [tuple(b) for b in type(self).queue]
        self._drain = [tuple(b) for b in type(self).drain]
        FakeTransport.instances.append(self)

    def send(self, message):
        if type(self).send_error is not None:
            raise type(self).send_error
        self.sent.append(message)

    def poll(self):
        if type(self).poll_error is not None:
            raise type(self).poll_error
        return self._scan(self._queue.pop(0) if self._queue else ())

    def alive(self):
        return True

    def close(self):
        self.closes += 1
        if type(self).close_error is not None:
            raise type(self).close_error
        for batch in self._drain:
            self._scan(batch)
        self.stopped = type(self).stop_on_close


class DiscoverInventoryTest(unittest.TestCase):
    def setUp(self):
        FakeTransport.instances = []
        FakeTransport.queue = ()
        FakeTransport.drain = ()
        FakeTransport.poll_error = None
        FakeTransport.send_error = None
        FakeTransport.close_error = None
        FakeTransport.stop_on_close = True
        FakeTransport.native_version = "codex-cli 0.160.1"
        for patcher in (
                mock.patch.object(ci, "_InventoryTransport", FakeTransport),
                mock.patch.dict(os.environ, {
                    "HOME": "/h", "PATH": "/p", "TMPDIR": "/t", "USER": "u",
                    "LOGNAME": "u", "LANG": "en_US.UTF-8",
                    "OPENAI_API_KEY": "sk-test", "CODEX_HOME": "/x"},
                    clear=True)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def call(self, **kwargs):
        args = {"before_launch": mock.Mock(), "on_stopped": mock.Mock(),
                "timeout": 5}
        args.update(kwargs)
        return ci.discover_inventory("/exe", "/ws", **args)

    def transport(self):
        self.assertEqual(len(FakeTransport.instances), 1)
        return FakeTransport.instances[0]

    def assert_invalid(self, **kwargs):
        with self.assertRaises(NativeError) as ctx:
            self.call(**kwargs)
        self.assertEqual(str(ctx.exception), "native_inventory_invalid")
        return self.transport()

    def test_real_imports_and_fixed_version(self):
        self.assertIs(ci.OwnedTransport, text_transport.OwnedTransport)
        self.assertIs(ci.SUPPORTED_TEXT_CLI,
                      text_transport.SUPPORTED_TEXT_CLI)
        self.assertEqual(ci.SUPPORTED_TEXT_CLI, "codex-cli 0.160.1")
        self.assertIs(ci.rpc_key, text_validation.rpc_key)
        self.assertIs(ci.frame_kind, text_validation.frame_kind)
        self.assertIs(ci.ValidationError, text_validation.ValidationError)
        self.assertIs(ci.account_updated_notification,
                      codex_permissions.account_updated_notification)
        self.assertIs(ci.disabled_remote_notification,
                      codex_permissions.disabled_remote_notification)
        self.assertNotIn("co_v4.codex_owned", sys.modules)

    def test_success_names_only_canonical_outgoing(self):
        FakeTransport.queue = _success_queue()
        result = self.call()
        self.assertEqual(result, {
            "native_version": "codex-cli 0.160.1",
            "disabled_mcp_servers": ("alpha", "zeta"),
            "cleared_environment_keys": ("A_KEY", "B_KEY")})
        t = self.transport()
        self.assertEqual(t.sent, [
            {"jsonrpc": "2.0", "id": ci._ID_INITIALIZE,
             "method": "initialize",
             "params": {
                 "clientInfo": {"name": "co04_native_inventory",
                                "version": "0.4"},
                 "capabilities": {"experimentalApi": True}}},
            {"jsonrpc": "2.0", "method": "initialized"},
            {"jsonrpc": "2.0", "id": ci._ID_CONFIG_READ,
             "method": "config/read",
             "params": {"cwd": "/ws", "includeLayers": False}}])
        self.assertEqual(t.closes, 1)
        self.assertTrue(t.stopped)

    def test_no_forbidden_rpcs(self):
        FakeTransport.queue = _success_queue()
        self.call()
        sent = self.transport().sent
        self.assertEqual([m.get("method") for m in sent],
                         ["initialize", "initialized", "config/read"])
        ids = [m["id"] for m in sent if "id" in m]
        self.assertEqual(ids, [ci._ID_INITIALIZE, ci._ID_CONFIG_READ])
        self.assertFalse(any("params" in m and m["params"].get("model")
                             for m in sent))

    def test_ctor_env_hooks_version(self):
        FakeTransport.queue = _success_queue()
        before, stopped = mock.Mock(), mock.Mock()
        self.call(before_launch=before, on_stopped=stopped)
        t = self.transport()
        self.assertEqual(t.args, ("/exe", "/ws"))
        self.assertIs(t.kwargs["before_launch"], before)
        self.assertIs(t.kwargs["on_stopped"], stopped)
        self.assertEqual(t.kwargs["required_version"],
                         "codex-cli 0.160.1")
        self.assertEqual(t.kwargs["max_drain_s"], 1)
        env = t.kwargs["env"]
        self.assertEqual(env, {"HOME": "/h", "PATH": "/p",
                               "TMPDIR": "/t", "USER": "u",
                               "LOGNAME": "u", "LANG": "en_US.UTF-8"})
        self.assertNotIn("OPENAI_API_KEY", env)
        self.assertNotIn("CODEX_HOME", env)
        overrides = t.kwargs["config_overrides"]
        self.assertIn("features.remote_control=false", overrides)
        for name in FEATURES_01601:
            self.assertIn("features." + name + "=false", overrides)

    def test_wrong_native_version_refused(self):
        FakeTransport.queue = _success_queue()
        FakeTransport.native_version = "codex-cli 0.160.0"
        self.assert_invalid()

    def test_notification_allowlist(self):
        FakeTransport.queue = [
            [_notification("account/updated",
                           {"authMode": "apikey", "planType": "pro"}),
             _notification("remoteControl/status/changed",
                           {"status": "disabled", "installationId": "i",
                            "serverName": "s"}),
             _notification("account/rateLimits/updated"),
             _notification("warning", {"message": "hello"})],
        ] + _success_queue()
        self.call()
        for bad in (_notification("tool/call"),
                    _notification("warning", {"message": "m", "x": 1}),
                    _notification("warning", {"extra": 1}),
                    {"jsonrpc": "2.0", "id": 9, "method": "m",
                     "params": {}},
                    {"jsonrpc": "2.0", "id": 9, "method": "m"}):
            FakeTransport.instances = []
            FakeTransport.queue = [[bad]] + _success_queue()
            t = self.assert_invalid()
            self.assertEqual(t.closes, 1)

    def test_future_config_response_refused(self):
        FakeTransport.queue = [[
            _response(ci._ID_INITIALIZE, {"userAgent": "u"}),
            _response(ci._ID_CONFIG_READ, {"config": _config()})]]
        t = self.assert_invalid()
        self.assertEqual(t.closes, 1)

    def test_duplicate_after_final_refused(self):
        for tail in (_response(ci._ID_CONFIG_READ,
                               {"config": _config()}),
                     _response("other-id", {}),
                     _response(7, {})):
            FakeTransport.instances = []
            FakeTransport.queue = [
                [_response(ci._ID_INITIALIZE, {"userAgent": "u"})],
                [_response(ci._ID_CONFIG_READ, {"config": _config()}),
                 tail]]
            t = self.assert_invalid()
            self.assertEqual(t.closes, 1)

    def test_late_close_native_request_refused(self):
        FakeTransport.queue = _success_queue()
        FakeTransport.drain = [[
            {"jsonrpc": "2.0", "id": 3, "method": "x", "params": {}}]]
        t = self.assert_invalid()
        self.assertEqual(t.closes, 1)

    def test_swallowed_drain_error_still_refuses_inventory(self):
        FakeTransport.queue = _success_queue()

        def close_after_drain(transport):
            transport.closes += 1
            try:
                transport._scan(({'id': 3, 'method': 'tool/call',
                                  'params': {}},))
            except NativeError:
                pass
            transport.stopped = True

        with mock.patch.object(FakeTransport, 'close', close_after_drain):
            transport = self.assert_invalid()
        self.assertTrue(transport.stopped)
        self.assertTrue(transport._protocol_invalid)
        self.assertEqual(transport.closes, 1)

    def test_swallowed_late_framing_error_still_refuses_inventory(self):
        FakeTransport.queue = _success_queue()

        def close_after_bad_frame(transport):
            transport.closes += 1
            with mock.patch.object(text_transport.OwnedTransport, 'poll',
                                   side_effect=NativeError('invalid JSON')):
                try:
                    INVENTORY_POLL(transport)
                except NativeError:
                    pass
            transport.stopped = True

        with mock.patch.object(FakeTransport, 'close', close_after_bad_frame):
            transport = self.assert_invalid()
        self.assertTrue(transport.stopped)
        self.assertTrue(transport._protocol_invalid)
        self.assertEqual(transport.closes, 1)

    def test_frame_budget_includes_drain(self):
        FakeTransport.queue = _success_queue()
        FakeTransport.drain = [
            [_notification("account/rateLimits/updated")] * 127]
        self.assert_invalid()
        FakeTransport.instances = []
        FakeTransport.drain = ()
        FakeTransport.queue = [[
            _notification("account/rateLimits/updated")] * 129]
        t = self.assert_invalid()
        self.assertEqual(t.closes, 1)

    def test_send_poll_parse_failures_close(self):
        FakeTransport.poll_error = NativeError("x")
        self.assert_invalid()
        FakeTransport.instances = []
        FakeTransport.poll_error = OSError("x")
        self.assert_invalid()
        FakeTransport.instances = []
        FakeTransport.poll_error = None
        FakeTransport.send_error = OSError("boom")
        t = self.assert_invalid()
        self.assertEqual(t.closes, 1)
        FakeTransport.instances = []
        FakeTransport.send_error = None
        FakeTransport.queue = [
            [_response(ci._ID_INITIALIZE, {"userAgent": "u"})],
            [_response(ci._ID_CONFIG_READ,
                       {"config": {**_config(),
                                   "web_search": "on"}})]]
        t = self.assert_invalid()
        self.assertEqual(t.closes, 1)

    def test_constructor_errors_sanitized(self):
        for exc in (OSError("spawn"), NativeError("raw_payload"),
                    ValueError("x")):
            with mock.patch.object(
                    ci, "_InventoryTransport",
                    mock.Mock(side_effect=exc)):
                with self.assertRaises(NativeError) as ctx:
                    self.call()
                self.assertEqual(str(ctx.exception),
                                 "native_inventory_invalid")
        with mock.patch.object(
                ci, "_InventoryTransport",
                mock.Mock(side_effect=KeyboardInterrupt())):
            with self.assertRaises(KeyboardInterrupt):
                self.call()
        self.assertEqual(FakeTransport.instances, [])

    def test_monotonic_failure_after_ctor_closes(self):
        FakeTransport.queue = _success_queue()
        with mock.patch.object(time, "monotonic",
                               side_effect=RuntimeError("clock")):
            t = self.assert_invalid()
        self.assertEqual(t.closes, 1)

    def test_timeout_uses_monotonic(self):
        clock = {"now": 0.0}

        def fake_monotonic():
            clock["now"] += 0.6
            return clock["now"]

        with mock.patch.object(time, "monotonic", fake_monotonic):
            t = self.assert_invalid(timeout=1)
        self.assertEqual(t.closes, 1)

    def test_interrupts_propagate_after_cleanup(self):
        FakeTransport.poll_error = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            self.call()
        self.assertEqual(self.transport().closes, 1)
        FakeTransport.instances = []
        FakeTransport.poll_error = OSError("x")
        FakeTransport.close_error = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            self.call()
        self.assertEqual(self.transport().closes, 1)

    def test_missing_stopped_proof_refused(self):
        FakeTransport.queue = _success_queue()
        FakeTransport.stop_on_close = False
        self.assert_invalid()

    def test_argument_validation(self):
        for kwargs in ({"before_launch": None}, {"on_stopped": 3},
                       {"timeout": 0}, {"timeout": 21},
                       {"timeout": 1.5}, {"timeout": True}):
            with self.assertRaises(NativeError):
                self.call(**kwargs)
        self.assertEqual(FakeTransport.instances, [])


if __name__ == "__main__":
    unittest.main()
