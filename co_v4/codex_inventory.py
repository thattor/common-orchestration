"""Pure inventory extraction from a codex ``config/read`` result.

Validates the inventory maps and the known denial controls of an
already-read config dict and returns only the identifiers the next Host
must disable or clear. Values, payloads and other config contents never
leave this module.
"""

import os
import re
import time

from .adapters.codex import NativeError
from .codex_host import FEATURES_01601, OVERRIDES
from .codex_permissions import (account_updated_notification,
                                disabled_remote_notification)
from .codex_text_transport import OwnedTransport, SUPPORTED_TEXT_CLI
from .codex_text_validation import ValidationError, frame_kind, rpc_key

_MCP_NAME = re.compile(r"[A-Za-z0-9_-]{1,128}")
_ENV_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
_MAX_MCP_SERVERS = 64
_MAX_ENV_KEYS = 128


def _invalid():
    raise NativeError("native_inventory_invalid") from None


def _exact_string(value, expected):
    return type(value) is str and value == expected


def _denial_controls(config, policy):
    features = config.get("features")
    if type(features) is not dict:
        _invalid()
    for name in FEATURES_01601:
        if features.get(name) is not False:
            _invalid()
    if not _exact_string(config.get("web_search"), "disabled"):
        _invalid()
    notify = config.get("notify")
    if notify is not None and (type(notify) is not list or notify):
        _invalid()
    if not _exact_string(policy.get("inherit"), "none"):
        _invalid()
    include_only = policy.get("include_only")
    if type(include_only) is not list or include_only:
        _invalid()


def _mcp_server_names(config):
    servers = config.get("mcp_servers")
    if servers is None:
        return ()
    if type(servers) is not dict or len(servers) > _MAX_MCP_SERVERS:
        _invalid()
    names = []
    for name, entry in servers.items():
        if type(name) is not str or not _MCP_NAME.fullmatch(name):
            _invalid()
        if type(entry) is not dict:
            _invalid()
        names.append(name)
    return tuple(sorted(names))


def _environment_key_names(policy):
    values = policy.get("set")
    if values is None:
        return ()
    if type(values) is not dict or len(values) > _MAX_ENV_KEYS:
        _invalid()
    for key in values:
        if type(key) is not str or not _ENV_KEY.fullmatch(key):
            _invalid()
    return tuple(sorted(values))


def parse_inventory(config):
    """Validate a ``config/read`` config dict and return name tuples.

    The result is a fresh dict with exactly ``disabled_mcp_servers`` and
    ``cleared_environment_keys``: identifiers the next Host must disable
    or clear, not proof that they are disabled. Any shape or
    denial-control violation raises
    ``NativeError('native_inventory_invalid')``.
    """
    if type(config) is not dict:
        _invalid()
    policy = config.get("shell_environment_policy")
    if type(policy) is not dict:
        _invalid()
    _denial_controls(config, policy)
    return {
        "disabled_mcp_servers": _mcp_server_names(config),
        "cleared_environment_keys": _environment_key_names(policy),
    }


_MAX_FRAMES = 128
_MAX_USER_AGENT_BYTES = 1024
_MAX_WARNING_BYTES = 8192
_ID_INITIALIZE = "co04-inventory-initialize"
_ID_CONFIG_READ = "co04-inventory-config-read"
_PASSTHROUGH_ENV = ("HOME", "PATH", "TMPDIR", "USER", "LOGNAME", "LANG")


def _utf8_within(value, limit):
    try:
        return len(value.encode("utf-8")) <= limit
    except UnicodeEncodeError:
        return False


def _metadata_notification(frame):
    method = frame["method"]
    params = frame["params"]
    try:
        if method == "account/updated":
            accepted = bool(account_updated_notification(frame))
        elif method == "remoteControl/status/changed":
            accepted = bool(disabled_remote_notification(frame))
        elif method == "account/rateLimits/updated":
            accepted = type(params) is dict
        elif method == "warning":
            accepted = (set(params) == {"message"}
                        and type(params["message"]) is str
                        and _utf8_within(params["message"],
                                         _MAX_WARNING_BYTES))
        else:
            accepted = False
    except ValidationError:
        accepted = False
    if not accepted:
        _invalid()


class _InventoryTransport(OwnedTransport):
    """OwnedTransport that validates every Native frame, including drain.

    ``OwnedTransport._drain`` invokes ``self.poll`` virtually, so the
    frame scan must live on the subclass; an outside wrapper would lose
    all frames received while ``close`` drains the helper.
    """

    def __init__(self, *args, **kwargs):
        self._received = 0
        self._pending = {}
        self._answers = {}
        self._protocol_invalid = False
        super().__init__(*args, **kwargs)

    def expect(self, request_id):
        self._pending[rpc_key(request_id)] = True

    def pending(self):
        return bool(self._pending)

    def answer(self, request_id):
        try:
            return self._answers.pop(rpc_key(request_id))
        except KeyError:
            _invalid()

    def poll(self):
        try:
            return self._scan(super().poll())
        except BaseException:
            self._protocol_invalid = True
            raise

    def _scan(self, batch):
        try:
            return self._scan_checked(batch)
        except BaseException:
            self._protocol_invalid = True
            raise

    def _scan_checked(self, batch):
        if type(batch) is not tuple:
            _invalid()
        self._received += len(batch)
        if self._received > _MAX_FRAMES:
            _invalid()
        for frame in batch:
            try:
                kind = frame_kind(frame)
            except ValidationError:
                _invalid()
            if kind == "notification":
                _metadata_notification(frame)
                continue
            try:
                key = rpc_key(frame["id"])
            except ValidationError:
                _invalid()
            if key not in self._pending:
                _invalid()
            del self._pending[key]
            if type(frame["result"]) is not dict:
                _invalid()
            self._answers[key] = frame["result"]
        return batch


def _await_pending(transport, deadline):
    while transport.pending():
        if time.monotonic() >= deadline:
            _invalid()
        if transport.poll():
            continue
        if not transport.alive():
            _invalid()
        time.sleep(0.01)


def _read_session(transport, workspace, deadline):
    transport.expect(_ID_INITIALIZE)
    transport.send({
        "jsonrpc": "2.0",
        "id": _ID_INITIALIZE,
        "method": "initialize",
        "params": {
            "clientInfo": {"name": "co04_native_inventory",
                           "version": "0.4"},
            "capabilities": {"experimentalApi": True},
        },
    })
    _await_pending(transport, deadline)
    agent = transport.answer(_ID_INITIALIZE).get("userAgent")
    if (type(agent) is not str or not agent
            or not _utf8_within(agent, _MAX_USER_AGENT_BYTES)):
        _invalid()
    transport.send({"jsonrpc": "2.0", "method": "initialized"})
    transport.expect(_ID_CONFIG_READ)
    transport.send({
        "jsonrpc": "2.0",
        "id": _ID_CONFIG_READ,
        "method": "config/read",
        "params": {"cwd": workspace, "includeLayers": False},
    })
    _await_pending(transport, deadline)
    config = transport.answer(_ID_CONFIG_READ).get("config")
    if type(config) is not dict:
        _invalid()
    return parse_inventory(config)


def discover_inventory(executable, workspace, *, before_launch, on_stopped,
                       timeout=20):
    """Read MCP/env-name inventory over one owned Native metadata session.

    Spawns a single ``_InventoryTransport``, performs only initialize /
    initialized / config/read, and returns ``native_version`` plus the
    two sorted name tuples from :func:`parse_inventory`. Any failure or
    missing stopped proof surfaces as
    ``NativeError('native_inventory_invalid')``; KeyboardInterrupt and
    SystemExit propagate after cleanup still runs.
    """
    if type(timeout) is not int or not 1 <= timeout <= 20:
        _invalid()
    if not callable(before_launch) or not callable(on_stopped):
        _invalid()
    overrides = OVERRIDES + tuple(
        "features." + name + "=false" for name in FEATURES_01601
    ) + ("features.remote_control=false",)
    env = {key: os.environ[key] for key in _PASSTHROUGH_ENV
           if key in os.environ}
    try:
        transport = _InventoryTransport(
            executable,
            workspace,
            config_overrides=overrides,
            env=env,
            required_version=SUPPORTED_TEXT_CLI,
            before_launch=before_launch,
            on_stopped=on_stopped,
            max_drain_s=1,
        )
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException:
        _invalid()
    state = None
    try:
        try:
            inventory = _read_session(
                transport, workspace, time.monotonic() + timeout)
        except (KeyboardInterrupt, SystemExit):
            state = "interrupted"
            raise
        except BaseException:
            state = "failed"
    finally:
        try:
            transport.close()
        except (KeyboardInterrupt, SystemExit):
            raise
        except BaseException:
            if state is None:
                state = "failed"
    if state is not None:
        _invalid()
    try:
        proven = (transport.stopped is True
                  and transport._protocol_invalid is False
                  and transport.native_version == SUPPORTED_TEXT_CLI)
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException:
        _invalid()
    if not proven:
        _invalid()
    return {
        "native_version": SUPPORTED_TEXT_CLI,
        "disabled_mcp_servers": inventory["disabled_mcp_servers"],
        "cleared_environment_keys": inventory["cleared_environment_keys"],
    }
