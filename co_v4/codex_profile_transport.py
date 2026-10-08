"""One Attempt's named-profile transport; no Human or cessation capability."""
from .codex_permissions import ProfileError, disabled_remote_notification, account_updated_notification


class CodexProfileTransport:
    def __init__(self, inner, request, profile, effort, command_prefix, before_turn):
        self.inner, self.request, self.profile = inner, request, profile
        self.effort, self.command_prefix, self.before_turn = effort, command_prefix, before_turn
        self.native_version = inner.native_version
        self.initialized = False
        self.thread_request_id = None
        self.thread_id = None
        self.warning_thread_candidate = None
        self.informational_warnings = 0
        self.disabled_remote_notifications = 0
        self.account_notifications = 0
        self.submitted = False

    def send(self, message):
        method, params = message.get("method"), message.get("params", {})
        cwd = self.request.conditions.workspace
        if method == "initialize":
            if (self.initialized or params.get("capabilities") != {"experimentalApi": True}
                    or params["capabilities"]["experimentalApi"] is not True):
                raise ProfileError("experimental_initialization_invalid")
            self.initialized = True
        elif method is not None and not self.initialized:
            raise ProfileError("experimental_initialization_missing")
        if method in {"thread/start", "config/read", "command/exec", "turn/start"} and params.get("cwd") != cwd:
            raise ProfileError("profile_cwd_mismatch")
        if method == "thread/start":
            if (params.get("permissions") != self.profile or "sandbox" in params
                    or params.get("environments") != [] or self.thread_request_id is not None
                    or type(message.get("id")) is not str or not message["id"]):
                raise ProfileError("thread_profile_mismatch")
            self.thread_request_id = message["id"]
        if method == "command/exec" and (
                set(params) != {"permissionProfile", "cwd", "command", "timeoutMs", "outputBytesCap"}
                or params.get("permissionProfile") != self.profile
                or type(params.get("command")) is not list or len(params["command"]) != 6
                or params["command"][:5] != self.command_prefix
                or params.get("timeoutMs") != 5000 or params.get("outputBytesCap") != 8192):
            raise ProfileError("command_profile_mismatch")
        if method == "turn/start":
            keys = {"threadId", "input", "permissions", "cwd"} | ({"effort"} if self.effort is not None else set())
            if (self.submitted or self.thread_id is None or set(params) != keys
                    or params.get("threadId") != self.thread_id or params.get("permissions") != self.profile
                    or params.get("effort") != self.effort):
                raise ProfileError("turn_profile_mismatch")
            self.before_turn()
            self.submitted = True
        if method == "model/list":
            if (self.submitted or self.thread_id is None
                    or set(params) not in ({"includeHidden", "limit"}, {"includeHidden", "limit", "cursor"})
                    or params.get("includeHidden") is not False or type(params.get("limit")) is not int
                    or params["limit"] != 100
                    or ("cursor" in params and (type(params["cursor"]) is not str or not 1 <= len(params["cursor"]) <= 1024))):
                raise ProfileError("model_metadata_request_unbound")
        if method in {"account/read", "account/rateLimits/read"}:
            expected = {"refreshToken": False} if method == "account/read" else {}
            if self.submitted or params != expected or (method == "account/read" and params.get("refreshToken") is not False):
                raise ProfileError("account_metadata_request_unbound")
        if method not in {None, "initialize", "initialized", "thread/start", "config/read", "command/exec", "turn/start", "turn/interrupt", "account/read", "account/rateLimits/read", "model/list"}:
            raise ProfileError("profile_rpc_unsupported")
        if method == "turn/interrupt" and params.get("threadId") != self.thread_id:
            raise ProfileError("interrupt_thread_mismatch")
        self.inner.send(message)

    def poll(self):
        result = []
        for message in self.inner.poll():
            if (self.thread_request_id is not None and message.get("id") == self.thread_request_id
                    and "method" not in message and "result" in message):
                reply = message["result"]
                thread = reply.get("thread") if type(reply) is dict else None
                identity = thread.get("id") if type(thread) is dict else None
                if (type(identity) is not str or not identity or self.thread_id is not None
                        or self.warning_thread_candidate not in (None, identity)):
                    raise ProfileError("warning_thread_binding_mismatch")
                self.thread_id = identity
            if message.get("method") == "remoteControl/status/changed":
                if not disabled_remote_notification(message):
                    raise ProfileError("remote_control_notification_unverified")
                self.disabled_remote_notifications += 1
                if self.disabled_remote_notifications > 8:
                    raise ProfileError("remote_status_frame_limit")
            elif message.get("method") == "account/updated":
                if not account_updated_notification(message):
                    raise ProfileError("account_notification_unverified")
                self.account_notifications += 1
                if self.account_notifications > 8:
                    raise ProfileError("account_notification_limit")
            elif message.get("method") == "warning":
                if not self._pending_warning(message):
                    raise ProfileError("warning_notification_unverified")
                self.informational_warnings += 1
                if self.informational_warnings > 8:
                    raise ProfileError("warning_frame_limit")
            else:
                result.append(message)
        return tuple(result)

    def alive(self): return self.inner.alive()
    def close(self): return self.inner.close()

    def _pending_warning(self, message):
            # Source-defined information may arrive before thread/start's reply.
            # A nonempty thread id is only a candidate until that exact RPC binds it.
            if message.get("method") != "warning" or self.thread_request_id is None:
                return False
            params = message.get("params")
            if (set(message) - {"method", "params", "jsonrpc", "emittedAtMs"}
                    or ("jsonrpc" in message and message["jsonrpc"] != "2.0")
                    or ("emittedAtMs" in message and (type(message["emittedAtMs"]) is not int
                        or not -(2 ** 63) <= message["emittedAtMs"] < 2 ** 63))
                    or type(params) is not dict or set(params) not in ({"message"}, {"message", "threadId"})):
                return False
            try:
                if type(params["message"]) is not str or len(params["message"].encode("utf-8")) > 8192:
                    return False
                thread = params.get("threadId")
                if thread is not None and (type(thread) is not str or not thread
                        or len(thread.encode("utf-8")) > 1024):
                    return False
            except UnicodeEncodeError:
                return False
            if thread is not None:
                expected = self.thread_id or self.warning_thread_candidate
                if expected is not None and thread != expected:
                    raise ProfileError("warning_thread_binding_mismatch")
                self.warning_thread_candidate = thread
            return True
