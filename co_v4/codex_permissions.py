"""Fixed Codex 0.159.2 profile serialization; no grants or admission authority."""
from pathlib import Path
import json
import re

class ProfileError(RuntimeError):
    """Fixed, non-sensitive profile error."""

def account_updated_notification(message):
    """0.159.2 AccountUpdatedNotification: process-global information, no grant.

    Source ff6aec96948b70d94983af2641a6b67c94faeff5, v2 schema. There is
    no RPC/thread identity in this notification; timing cannot bind it to a read.
    """
    if type(message) is not dict or message.get("method") != "account/updated":
        return False
    if (set(message) - {"method", "params", "jsonrpc", "emittedAtMs"}
            or ("jsonrpc" in message and message["jsonrpc"] != "2.0")
            or ("emittedAtMs" in message and (type(message["emittedAtMs"]) is not int
                or not -(2 ** 63) <= message["emittedAtMs"] < 2 ** 63))):
        return False
    params = message.get("params")
    if type(params) is not dict or set(params) - {"authMode", "planType"}:
        return False
    enums = {
        "authMode": {"apikey", "chatgpt", "chatgptAuthTokens", "headers", "agentIdentity",
                     "personalAccessToken", "bedrockApiKey", "bedrockAccessKeys"},
        "planType": {"free", "go", "plus", "pro", "prolite", "promax", "team",
                     "self_serve_business_prolite", "self_serve_business_usage_based", "business",
                     "ent26", "enterprise_cbp_automation", "enterprise_cbp_usage_based", "enterprise",
                     "edu", "edu_plus", "edu_pro", "unknown"}}
    return all(value is None or (type(value) is str and value in enums[key])
               for key, value in params.items())


def disabled_remote_notification(message):
    """Only disabled status metadata; no action, identity or success evidence."""
    if type(message) is not dict or message.get("method") != "remoteControl/status/changed":
        return False
    if (set(message) - {"method", "params", "jsonrpc", "emittedAtMs"}
            or ("jsonrpc" in message and message["jsonrpc"] != "2.0")
            or ("emittedAtMs" in message and (type(message["emittedAtMs"]) is not int
                or not -(2 ** 63) <= message["emittedAtMs"] < 2 ** 63))):
        return False
    params = message.get("params")
    if (type(params) is not dict or set(params) not in (
            {"status", "installationId", "serverName"},
            {"status", "installationId", "serverName", "environmentId"})
            or params.get("status") != "disabled" or params.get("environmentId") is not None):
        return False
    try:
        return all(type(params[k]) is str and len(params[k].encode("utf-8")) <= 1024
                   for k in ("installationId", "serverName"))
    except UnicodeEncodeError:
        return False


def profile_definition(credentials, protected):
    if not 1 <= len(credentials) <= 8 or not 1 <= len(protected) <= 8:
        raise ProfileError("profile_inventory_invalid")
    paths = (*credentials, *protected)
    if any(type(p) is not Path and not isinstance(p, Path) for p in paths):
        raise ProfileError("profile_inventory_invalid")
    if any(not p.is_absolute() or p.resolve(strict=True) != p or not p.is_file() for p in paths):
        raise ProfileError("profile_inventory_invalid")
    # Exact targets only; no glob expansion or unknown symbolic paths.
    return {"filesystem": {":root": "read", **{str(p): "deny" for p in paths}},
            "network": {"enabled": False}}


def profile_overrides(name, definition):
    if type(name) is not str or not re.fullmatch(r"co_readonly_[0-9a-f]{32}", name):
        raise ProfileError("profile_name_invalid")
    # json string escaping is also valid for these TOML basic strings. This is
    # argv data, never shell text. Only exact canonical paths and fixed enums.
    filesystem = ", ".join(json.dumps(k) + " = " + json.dumps(v)
                           for k, v in definition["filesystem"].items())
    return (f"permissions.{name}.filesystem={{ {filesystem} }}",
            f"permissions.{name}.network.enabled=false")


def validate_profile_config(config, name, definition):
    profiles = config.get("permissions") if type(config) is dict else None
    actual = profiles.get(name) if type(profiles) is dict else None
    if type(actual) is not dict:
        raise ProfileError("effective_profile_mismatch")
    actual = dict(actual)
    # Fixed Rust Option fields serialize as null (no skip_serializing_if).
    # Remove only schema-known absent values, never unknown or effective grants.
    for key in ("description", "extends", "workspace_roots"):
        if key in actual and actual[key] is None:
            del actual[key]
    filesystem, network = actual.get("filesystem"), actual.get("network")
    if type(filesystem) is dict:
        filesystem = dict(filesystem)
        if filesystem.get("glob_scan_max_depth", "absent") is None:
            del filesystem["glob_scan_max_depth"]
        actual["filesystem"] = filesystem
    if type(network) is dict:
        network = dict(network)
        optional = ("proxy_url", "enable_socks5", "socks_url", "enable_socks5_udp",
            "allow_upstream_proxy", "dangerously_allow_non_loopback_proxy",
            "dangerously_allow_all_unix_sockets", "mode", "domains", "unix_sockets",
            "allow_local_binding", "mitm")
        for key in optional:
            if key in network and network[key] is None:
                del network[key]
        actual["network"] = network
    if (actual != definition or type(network) is not dict
            or network.get("enabled") is not False):
        raise ProfileError("effective_profile_mismatch")
