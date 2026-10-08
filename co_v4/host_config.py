"""co_v4/host_config.py — closed host configuration, Phase A only.

load_host_config() validates a 'co.service-host/1' document read through a
protected fd: same uid, mode 0600, regular file, single link, O_NOFOLLOW |
O_CLOEXEC, fstat identity before a bounded read. Every level is a closed
key set; duplicate JSON keys, non-finite constants, floats in int fields
and bool-for-int are refused. All path fields must be canonical absolute.
state_root must be an existing directory (ServiceOwner validates
0700/APFS later); ledger_path may be absent but its parent must be a
canonical directory; principals/registry/credential/manifest/launch
records must be canonical paths to existing regular files -- this loader
may stat them but never opens them: each consumer re-checks 0600/uid/
nlink at use.

Phase A produces immutable, unqualified specs. The wire digest fields are
syntax-checked only: profile_digest is 'sha256:'+hex64 and
environment_ref is 'env:sha256:'+hex64. No manifest, capture, credential
or launch file is opened; no route, listener or Native connection is
made; no RouteProtocolProfile is constructed. Phase B (after
ServiceOwner.acquire) runs verify_manifest -> issue_profile -> the
prefixed wire-digest/env_ref/model/auth_ref/argv comparisons and builds
real RouteConfig objects; a later builder dedups credential_file paths.

CredentialSupplier reads its protected file exactly once into memory and
exposes only the non-secret credential_ref.
"""
from dataclasses import dataclass
import os
import stat
import urllib.parse

from .openai_transport import Deadlines, strict_json
from .profile_registry import STANDARD_USE_CASES
from .protocol_profile import INDEX_MODES, PROTOCOLS, SEQUENCE_MODES

SCHEMA = 'co.service-host/1'
MAX_CONFIG_BYTES = 1024 * 1024
DIGEST_PREFIX = 'sha256:'
ENV_PREFIX = 'env:sha256:'
ADAPTERS = {'openai.responses': 'responses', 'openai.chat': 'chat'}
STORE_PARAMS = frozenset({'send_false', 'omit'})
TOP_KEYS = frozenset({'schema', 'state_root', 'ledger_path', 'bind',
    'principals_file', 'registry_file', 'max_body_bytes', 'sync_wait_s',
    'routes'})
BIND_KEYS = frozenset({'host', 'port'})
ROUTE_KEYS = frozenset({'model', 'adapter', 'endpoint', 'auth_ref',
    'credential_file', 'manifest_file', 'launch_record', 'profile',
    'profile_digest', 'environment_ref', 'store_param', 'deadlines',
    'max_drain_s', 'verification'})
PROFILE_KEYS = frozenset({'protocol', 'index_mode', 'sequence_mode',
    'inert_fields'})
DEADLINE_KEYS = frozenset({'connect_s', 'first_byte_s', 'idle_s',
    'total_s'})
VERIFY_KEYS = frozenset({'use_case', 'official_ref', 'implementation_ref',
    'measurement_ref', 'ac_ref', 'output_mode'})


class HostConfigInvalid(ValueError):
    """Fixed refusal; never carries file content or exception text."""
    code = 'host_config_invalid'

    def __init__(self):
        super().__init__(self.code)


def _text(value, limit=1024):
    """Bounded nonempty str that encodes strict UTF-8 (no surrogates)."""
    if type(value) is not str or not 0 < len(value) <= limit:
        return False
    try:
        value.encode('utf-8')
    except UnicodeEncodeError:
        return False
    return True


def _int(value, lo, hi):
    """Exact int only; bool and float are refused."""
    return type(value) is int and lo <= value <= hi


def _ref(value, limit=256):
    """Printable whitespace-free bounded text (refs, names)."""
    return (_text(value, limit) and value.isprintable()
            and ' ' not in value)


def _hex64(value):
    return (type(value) is str and len(value) == 64
            and all(ch in '0123456789abcdef' for ch in value))


def _prefixed_hex(value, prefix):
    return (type(value) is str and value.startswith(prefix)
            and _hex64(value[len(prefix):]))


def _read_protected(path, maximum):
    """O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC open, fstat identity, bounded read.
    NONBLOCK keeps a FIFO/blocking-target race at the open seam from ever
    hanging; fstat still requires a regular file."""
    flags = (os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC
             | getattr(os, 'O_NOFOLLOW', 0))
    try:
        fd = os.open(path, flags)
    except OSError:
        raise HostConfigInvalid() from None
    try:
        try:
            info = os.fstat(fd)
        except OSError:
            raise HostConfigInvalid() from None
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1):
            raise HostConfigInvalid()
        try:
            with os.fdopen(fd, 'rb') as handle:
                fd = -1
                blob = handle.read(maximum + 1)
        except OSError:
            raise HostConfigInvalid() from None
        if len(blob) > maximum:
            raise HostConfigInvalid()
        return blob
    finally:
        if fd >= 0:
            os.close(fd)


def _canonical(value, kind):
    """Canonical absolute path; lstat only, never opens the target.

    kind 'dir': existing directory; 'file': existing regular file;
    'new_file': canonical parent directory, the file itself absent or
    regular. Paths containing any symlink component fail the realpath
    identity comparison."""
    if not _text(value, 4096) or not os.path.isabs(value):
        raise HostConfigInvalid()
    try:
        real = os.path.realpath(value)
    except (OSError, ValueError):
        raise HostConfigInvalid() from None
    if real != value:
        raise HostConfigInvalid()
    try:
        st = os.lstat(value)
    except FileNotFoundError:
        st = None
    except (OSError, ValueError):
        raise HostConfigInvalid() from None
    if kind == 'dir':
        if st is None or not stat.S_ISDIR(st.st_mode):
            raise HostConfigInvalid()
    elif kind == 'file':
        if st is None or not stat.S_ISREG(st.st_mode):
            raise HostConfigInvalid()
    elif kind == 'new_file':
        parent = os.path.dirname(value)
        try:
            ok = (os.path.realpath(parent) == parent
                  and stat.S_ISDIR(os.lstat(parent).st_mode))
        except (OSError, ValueError):
            ok = False
        if not ok or (st is not None and not stat.S_ISREG(st.st_mode)):
            raise HostConfigInvalid()
    return value


def _endpoint(value):
    """Literal loopback http only: 127.0.0.1 or [::1], explicit port, /v1."""
    if not _text(value):
        raise HostConfigInvalid()
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError:
        raise HostConfigInvalid() from None
    if (parsed.geturl() != value
            or parsed.scheme != 'http'
            or parsed.hostname not in ('127.0.0.1', '::1')
            or parsed.username is not None or parsed.password is not None
            or port is None or not 1 <= port <= 65535
            or parsed.path != '/v1' or parsed.query or parsed.fragment):
        raise HostConfigInvalid()
    return value


@dataclass(frozen=True)
class ProfileSpec:
    """Unqualified Phase A profile input; Phase B feeds it to
    issue_profile() and compares the declared digest. Never accepted
    where a RouteProtocolProfile is required."""
    protocol: str
    index_mode: str
    sequence_mode: str
    inert_fields: tuple             # ((event_type, (key, ...)), ...) sorted


@dataclass(frozen=True)
class RouteSpec:
    """One validated route entry; nothing here is qualified or open."""
    model: str
    adapter: str
    endpoint: str
    auth_ref: str
    credential_file: str
    manifest_file: str
    launch_record: str
    profile: ProfileSpec
    profile_digest: str             # declared 'sha256:' + hex64 wire form
    environment_ref: str            # declared 'env:sha256:' + hex64
    store_param: str
    deadlines: Deadlines
    max_drain_s: int
    verification: tuple             # (use_case, official, impl, measure, ac)


@dataclass(frozen=True)
class HostConfig:
    state_root: str
    ledger_path: str
    bind_host: str
    bind_port: int
    principals_file: str
    registry_file: str
    max_body_bytes: int
    sync_wait_s: int
    routes: tuple                   # RouteSpec, declaration order


def _profile(value, adapter):
    if type(value) is not dict or set(value) != PROFILE_KEYS:
        raise HostConfigInvalid()
    protocol = value['protocol']
    inert = value['inert_fields']
    if (type(protocol) is not str or protocol not in PROTOCOLS
            or protocol != ADAPTERS[adapter]
            or type(value['index_mode']) is not str
            or value['index_mode'] not in INDEX_MODES
            or type(value['sequence_mode']) is not str
            or value['sequence_mode'] not in SEQUENCE_MODES
            or (value['index_mode'] == 'absent_single_part'
                and (protocol != 'responses'
                     or value['sequence_mode'] != 'absent'))):
        raise HostConfigInvalid()
    if type(inert) is not dict or len(inert) > 64:
        raise HostConfigInvalid()
    for event_type, keys in inert.items():
        if (not _text(event_type, 128)
                or type(keys) is not list or len(keys) > 16
                or any(type(k) is not str or not _ref(k, 128)
                       for k in keys)
                or keys != sorted(set(keys))):
            raise HostConfigInvalid()
    return ProfileSpec(protocol, value['index_mode'],
                       value['sequence_mode'],
                       tuple(sorted((k, tuple(v))
                                    for k, v in inert.items())))


def _verification(value):
    if (type(value) is not dict or set(value) != VERIFY_KEYS
            or value['output_mode'] != 'collect'
            or type(value['use_case']) is not str
            or value['use_case'] not in STANDARD_USE_CASES
            or any(not _ref(value[key], 1024)
                   for key in ('official_ref', 'implementation_ref',
                               'measurement_ref', 'ac_ref'))):
        raise HostConfigInvalid()
    return (value['use_case'], value['official_ref'],
            value['implementation_ref'], value['measurement_ref'],
            value['ac_ref'])


def _route(value):
    if type(value) is not dict or set(value) != ROUTE_KEYS:
        raise HostConfigInvalid()
    model, adapter = value['model'], value['adapter']
    if (not _text(model, 256) or type(adapter) is not str
            or adapter not in ADAPTERS):
        raise HostConfigInvalid()
    endpoint = _endpoint(value['endpoint'])
    if (not _ref(value['auth_ref'])
            or not _prefixed_hex(value['profile_digest'], DIGEST_PREFIX)
            or not _prefixed_hex(value['environment_ref'], ENV_PREFIX)
            or type(value['store_param']) is not str
            or value['store_param'] not in STORE_PARAMS
            or not _int(value['max_drain_s'], 1, 600)):
        raise HostConfigInvalid()
    deadlines = value['deadlines']
    if (type(deadlines) is not dict or set(deadlines) != DEADLINE_KEYS
            or any(not _int(deadlines[k], 1, 600) for k in DEADLINE_KEYS)):
        raise HostConfigInvalid()
    return RouteSpec(
        model=model, adapter=adapter, endpoint=endpoint,
        auth_ref=value['auth_ref'],
        credential_file=_canonical(value['credential_file'], 'file'),
        manifest_file=_canonical(value['manifest_file'], 'file'),
        launch_record=_canonical(value['launch_record'], 'file'),
        profile=_profile(value['profile'], adapter),
        profile_digest=value['profile_digest'],
        environment_ref=value['environment_ref'],
        store_param=value['store_param'],
        deadlines=Deadlines(connect=deadlines['connect_s'],
                            first_byte=deadlines['first_byte_s'],
                            idle=deadlines['idle_s'],
                            total=deadlines['total_s']),
        max_drain_s=value['max_drain_s'],
        verification=_verification(value['verification']))


def load_host_config(path):
    """Parse and fully validate the closed config; fixed refusal only."""
    path = _canonical(path, 'file')
    try:
        data = strict_json(
            _read_protected(path, MAX_CONFIG_BYTES).decode('utf-8'))
    except HostConfigInvalid:
        raise
    except Exception:
        raise HostConfigInvalid() from None
    bind = data.get('bind') if type(data) is dict else None
    if (type(data) is not dict or set(data) != TOP_KEYS
            or type(data['schema']) is not str or data['schema'] != SCHEMA
            or type(bind) is not dict or set(bind) != BIND_KEYS
            or bind['host'] != '127.0.0.1'
            or not _int(bind['port'], 1024, 65535)
            or not _int(data['max_body_bytes'], 1, 262144)
            or not _int(data['sync_wait_s'], 1, 60)):
        raise HostConfigInvalid()
    routes = data['routes']
    if type(routes) is not list or not 1 <= len(routes) <= 64:
        raise HostConfigInvalid()
    specs = tuple(_route(r) for r in routes)
    keys = [(s.model, s.adapter, s.environment_ref) for s in specs]
    if len(set(keys)) != len(keys):
        raise HostConfigInvalid()
    return HostConfig(
        state_root=_canonical(data['state_root'], 'dir'),
        ledger_path=_canonical(data['ledger_path'], 'new_file'),
        bind_host=bind['host'], bind_port=bind['port'],
        principals_file=_canonical(data['principals_file'], 'file'),
        registry_file=_canonical(data['registry_file'], 'file'),
        max_body_bytes=data['max_body_bytes'],
        sync_wait_s=data['sync_wait_s'], routes=specs)


class CredentialSupplier:
    """One protected credential file, read exactly once into memory.

    The file is exactly the token: 32..512 bytes of printable ASCII
    0x21..0x7E with no whitespace anywhere -- no stripping, no newline
    tolerance. __call__ returns a fresh {'Authorization': 'Bearer ...'}
    dict each time (the HttpSseTransport auth-supplier contract). Only
    the non-secret credential_ref is exposed; repr/str and every failure
    never carry token bytes.
    """
    def __init__(self, filename, credential_ref):
        if not _ref(credential_ref, 128):
            raise HostConfigInvalid()
        filename = _canonical(filename, 'file')
        blob = _read_protected(filename, 512)
        if (not 32 <= len(blob) <= 512
                or any(not 0x21 <= b <= 0x7E for b in blob)):
            raise HostConfigInvalid()
        self._token = blob.decode('ascii')
        self.credential_ref = credential_ref

    def __call__(self):
        return {'Authorization': 'Bearer ' + self._token}

    def __repr__(self):
        return 'CredentialSupplier(%r)' % self.credential_ref
