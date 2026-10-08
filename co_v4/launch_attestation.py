"""Launch record verification for qualified loopback providers (#190 M3).

An external host-owned launcher writes co.provider-launch/1 only after
starting the provider from the manifest argv. LaunchAttestor checks the
record against kernel facts of the recorded PID only — uid, exact start
time, executable path, exact argv — read through co_v4.process_identity,
plus identity-before-hash checks of the executable, model and template
files and the pinned closed argv allowlist (b11429). A file or a
boolean is never
proof: passing requires a live same-uid process started with exactly
the qualified argv. Same-uid trust model; environment variables are
never read or attested.
"""
import hashlib
import json
import os
import stat
import urllib.request
from dataclasses import dataclass
from urllib.parse import urlsplit

from .openai_transport import strict_json
from .process_identity import ProcessIdentity, read_owned_process
from .protocol_profile import canonical

RECORD_SCHEMA = 'co.provider-launch/1'
MAX_RECORD_BYTES = 65536
MAX_PROBE_BYTES = 1024 * 1024
_HASH_CHUNK = 1024 * 1024
RECORD_KEYS = frozenset({'schema', 'manifest_sha256', 'pid', 'start_time',
    'uid', 'executable', 'argv', 'model', 'template', 'endpoint',
    'credential_ref'})
DESC_KEYS = frozenset({'path', 'sha256', 'dev', 'ino', 'size', 'mtime_ns'})
DESC_FIELDS = ('path', 'sha256', 'dev', 'ino', 'size', 'mtime_ns')
# Closed argv allowlist pinned to build b11429: flag spelling -> arity.
# Short aliases, joined '=' forms, attached values and positional
# tokens are all rejected simply by being unlisted.
_ARGV_ARITY = {
    '-m': 1, '--model': 1, '--chat-template-file': 1,
    '--api-key-file': 1, '--host': 1, '--port': 1, '--alias': 1,
    '--threads': 1, '--parallel': 1, '--device': 1,
    '--n-gpu-layers': 1, '--reasoning': 1, '--reasoning-budget': 1,
    '--no-webui': 0, '--no-ui-mcp-proxy': 0,
    '--threads-batch': 1, '--threads-http': 1, '--ctx-size': 1,
    '--reasoning-format': 1, '--cors-origins': 1, '--timeout': 1,
    '--no-warmup': 0, '--jinja': 0,
    '--temp': 1,
}
# -m/--model is required jointly and tracked separately.
_REQUIRED_FLAGS = frozenset({
    '--chat-template-file', '--api-key-file', '--host', '--port',
    '--alias', '--threads', '--parallel', '--device',
    '--n-gpu-layers', '--reasoning', '--reasoning-budget', '--temp',
    '--no-webui', '--no-ui-mcp-proxy'})


class RouteUnqualified(Exception):
    """Fixed-code launch attestation failure; no paths or text."""
    def __init__(self, code):
        self.code = code
        super().__init__(code)


class ProbeFailed(Exception):
    """Fixed-code observable-identity probe failure."""
    def __init__(self, code):
        self.code = code
        super().__init__(code)


class LaunchRecordError(ValueError):
    """Record preparation invariant failed; no record is produced."""
    def __init__(self, code):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class FileDescriptor:
    """Immutable {path, sha256, dev, ino, size, mtime_ns} identity."""
    path: str
    sha256: str
    dev: int
    ino: int
    size: int
    mtime_ns: int


@dataclass(frozen=True)
class LaunchRecord:
    """Parsed co.provider-launch/1; closed schema, typed fields."""
    manifest_sha256: str
    pid: int
    start_time: tuple
    uid: int
    executable: FileDescriptor
    argv: tuple
    model: FileDescriptor
    template: FileDescriptor
    endpoint: str
    credential_ref: str


def _hex64(value):
    return (type(value) is str and len(value) == 64
            and all(ch in '0123456789abcdef' for ch in value))


def _canonical(path):
    try:
        return (type(path) is str and os.path.isabs(path)
                and os.path.realpath(path) == path)
    except (OSError, ValueError):
        return False


def _int(value):
    return type(value) is int and value >= 0


def _desc(value):
    if not (type(value) is dict and set(value) == DESC_KEYS
            and _canonical(value['path']) and _hex64(value['sha256'])
            and all(_int(value[k])
                    for k in DESC_KEYS - {'path', 'sha256'})):
        raise RouteUnqualified('record descriptor invalid')
    return FileDescriptor(**{k: value[k] for k in DESC_FIELDS})


def _record(raw):
    if not (type(raw) is dict and set(raw) == RECORD_KEYS
            and raw['schema'] == RECORD_SCHEMA
            and _hex64(raw['manifest_sha256'])
            and _int(raw['pid']) and raw['pid'] > 0
            and _int(raw['uid'])
            and type(raw['start_time']) is dict
            and set(raw['start_time']) == {'sec', 'usec'}
            and _int(raw['start_time']['sec'])
            and type(raw['start_time']['usec']) is int
            and 0 <= raw['start_time']['usec'] <= 999999
            and type(raw['argv']) is list
            and 1 <= len(raw['argv']) <= 64
            and all(type(a) is str and 0 < len(a) <= 1024
                    and a.isprintable() for a in raw['argv'])
            and type(raw['endpoint']) is str and raw['endpoint']
            and type(raw['credential_ref']) is str
            and raw['credential_ref']):
        raise RouteUnqualified('record fields invalid')
    return LaunchRecord(
        raw['manifest_sha256'], raw['pid'],
        (raw['start_time']['sec'], raw['start_time']['usec']),
        raw['uid'], _desc(raw['executable']), tuple(raw['argv']),
        _desc(raw['model']), _desc(raw['template']),
        raw['endpoint'], raw['credential_ref'])


def load_launch_record(path):
    """0600/uid/nlink-1/regular/noFOLLOW bounded strict-JSON record.

    The protective checks run on the opened fd (fstat after O_NOFOLLOW
    open, cross-checked against lstat), never on the path alone."""
    if not _canonical(path):
        raise RouteUnqualified('record path invalid')
    try:
        lst = os.lstat(path)
        fd = os.open(path,
                     os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
                     | os.O_NONBLOCK)
    except (OSError, ValueError):
        raise RouteUnqualified('record unreadable') from None
    try:
        try:
            st = os.fstat(fd)
        except OSError:
            raise RouteUnqualified('record unreadable') from None
        if ((st.st_dev, st.st_ino) != (lst.st_dev, lst.st_ino)
                or not stat.S_ISREG(st.st_mode)
                or stat.S_IMODE(st.st_mode) != 0o600
                or st.st_uid != os.getuid() or st.st_nlink != 1):
            raise RouteUnqualified('record file invalid')
        chunks, total = [], 0
        while True:
            try:
                chunk = os.read(fd, MAX_RECORD_BYTES + 1 - total)
            except OSError:
                raise RouteUnqualified('record unreadable') from None
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_RECORD_BYTES:
                raise RouteUnqualified('record too large')
    finally:
        os.close(fd)
    try:
        raw = strict_json(b''.join(chunks).decode('utf-8'))
    except Exception:
        raise RouteUnqualified('record document invalid') from None
    return _record(raw)


def _int_token(value, lo, hi):
    """Plain ASCII decimal, no sign, no leading zeros."""
    return (type(value) is str and value.isascii() and value.isdigit()
            and (value == '0' or not value.startswith('0'))
            and len(value) <= len(str(hi))
            and lo <= int(value) <= hi)


def _alias_token(value):
    return (type(value) is str and 0 < len(value) <= 128
            and all(c.isascii() and (c.isalnum() or c in '._-')
                    for c in value))


def validate_launch_argv(argv, *, executable_path, model_path,
                         template_path, credential_file, model_id,
                         threads, slots, host, port):
    """Closed argv allowlist for the pinned provider build.

    argv[0] must equal the descriptor executable path (the attestor
    also compares proc_pidpath, rejecting trampolines). Every other
    token must be one listed spelling, separated form, exactly its
    arity, and each flag appears at most once; every required flag is
    present. Value rules pin the model/template/credential paths, the
    endpoint host+port, --alias=model_id, --threads=launch.threads,
    --parallel=launch.slots and the fixed CPU/reasoning literals. The
    launcher calls this before Popen; the attestor and the record
    builder reuse it."""
    if (type(argv) is not tuple or not argv
            or any(type(a) is not str or not a for a in argv)):
        raise RouteUnqualified('argv invalid')
    if argv[0] != executable_path:
        raise RouteUnqualified('argv executable mismatch')
    if (host not in ('127.0.0.1', '::1') or type(host) is not str
            or type(port) is not int or not 1 <= port <= 65535
            or type(threads) is not int or threads < 1
            or type(slots) is not int or slots < 1):
        raise RouteUnqualified('argv premises invalid')
    seen = {}
    i = 1
    while i < len(argv):
        tok = argv[i]
        arity = _ARGV_ARITY.get(tok)
        vals = argv[i + 1:i + 1 + (arity or 0)]
        if (arity is None or tok in seen or len(vals) != arity
                or any(v in _ARGV_ARITY for v in vals)):
            raise RouteUnqualified('argv flag invalid')
        seen[tok] = vals
        i += 1 + arity
    nmodel = ('-m' in seen) + ('--model' in seen)
    if _REQUIRED_FLAGS - set(seen) or nmodel != 1:
        raise RouteUnqualified('argv required flag missing')
    mval = seen['-m'][0] if '-m' in seen else seen['--model'][0]
    checks = (
        (mval == model_path, 'model flag invalid'),
        (seen['--chat-template-file'][0] == template_path,
         'template flag invalid'),
        (seen['--api-key-file'][0] == credential_file,
         'credential flag invalid'),
        (seen['--host'][0] == host, 'host flag invalid'),
        (type(port) is int and seen['--port'][0] == str(port),
         'port flag invalid'),
        (seen['--alias'][0] == model_id and _alias_token(model_id),
         'alias flag invalid'),
        (type(threads) is int and seen['--threads'][0] == str(threads),
         'threads flag invalid'),
        (type(slots) is int and seen['--parallel'][0] == str(slots),
         'slots flag invalid'),
        (seen['--device'][0] == 'none', 'device flag invalid'),
        (seen['--n-gpu-layers'][0] == '0', 'gpu flag invalid'),
        (seen['--reasoning'][0] == 'off', 'reasoning flag invalid'),
        (seen['--reasoning-budget'][0] == '0', 'budget flag invalid'),
        (seen['--temp'][0] == '0', 'temp flag invalid'),
    )
    for ok, code in checks:
        if not ok:
            raise RouteUnqualified(code)
    cors = 'http://' + ('[::1]' if host == '::1' else host)
    optionals = (
        ('--threads-batch', lambda v: v == seen['--threads'][0],
         'threads batch invalid'),
        ('--threads-http', lambda v: _int_token(v, 1, 16),
         'threads http invalid'),
        ('--ctx-size', lambda v: _int_token(v, 1, 32768),
         'ctx size invalid'),
        ('--reasoning-format', lambda v: v == 'auto',
         'reasoning format invalid'),
        ('--cors-origins', lambda v: v == cors, 'cors origins invalid'),
        ('--timeout', lambda v: _int_token(v, 1, 3600),
         'timeout invalid'),
    )
    for flag, ok, code in optionals:
        if flag in seen and not ok(seen[flag][0]):
            raise RouteUnqualified(code)
    if ('--jinja' in seen
            and argv.index('--jinja')
            > argv.index('--chat-template-file')):
        raise RouteUnqualified('jinja order invalid')


def _file_lstat(path):
    try:
        st = os.lstat(path)
    except (OSError, ValueError):
        return None
    if not stat.S_ISREG(st.st_mode):
        return None
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)


def file_descriptor(path):
    """lstat identity plus sha256 of one regular non-symlink file."""
    if not _canonical(path):
        raise LaunchRecordError('file path invalid')
    ident = _file_lstat(path)
    if ident is None:
        raise LaunchRecordError('file invalid')
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
                     | os.O_NONBLOCK)
    except (OSError, ValueError):
        raise LaunchRecordError('file unreadable') from None
    try:
        try:
            st = os.fstat(fd)
        except OSError:
            raise LaunchRecordError('file unreadable') from None
        if (not stat.S_ISREG(st.st_mode)
                or (st.st_dev, st.st_ino, st.st_size,
                    st.st_mtime_ns) != ident):
            raise LaunchRecordError('file changed')
        h = hashlib.sha256()
        try:
            while chunk := os.read(fd, _HASH_CHUNK):
                h.update(chunk)
        except OSError:
            raise LaunchRecordError('file unreadable') from None
        try:
            st = os.fstat(fd)
        except OSError:
            raise LaunchRecordError('file unreadable') from None
        if (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns) != ident \
                or _file_lstat(path) != ident:
            raise LaunchRecordError('file changed')
    finally:
        os.close(fd)
    return FileDescriptor(path, h.hexdigest(),
                          ident[0], ident[1], ident[2], ident[3])


def build_launch_record(*, proc, before, argv, manifest_sha256, endpoint,
                        credential_ref, credential_file, model_id,
                        threads, slots,
                        read_process=read_owned_process):
    """After-launch record bytes; the caller writes them atomically 0600
    and owns stopping the child on failure. before holds the
    {executable, model, template} FileDescriptors taken before exec;
    each is re-lstated after start and must be byte-identical. The
    closed argv contract is checked after the kernel argv read."""
    pid = getattr(proc, 'pid', proc)
    argv = tuple(argv)
    if (type(pid) is not int or pid <= 0 or not callable(read_process)
            or not all(type(a) is str for a in argv)
            or not _canonical(credential_file)):
        raise LaunchRecordError('launch arguments invalid')
    try:
        identity = read_process(pid, os.getuid())
    except Exception:
        raise LaunchRecordError('process identity failed') from None
    if (type(identity) is not ProcessIdentity
            or identity.pid != pid or identity.uid != os.getuid()
            or tuple(identity.argv) != argv):
        raise LaunchRecordError('process identity mismatch')
    descs = {}
    for name in ('executable', 'model', 'template'):
        desc = before.get(name) if type(before) is dict else None
        if type(desc) is not FileDescriptor:
            raise LaunchRecordError('descriptor missing')
        if _file_lstat(desc.path) != (desc.dev, desc.ino, desc.size,
                                      desc.mtime_ns):
            raise LaunchRecordError('file changed during launch')
        descs[name] = desc
    if identity.executable != descs['executable'].path:
        raise LaunchRecordError('executable path mismatch')
    try:
        parts = _endpoint_parts(endpoint)
        validate_launch_argv(
            argv, executable_path=descs['executable'].path,
            model_path=descs['model'].path,
            template_path=descs['template'].path,
            credential_file=credential_file, model_id=model_id,
            threads=threads, slots=slots,
            host=parts.hostname, port=parts.port)
    except RouteUnqualified as exc:
        raise LaunchRecordError(exc.code) from None
    body = {'schema': RECORD_SCHEMA,
            'manifest_sha256': manifest_sha256, 'pid': pid,
            'start_time': {'sec': identity.start_sec,
                           'usec': identity.start_usec},
            'uid': identity.uid,
            'executable': {k: getattr(descs['executable'], k)
                           for k in DESC_FIELDS},
            'argv': list(argv),
            'model': {k: getattr(descs['model'], k) for k in DESC_FIELDS},
            'template': {k: getattr(descs['template'], k)
                         for k in DESC_FIELDS},
            'endpoint': endpoint, 'credential_ref': credential_ref}
    data = canonical(body)
    _record(json.loads(data))  # emit only bytes that pass the closed schema
    return data


class LaunchAttestor:
    """The gate's launch_attested callback: record + kernel + files.

    Constructed from a record path, the trusted credential_file path and
    a process reader; there is no way to pass True, config, or CLI
    authority. Any failure is a fixed-code RouteUnqualified."""

    def __init__(self, record_path, credential_file, *,
                 read_process=read_owned_process):
        if not _canonical(credential_file) or not callable(read_process):
            raise ValueError('credential file path and reader required')
        self._path = record_path
        self._credential_file = credential_file
        self._read_process = read_process
        self._cache = {}

    def _hash(self, desc):
        ident = (desc.dev, desc.ino, desc.size, desc.mtime_ns)
        if _file_lstat(desc.path) != ident:
            raise RouteUnqualified('file identity changed')
        key = (desc.path,) + ident
        digest = self._cache.get(key)
        if digest is None:
            try:
                fd = os.open(desc.path,
                             os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
                             | os.O_NONBLOCK)
            except (OSError, ValueError):
                raise RouteUnqualified('file unreadable') from None
            try:
                try:
                    st = os.fstat(fd)
                except OSError:
                    raise RouteUnqualified('file unreadable') from None
                if (not stat.S_ISREG(st.st_mode)
                        or (st.st_dev, st.st_ino, st.st_size,
                            st.st_mtime_ns) != ident):
                    raise RouteUnqualified('file identity changed')
                h = hashlib.sha256()
                try:
                    while chunk := os.read(fd, _HASH_CHUNK):
                        h.update(chunk)
                except OSError:
                    raise RouteUnqualified('file unreadable') from None
                try:
                    st = os.fstat(fd)
                except OSError:
                    raise RouteUnqualified('file unreadable') from None
                if (st.st_dev, st.st_ino, st.st_size,
                        st.st_mtime_ns) != ident:
                    raise RouteUnqualified('file identity changed')
            finally:
                os.close(fd)
            if _file_lstat(desc.path) != ident:
                raise RouteUnqualified('file identity changed')
            digest = h.hexdigest()
            self._cache[key] = digest
        return digest

    def __call__(self, manifest_fields, endpoint, auth_ref):
        record = load_launch_record(self._path)
        if type(manifest_fields) is not dict:
            raise RouteUnqualified('manifest invalid')
        try:
            recomputed = hashlib.sha256(canonical(
                {k: v for k, v in manifest_fields.items()
                 if k != 'manifest_sha256'})).hexdigest()
        except Exception:
            raise RouteUnqualified('manifest invalid') from None
        launch = manifest_fields.get('launch')
        argv = launch.get('argv') if type(launch) is dict else None
        auth = manifest_fields.get('auth')
        # The gate hands a detached sealed manifest BODY that has no
        # manifest_sha256 key: canonical(body) is exactly the sealed
        # bytes, so its sha256 is the verified digest the record must
        # match. A standalone caller may pass the full document — a
        # present manifest_sha256 must equal the recompute and is never
        # silently ignored when wrong.
        declared = manifest_fields.get('manifest_sha256')
        if (('manifest_sha256' in manifest_fields
                and (not _hex64(declared) or declared != recomputed))
                or record.manifest_sha256 != recomputed
                or endpoint != record.endpoint
                or auth_ref != record.credential_ref
                or type(auth) is not dict
                or auth.get('credential_ref') != auth_ref
                or type(argv) is not list
                or record.argv != tuple(argv)):
            raise RouteUnqualified('record binding mismatch')
        # A wrong-uid record is refused before any kernel read of the
        # PID, so no foreign process is ever inspected.
        if record.uid != os.getuid():
            raise RouteUnqualified('record uid invalid')
        try:
            identity = self._read_process(record.pid, os.getuid(),
                                          record.start_time)
        except Exception:
            raise RouteUnqualified('process identity failed') from None
        if (type(identity) is not ProcessIdentity
                or identity.pid != record.pid
                or identity.uid != record.uid
                or (identity.start_sec, identity.start_usec)
                    != record.start_time
                or identity.executable != record.executable.path
                or tuple(identity.argv) != record.argv):
            raise RouteUnqualified('process identity mismatch')
        parts = _endpoint_parts(endpoint)
        validate_launch_argv(
            record.argv, executable_path=record.executable.path,
            model_path=record.model.path,
            template_path=record.template.path,
            credential_file=self._credential_file,
            model_id=manifest_fields.get('model_id'),
            threads=launch.get('threads'),
            slots=launch.get('slots'),
            host=parts.hostname, port=parts.port)
        if (self._hash(record.executable) != record.executable.sha256
                or self._hash(record.model) != record.model.sha256
                or self._hash(record.template) != record.template.sha256):
            raise RouteUnqualified('file hash mismatch')
        if (record.model.sha256 != manifest_fields.get('model_sha256')
                or record.template.sha256 != launch.get(
                    'chat_template_sha256')):
            raise RouteUnqualified('manifest file binding mismatch')
        return True


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _endpoint_parts(endpoint):
    """Literal http loopback URL: scheme+host+explicit port+'/v1' only."""
    if type(endpoint) is not str:
        raise RouteUnqualified('endpoint invalid')
    try:
        parts = urlsplit(endpoint)
    except ValueError:
        raise RouteUnqualified('endpoint invalid') from None
    try:
        port = parts.port
    except ValueError:
        raise RouteUnqualified('endpoint invalid') from None
    if (parts.scheme != 'http'
            or parts.hostname not in ('127.0.0.1', '::1')
            or parts.username is not None or parts.password is not None
            or port is None or not 1 <= port <= 65535
            or parts.path != '/v1' or parts.query or parts.fragment
            or parts.geturl() != endpoint):
        raise RouteUnqualified('endpoint invalid')
    return parts


def make_models_probe(endpoint, supplier, expected_model,
                      timeout_seconds=5.0):
    """Factory -> () -> {'model': id[, 'build'][, 'commit']}.

    GET {endpoint}/models using the same supplier object as POSTs;
    supplier() returns a fresh {'Authorization': ...} dict used verbatim
    as the request headers — never logged, str()'d or reconstructed.
    Redirects and ambient proxies are disabled; status must be 200 with
    a bounded strict-JSON body whose served ids contain expected_model
    exactly. Vendor-listed extra ids are ignored."""
    _endpoint_parts(endpoint)
    if (not callable(supplier)
            or type(expected_model) is not str or not expected_model
            or type(timeout_seconds) is bool
            or type(timeout_seconds) not in (int, float)
            or not 0 < timeout_seconds <= 60):
        raise RouteUnqualified('probe arguments invalid')
    url = endpoint + '/models'
    opener = urllib.request.build_opener(
        _NoRedirect, urllib.request.ProxyHandler({}))

    def probe():
        try:
            headers = supplier()
            if (type(headers) is not dict
                    or set(headers) != {'Authorization'}
                    or type(headers['Authorization']) is not str
                    or not headers['Authorization']):
                raise ProbeFailed('credential unavailable')
            req = urllib.request.Request(url, headers=headers)
            with opener.open(req, timeout=timeout_seconds) as resp:
                if resp.status != 200:
                    raise ProbeFailed('probe status rejected')
                body = resp.read(MAX_PROBE_BYTES + 1)
        except ProbeFailed:
            raise
        except Exception:
            raise ProbeFailed('probe transport failed') from None
        if len(body) > MAX_PROBE_BYTES:
            raise ProbeFailed('probe body too large')
        try:
            doc = strict_json(body.decode('utf-8'))
        except Exception:
            raise ProbeFailed('probe document invalid') from None
        data = doc.get('data') if type(doc) is dict else None
        if (type(data) is not list
                or any(type(m) is not dict
                       or type(m.get('id')) is not str for m in data)):
            raise ProbeFailed('probe document invalid')
        if expected_model not in [m['id'] for m in data]:
            raise ProbeFailed('served model mismatch')
        observed = {'model': expected_model}
        for key in ('build', 'commit'):
            if type(doc.get(key)) is str:
                observed[key] = doc[key]
        return observed
    return probe
