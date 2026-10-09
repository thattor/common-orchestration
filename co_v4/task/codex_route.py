'''Read-only validation for saved Codex text-route measurements.

The helpers in this module verify a previously emitted binding. They do not
spawn Codex, establish Native qualification, consult ledgers, or provide a
fallback for fresh Host checks.
'''
import hashlib
import os
import pwd
import re
import stat
from pathlib import Path, PurePosixPath

from ..openai_transport import strict_json
from .common import TaskError, canonical, digest


ROUTE = 'codex'
ROUTE_VERSION = 'codex-cli 0.160.1'
CONFIG_SCHEMA = 'co.codex-text-binding/1'

_ARGV_TEMPLATE = (
    'codex',
    'app-server',
    '--stdio',
    'co-owned-text/1',
    'normal',
    'named-readonly',
    'never',
    'strict-text',
)
ARGV_TEMPLATE = list(_ARGV_TEMPLATE)

SOURCE_FILES = (
    'codex_engine.py',
    'codex_host.py',
    'adapters/codex.py',
    'codex_permissions.py',
    'codex_model_selection.py',
    'codex_service_tier.py',
    'codex_profile_transport.py',
    'codex_errors.py',
    'codex_text_transport.py',
    'codex_text_validation.py',
    'codex_rpc_tracker.py',
    'codex_text_observer.py',
    'codex_inventory.py',
    'delegation.py',
    'contracts.py',
    'task/codex_route.py',
    'task/common.py',
    'task/admission.py',
    'task/infer.py',
    'task/child_status.py',
    'codex_rpc_sequence.py',
    'codex_item_ledger.py',
    'openai_transport.py',
    'adapter_capacity.py',
    'state.py',
)

_ENTRY_ALL_KEYS = frozenset({
    'route',
    'version',
    'model',
    'effort',
    'binary',
    'config',
    'native_cwd',
    'available',
    'measured_at',
    'argv_template',
    'argv_digest',
    'config_digest',
    'probes',
    'known_context',
    'measurement_digest',
})
_ENTRY_COMPUTE_KEYS = _ENTRY_ALL_KEYS - {'measurement_digest'}
_PROBE_KEYS = frozenset({
    'kind',
    'success',
    'input_digest',
    'output_digest',
    'nonce_digest',
})
_CONFIG_KEYS = frozenset({
    'schema',
    'binary',
    'binary_digest',
    'python',
    'python_digest',
    'measurement_home',
    'credential_files',
    'disabled_mcp_servers',
    'cleared_environment_keys',
    'sources',
})
_CREDENTIAL_KEYS = frozenset({'path', 'dev', 'ino', 'uid', 'mode'})

_DIGEST_RE = re.compile(r'sha256:[0-9a-f]{64}')
_EFFORT_RE = re.compile(r'[a-z][a-z0-9_]{0,63}')
_MCP_NAME_RE = re.compile(r'[A-Za-z0-9_-]{1,128}')
_ENV_KEY_RE = re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,127}')

_ARGV_DIGEST = digest(canonical(list(_ARGV_TEMPLATE)).encode('utf-8'))
_MAX_PATH = 4096
_MAX_CONFIG_BYTES = 262144
_MAX_CODE_BYTES = 512 * 1024 * 1024
_MAX_SOURCE_BYTES = 1024 * 1024
_READ_CHUNK = 65536
_RESERVED_VALUES = frozenset({'auto', 'default'})


def _fail():
    raise TaskError('route_unmeasured') from None


def _package_root():
    return Path(__file__).resolve().parents[1]


def _require_digest(value):
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        _fail()


def _lexical_path(value):
    if (not isinstance(value, str) or not value or len(value) > _MAX_PATH
            or '\0' in value):
        _fail()
    if not os.path.isabs(value) or value.startswith('//'):
        _fail()
    parts = PurePosixPath(value).parts
    if (any(part in ('.', '..') for part in parts)
            or os.path.normpath(value) != value):
        _fail()
    return value


def _canonical_path(value):
    value = _lexical_path(value)
    try:
        resolved = os.path.realpath(value)
    except Exception:
        _fail()
    if resolved != value:
        _fail()
    return value


def _within(path, root):
    try:
        return os.path.commonpath((path, root)) == root
    except Exception:
        _fail()


def _validate_model(value):
    if (not isinstance(value, str) or not value.startswith('gpt-')
            or len(value) <= 4 or len(value) > 128
            or value.lower() in _RESERVED_VALUES):
        _fail()
    try:
        value.encode('ascii')
    except UnicodeEncodeError:
        _fail()
    if any(ord(char) < 0x21 or ord(char) > 0x7e or char == '/'
           for char in value):
        _fail()


def _validate_effort(value):
    if (not isinstance(value, str) or not _EFFORT_RE.fullmatch(value)
            or value in _RESERVED_VALUES):
        _fail()


def _validate_known_context(value):
    if not isinstance(value, list) or len(value) > 128:
        _fail()
    for item in value:
        if not isinstance(item, str):
            _fail()
        try:
            encoded = item.encode('utf-8')
        except UnicodeEncodeError:
            _fail()
        if len(encoded) > 4096:
            _fail()


def _validate_probes(value, *, complete):
    if (not isinstance(value, list) or len(value) > 2
            or (complete and len(value) != 2)):
        _fail()
    for index, probe in enumerate(value):
        expected_kind = ('text', 'json')[index]
        if not isinstance(probe, dict) or set(probe) != _PROBE_KEYS:
            _fail()
        if probe['kind'] != expected_kind or probe['success'] is not True:
            _fail()
        _require_digest(probe['input_digest'])
        _require_digest(probe['output_digest'])
        _require_digest(probe['nonce_digest'])


def _validate_entry_shape(entry, require_measurement, canonical_paths):
    if not isinstance(entry, dict):
        _fail()
    expected = _ENTRY_ALL_KEYS
    if not require_measurement and 'measurement_digest' not in entry:
        expected = _ENTRY_COMPUTE_KEYS
    if set(entry) != expected:
        _fail()

    if entry['route'] != ROUTE or entry['version'] != ROUTE_VERSION:
        _fail()
    _validate_model(entry['model'])
    _validate_effort(entry['effort'])

    check_path = _canonical_path if canonical_paths else _lexical_path
    check_path(entry['binary'])
    check_path(entry['config'])
    check_path(entry['native_cwd'])

    if type(entry['available']) is not bool:
        _fail()
    if type(entry['measured_at']) is not int or entry['measured_at'] < 0:
        _fail()
    if (not isinstance(entry['argv_template'], list)
            or entry['argv_template'] != list(_ARGV_TEMPLATE)):
        _fail()
    if entry['argv_digest'] != _ARGV_DIGEST:
        _fail()
    _require_digest(entry['config_digest'])
    _validate_probes(entry['probes'], complete=entry['available'])
    _validate_known_context(entry['known_context'])
    if 'measurement_digest' in entry:
        _require_digest(entry['measurement_digest'])


def measurement_digest(entry):
    '''Return the canonical measurement digest for a closed entry shape.'''
    try:
        _validate_entry_shape(entry, require_measurement=False,
                              canonical_paths=False)
        body = {key: value for key, value in entry.items()
                if key != 'measurement_digest'}
        return digest(canonical(body).encode('utf-8'))
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        _fail()


def _lstat(path):
    try:
        return os.lstat(path)
    except Exception:
        _fail()


def _require_private_dir(path):
    path = _canonical_path(path)
    st = _lstat(path)
    if (stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode)
            or st.st_uid != os.geteuid()
            or stat.S_IMODE(st.st_mode) != 0o700):
        _fail()
    return path


def _require_config_location(config_path, native_cwd):
    parent = _canonical_path(os.path.dirname(config_path))
    st = _lstat(parent)
    if (stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode)
            or st.st_uid != os.geteuid()
            or stat.S_IMODE(st.st_mode) != 0o700):
        _fail()
    if (_within(parent, native_cwd) or _within(native_cwd, parent)
            or _within(config_path, native_cwd)):
        _fail()


def _check_owned_config_stat(st):
    if (st.st_uid != os.geteuid() or st.st_nlink != 1
            or stat.S_IMODE(st.st_mode) != 0o600):
        _fail()


def _open_readonly(path):
    try:
        flags = (os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                 | os.O_CLOEXEC)
        return os.open(path, flags)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        _fail()


def _close_quietly(fd):
    try:
        os.close(fd)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        pass


def _consume_fd(fd, max_size, check=None, collect=False):
    st = os.fstat(fd)
    if (not stat.S_ISREG(st.st_mode) or st.st_size < 0
            or st.st_size > max_size):
        _fail()
    if check is not None:
        check(st)

    hasher = hashlib.sha256()
    total = 0
    parts = [] if collect else None
    while total < st.st_size:
        try:
            chunk = os.read(fd, min(_READ_CHUNK, st.st_size - total))
        except OSError:
            _fail()
        if not chunk or len(chunk) > st.st_size - total:
            _fail()
        total += len(chunk)
        hasher.update(chunk)
        if collect:
            parts.append(chunk)
    try:
        if os.read(fd, 1):
            _fail()
    except OSError:
        _fail()

    payload = b''.join(parts) if collect else None
    return st, payload, 'sha256:' + hasher.hexdigest()


def _read_path(path, max_size, check=None, collect=False):
    fd = _open_readonly(path)
    try:
        result = _consume_fd(fd, max_size, check=check, collect=collect)
    except (KeyboardInterrupt, SystemExit):
        _close_quietly(fd)
        raise
    except Exception:
        _close_quietly(fd)
        _fail()
    try:
        os.close(fd)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        _fail()
    return result


def _hash_path(path, max_size, executable=False, forbidden=frozenset()):
    st = _lstat(path)
    if (not stat.S_ISREG(st.st_mode) or st.st_size < 0
            or st.st_size > max_size):
        _fail()
    identity = (st.st_dev, st.st_ino)
    if identity in forbidden:
        _fail()
    if executable and not (st.st_mode & 0o111):
        _fail()

    def check(fstat):
        if ((fstat.st_dev, fstat.st_ino) != identity
                or identity in forbidden):
            _fail()
        if executable and not (fstat.st_mode & 0o111):
            _fail()

    return _read_path(path, max_size, check=check)[2]


def _current_auth_identity(home):
    try:
        st = os.stat(os.path.join(home, '.codex', 'auth.json'))
    except FileNotFoundError:
        return None
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        _fail()
    return (st.st_dev, st.st_ino)


def _check_private_config_stat(st, home, before):
    _check_owned_config_stat(st)
    after = _current_auth_identity(home)
    identity = (st.st_dev, st.st_ino)
    if before is not None and identity == before or (after is not None and identity == after):
        _fail()


def _read_private_config(path, home):
    before = _current_auth_identity(home)
    try:
        st = os.stat(path, follow_symlinks=False)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        _fail()
    if not stat.S_ISREG(st.st_mode) or (before is not None and (st.st_dev, st.st_ino) == before):
        _fail()
    return _read_path(path, _MAX_CONFIG_BYTES, check=lambda st: _check_private_config_stat(st, home, before), collect=True)


def _expected_home():
    try:
        home = pwd.getpwuid(os.geteuid()).pw_dir
    except Exception:
        _fail()
    return _canonical_path(home)


def _validate_credentials(items, native_cwd):
    if not isinstance(items, list) or not items or len(items) > 8:
        _fail()
    seen_paths = set()
    identities = set()
    euid = os.geteuid()
    for item in items:
        if not isinstance(item, dict) or set(item) != _CREDENTIAL_KEYS:
            _fail()
        path = _canonical_path(item['path'])
        for key in ('dev', 'ino', 'uid', 'mode'):
            if type(item[key]) is not int or item[key] < 0:
                _fail()
        if (item['uid'] != euid or not stat.S_ISREG(item['mode'])
                or stat.S_IMODE(item['mode']) != 0o600):
            _fail()
        if _within(path, native_cwd):
            _fail()

        parent = _canonical_path(os.path.dirname(path))
        pst = _lstat(parent)
        if stat.S_ISLNK(pst.st_mode) or not stat.S_ISDIR(pst.st_mode):
            _fail()

        st = _lstat(path)
        identity = (st.st_dev, st.st_ino)
        if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1
                or st.st_uid != euid or st.st_dev != item['dev']
                or st.st_ino != item['ino'] or st.st_uid != item['uid']
                or st.st_mode != item['mode']):
            _fail()
        if path in seen_paths or identity in identities:
            _fail()
        seen_paths.add(path)
        identities.add(identity)
    return frozenset(identities)


def _validate_sorted_list(value, limit, pattern):
    if not isinstance(value, list) or len(value) > limit:
        _fail()
    for item in value:
        if not isinstance(item, str) or not pattern.fullmatch(item):
            _fail()
    if value != sorted(value) or len(set(value)) != len(value):
        _fail()


def _validate_sources(value, forbidden):
    if not isinstance(value, dict) or set(value) != set(SOURCE_FILES):
        _fail()
    root = _canonical_path(os.fspath(_package_root()))
    for relative in SOURCE_FILES:
        pure = PurePosixPath(relative)
        if (not relative or pure.is_absolute()
                or pure.as_posix() != relative
                or any(part in ('', '.', '..') for part in pure.parts)):
            _fail()
        path = _canonical_path(os.path.join(root, *pure.parts))
        if not _within(path, root):
            _fail()
        _require_digest(value[relative])
        if _hash_path(path, _MAX_SOURCE_BYTES,
                      forbidden=forbidden) != value[relative]:
            _fail()


def _validate_config_object(config, entry, native_cwd, config_identity):
    if not isinstance(config, dict) or set(config) != _CONFIG_KEYS:
        _fail()
    if config['schema'] != CONFIG_SCHEMA:
        _fail()

    forbidden = _validate_credentials(config['credential_files'], native_cwd)
    if config_identity in forbidden:
        _fail()

    binary = _canonical_path(config['binary'])
    python = _canonical_path(config['python'])
    if binary != entry['binary']:
        _fail()
    _require_digest(config['binary_digest'])
    _require_digest(config['python_digest'])

    home = _canonical_path(config['measurement_home'])
    expected_home = _expected_home()
    if (home != expected_home or os.environ.get('HOME') != expected_home
            or 'CODEX_HOME' in os.environ):
        _fail()
    auth = _canonical_path(os.path.join(home, '.codex', 'auth.json'))
    if auth not in {item['path'] for item in config['credential_files']}:
        _fail()

    _validate_sorted_list(config['disabled_mcp_servers'], 64, _MCP_NAME_RE)
    _validate_sorted_list(config['cleared_environment_keys'], 128,
                          _ENV_KEY_RE)
    _validate_sources(config['sources'], forbidden)

    if (_hash_path(binary, _MAX_CODE_BYTES, executable=True,
                   forbidden=forbidden) != config['binary_digest']):
        _fail()
    if (_hash_path(python, _MAX_CODE_BYTES, executable=True,
                   forbidden=forbidden) != config['python_digest']):
        _fail()


def read_config(entry):
    '''Verify and return a fresh dict from the entry\'s private metadata.'''
    try:
        _validate_entry_shape(entry, require_measurement=True,
                              canonical_paths=True)
        if entry['measurement_digest'] != measurement_digest(entry):
            _fail()
        native_cwd = _require_private_dir(entry['native_cwd'])
        config_path = entry['config']
        _require_config_location(config_path, native_cwd)
        home = _expected_home()
        if os.environ.get('HOME') != home or 'CODEX_HOME' in os.environ:
            _fail()
        if _within(config_path, _canonical_path(os.path.join(home, '.codex'))):
            _fail()

        st, raw, config_digest = _read_private_config(config_path, home)
        if config_digest != entry['config_digest']:
            _fail()
        try:
            text = raw.decode('utf-8', errors='strict')
        except UnicodeDecodeError:
            _fail()
        stripped = text.strip()
        if (text.startswith('\ufeff') or stripped.startswith('```')
                or stripped.endswith('```')):
            _fail()
        config = strict_json(text)
        if not isinstance(config, dict):
            _fail()
        _validate_config_object(config, entry, native_cwd,
                                (st.st_dev, st.st_ino))
        return dict(config)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        _fail()


def _validated_config(entry, model, cwd):
    try:
        _validate_entry_shape(entry, require_measurement=True,
                              canonical_paths=True)
        _validate_model(model)
        expected_cwd = _canonical_path(os.fspath(cwd))
        _require_private_dir(expected_cwd)
        if (entry['available'] is not True or entry['model'] != model
                or entry['native_cwd'] != expected_cwd):
            _fail()
        if entry['measurement_digest'] != measurement_digest(entry):
            _fail()
        return read_config(entry)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        _fail()

def validate_entry(entry, model, cwd):
    '''Validate a saved entry and return the identical object on success.'''
    try:
        _validated_config(entry, model, cwd)
        return entry
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        _fail()


def _capture_sources(forbidden):
    if (type(forbidden) is not frozenset
            or not 1 <= len(forbidden) <= 8):
        _fail()
    for identity in forbidden:
        if (type(identity) is not tuple or len(identity) != 2
                or any(type(part) is not int or part < 0
                       for part in identity)):
            _fail()

    root = _canonical_path(os.fspath(_package_root()))
    captured = {}
    for name in SOURCE_FILES:
        if not isinstance(name, str) or not name or chr(0) in name:
            _fail()
        try:
            rel = PurePosixPath(name)
        except Exception:
            _fail()
        if (rel.is_absolute() or not rel.parts or name != rel.as_posix()
                or any(part in ('', '.', '..') for part in rel.parts)):
            _fail()
        path = _canonical_path(os.path.join(root, rel.as_posix()))
        if not _within(path, root):
            _fail()
        captured[name] = _hash_path(
            path, _MAX_SOURCE_BYTES, forbidden=forbidden)
    return captured


def _capture_credentials(credential_files, cwd, home):
    try:
        if (type(credential_files) is not tuple or not credential_files
                or len(credential_files) > 8):
            _fail()
        for value in credential_files + (cwd, home):
            if not isinstance(value, (str, Path)):
                _fail()
        canonical_cwd = _canonical_path(os.fspath(cwd))
        canonical_home = _canonical_path(os.fspath(home))
        native_auth = _canonical_path(
            os.path.join(canonical_home, '.codex', 'auth.json'))
        paths = [_canonical_path(os.fspath(value))
                 for value in credential_files]
        if native_auth not in paths:
            _fail()
        records = []
        for path in paths:
            st = _lstat(path)
            records.append({'path': path, 'dev': st.st_dev, 'ino': st.st_ino,
                            'uid': st.st_uid, 'mode': st.st_mode})
        forbidden = _validate_credentials(list(records), canonical_cwd)
        return tuple(records), forbidden
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        _fail()


def capture_binding(binary, python, cwd, inventory, *, credential_files):
    try:
        if not all(isinstance(value, (str, Path))
                   for value in (binary, python, cwd)):
            _fail()
        canonical_binary = _canonical_path(os.fspath(binary))
        canonical_python = _canonical_path(os.fspath(python))
        home = _expected_home()
        if (os.environ.get('HOME') != home
                or 'CODEX_HOME' in os.environ):
            _fail()
        canonical_cwd = _require_private_dir(os.fspath(cwd))
        if (type(inventory) is not dict
                or set(inventory) != {'native_version',
                                      'disabled_mcp_servers',
                                      'cleared_environment_keys'}):
            _fail()
        if (type(inventory['native_version']) is not str
                or inventory['native_version'] != ROUTE_VERSION):
            _fail()
        servers = inventory['disabled_mcp_servers']
        env_keys = inventory['cleared_environment_keys']
        if (type(servers) is not tuple or len(servers) > 64
                or type(env_keys) is not tuple or len(env_keys) > 128
                or any(type(item) is not str
                       for item in servers + env_keys)):
            _fail()
        servers = list(servers)
        env_keys = list(env_keys)
        _validate_sorted_list(servers, 64, _MCP_NAME_RE)
        _validate_sorted_list(env_keys, 128, _ENV_KEY_RE)
        records, forbidden = _capture_credentials(
            credential_files, canonical_cwd, home)
        codex_dir = _canonical_path(os.path.join(home, '.codex'))
        credential_paths = {record['path'] for record in records}
        for path in (canonical_binary, canonical_python):
            if (path == codex_dir or _within(path, codex_dir)
                    or path in credential_paths):
                _fail()
        binary_digest = _hash_path(canonical_binary, _MAX_CODE_BYTES,
                                   executable=True, forbidden=forbidden)
        python_digest = _hash_path(canonical_python, _MAX_CODE_BYTES,
                                   executable=True, forbidden=forbidden)
        sources = _capture_sources(forbidden)
        return {
            'schema': CONFIG_SCHEMA,
            'binary': canonical_binary,
            'binary_digest': binary_digest,
            'python': canonical_python,
            'python_digest': python_digest,
            'measurement_home': home,
            'credential_files': [dict(record) for record in records],
            'disabled_mcp_servers': servers,
            'cleared_environment_keys': env_keys,
            'sources': dict(sources),
        }
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        _fail()


def _validate_protected_state(protected_state, cwd):
    try:
        if type(protected_state) is not tuple or not 1 <= len(protected_state) <= 8:
            _fail()
        if type(cwd) is not str:
            _fail()
        cwd = _require_private_dir(cwd)
        files = []
        for entry in protected_state:
            if not isinstance(entry, Path):
                _fail()
            value = os.fspath(entry)
            path = _canonical_path(value)
            st = _lstat(path)
            if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
                _fail()
            parent = _canonical_path(os.path.dirname(path))
            if _within(parent, cwd) or _within(cwd, parent):
                _fail()
            files.append(Path(path))
        from . import admission
        ledger = os.fspath(admission.canonical_ledger_path())
        ledger = _canonical_path(ledger)
        st = _lstat(ledger)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or (stat.S_IMODE(st.st_mode) != 384) or (st.st_nlink != 1):
            _fail()
        root = _canonical_path(os.path.dirname(ledger))
        st = _lstat(root)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or (stat.S_IMODE(st.st_mode) != 448):
            _fail()
        if Path(ledger) not in files:
            _fail()
        return tuple(files)
    except TaskError:
        raise
    except Exception:
        _fail()


__all__ = (
    'ARGV_TEMPLATE',
    'SOURCE_FILES',
    'capture_binding',
    'measurement_digest',
    'read_config',
    'validate_entry',
)
