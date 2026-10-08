"""Deterministic archive builder + Release manifest generator (#190 M5).

Archive: built ONLY from the exact tagged SHA's git tree — `git ls-tree
-r` for the inventory, `git show SHA:path` for every byte; the working
tree can never influence output. The checkout is the flattened
runtime_v4 root itself. Payload is exact: every co_v4/**/*.py
recursively plus VERSION, README.md, RUNBOOK.md, LICENSE.md, NOTICE,
examples/host.example.json and the two literal template
PROVENANCE/LICENSE files (no Jinja payload), plus the bundled
skills/co-task/SKILL.md file. Every other tracked blob at the root
must match the EXACT declared exclusions (.github/, tools/, probes/,
tests/, the six named top-level docs, run_ci_tests.py,
requirements-sdk-test.txt, model-lifecycle.example.json and
co_v4/t3code_rpc.mjs — the .mjs is an unqualified Native asset shipped
repo-side only, an unsupported path, not functionality). An unknown
path refuses the build: nothing silently ships, nothing silently drops.
One fixed top-level prefix, entries globally lexicographically sorted
(root first, directories and files interleaved), uid/gid 0, empty owner
names, 0644/0755, commit unix mtime, fixed USTAR, gzip mtime 0 no name.

Manifest: constants are literal-AST reads of the SHA's blobs — never
executed, never a dirty source dir. Every co_v4/adapters/*.py module is
an adapter and MUST carry literal ADAPTER + ADAPTER_VERSION at module
top level; a missing version on a real adapter fails the build until
the baseline constants land — helpers are never silently kept or
dropped. Each OpenAI adapter records exactly ONE native_tested entry
for its OWN protocol with that protocol's actual profile_digest and
environment_ref re-derived from the measured endpoint/auth_ref; shared
bindings refuse. Every payload sha256 is recomputed from the SHA's
blobs; the archive digest is read from the actual archive file.
Evidence is a closed JSON schema; type slips are fixed ReleaseError,
never TypeError. Stdlib only; no installer, daemon, product API, gate
or qualification claim — nothing reads the manifest and it qualifies
nothing.
"""
import ast
import gzip
import hashlib
import io
import json
import os
import re
import subprocess
import tarfile

PREFIX = 'common-orchestration-v0.4.5'
DOCS = ('VERSION', 'README.md', 'RUNBOOK.md', 'LICENSE.md', 'NOTICE',
        'examples/host.example.json',
        'examples/templates/PROVENANCE',
        'examples/templates/LICENSE-Apache-2.0',
        'skills/co-task/SKILL.md')
EXCLUDED_DIRS = frozenset({'.github', 'tools', 'probes', 'tests'})
EXCLUDED_FILES = frozenset({
    'ADAPTER-CONCURRENCY.md', 'CLAUDE-CONTROLLER-ACCEPTANCE.md',
    'CODEX-FAST-MODE.md', 'CODEX-PERMISSION-PROFILE.md',
    'DEVIN-WORKSPACE-BINDING.md', 'MODEL-LIFECYCLE.md',
    'run_ci_tests.py', 'requirements-sdk-test.txt',
    'model-lifecycle.example.json', 'co_v4/t3code_rpc.mjs'})
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_ARCHIVE_BYTES = 1024 * 1024 * 1024
_SHA40 = re.compile(r'[0-9a-f]{40}\Z')
_HEX64 = re.compile(r'[0-9a-f]{64}\Z')
_PYVER = re.compile(r'[0-9]+\.[0-9]+(\.[0-9]+)?\Z')
PROTOCOLS = frozenset({'responses', 'chat'})
READINESS = frozenset({'qualified', 'unqualified'})
# The only three task-owned argv values the fresh-reinstall comparator
# may normalize; executable, model and every other flag stay literal.
NORMALIZED = frozenset(
    {'--chat-template-file', '--api-key-file', '--port'})
# Each OpenAI adapter records exactly ONE entry for its OWN protocol;
# the pair collectively covers both — Responses never claims Chat.
ADAPTER_PROTOCOL = {'openai.responses': 'responses',
                    'openai.chat': 'chat'}
MANIFEST_KEYS = frozenset({'co_version', 'tag', 'git_sha', 'prefix',
    'controller', 'adapters', 'sdk', 'python_versions', 'darwin',
    'files', 'archive_sha256'})
EVIDENCE_KEYS = frozenset({'git_sha', 'tag', 'adapters', 'sdk',
    'python_versions', 'darwin'})
ADAPTER_KEYS = frozenset({'controller_compat', 'readiness',
    'native_tested', 'unsupported'})
# One measured qualification binding for ONE protocol: identical
# provider/model/template/manifest fields across a product's entries,
# distinct per-protocol profile_digest and the environment_ref re-derived
# from the measured endpoint/auth_ref — never a shared binding.
TESTED_KEYS = frozenset({'product', 'provider_build', 'provider_commit',
    'model_id', 'model_sha256', 'chat_template_sha256',
    'provider_manifest_sha256', 'protocols', 'profile_digest',
    'endpoint', 'auth_ref', 'environment_ref'})
ENV_PREFIX = 'env:sha256:'
ENV_DOMAIN = b'co.env/1\n'


class ReleaseError(ValueError):
    """Fixed-code release-tool refusal; never raw exception text."""
    code = 'release_failed'

    def __init__(self, code='release_failed'):
        self.code = code
        super().__init__(code)


def _git(repo, *args):
    try:
        return subprocess.run(['git', '-C', repo] + list(args),
            check=True, capture_output=True, timeout=120).stdout
    except (OSError, subprocess.SubprocessError):
        raise ReleaseError() from None


def inventory(repo, sha):
    """(payload tuple sorted, commit unix mtime) at SHA; exact set rules."""
    if (type(sha) is not str or _SHA40.fullmatch(sha) is None
            or type(repo) is not str or not os.path.isdir(repo)):
        raise ReleaseError()
    try:
        listing = _git(repo, 'ls-tree', '-r', sha).decode('utf-8')
        mtime = int(_git(repo, 'show', '-s', '--format=%ct', sha).strip())
    except (ValueError, UnicodeDecodeError):
        raise ReleaseError() from None
    seen, payload = set(), []
    for line in listing.splitlines():
        try:
            meta, path = line.split('\t', 1)
            mode, kind, _blob = meta.split(' ')
        except ValueError:
            raise ReleaseError() from None
        rel = path
        head = rel.split('/', 1)[0]
        if (head != rel and head in EXCLUDED_DIRS) \
                or rel in EXCLUDED_FILES:
            continue
        if (kind != 'blob' or mode not in ('100644', '100755')
                or rel in seen or '..' in rel.split('/')):
            raise ReleaseError()
        seen.add(rel)
        if rel in DOCS or (rel.startswith('co_v4/')
                           and rel.endswith('.py')):
            payload.append(rel)
        else:
            raise ReleaseError()              # unknown entry: refuse
    if (any(doc not in seen for doc in DOCS)
            or not any(p.startswith('co_v4/') for p in payload)):
        raise ReleaseError()                  # missing required payload
    return tuple(sorted(payload)), mtime


def _read(repo, sha, rel):
    blob = _git(repo, 'show', sha + ':' + rel)
    if not blob or len(blob) > MAX_FILE_BYTES:
        raise ReleaseError()
    return blob


def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def _archive_bytes(repo, sha):
    """Canonical archive bytes for SHA — the ONE deterministic builder
    shared by build() and generate_manifest(); working tree never read.
    Returns (gzip bytes, {rel: blob}) sourced only from git blobs."""
    files, mtime = inventory(repo, sha)
    contents = {rel: _read(repo, sha, rel) for rel in files}
    dirs = set()
    for rel in files:
        parts = rel.split('/')
        for i in range(1, len(parts)):
            dirs.add('/'.join(parts[:i]))
    rest = [(name, None, 0o755) for name in dirs]
    rest += [(rel, contents[rel], 0o644) for rel in files]
    # Globally lexicographically sorted; the bare root dir sorts first.
    entries = [(PREFIX, None, 0o755)] + [
        (PREFIX + '/' + name, blob, mode)
        for name, blob, mode in sorted(rest, key=lambda e: e[0])]
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode='w',
                      format=tarfile.USTAR_FORMAT) as tar:
        for name, blob, mode in entries:
            info = tarfile.TarInfo(name)
            info.uid = info.gid = 0
            info.uname = info.gname = ''
            info.mtime, info.mode = mtime, mode
            if blob is None:
                info.type = tarfile.DIRTYPE
                tar.addfile(info)
            else:
                info.type = tarfile.REGTYPE
                info.size = len(blob)
                tar.addfile(info, io.BytesIO(blob))
    out = io.BytesIO()
    with gzip.GzipFile(filename='', mode='wb', fileobj=out,
                       mtime=0) as gz:
        gz.write(raw.getvalue())
    return out.getvalue(), contents


def build(repo, sha, out_path):
    """Write the deterministic archive; return
    {'archive_sha256', 'prefix', 'files': {rel: sha256}} measured here."""
    blob, contents = _archive_bytes(repo, sha)
    if len(blob) > MAX_ARCHIVE_BYTES:
        raise ReleaseError()
    with open(out_path, 'wb') as handle:
        handle.write(blob)
    return {'archive_sha256': _sha256_file(out_path), 'prefix': PREFIX,
            'files': {rel: hashlib.sha256(data).hexdigest()
                      for rel, data in contents.items()}}


def _assigns(repo, sha, rel):
    """{name: literal or ('ref', name)} of MODULE TOP-LEVEL assignments
    only in one SHA blob — never executed, never nested scopes."""
    try:
        tree = ast.parse(_read(repo, sha, rel).decode('utf-8'))
    except (SyntaxError, ValueError):
        raise ReleaseError() from None
    out = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    if isinstance(node.value, ast.Constant):
                        out[target.id] = node.value.value
                    elif isinstance(node.value, ast.Name):
                        out[target.id] = ('ref', node.value.id)
    return out


def _const(assigns, name):
    """Resolve a literal through name-alias chains; cycles fail closed."""
    value, seen = assigns.get(name), {name}
    while type(value) is tuple and value[0] == 'ref':
        if value[1] in seen:
            return None
        seen.add(value[1])
        value = assigns.get(value[1])
    return value if not (type(value) is tuple) else None


def _adapters(repo, sha, payload):
    """{adapter_id: ADAPTER_VERSION} for every adapter module at SHA.

    Every co_v4/adapters/*.py is an adapter: a missing or non-literal
    ADAPTER or ADAPTER_VERSION FAILS — the baseline constants are
    required, helpers are never silently kept or silently dropped.
    """
    result = {}
    for rel in payload:
        if (not rel.startswith('co_v4/adapters/')
                or not rel.endswith('.py')
                or rel.endswith('/__init__.py')):
            continue
        assigns = _assigns(repo, sha, rel)
        adapter_id, version = (_const(assigns, 'ADAPTER'),
                               _const(assigns, 'ADAPTER_VERSION'))
        identity = assigns.get('ADAPTER_ID')
        if (type(adapter_id) is not str or not adapter_id
                or type(version) is not str or not 0 < len(version) <= 64
                or adapter_id in result
                or (identity is not None and (
                    _const(assigns, 'ADAPTER_ID') is None
                    or _const(assigns, 'ADAPTER_ID') != adapter_id))):
            raise ReleaseError()
        result[adapter_id] = version
    if not result:
        raise ReleaseError()
    return result


def _env_ref(value):
    return (type(value) is str and value.startswith(ENV_PREFIX)
            and _HEX64.fullmatch(value[len(ENV_PREFIX):]) is not None)


def _derive_env(endpoint, auth_ref, profile_digest):
    """Exact protocol_profile.environment_ref algorithm, re-derived —
    never trusted from input: env:sha256 of ENV_DOMAIN + canonical JSON."""
    body = json.dumps({'endpoint': endpoint, 'auth_ref': auth_ref,
        'profile_digest': profile_digest}, sort_keys=True,
        ensure_ascii=False, allow_nan=False,
        separators=(',', ':')).encode('utf-8')
    return ENV_PREFIX + hashlib.sha256(ENV_DOMAIN + body).hexdigest()


def _tested_entry(value):
    """Closed typed check of ONE measured per-protocol binding.

    endpoint/auth_ref are nonsecret measured inputs used to re-derive
    environment_ref; a supplied ref that does not match the derivation
    or is shared across protocols is refused by the caller loop.
    """
    try:
        return (type(value) is dict and set(value) == TESTED_KEYS
            and type(value['product']) is str
            and 0 < len(value['product']) <= 128
            and type(value['provider_build']) is str
            and 0 < len(value['provider_build']) <= 128
            and _SHA40.fullmatch(value['provider_commit']) is not None
            and type(value['model_id']) is str
            and 0 < len(value['model_id']) <= 1024
            and _HEX64.fullmatch(value['model_sha256']) is not None
            and _HEX64.fullmatch(
                value['chat_template_sha256']) is not None
            and _HEX64.fullmatch(
                value['provider_manifest_sha256']) is not None
            and type(value['protocols']) is list
            and value['protocols']
            and set(value['protocols']) <= PROTOCOLS
            and len(set(value['protocols']))
                == len(value['protocols'])
            and _HEX64.fullmatch(value['profile_digest']) is not None
            and type(value['endpoint']) is str
            and 0 < len(value['endpoint']) <= 1024
            and type(value['auth_ref']) is str
            and 0 < len(value['auth_ref']) <= 128
            and ' ' not in value['auth_ref']
            and _env_ref(value['environment_ref'])
            and value['environment_ref'] == _derive_env(
                value['endpoint'], value['auth_ref'],
                value['profile_digest']))
    except (TypeError, AttributeError, KeyError):
        return False


def _evidence(doc):
    """Closed measured-evidence validation; any type slip refuses.

    Within each adapter the same protocol may not appear twice; across
    the whole document one environment_ref may not cover two different
    protocols — no shared binding can pretend identical profile digests.
    Each OpenAI adapter carries exactly one entry for its own protocol.
    """
    try:
        if not (type(doc) is dict and set(doc) == EVIDENCE_KEYS
            and type(doc['git_sha']) is str
            and _SHA40.fullmatch(doc['git_sha']) is not None
            and type(doc['tag']) is str and 0 < len(doc['tag']) <= 128
            and type(doc['sdk']) is dict and 'openai' in doc['sdk']
            and all(type(k) is str and type(v) is str
                    and 0 < len(v) <= 128 for k, v in doc['sdk'].items())
            and type(doc['python_versions']) is list
            and 0 < len(doc['python_versions']) <= 16
            and all(type(v) is str and _PYVER.fullmatch(v) is not None
                    for v in doc['python_versions'])
            and type(doc['darwin']) is dict
            and set(doc['darwin']) == {'version', 'arch'}
            and all(type(doc['darwin'][k]) is str
                    and 0 < len(doc['darwin'][k]) <= 128
                    for k in ('version', 'arch'))
            and type(doc['adapters']) is dict and doc['adapters']):
            raise ReleaseError()
        env_protocols = {}
        for key, value in doc['adapters'].items():
            if (type(key) is not str or not key
                    or type(value) is not dict
                    or not set(value) <= ADAPTER_KEYS):
                raise ReleaseError()
            readiness, tested = (value.get('readiness'),
                                 value.get('native_tested'))
            compat, unsupported = (value.get('controller_compat'),
                                   value.get('unsupported'))
            if (readiness not in READINESS or type(tested) is not list
                    or (compat is not None and (type(compat) is not str
                        or not 0 < len(compat) <= 64))
                    or (unsupported is not None and (
                        type(unsupported) is not list
                        or any(type(u) is not dict
                               or set(u) != {'path', 'ref'}
                               or not all(type(u[k]) is str and u[k]
                                          for k in ('path', 'ref'))
                               for u in unsupported)))):
                raise ReleaseError()
            if (readiness == 'unqualified' and tested != []) \
                    or (readiness == 'qualified' and not tested):
                raise ReleaseError()
            # Qualification binds only the two measured OpenAI adapters;
            # a caller-qualified copied Native is fabricated evidence.
            if readiness == 'qualified' and key not in ADAPTER_PROTOCOL:
                raise ReleaseError()
            seen_here = set()
            for entry in tested:
                if not _tested_entry(entry):
                    raise ReleaseError()
                for protocol in entry['protocols']:
                    if protocol in seen_here:
                        raise ReleaseError()      # dup protocol/adapter
                    seen_here.add(protocol)
                    if (env_protocols.get(entry['environment_ref'])
                            not in (None, protocol)):
                        raise ReleaseError()      # shared binding refuse
                    env_protocols[entry['environment_ref']] = protocol
            # Opus binding: each OpenAI adapter has exactly one entry
            # listing only its own protocol; no cross-listing.
            own = ADAPTER_PROTOCOL.get(key)
            if own is not None and (
                    readiness != 'qualified' or len(tested) != 1
                    or tested[0]['protocols'] != [own]):
                raise ReleaseError()
    except (TypeError, AttributeError, KeyError, IndexError):
        raise ReleaseError() from None
    return doc


def generate_manifest(repo, sha, evidence, archive_path):
    """Manifest dict bound to the exact SHA AND the exact archive bytes.

    The canonical archive is rebuilt from the SHA's blobs via the same
    deterministic builder build() uses; archive_path must hash to those
    exact bytes — an altered tarball, a foreign tarball, or an archive
    of any other source is refused BEFORE the manifest returns. Nothing
    supplied can pretend verification: payload hashes are recomputed
    from the SHA's blobs and evidence git_sha/tag must match.
    """
    doc = _evidence(evidence)
    canonical, contents = _archive_bytes(repo, sha)
    try:
        co_version = contents['VERSION'].decode('ascii').strip()
        state = _assigns(repo, sha, 'co_v4/state.py')
        contract, controller_version = (_const(state, 'CONTRACT_MARKER'),
                                        _const(state, 'CONTROLLER_VERSION'))
        st = os.stat(archive_path)
        if (not os.path.isfile(archive_path)
                or not 0 < st.st_size <= MAX_ARCHIVE_BYTES):
            raise ReleaseError()
        archive_sha256 = _sha256_file(archive_path)
    except ReleaseError:
        raise
    except (OSError, ValueError, KeyError):
        raise ReleaseError() from None
    # Binding: the supplied archive must be byte-exact the canonical
    # build for THIS SHA — wrong source or one flipped bit refuses.
    if archive_sha256 != hashlib.sha256(canonical).hexdigest():
        raise ReleaseError()
    if (not (type(co_version) is str and 0 < len(co_version) <= 64)
            or type(contract) is not str
            or type(controller_version) is not str
            or doc['git_sha'] != sha
            or doc['tag'] != 'common-orchestration-v' + co_version):
        raise ReleaseError()
    shipped = _adapters(repo, sha, tuple(sorted(contents)))
    if set(doc['adapters']) != set(shipped):
        raise ReleaseError()
    adapters = {}
    for adapter_id, version in shipped.items():
        entry = doc['adapters'][adapter_id]
        record = {'version': version, 'readiness': entry['readiness'],
                  'native_tested': entry['native_tested']}
        if entry.get('controller_compat') is not None:
            record['controller_compat'] = entry['controller_compat']
        if 'unsupported' in entry:
            record['unsupported'] = entry['unsupported']
        adapters[adapter_id] = record
    files = {rel: hashlib.sha256(data).hexdigest()
             for rel, data in contents.items()}
    return {'co_version': co_version, 'tag': doc['tag'],
            'git_sha': sha, 'prefix': PREFIX,
            'controller': {'version': controller_version,
                           'contract': contract},
            'adapters': adapters, 'sdk': doc['sdk'],
            'python_versions': doc['python_versions'],
            'darwin': doc['darwin'],
            'files': dict(sorted(files.items())),
            'archive_sha256': archive_sha256}


def write_manifest(manifest, path):
    with open(path, 'wb') as handle:
        handle.write(json.dumps(manifest, sort_keys=True, indent=2,
            ensure_ascii=False).encode('utf-8') + b'\n')
