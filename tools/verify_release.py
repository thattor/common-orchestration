"""Release asset verifier (#190 M5): sums, safe extract, import, binds.

verify_assets(directory) — bounded reads: manifest capped AND truncated
input refused, closed top-level keys with fixed prefix and typed hex
fields; archive sha256 must equal manifest.archive_sha256; SHA256SUMS
covers exactly the archive and manifest — duplicate names, non-hex
digests or a third entry refuse, never dict-overwrite. The caller must
still run it against the PUBLISHED assets (phase D); this tool proves
hash agreement, not provenance.

extract(archive, manifest, dest) — two passes: EVERY member's path,
kind (dirs only inside the declared set, regular files only, duplicate
names of either kind refused), inventory membership, size and sha256 is
validated while bytes are staged in a bounded dict; only on full
success are files written 0644 via O_EXCL|O_NOFOLLOW with realpath
containment inside a FRESH EMPTY owned canonical dest — no partial
output, never extractall. tarfile normalizes directory names: the root
member is exactly PREFIX; every other member lives under PREFIX + '/'.

import_check(root) — `python -I` with an explicit realpath sys.path
bootstrap inside the extracted tree, importing co_v4 plus every adapter
module and asserting each resolved __file__ stays under the extracted
root — cwd and PYTHONPATH cannot leak the repo copy.

Comparators normalize ONLY --chat-template-file/--api-key-file/--port
(the three task-owned argv values); semantic manifest/profile fields
must all be present AND equal — missing is not equal — and fresh
profile_digest/env_ref differ upstream; this tool never forces or
reuses an old binding. Stdlib only; no qualification claim lives here.
"""
import hashlib
import json
import os
import posixpath
import re
import stat
import subprocess
import sys
import tarfile
import unicodedata

from build_release import (MANIFEST_KEYS, NORMALIZED, PREFIX,
                           ReleaseError)

MAX_MANIFEST_BYTES = 1024 * 1024
MAX_SUMS_BYTES = 1024 * 1024
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024 * 1024
MANIFEST_NAME = 'RELEASE-MANIFEST.json'
SUMS_NAME = 'SHA256SUMS'
_HEX64 = re.compile(r'[0-9a-f]{64}\Z')
_SHA40 = re.compile(r'[0-9a-f]{40}\Z')
_SEMANTIC_MANIFEST = (
    ('provider_build',), ('provider_commit',), ('model_id',),
    ('model_sha256',), ('launch', 'chat_template_sha256'),
    ('launch', 'slots'), ('launch', 'threads'),
    ('qualification', 'sdk_version'), ('qualification', 'auth_results'),
    ('assertions',), ('multipart', 'kind'))
_SEMANTIC_PROFILE = ('protocol', 'index_mode', 'sequence_mode',
                     'inert_fields', 'model')


def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_rel(rel):
    """Syntactic gate: nonempty str, relative, no backslash, no NUL,
    no empty/'.'/'..' component, equal to its own posixpath.normpath —
    './x', 'a//x', 'x/' and 'a/./x' can never pass."""
    return (type(rel) is str and rel and not rel.startswith('/')
            and '\\' not in rel and '\x00' not in rel
            and all(seg not in ('', '.', '..')
                    for seg in rel.split('/'))
            and rel == posixpath.normpath(rel))


def _comp_key(component):
    """Unicode canonical caseless key: NFD(casefold(NFD(c)))."""
    return unicodedata.normalize(
        'NFD', unicodedata.normalize('NFD', component).casefold())


def _inventory(files):
    """Manifest files map validated BEFORE any filesystem write.

    After _canonical_rel: file keys (tuples of component keys) must be
    unique; no file key may equal any entry's proper-prefix key (a file
    'a.py' plus 'a.py/x.py' would write a file then a directory at one
    path — refused on every platform, not just casefold filesystems);
    and each prefix key may appear with exactly one original spelling
    ('A/x.py' + 'a/y.py', or composed vs decomposed dirs, yield trees
    that differ between case-sensitive and insensitive filesystems).
    Result is order-independent. Over-refusal is intentional and
    documented: e.g. casefold('ß') == 'ss' may fold more than APFS.
    Returns the files map on success, None on refusal — a refused
    manifest never leaves a partial fresh destination."""
    if type(files) is not dict or not files:
        return None
    file_keys, prefix_spellings = set(), {}
    for rel in files:
        if not _canonical_rel(rel):
            return None
        parts = rel.split('/')
        keys = tuple(_comp_key(c) for c in parts)
        if keys in file_keys:             # duplicate file key
            return None
        file_keys.add(keys)
        for i in range(1, len(parts)):
            prior = prefix_spellings.setdefault(
                keys[:i], tuple(parts[:i]))
            if prior != tuple(parts[:i]): # one spelling per dir
                return None
    if file_keys & set(prefix_spellings): # file-as-ancestor
        return None
    return files


def load_manifest(path):
    try:
        with open(path, 'rb') as handle:
            blob = handle.read(MAX_MANIFEST_BYTES + 1)
        if len(blob) > MAX_MANIFEST_BYTES:
            raise ReleaseError()
        doc = json.loads(blob.decode('utf-8'))
    except ReleaseError:
        raise
    except Exception:
        raise ReleaseError() from None
    try:
        ok = (type(doc) is dict and set(doc) == MANIFEST_KEYS
            and doc['prefix'] == PREFIX
            and _SHA40.fullmatch(doc['git_sha']) is not None
            and _HEX64.fullmatch(doc['archive_sha256']) is not None
            and _inventory(doc['files']) is not None
            and all(_HEX64.fullmatch(v) is not None
                    for v in doc['files'].values()))
    except (TypeError, AttributeError, KeyError):
        raise ReleaseError() from None
    if not ok:
        raise ReleaseError()
    return doc


def verify_assets(directory):
    """SHA256SUMS + manifest + archive cross-check; returns manifest."""
    manifest = load_manifest(os.path.join(directory, MANIFEST_NAME))
    archive_name = PREFIX + '.tar.gz'
    archive = os.path.join(directory, archive_name)
    try:
        if _sha256_file(archive) != manifest['archive_sha256']:
            raise ReleaseError()
        with open(os.path.join(directory, SUMS_NAME), 'rb') as handle:
            blob = handle.read(MAX_SUMS_BYTES + 1)
        if len(blob) > MAX_SUMS_BYTES:
            raise ReleaseError()
        lines = blob.decode('ascii').splitlines()
    except ReleaseError:
        raise
    except Exception:
        raise ReleaseError() from None
    sums = {}
    for line in lines:
        parts = line.split()
        if (len(parts) != 2 or _HEX64.fullmatch(parts[0]) is None
                or parts[1] in sums):
            raise ReleaseError()          # malformed or duplicate line
        sums[parts[1]] = parts[0]
    expected = {archive_name: manifest['archive_sha256'],
                MANIFEST_NAME: _sha256_file(
                    os.path.join(directory, MANIFEST_NAME))}
    if sums != expected:
        raise ReleaseError()
    return manifest


def extract(archive_path, manifest, dest):
    """Validate the ENTIRE archive before writing anything.

    The manifest files map must satisfy the same canonical /
    key-unique / one-spelling contract as load_manifest, refused
    pre-write; after validation ordinary I/O failure (disk full) may
    still leave a partial tree — no rollback is promised. Two passes:
    every member's path, kind, inventory membership,
    duplicate status (files AND directories), size and sha256 is checked
    while bytes are staged in a bounded dict (<= MAX_TOTAL_BYTES); only
    on full success are files written 0644 via O_EXCL|O_NOFOLLOW into
    the fresh empty owned canonical dest — a malicious archive never
    leaves partial output. tarfile normalizes directory names: the root
    member is exactly PREFIX (no slash); every other member must live
    under PREFIX + '/'.
    """
    try:
        real_dest = os.path.realpath(dest)
        st = os.lstat(dest)
    except OSError:
        raise ReleaseError() from None
    if (not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid()
            or real_dest != os.path.abspath(dest)
            or os.listdir(dest)):
        raise ReleaseError()              # fresh/empty/owned/real only
    try:
        files = manifest['files']
    except (TypeError, KeyError):
        raise ReleaseError() from None
    if _inventory(files) is None:         # same contract, pre-write
        raise ReleaseError()
    prefix = PREFIX + '/'
    expected = set(files)
    allowed_dirs = {PREFIX}
    for rel in expected:
        parts = rel.split('/')
        for i in range(1, len(parts)):
            allowed_dirs.add(prefix + '/'.join(parts[:i]))
    blobs, seen_dirs, total = {}, set(), 0
    try:
        tar = tarfile.open(archive_path, mode='r:gz')
    except (OSError, tarfile.TarError):
        raise ReleaseError() from None
    with tar:                             # pass 1: validate only
        for member in tar:
            name = member.name
            if member.isdir():
                if name not in allowed_dirs or name in seen_dirs:
                    raise ReleaseError()
                seen_dirs.add(name)
                continue
            if (name == PREFIX or not name.startswith(prefix)
                    or '..' in name.split('/')):
                raise ReleaseError()
            rel = name[len(prefix):]
            if (not member.isreg() or rel not in expected
                    or rel in blobs
                    or not 0 < member.size <= MAX_FILE_BYTES
                    or (total := total + member.size) > MAX_TOTAL_BYTES):
                raise ReleaseError()
            blob = tar.extractfile(member).read(MAX_FILE_BYTES + 1)
            if (len(blob) != member.size
                    or hashlib.sha256(blob).hexdigest()
                    != manifest['files'][rel]):
                raise ReleaseError()
            blobs[rel] = blob
    if set(blobs) != expected:
        raise ReleaseError()
    for rel in sorted(blobs):             # pass 2: write after success
        target = os.path.join(dest, *rel.split('/'))
        parent = os.path.dirname(target)
        os.makedirs(parent, exist_ok=True)
        # No component may resolve outside the fresh owned dest.
        if not (os.path.realpath(parent) == real_dest
                or os.path.realpath(parent).startswith(
                    real_dest + os.sep)):
            raise ReleaseError()
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | getattr(os, 'O_NOFOLLOW', 0), 0o644)
        with os.fdopen(fd, 'wb') as handle:
            handle.write(blobs[rel])
    return dest


_IMPORT_CODE = (
    "import sys, os, pkgutil, importlib\n"
    "root = os.path.realpath(sys.argv[1])\n"
    "sys.path.insert(0, root)\n"
    "import co_v4\n"
    "assert os.path.realpath(co_v4.__file__).startswith(\n"
    "    root + os.sep), co_v4.__file__\n"
    "import co_v4.adapters as _a\n"
    "for _m in pkgutil.iter_modules(_a.__path__):\n"
    "    _mod = importlib.import_module('co_v4.adapters.' + _m.name)\n"
    "    assert os.path.realpath(_mod.__file__).startswith(\n"
    "        root + os.sep), _mod.__file__\n")


def import_check(extract_root):
    """`python -I` realpath bootstrap; co_v4 + each adapter's __file__
    must resolve inside the extracted root."""
    root = os.path.realpath(extract_root)
    try:
        proc = subprocess.run([sys.executable, '-I', '-c', _IMPORT_CODE,
                               root], capture_output=True, timeout=120)
    except (OSError, subprocess.SubprocessError):
        raise ReleaseError() from None
    if proc.returncode != 0:
        raise ReleaseError()


def normalize_argv(argv):
    """Placeholder the three task-owned values; all else literal."""
    argv = tuple(argv)
    out, i = [], 0
    while i < len(argv):
        if argv[i] in NORMALIZED:
            if i + 1 >= len(argv):
                raise ReleaseError()
            out.extend((argv[i], '<task-owned>'))
            i += 2
        else:
            out.append(argv[i])
            i += 1
    return tuple(out)


def argv_semantics_equal(release_argv, fresh_argv):
    try:
        return normalize_argv(release_argv) == normalize_argv(fresh_argv)
    except (TypeError, ReleaseError):
        raise ReleaseError() from None


def _dig(doc, path):
    for key in path:
        doc = doc.get(key) if type(doc) is dict else None
    return doc


def manifest_semantics_equal(release_doc, fresh_doc):
    """Closed semantic field equality; missing fields fail closed, and
    argv compares only after the three-name normalization."""
    if type(release_doc) is not dict or type(fresh_doc) is not dict:
        return False
    for path in _SEMANTIC_MANIFEST:
        left, right = _dig(release_doc, path), _dig(fresh_doc, path)
        if left is None or right is None or left != right:
            return False
    rel_argv = _dig(release_doc, ('launch', 'argv'))
    new_argv = _dig(fresh_doc, ('launch', 'argv'))
    if type(rel_argv) is not list or type(new_argv) is not list:
        return False
    return argv_semantics_equal(rel_argv, new_argv)


def profile_semantics_equal(release_fields, fresh_fields):
    """All five semantic fields present and equal; missing is not equal.
    provider_manifest_sha256 is excluded; fresh digests differ upstream."""
    if type(release_fields) is not dict or type(fresh_fields) is not dict:
        return False
    return all(key in release_fields and key in fresh_fields
               and release_fields[key] == fresh_fields[key]
               for key in _SEMANTIC_PROFILE)
