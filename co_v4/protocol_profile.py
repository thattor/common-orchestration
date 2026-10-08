"""Host-owned provider qualification artifacts for OpenAI-compatible routes.

Three-layer binding per design/0.4/OPENAI-COMPATIBLE-EDGES.md (qualified
route profile ruling): an immutable provider manifest records the full
qualification evidence; a small route protocol profile hashes to
profile_digest; environment_ref derives from endpoint, auth_ref and
profile_digest and is never chosen. Each layer hashes only data below it,
so no identity covers itself. Constructing or comparing these objects is
never qualification: only verify_manifest() rehashes raw captures and
checks every mandatory assertion, and only its private result feeds
issue_profile(). Runtime observable-identity preflight, route exclusion
and the absent_single_part parser path are a separate integration (TODO);
nothing here qualifies a real provider on its own.
"""
from dataclasses import dataclass
import hashlib
import json
import re
from types import MappingProxyType

from .openai_transport import strict_json

MANIFEST_SCHEMA = 'co.provider-manifest/1'
PROFILE_SCHEMA = 'co.route-protocol/2'
ENV_PREFIX = 'env:sha256:'
PROFILE_DOMAIN = b'co.route-protocol/2\n'
ENV_DOMAIN = b'co.env/1\n'
PROTOCOLS = frozenset({'responses', 'chat'})
INDEX_MODES = frozenset({'present', 'absent_single_part'})
SEQUENCE_MODES = frozenset({'present', 'absent'})
# Mandatory capture assertions from the wire-qualification ruling.
ASSERTIONS = ('no_defaulted_indices', 'single_item_single_part',
              'no_mixed_presence', 'terminal_byte_agreement',
              'base_rules_unchanged')
AUTH_RESULTS = {'missing': 401, 'wrong': 401, 'valid': 200}
MAX_CAPTURE = 8 * 1024 * 1024
_HEX40 = re.compile('[0-9a-f]{40}\\Z')
_HEX64 = re.compile('[0-9a-f]{64}\\Z')
MANIFEST_KEYS = frozenset({'schema', 'provider_build', 'provider_commit',
    'model_sha256', 'model_id', 'launch', 'auth', 'qualification',
    'captures', 'assertions', 'multipart', 'manifest_sha256'})
LAUNCH_KEYS = frozenset({'argv', 'chat_template_sha256', 'slots', 'threads',
    'bind'})
CAPTURE_KEYS = frozenset({'protocol', 'path', 'sha256'})


class ProfileError(ValueError):
    """Failed qualification or identity check; fixed vocabulary only."""


def canonical(obj):
    """Canonical JSON bytes; the same convention as transport digests."""
    return json.dumps(obj, sort_keys=True, ensure_ascii=False,
        allow_nan=False, separators=(',', ':')).encode('utf-8')


def _text(value, limit=1024):
    return type(value) is str and 0 < len(value) <= limit


def _hex(value, rx=_HEX64):
    return type(value) is str and rx.fullmatch(value) is not None


def _ref(value):
    """A host credential reference name: printable nonspace, never a token."""
    return (_text(value, 128) and value.isprintable() and ' ' not in value)


def parse_manifest(text):
    """Strict JSON load plus structural validation; duplicate keys reject."""
    try:
        data = strict_json(text)
    except Exception:
        raise ProfileError('invalid manifest document') from None
    return load_manifest(data)


def load_manifest(data):
    """Closed-schema structural validation of a provider manifest dict.

    Structure and field values only: the manifest hash and capture bytes
    are verified by verify_manifest(), never by construction."""
    if type(data) is not dict or set(data) != MANIFEST_KEYS:
        raise ProfileError('manifest keys invalid')
    launch, auth, qual = data['launch'], data['auth'], data['qualification']
    captures, assertions = data['captures'], data['assertions']
    multipart = data['multipart']
    if (data['schema'] != MANIFEST_SCHEMA
            or not _text(data['provider_build'], 128)
            or not _hex(data['provider_commit'], _HEX40)
            or not _hex(data['model_sha256']) or not _text(data['model_id'])
            or not _hex(data['manifest_sha256'])):
        raise ProfileError('manifest fields invalid')
    if (type(launch) is not dict or set(launch) != LAUNCH_KEYS
            or type(launch['argv']) is not list
            or not 1 <= len(launch['argv']) <= 64
            or any(type(a) is not str or not 0 < len(a) <= 1024
                   or not a.isprintable() for a in launch['argv'])
            or not _hex(launch['chat_template_sha256'])
            or type(launch['slots']) is not int or launch['slots'] < 1
            or type(launch['threads']) is not int or launch['threads'] < 1
            or not _text(launch['bind'], 256)):
        raise ProfileError('manifest launch invalid')
    # Auth is mode plus a credential reference name only: no token or hash.
    if (type(auth) is not dict or set(auth) != {'mode', 'credential_ref'}
            or not _text(auth['mode'], 64)
            or not _ref(auth['credential_ref'])):
        raise ProfileError('manifest auth invalid')
    if (type(qual) is not dict or set(qual) != {'sdk_version', 'auth_results'}
            or not _text(qual['sdk_version'], 64)
            or qual['auth_results'] != AUTH_RESULTS):
        raise ProfileError('manifest qualification invalid')
    if (type(captures) is not list or not 1 <= len(captures) <= 32
            or any(type(c) is not dict or set(c) != CAPTURE_KEYS
                   or c['protocol'] not in PROTOCOLS
                   or not _text(c['path']) or not _hex(c['sha256'])
                   for c in captures)):
        raise ProfileError('manifest captures invalid')
    if (type(assertions) is not dict or set(assertions) != set(ASSERTIONS)
            or any(type(a) is not dict or not set(a) <= {'passed', 'detail'}
                   or a.get('passed') is not True
                   or ('detail' in a and not _text(a['detail']))
                   for a in assertions.values())):
        raise ProfileError('manifest assertions incomplete')
    hashes = {c['sha256'] for c in captures}
    if (type(multipart) is not dict
            or multipart.get('kind') not in ('rejection_capture',
                                             'source_evidence')
            or set(multipart) != ({'kind', 'sha256'}
                if multipart['kind'] == 'rejection_capture'
                else {'kind', 'sha256', 'path', 'commit'})
            or not _hex(multipart.get('sha256'))):
        raise ProfileError('multipart evidence invalid')
    if (multipart['kind'] == 'rejection_capture'
            and multipart['sha256'] not in hashes):
        raise ProfileError('multipart capture not qualified')
    # Source/version evidence must name the exact provider source commit it
    # was captured from; a file at any other commit is unread evidence.
    if (multipart['kind'] == 'source_evidence'
            and (not _text(multipart['path'])
                 or multipart['commit'] != data['provider_commit'])):
        raise ProfileError('multipart evidence invalid')
    return data


def _rehash(path, declared, read_evidence, what):
    """Fresh sha256 of one evidence file through the injected host reader."""
    try:
        blob = read_evidence(path)
    except Exception:
        raise ProfileError(what + ' unreadable') from None
    if type(blob) is not bytes or not blob or len(blob) > MAX_CAPTURE:
        raise ProfileError(what + ' invalid')
    if hashlib.sha256(blob).hexdigest() != declared:
        raise ProfileError(what + ' sha256 mismatch')


@dataclass(frozen=True)
class _VerifiedManifest:
    """Sealed canonical manifest bytes plus their verified sha256.

    Only verify_manifest() produces one. manifest reparses a detached copy
    of the sealed bytes on every access, so no caller-held dict can reach
    or mutate the verified content."""
    manifest_bytes: bytes
    manifest_sha256: str

    @property
    def manifest(self):
        return json.loads(self.manifest_bytes)


def verify_manifest(data, read_evidence):
    """Qualification: strict structure, manifest_sha256 recompute, then a
    fresh sha256 of every raw capture (and any source_evidence file)
    through the injected host reader. The input is detached into a
    canonical snapshot before validation, so caller or reader mutation can
    never change which evidence is checked."""
    try:
        snapshot = json.loads(canonical(data))
    except Exception:
        raise ProfileError('manifest not serializable') from None
    manifest = load_manifest(snapshot)
    body = {k: v for k, v in manifest.items() if k != 'manifest_sha256'}
    sealed = canonical(body)
    declared = manifest['manifest_sha256']
    if hashlib.sha256(sealed).hexdigest() != declared:
        raise ProfileError('manifest_sha256 mismatch')
    for cap in manifest['captures']:
        _rehash(cap['path'], cap['sha256'], read_evidence, 'capture')
    mp = manifest['multipart']
    if mp['kind'] == 'source_evidence':
        _rehash(mp['path'], mp['sha256'], read_evidence, 'source evidence')
    return _VerifiedManifest(sealed, declared)


@dataclass(frozen=True)
class RouteProtocolProfile:
    """Schema co.route-protocol/2: digests exactly these six fields. A
    route with no profile keeps the generic present/present strict default."""
    protocol: str
    index_mode: str
    sequence_mode: str
    inert_fields: dict        # {event_type: tuple of sorted key names}
    model: str
    provider_manifest_sha256: str

    def __post_init__(self):
        # Type guards precede every membership test so unhashable dicts or
        # lists fail closed as ProfileError, never TypeError.
        if (type(self.protocol) is not str or self.protocol not in PROTOCOLS
                or type(self.index_mode) is not str
                or self.index_mode not in INDEX_MODES
                or type(self.sequence_mode) is not str
                or self.sequence_mode not in SEQUENCE_MODES
                or (self.index_mode == 'absent_single_part'
                    and (self.protocol != 'responses'
                         or self.sequence_mode != 'absent'))
                or not _text(self.model, 256)
                or not _hex(self.provider_manifest_sha256)):
            raise ProfileError('invalid route profile')
        try:
            bad = (type(self.inert_fields) is not dict
                or len(self.inert_fields) > 64
                or any(type(etype) is not str or not 0 < len(etype) <= 128
                       or type(keys) is not tuple or len(keys) > 16
                       or list(keys) != sorted(keys)
                       or len(set(keys)) != len(keys)
                       or any(not _ref(key) for key in keys)
                       for etype, keys in self.inert_fields.items()))
        except (TypeError, AttributeError):
            bad = True
        if bad:
            raise ProfileError('invalid inert allowlist')
        # Deep seal: a detached mapping; the caller's dict cannot mutate the
        # profile after construction and no nested alias escapes.
        object.__setattr__(self, 'inert_fields', MappingProxyType(
            {etype: tuple(keys)
             for etype, keys in self.inert_fields.items()}))

    @property
    def profile_digest(self):
        """sha256 of the schema domain plus canonical JSON of the fields."""
        return hashlib.sha256(PROFILE_DOMAIN + canonical({
            'protocol': self.protocol,
            'index_mode': self.index_mode,
            'sequence_mode': self.sequence_mode,
            'inert_fields': {k: list(v)
                             for k, v in self.inert_fields.items()},
            'model': self.model,
            'provider_manifest_sha256':
                self.provider_manifest_sha256})).hexdigest()


def issue_profile(verified, protocol, *, index_mode='present',
                  sequence_mode='present', inert_fields=None):
    """Emit a route profile only for a sealed manifest whose canonical
    bytes still hash to the verified sha256; the protocol must have a
    qualified raw capture inside it. No caller-mutable proof data is read."""
    sealed = getattr(verified, 'manifest_bytes', None)
    if (type(verified) is not _VerifiedManifest or type(sealed) is not bytes
            or hashlib.sha256(sealed).hexdigest()
            != verified.manifest_sha256):
        raise ProfileError('manifest not qualified')
    manifest = verified.manifest
    if (protocol not in PROTOCOLS or not any(
            c['protocol'] == protocol for c in manifest['captures'])):
        raise ProfileError('no qualified capture for protocol')
    if (index_mode == 'absent_single_part'
            and (protocol != 'responses' or sequence_mode != 'absent')):
        raise ProfileError('single-part mode requires absent responses sequence')
    return RouteProtocolProfile(protocol=protocol, index_mode=index_mode,
        sequence_mode=sequence_mode,
        inert_fields={etype: tuple(keys)
                      for etype, keys in (inert_fields or {}).items()},
        model=manifest['model_id'],
        provider_manifest_sha256=verified.manifest_sha256)


def environment_ref(endpoint, auth_ref, profile_digest):
    """Derived route identity bound by Catalog Verification; never chosen."""
    if (not _text(endpoint, 1024) or not _ref(auth_ref)
            or not _hex(profile_digest)):
        raise ProfileError('invalid environment inputs')
    return ENV_PREFIX + hashlib.sha256(ENV_DOMAIN + canonical({
        'endpoint': endpoint, 'auth_ref': auth_ref,
        'profile_digest': profile_digest})).hexdigest()
