"""Trusted, file-pinned model retirement policy; no discovery or fallback.

The host owns the file, UTC clock and reviewed auth-route/environment evidence.
Changing a loaded file blocks admission until deliberate host recomposition.
Official date-only announcements never supply an invented shutdown instant.
"""
from dataclasses import dataclass
from datetime import date, datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

AUTH_ROUTES = frozenset({'chatgpt', 'api-key', 'subscription', 'oauth', 'account'})
_LIMIT = 1024 * 1024


def _exact(value):
    return type(value) is str and bool(value) and value.strip() == value


def _date(value):
    if type(value) is not str or not re.fullmatch(r'\d{4}-\d{2}-\d{2}', value):
        raise ValueError('exact ISO date required')
    return date.fromisoformat(value)


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('duplicate policy key')
        result[key] = value
    return result


def _read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022 or info.st_size > _LIMIT:
            raise ValueError('protected bounded policy file required')
        with os.fdopen(fd, 'rb', closefd=False) as source:
            value = source.read(_LIMIT + 1)
        if len(value) > _LIMIT:
            raise ValueError('policy file exceeds bound')
        return value
    finally:
        os.close(fd)


@dataclass(frozen=True)
class LifecycleRule:
    adapter: str
    model: str
    auth_route: str
    cutoff: datetime
    cutoff_field: str
    cutoff_timezone: str
    cutoff_basis: str
    announcement_url: str
    announced_on: str | None
    retirement_on: str | None
    replacements: tuple[str, ...]

    @property
    def key(self):
        return self.adapter, self.model, self.auth_route

    @classmethod
    def parse(cls, row):
        required = {'adapter', 'model', 'auth_route', 'cutoff_timezone', 'cutoff_basis',
                    'announcement_url', 'announced_on', 'retirement_on', 'replacements'}
        if type(row) is not dict or set(row) not in (required | {'disable_from'}, required | {'expires_at'}):
            raise ValueError('exact lifecycle fields and one cutoff required')
        if (not all(_exact(row[k]) for k in ('adapter', 'model', 'cutoff_timezone', 'announcement_url'))
                or type(row['auth_route']) is not str or row['auth_route'] not in AUTH_ROUTES
                or type(row['cutoff_basis']) is not str or row['cutoff_basis'] not in {'maintainer', 'official'}):
            raise ValueError('exact route and cutoff basis required')
        url = urlsplit(row['announcement_url'])
        if url.scheme != 'https' or not url.hostname or url.username or url.password:
            raise ValueError('HTTPS announcement URL required')
        for field in ('announced_on', 'retirement_on'):
            if row[field] is not None:
                _date(row[field])
        replacements = row['replacements']
        if (type(replacements) is not list or len(replacements) > 32
                or any(not _exact(v) for v in replacements) or len(set(replacements)) != len(replacements)):
            raise ValueError('exact informational replacement candidates required')
        field = 'disable_from' if 'disable_from' in row else 'expires_at'
        raw = row[field]
        if (type(raw) is not str or not re.fullmatch(
                r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})', raw)
                or raw.endswith('-00:00')):
            raise ValueError('explicit cutoff instant and known offset required')
        instant = datetime.fromisoformat(raw.replace('Z', '+00:00'))
        try:
            zone = ZoneInfo(row['cutoff_timezone'])
        except (ValueError, ZoneInfoNotFoundError) as exc:
            raise ValueError('known IANA cutoff timezone required') from exc
        local = instant.astimezone(zone)
        if local.utcoffset() != instant.utcoffset() or local.replace(tzinfo=None) != instant.replace(tzinfo=None):
            raise ValueError('cutoff offset must match named timezone')
        return cls(row['adapter'], row['model'], row['auth_route'], instant.astimezone(timezone.utc),
                   field, row['cutoff_timezone'], row['cutoff_basis'], row['announcement_url'],
                   row['announced_on'], row['retirement_on'], tuple(replacements))


@dataclass(frozen=True)
class ModelLifecyclePolicy:
    path: Path
    sha256: str
    rules: tuple[LifecycleRule, ...]

    @property
    def ref(self):
        return 'model-lifecycle:sha256:' + self.sha256

    def __post_init__(self):
        # Even dataclass construction/replacement must preserve the file binding.
        raw = _read(self.path)
        if hashlib.sha256(raw).hexdigest() != self.sha256 or _rules(raw) != self.rules:
            raise ValueError('lifecycle rules must match the pinned file')

    @classmethod
    def load(cls, path):
        path = Path(path).absolute()
        raw = _read(path)
        return cls(path, hashlib.sha256(raw).hexdigest(), _rules(raw))

    def admission_reason(self, model, adapter, auth_route, *, now):
        try:
            current = _read(self.path)
        except (OSError, ValueError):
            return 'model_lifecycle_policy_unavailable'
        if hashlib.sha256(current).hexdigest() != self.sha256:
            return 'model_lifecycle_policy_changed'
        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
            return 'model_lifecycle_clock_invalid'
        applicable = tuple(r for r in self.rules if (r.adapter, r.model) == (adapter, model))
        if not applicable:
            return None  # Unconfigured combinations retain legacy behavior.
        if type(auth_route) is not str or auth_route not in AUTH_ROUTES:
            return 'model_lifecycle_auth_unverified'
        if any(r.auth_route == auth_route and now >= r.cutoff for r in applicable):
            return 'model_lifecycle_expired'
        return None


def _rules(raw):
    document = json.loads(raw, object_pairs_hook=_pairs)
    if (type(document) is not dict or set(document) != {'version', 'rules'}
            or type(document['version']) is not int or document['version'] != 1
            or type(document['rules']) is not list or len(document['rules']) > 1024):
        raise ValueError('unsupported lifecycle policy')
    rules = tuple(LifecycleRule.parse(row) for row in document['rules'])
    if len({rule.key for rule in rules}) != len(rules):
        raise ValueError('duplicate lifecycle route')
    return rules
