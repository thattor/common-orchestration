"""Loopback HTTP token auth and one-shot ingress receipts (#190 M3).

The principals file is a closed JSON list of {principal, token_sha256}
rows read through a protected fd: same uid, mode 0600, regular file,
nlink 1, O_NOFOLLOW|O_CLOEXEC, fstat identity before a bounded read.
It holds hashes only -- nothing here reads or migrates an existing secret.

authenticate() admits an exact 'Bearer ' scheme and compares the token
hash against EVERY entry in constant time with no early return; only the
file-supplied principal leaves this module, and a missing or wrong token
is one fixed AuthRejected (401), never exception text.

IngressBroker mints one-shot IngressReceipts under a bounded, thread-safe
pending map on the host store clock. Every operation -- including each
poll of a synchronous wait -- must mint a NEW ref: verifier() pops once
and a consumed ref can never be replayed. The client supplies no
principal, ref or event; cleanup removes an unconsumed receipt.
"""
from contextlib import contextmanager
import hashlib
import hmac
import json
import os
import stat
from threading import Lock
from uuid import uuid4

from .state import IngressReceipt, StoreUnavailable, body_digest

MAX_FILE_BYTES = 65536
MAX_TOKEN_CHARS = 4096          # generous bound; SDK keys are far smaller
MAX_PRINCIPAL_CHARS = 256
MAX_PENDING = 64


class AuthConfigError(Exception):
    """Fixed startup refusal; never carries token, hash or exception text."""
    code = 'auth_config_invalid'

    def __init__(self):
        super().__init__(self.code)


class AuthRejected(Exception):
    """Fixed 401 for a missing or wrong Bearer token; no detail echoed."""
    code = 'unauthorized'

    def __init__(self):
        super().__init__(self.code)


def _reject_constant(_value):
    raise AuthConfigError()


def _object(pairs):
    seen, out = set(), {}
    for key, value in pairs:
        if key in seen:
            raise AuthConfigError()
        seen.add(key)
        out[key] = value
    return out


def _principal(value):
    if type(value) is not str or not 0 < len(value) <= MAX_PRINCIPAL_CHARS:
        return False
    try:
        value.encode('utf-8')
    except UnicodeEncodeError:
        return False
    return True


def _hex_digest(value):
    return (type(value) is str and len(value) == 64
            and all(ch in '0123456789abcdef' for ch in value))


def _read_fd(path):
    """O_NOFOLLOW|O_CLOEXEC open, fstat identity check, bounded read."""
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1):
            raise AuthConfigError()
        with os.fdopen(fd, 'rb') as handle:
            fd = -1
            blob = handle.read(MAX_FILE_BYTES + 1)
        if len(blob) > MAX_FILE_BYTES:
            raise AuthConfigError()
        return blob
    finally:
        if fd >= 0:
            os.close(fd)


def load_principals(path):
    """Validate and freeze the file; raises only AuthConfigError."""
    try:
        data = json.loads(_read_fd(path).decode('utf-8'),
                          object_pairs_hook=_object,
                          parse_constant=_reject_constant)
    except AuthConfigError:
        raise
    except Exception:
        raise AuthConfigError() from None
    if type(data) is not list or not data:
        raise AuthConfigError()
    entries = []
    seen_principals, seen_hashes = set(), set()
    for row in data:
        if type(row) is not dict or set(row) != {'principal', 'token_sha256'}:
            raise AuthConfigError()
        principal, hashed = row['principal'], row['token_sha256']
        if (not _principal(principal) or not _hex_digest(hashed)
                or principal in seen_principals or hashed in seen_hashes):
            raise AuthConfigError()
        seen_principals.add(principal)
        seen_hashes.add(hashed)
        entries.append((principal, hashed))
    return TokenAuth(tuple(entries))


class TokenAuth:
    """Closed verifier; token values themselves are never stored."""

    def __init__(self, entries):
        self._entries = entries

    def authenticate(self, header):
        """Exact 'Bearer <token>'; constant-time across every entry."""
        if type(header) is not str or not header.startswith('Bearer '):
            raise AuthRejected()
        token = header[7:]
        if (not token or len(token) > MAX_TOKEN_CHARS
                or any(ord(ch) > 0x7F for ch in token)):
            raise AuthRejected()
        digest = hashlib.sha256(token.encode('ascii')).hexdigest()
        match = None
        for principal, known in self._entries:
            if hmac.compare_digest(digest, known):
                match = principal
        if match is None:
            raise AuthRejected()
        return match


class IngressBroker:
    """Bounded one-shot IngressReceipt minter on the host store clock."""

    def __init__(self, store_clock):
        self._clock, self._pending, self._lock = store_clock, {}, Lock()

    @contextmanager
    def receipt_ref(self, principal, operation_body):
        """Mint a 'http:' + CSPRNG-uuid ref bound to the exact operation
        body; an unconsumed receipt is dropped by the finally."""
        if not _principal(principal):
            raise ValueError('authenticated principal required')
        ref = 'http:' + uuid4().hex
        receipt = IngressReceipt(principal, uuid4().hex,
                                 body_digest(operation_body), self._clock())
        with self._lock:
            if len(self._pending) >= MAX_PENDING:
                raise StoreUnavailable('ingress receipt capacity')
            self._pending[ref] = receipt
        try:
            yield ref
        finally:
            with self._lock:
                self._pending.pop(ref, None)

    def verifier(self, ref):
        """Store seam: resolve and pop exactly once; a second use fails."""
        with self._lock:
            return self._pending.pop(ref)   # KeyError on absent/consumed
