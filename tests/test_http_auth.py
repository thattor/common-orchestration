"""#190 M3 http_auth: protected principals loader, Bearer auth, broker.

Fresh CSPRNG tokens only, written to owned 0600 tempfiles; no existing
secret is read. Broker receipts are exercised through the real
ControlStore/Gateway ingress verifier, never a stub.
"""
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import errno
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import tempfile
import unittest
from unittest import mock

from co_v4 import contracts as c
from co_v4.gateway_store import lookup_body, submit_body
import co_v4.http_auth as ha
from co_v4.http_auth import (AuthConfigError, AuthRejected, IngressBroker,
                             MAX_FILE_BYTES, MAX_PENDING, load_principals)
from co_v4.responses_input import parse
from co_v4.state import (ControlStore, StoreUnavailable,
                         UntrustedInput, body_digest)

NOW = '2026-10-06T00:00:00Z'
PURE = c.TaskProfile('p-pure', 'sha256:' + '0' * 64, 'pure')


def digest(token):
    return hashlib.sha256(token.encode('ascii')).hexdigest()


class LoaderTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.path = self.dir / 'principals.json'
        self.tokens = [secrets.token_hex(20) for _ in range(3)]
        self.rows = [('p%d' % i, digest(t))
                     for i, t in enumerate(self.tokens)]

    def write(self, content, name=None, mode=0o600):
        path = self.dir / (name or 'principals.json')
        if type(content) is not bytes:
            content = json.dumps(content).encode('utf-8')
        path.write_bytes(content)
        path.chmod(mode)
        return path

    def doc(self):
        return [{'principal': p, 'token_sha256': h}
                for p, h in self.rows]

    def bad(self, path=None):
        with self.assertRaises(AuthConfigError) as caught:
            load_principals(path or self.path)
        # Fixed code only: no row bytes, hash or detail may be echoed.
        self.assertEqual(str(caught.exception), 'auth_config_invalid')
        self.assertNotIn(self.rows[0][1], str(caught.exception))

    def test_load_round_trip_and_authenticate(self):
        self.write(self.doc())
        auth = load_principals(self.path)
        for i, token in enumerate(self.tokens):
            self.assertEqual(auth.authenticate('Bearer ' + token),
                             'p%d' % i)

    def test_bearer_rejections_fixed_401(self):
        self.write(self.doc())
        auth = load_principals(self.path)
        token = self.tokens[0]
        # Guaranteed different: flip the last hex char, never an equal token.
        wrong = token[:-1] + ('f' if token[-1] != 'f' else 'e')
        cases = (None, '', 'Bearer', 'bearer ' + token,
                 'Basic ' + token, 'Bearer\t' + token,
                 'Bearer ' + wrong,
                 'Bearer ' + 'nope', 'Bearer ', 'Bearer ' + 'é',
                 'Bearer ' + 'x' * 4097, 7)
        for i, header in enumerate(cases):
            with self.subTest(case=i):
                with self.assertRaises(AuthRejected) as caught:
                    auth.authenticate(header)
                self.assertEqual(caught.exception.code, 'unauthorized')
                self.assertNotIn(token, str(caught.exception))

    def test_compare_digest_runs_every_entry(self):
        self.write(self.doc())
        auth = load_principals(self.path)
        calls = []
        real = hmac.compare_digest
        with mock.patch.object(ha.hmac, 'compare_digest',
                               lambda a, b: calls.append(1) or real(a, b)):
            # Even when the FIRST entry matches, all three are compared.
            self.assertEqual(auth.authenticate('Bearer ' + self.tokens[0]),
                             'p0')
        self.assertEqual(len(calls), 3)

    def test_file_mode_uid_nlink_symlink_nonregular_refusals(self):
        self.write(self.doc())
        self.path.chmod(0o644)
        self.bad()
        self.path.chmod(0o600)
        os.link(self.path, self.dir / 'hard')      # nlink 2
        self.bad()
        (self.dir / 'hard').unlink()
        link = self.dir / 'link.json'
        os.symlink(self.path, link)
        self.bad(link)
        self.bad(self.dir)                          # directory, not regular
        with mock.patch.object(ha.os, 'getuid',
                               return_value=os.getuid() + 1):
            self.bad()

    def test_oversize_file_refused(self):
        big = json.dumps(self.doc()).encode() + b' ' * (MAX_FILE_BYTES + 1)
        self.bad(self.write(big))

    def test_fd_closed_on_refusal(self):
        self.write(self.doc())
        closed = []
        real_close = os.close

        def wrapped(fd):
            closed.append(fd)
            return real_close(fd)

        with mock.patch.object(ha.os, 'close', wrapped):
            self.path.chmod(0o644)
            self.bad()                              # stat refusal
            self.bad(self.dir)                      # nonregular refusal
            self.bad(self.dir / 'link-missing')     # open fails: no close
        self.assertEqual(len(closed), 2)

    def test_read_failure_closes_opened_fd(self):
        # fdopen owns the fd past the stat checks, so patched os.close sees
        # nothing; closure is proven by EBADF on the captured opened fd.
        self.write(b'not json')
        opened = []
        real_open = os.open

        def hook(path, flags, *args):
            fd = real_open(path, flags, *args)
            opened.append(fd)
            return fd

        with mock.patch.object(ha.os, 'open', hook):
            self.bad()
        self.assertEqual(len(opened), 1)
        with self.assertRaises(OSError) as caught:
            os.fstat(opened[0])
        self.assertEqual(caught.exception.errno, errno.EBADF)

    def test_rename_swap_uses_opened_inode(self):
        # A symlink at the path is refused even though it resolves to a
        # perfectly valid file: the opened inode, not the path, is checked.
        self.write(self.doc(), name='real.json')
        link = self.dir / 'swapped.json'
        os.symlink(self.dir / 'real.json', link)
        self.bad(link)
        os.replace(self.dir / 'real.json', link)
        self.assertEqual(
            load_principals(link).authenticate('Bearer ' + self.tokens[1]),
            'p1')

    def test_open_to_read_swap_reads_opened_inode(self):
        # A real race: after the loader's single os.open returns, the PATH is
        # atomically swapped to a decoy while the original inode stays linked
        # (nlink 1 via 'held.json'). fstat/read must still hit the opened fd.
        self.write(self.doc())
        decoy_token = secrets.token_hex(20)
        decoy = self.write([{'principal': 'decoy',
                             'token_sha256': digest(decoy_token)}],
                           name='decoy.json')
        backup = self.dir / 'held.json'
        opened = []
        real_open = os.open

        def hook(path, flags, *args):
            fd = real_open(path, flags, *args)
            opened.append(fd)
            os.rename(path, backup)      # opened inode keeps one name
            os.replace(decoy, path)      # the path now names the decoy
            return fd

        with mock.patch.object(ha.os, 'open', hook):
            auth = load_principals(self.path)
        self.assertEqual(len(opened), 1)
        # Content came from the original inode, not the swapped-in path.
        self.assertEqual(auth.authenticate('Bearer ' + self.tokens[0]), 'p0')
        with self.assertRaises(AuthRejected):
            auth.authenticate('Bearer ' + decoy_token)

    def test_document_schema_refusals(self):
        cases = (
            {}, 'x', True,
            [],                                                     # empty
            [{'principal': 'p0'}],                                  # missing key
            [{'principal': 'p0', 'token_sha256': self.rows[0][1],
              'extra': 1}],
            [{'principal': '', 'token_sha256': self.rows[0][1]}],
            [{'principal': 'x' * 257, 'token_sha256': self.rows[0][1]}],
            [{'principal': 7, 'token_sha256': self.rows[0][1]}],
            [{'principal': 'p0', 'token_sha256': 'x' * 64}],        # non-hex
            [{'principal': 'p0',
              'token_sha256': self.rows[0][1].upper()}],            # not lower
            [{'principal': 'p0', 'token_sha256': self.rows[0][1][:-1]}],
            [{'principal': 'p0', 'token_sha256': 64}],
            [{'principal': 'p0', 'token_sha256': self.rows[0][1]},
             {'principal': 'p0', 'token_sha256': self.rows[1][1]}],  # dup name
            [{'principal': 'p0', 'token_sha256': self.rows[0][1]},
             {'principal': 'p1', 'token_sha256': self.rows[0][1]}],  # dup hash
        )
        for doc in cases:
            with self.subTest(doc=str(doc)[:50]):
                self.bad(self.write(doc))

    def test_duplicate_keys_nan_and_surrogate_refused(self):
        h = self.rows[0][1]
        raw = ('[{"principal":"p0","principal":"p0","token_sha256":"%s"}]'
               % h).encode()
        self.bad(self.write(raw))
        self.bad(self.write(b'[{"principal":"p0","token_sha256":NaN}]'))
        self.bad(self.write(
            ('[{"principal":"\\ud800","token_sha256":"%s"}]' % h).encode()))
        self.bad(self.write(b'\xff\xfe'))           # invalid UTF-8 bytes
        self.bad(self.write(b'not json'))


class BrokerTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.store = ControlStore(
            Path(tmp.name) / 'control.sqlite',
            verifier=lambda ref: self.broker.verifier(ref),
            evidence=lambda *_: None, clock=lambda: NOW,
            profile_resolver=lambda alias: PURE)
        self.broker = IngressBroker(self.store.now)
        self.gateway = self.store.gateway()
        self.addCleanup(self.store.close)
        self.intent = parse(json.dumps(
            {'model': 'co-auto', 'input': 'x'}).encode())

    def submit(self, key='k1'):
        body = submit_body(self.intent.body_hash, key)
        with self.broker.receipt_ref('p1', body) as ref:
            receipt = self.broker._pending[ref]
            sub = self.gateway.submit(self.intent, key, ref)
        return sub, ref, receipt, body

    def test_minted_receipt_binds_body_principal_event_clock(self):
        sub, ref, receipt, body = self.submit()
        self.assertTrue(ref.startswith('http:') and len(ref) == 37)
        self.assertEqual(receipt.principal, 'p1')
        self.assertEqual(receipt.body_digest, body_digest(body))
        self.assertEqual(receipt.received_at, NOW)
        self.assertEqual(len(receipt.source_event), 32)
        self.assertNotEqual(receipt.source_event, ref[5:])
        run = self.store.controller().get_run(sub.run_id)
        self.assertEqual(run.authenticated_origin_ref, ref)

    def test_one_shot_consume_and_replay_fails(self):
        sub, ref, _receipt, _body = self.submit()
        self.assertEqual(self.broker._pending, {})
        with self.assertRaises(KeyError):
            self.broker.verifier(ref)
        # A consumed ref can never authenticate a second submit.
        with self.assertRaises(UntrustedInput):
            self.gateway.submit(self.intent, 'k2', ref)
        self.assertIsNotNone(sub.response_id)

    def test_each_poll_mints_fresh_never_reuses(self):
        sub, _ref, _receipt, _body = self.submit()
        refs = []
        for _ in range(2):
            body = lookup_body(sub.response_id)
            with self.broker.receipt_ref('p1', body) as ref:
                refs.append(ref)
                self.gateway.lookup(sub.response_id, ref)
        self.assertEqual(len(set(refs)), 2)
        self.assertEqual(self.broker._pending, {})

    def test_body_digest_mismatch_rejects(self):
        with self.broker.receipt_ref(
                'p1', submit_body(self.intent.body_hash, 'k1')) as ref:
            with self.assertRaises(UntrustedInput):
                self.gateway.submit(self.intent, 'other-key', ref)
        # The verifier popped the receipt before the binding check ran.
        with self.assertRaises(KeyError):
            self.broker.verifier(ref)

    def test_finally_drops_unconsumed_receipt(self):
        held = []
        with self.assertRaises(RuntimeError):
            with self.broker.receipt_ref('p1', lookup_body('x')) as ref:
                held.append(ref)
                raise RuntimeError('handler failure')
        with self.assertRaises(KeyError):
            self.broker.verifier(held[0])
        self.assertEqual(self.broker._pending, {})

    def test_max_pending_capacity(self):
        body = lookup_body('x')
        with ExitStack() as stack:
            for _ in range(MAX_PENDING):
                stack.enter_context(self.broker.receipt_ref('p1', body))
            with self.assertRaises(StoreUnavailable):
                stack.enter_context(self.broker.receipt_ref('p1', body))
        self.assertEqual(self.broker._pending, {})

    def test_bad_principal_rejected_at_mint(self):
        for bad in ('', None, 'x' * 257):
            with self.subTest(bad=bad):
                with self.assertRaises((ValueError, TypeError)):
                    with self.broker.receipt_ref(bad, lookup_body('x')):
                        pass

    def test_concurrent_32_polls_unique_refs_no_leak(self):
        sub, _ref, _receipt, _body = self.submit()
        body = lookup_body(sub.response_id)

        def poll(_):
            with self.broker.receipt_ref('p1', body) as ref:
                self.gateway.lookup(sub.response_id, ref)
                return ref

        with ThreadPoolExecutor(32) as pool:
            refs = list(pool.map(poll, range(32)))
        self.assertEqual(len(set(refs)), 32)
        self.assertEqual(self.broker._pending, {})


if __name__ == '__main__':
    unittest.main()
