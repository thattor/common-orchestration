# tests/test_cli_owned.py
"""#190 M3 CLI lifecycle: real child processes, real owner/host/driver.

Each child runs co_v4.cli.main with trusted-Python injectable seams
(load/build/host_type) bound to the REAL ServiceHost, ServiceOwner,
ControlStore, CapacityLedger, PooledAdapter and driver; only the HTTP
listener is a counted close fixture except in the latch test, which runs
a real HttpService. Readiness is child-owned files/stdout only — no
guessed sleeps, no ambient environment or secrets; the parent passes
PATH only and argv paths. Cleanup terminates only our own children.
"""
import json
import os
import secrets
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from dataclasses import replace
from hashlib import sha256
from pathlib import Path

from co_v4.gateway_store import Gateway, submit_body
from co_v4.http_auth import IngressBroker
from co_v4.judgment import TrustedEvidence
from co_v4.profile_registry import (ProfileRegistryMismatch,
                                    load_registry, revision_digest)
from co_v4.responses_input import parse
from co_v4.service_owner import OwnerUnavailable, ServiceOwner
from co_v4.state import ControlStore, body_digest
import http.client
import test_service_host as fx
from test_profile_registry import registry_doc, wire_entry

TESTS = Path(__file__).resolve().parent
SRC = TESTS.parent
NOW = fx.NOW

CHILD = r'''
import json, sys
from pathlib import Path
from types import SimpleNamespace
sys.path[:0] = sys.argv[7:]
mode, root_s, ready_s, ctl_s, flag_s, url_s = sys.argv[1:7]
root = Path(root_s)
import co_v4.cli as cli
import co_v4.service_host as sh
from co_v4.ac import Acceptance
from co_v4.adapter_capacity import CapacityLedger, PooledAdapter
from co_v4.catalog import Catalog
from co_v4.controller import Controller
from co_v4.gateway_store import Gateway
from co_v4.http_auth import IngressBroker, load_principals
from co_v4.http_service import HttpService
from co_v4.judgment import TrustedEvidence
from co_v4.output_store import OutputStore
from co_v4.profile_registry import load_registry, revision_digest
from co_v4.service_host import Components, ServiceHost
from co_v4.state import ControlStore, body_digest
from co_v4.usage import UsageStore
from test_adapter_capacity import Child
import test_service_host as fx
from test_profile_registry import registry_doc, wire_entry

w = wire_entry()
registry = load_registry(json.dumps(registry_doc([w],
    [{'alias': 'co-text', 'profile_id': 'co-text',
      'revision_digest': revision_digest(w)}])),
    catalog=fx.CATALOG, routes=(fx.ROUTE,))
broker = IngressBroker(lambda: fx.NOW)
comp = {}

def evidence(run, request):
    return TrustedEvidence(body_digest(request), 'f:p', ('f:c',),
        'f:o', False, False, True, True, True, True)

class Fixture:
    # Construct-only factory: Host assigns _http then calls start().
    def start(self):
        if mode == 'start-unconfirmed':
            raise OSError('fixture bind refused')   # before any READY
        Path(ready_s).write_text('ready')
        print('READY', flush=True)
    def close(self):
        if mode in ('unconfirmed', 'start-unconfirmed') \
                and not Path(ctl_s).exists():
            with open(flag_s, 'a') as f:
                f.write('u')          # parent-visible unconfirmed mark
            return 'host_stop_unconfirmed'
        return 'stopped'

class ReadyHttp(HttpService):
    """Real listener; readiness/URL reported inside its real start()."""
    def start(self):
        url = super().start()
        Path(url_s).write_text(url)
        Path(ready_s).write_text('ready')
        print('READY', flush=True)
        return url

def http_factory(available):
    if mode == 'latch':
        return ReadyHttp(gateway=comp['c'].gateway, broker=broker,
            auth=load_principals(url_s + '.principals'),
            registry=registry, output_store=comp['c'].output_store,
            available=available, sync_timeout=1.0)
    return Fixture()

def controller_factory(run_id, snapshot):
    return Controller(run_id, state=comp['c'].store.controller(),
        judgment=comp['c'].store.judgment(), catalog=Catalog(),
        usage=UsageStore(), adapters={fx.ADAPTER: pool},
        acceptance=Acceptance(lambda r: (_ for _ in ()).throw(
            AssertionError('verifier must not run'))),
        planner=lambda *_: None, clock=lambda: fx.NOW_DT,
        output_store=comp['c'].output_store)

def build(owner, retain):
    store = retain(ControlStore(root / 'control.sqlite',
        verifier=broker.verifier, evidence=evidence, clock=lambda: fx.NOW,
        profile_resolver=registry.resolve, guard=owner.check))
    # Descriptor-free component: exact type + guard verified by the Host,
    # never retained and never closed.
    out = OutputStore(root / 'outputs', guard=owner.check)
    ledger = CapacityLedger(root / 'capacity.sqlite')
    global pool
    pool = retain(PooledAdapter(fx.ADAPTER, ledger=ledger,
        canonical_ledger=ledger.path, factory=lambda req: Child()))
    comp['c'] = Components(store, Gateway(store,
        bound_resolver=registry.unconfirmed_after_seconds), out, ledger,
        {fx.ADAPTER: pool}, registry, http_factory, controller_factory)
    return comp['c']

if mode == 'latch':
    real_sd = sh.ServiceDriver
    def wrap(*a, **k):
        d = real_sd(*a, **k)
        orig = d.tick
        def tick():
            if Path(flag_s).exists():
                raise RuntimeError('global latch')
            return orig()
        d.tick = tick
        return d
    sh.ServiceDriver = wrap

cfg = SimpleNamespace(state_root=str(root))
sys.exit(cli.main(['--config', 'x'], load=lambda _p: cfg,
                  build=lambda _c: build, host_type=ServiceHost))
'''


class CliOwnedTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name).resolve()
        self.root = self.dir / 'root'
        self.root.mkdir(mode=0o700)
        w = wire_entry()
        self.registry = load_registry(json.dumps(registry_doc([w],
            [{'alias': 'co-text', 'profile_id': 'co-text',
              'revision_digest': revision_digest(w)}])),
            catalog=fx.CATALOG, routes=(fx.ROUTE,))

    def spawn(self, mode):
        paths = [self.dir / (mode + '.' + suffix)
                 for suffix in ('ready', 'ctl', 'flag', 'url')]
        # Fresh CSPRNG token hash for the child's real principals file;
        # no existing credential is ever read.
        principals = Path(str(paths[3]) + '.principals')
        principals.write_text(json.dumps([{
            'principal': 'p',
            'token_sha256': sha256(
                secrets.token_hex(32).encode('ascii')).hexdigest()}]))
        principals.chmod(0o600)
        proc = subprocess.Popen(
            [sys.executable, '-c', CHILD, mode, str(self.root),
             *(str(p) for p in paths), str(TESTS), str(SRC)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env={'PATH': '/usr/bin:/bin'})
        self.addCleanup(self._reap, proc)
        return proc, *paths

    def _reap(self, proc):
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(5)
        for stream in (proc.stdout, proc.stderr):
            try:
                stream.close()
            except OSError:
                pass

    def wait_ready(self, proc, ready, timeout=20):
        deadline = time.monotonic() + timeout
        while not ready.exists():
            if proc.poll() is not None:
                self.fail('child exited %r: %s'
                          % (proc.returncode, proc.stderr.read()))
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.02)

    def wait_exit(self, proc, timeout=60):
        try:
            proc.wait(timeout)
        except subprocess.TimeoutExpired:
            self._reap(proc)          # own child: bounded kill first
            self.fail('child never exited')   # streams already closed
        return proc.returncode

    def wait_marks(self, proc, path, count, timeout=40):
        deadline = time.monotonic() + timeout
        while not path.exists() or len(path.read_text()) < count:
            if proc.poll() is not None:
                self.fail('child exited %r: %s'
                          % (proc.returncode, proc.stderr.read()[:500]))
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.02)

    def held(self):
        with self.assertRaises(OwnerUnavailable) as ei:
            ServiceOwner.acquire(self.root)
        self.assertEqual(ei.exception.code, 'owned_elsewhere')

    def released(self):
        ServiceOwner.acquire(self.root).close()

    def evidence(self, run, request):
        return TrustedEvidence(body_digest(request), 'f:p', ('f:c',),
            'f:o', False, False, True, True, True, True)

    def seed_ghost(self):
        """A pending gateway Run pinning an absent revision."""
        owner = ServiceOwner.acquire(self.root)
        broker = IngressBroker(lambda: NOW)
        store = ControlStore(self.root / 'control.sqlite',
            verifier=broker.verifier, evidence=self.evidence,
            clock=lambda: NOW, profile_resolver=self.registry.resolve,
            guard=owner.check)
        try:
            intent = parse(json.dumps(
                {'model': 'co-text', 'input': 'x'}).encode())
            with broker.receipt_ref('p', submit_body(
                    intent.body_hash, None)) as ref:
                run_id = gateway = Gateway(store).submit(
                    intent, None, ref).run_id
            with store._tx():
                data, before = store._load_locked(run_id)
                data['run'] = replace(data['run'], profile=fx.GHOST)
                store._store_locked(run_id, data, before)
        finally:
            store.close()
            owner.close()

    def test_sigterm_graceful_exit_owner_reacquired(self):
        proc, ready, _ctl, _flag, _url = self.spawn('term')
        self.wait_ready(proc, ready)
        self.held()
        os.kill(proc.pid, signal.SIGTERM)
        self.assertEqual(self.wait_exit(proc), 0)
        self.released()

    def test_unconfirmed_close_stays_alive_until_released(self):
        proc, ready, ctl, flag, _url = self.spawn('unconfirmed')
        self.wait_ready(proc, ready)
        os.kill(proc.pid, signal.SIGTERM)
        self.wait_marks(proc, flag, 1)           # first close unconfirmed
        self.assertIsNone(proc.poll())           # never exits unconfirmed
        self.held()                              # owner lock still held
        os.kill(proc.pid, signal.SIGINT)         # second signal: no force
        self.wait_marks(proc, flag, 2)           # retried, still unconfirmed
        self.assertIsNone(proc.poll())
        self.held()
        ctl.write_text('release')                # fixture close confirmed
        self.assertEqual(self.wait_exit(proc), 0)
        self.released()

    def test_latch_503_while_alive_then_sigterm_stops(self):
        proc, ready, _ctl, flag, url = self.spawn('latch')
        self.wait_ready(proc, ready)
        deadline = time.monotonic() + 20
        while not url.exists():
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.02)
        port = int(url.read_text().rsplit(':', 1)[1])
        flag.write_text('latch')                 # global driver failure
        deadline = time.monotonic() + 20
        status = None
        while status != 503 and time.monotonic() < deadline:
            conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
            try:
                conn.request('GET', '/v1/models')
                status = conn.getresponse().status
            finally:
                conn.close()
        self.assertEqual(status, 503)            # live process, latched
        self.assertIsNone(proc.poll())
        os.kill(proc.pid, signal.SIGTERM)
        self.assertEqual(self.wait_exit(proc), 0)
        self.released()

    def test_startup_refusal_exit1_owner_released(self):
        self.seed_ghost()
        proc, _ready, _ctl, _flag, _url = self.spawn('term')
        self.assertEqual(self.wait_exit(proc), 1)
        self.assertIn('host_start_failed', proc.stderr.read())
        self.released()

    def test_start_unconfirmed_retains_owner_then_exits_1(self):
        # Fixture.start raises before READY; the retained _http is drained
        # by teardown but never confirms until ctl exists. The CLI keeps
        # the process alive with owner/stores/leases held, ignores a
        # second signal, then exits host_start_failed once confirmed.
        proc, ready, ctl, flag, _url = self.spawn('start-unconfirmed')
        self.wait_marks(proc, flag, 1)             # unconfirmed teardown
        self.assertFalse(ready.exists())           # no listener ever bound
        self.assertIsNone(proc.poll())             # stays alive, refs held
        self.held()
        os.kill(proc.pid, signal.SIGINT)           # never escalates
        self.wait_marks(proc, flag, 2)             # retried, still held
        self.assertIsNone(proc.poll())
        self.held()
        ctl.write_text('release')
        self.assertEqual(self.wait_exit(proc), 1)
        self.assertIn('host_start_failed', proc.stderr.read())
        self.released()

if __name__ == '__main__':
    unittest.main()
