"""Dedicated single-Run host: Human ingress only before any Worker launch.

The host owns this driver, its directory, callbacks and sole lazy Native factory.
No Worker may receive these handles. This is a product composition boundary, not
a claim about every process on the macOS account. Do not attach another Run or
an already-running Native to this dedicated context. Origin/source callbacks
must authenticate actual host inputs; marker files cannot authenticate them.

The durable launch claim closes Human ingress before factory creation/execute,
even if either fails. Reopening after launch, active callback intake and Native
recovery are deliberately unsupported here. Pre-execution absence is never
supplied as execution-protection evidence; the Native factory/HostVerifier and
the caller's Judgment resolver retain that independent responsibility.
"""
import fcntl
import json
import os
from pathlib import Path
import stat
from threading import RLock

from . import contracts as c
from .human_connector import ConnectorGitHub
from .human_gateway import DeliveryUncertain, GatewayJournal, HumanGateway, IssueTarget
from .state import ControlStore, InvalidTransition, UntrustedInput, body_digest, create_run_body
from .trace import PublicationPolicy, Trace, canonical


class PreExecutionHumanDriver:
    """Trusted host API. Use create/open; no Native process starts in either."""

    @classmethod
    def create(cls, directory, *, run_id, intent, origin_ref, origin_verifier,
               evidence, target, approver_ids, publisher_id, fetch_raw, notifier,
               release_check, clock, native_factory):
        root = Path(directory)
        root.mkdir(mode=0o700)  # Existing directories are never adopted as fresh.
        driver = cls.__new__(cls)
        try:
            driver._configure(root, run_id, target, approver_ids, publisher_id,
                              clock, native_factory, creating=True)
            driver._origin_ref = origin_ref
            driver._write_marker('creating')
            driver._components(origin_verifier, evidence, fetch_raw, notifier, release_check)
            driver.store.intake().create_run(run_id, intent, origin_ref)
            driver._origin = body_digest(create_run_body(run_id, intent))
            driver._write_marker('never_launched')
            driver._capture_files()
            return driver
        except Exception:
            driver.close()
            raise

    @classmethod
    def open(cls, directory, *, run_id, origin_verifier, evidence, target,
             approver_ids, publisher_id, fetch_raw, notifier, release_check,
             clock, native_factory):
        driver = cls.__new__(cls)
        try:
            driver._configure(Path(directory), run_id, target, approver_ids,
                              publisher_id, clock, native_factory, creating=False)
            marker = driver._read_marker()
            if marker.get('phase') != 'never_launched':
                raise UntrustedInput('candidate launch history is not safely pre-execution')
            driver._origin = marker.get('origin_digest')
            driver._origin_ref = marker.get('origin_ref')
            if (not driver._origin or not isinstance(driver._origin_ref, str)
                    or not driver._origin_ref or marker != driver._marker('never_launched')):
                raise UntrustedInput('candidate binding mismatch')
            driver._capture_files()  # Refuse missing/replaced files before constructors.
            driver._components(origin_verifier, evidence, fetch_raw, notifier, release_check)
            if not driver.guard(approver_ids):
                raise UntrustedInput('candidate is not a fresh pre-execution context')
            return driver
        except Exception:
            driver.close()
            raise

    def _configure(self, root, run_id, target, approvers, publisher, clock, factory, *, creating):
        self._owner_fd = None
        self._lock = RLock()
        self._closed = False
        self._claimed = False
        self._native = self._request = None
        self._origin = None
        self._origin_ref = None
        self.store = self.journal = self.trace = None
        if (not root.is_dir() or root.is_symlink() or root.absolute() != root.resolve()
                or not isinstance(run_id, str) or not run_id
                or type(target) is not IssueTarget
                or type(approvers) is not frozenset or not approvers
                or any(type(value) is not int or value < 1 for value in approvers)
                or type(publisher) is not int or publisher < 1
                or not callable(factory)):
            raise ValueError('dedicated canonical directory and exact host bindings required')
        self.root, self.run_id = root.resolve(), run_id
        self._target, self._approvers, self._publisher = target, approvers, publisher
        self._clock, self._factory = clock, factory
        self._root_identity = self._identity(self.root, directory=True)
        flags = os.O_RDWR | os.O_NOFOLLOW | (os.O_CREAT | os.O_EXCL if creating else 0)
        self._owner_fd = os.open(self.root / 'owner.lock', flags, 0o600)
        try:
            fcntl.flock(self._owner_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise UntrustedInput('candidate already has an active owner') from None

    @staticmethod
    def _identity(path, *, directory=False):
        info = path.lstat()
        if (not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
                or info.st_uid != os.getuid()):
            raise UntrustedInput('candidate file ownership/type changed')
        return info.st_dev, info.st_ino

    def _marker(self, phase):
        return {'schema': 'co.preexecution-human.v1', 'run_id': self.run_id,
                'repository': self._target.repository, 'issue': self._target.number,
                'approver_ids': sorted(self._approvers), 'publisher_id': self._publisher,
                'origin_digest': self._origin, 'origin_ref': self._origin_ref, 'phase': phase}

    def _read_marker(self):
        fd = os.open(self.root / 'driver.json', os.O_RDONLY | os.O_NOFOLLOW)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise ValueError('marker type')
            raw = os.read(fd, 4097)
            if len(raw) > 4096:
                raise ValueError('marker size')
            value = json.loads(raw)
            if type(value) is not dict or canonical(value).encode() != raw:
                raise ValueError('canonical marker required')
            return value
        except Exception:
            raise UntrustedInput('candidate launch marker unavailable') from None
        finally:
            os.close(fd)

    def _write_marker(self, phase):
        temporary = self.root / 'driver.next'
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            payload = canonical(self._marker(phase)).encode()
            with os.fdopen(fd, 'wb', closefd=False) as output:
                output.write(payload)
                output.flush()
                os.fsync(fd)
            os.replace(temporary, self.root / 'driver.json')
            directory_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
            try: os.fsync(directory_fd)
            finally: os.close(directory_fd)
        finally:
            os.close(fd)

    def _capture_files(self):
        if (self._identity(self.root, directory=True) != self._root_identity
                or (self.root / 'driver.next').exists()):
            raise UntrustedInput('candidate directory or interrupted marker update changed')
        names = ('control.sqlite', 'gateway.sqlite', 'trace.sqlite', 'owner.lock')
        self._files = {name: self._identity(self.root / name) for name in names}

    def _files_intact(self):
        return (self._identity(self.root, directory=True) == self._root_identity
                and not (self.root / 'driver.next').exists()
                and all(self._identity(self.root / name) == identity
                        for name, identity in self._files.items()))

    def _components(self, origin_verifier, evidence, fetch_raw, notifier, release_check):
        self.journal = GatewayJournal(self.root / 'gateway.sqlite')
        def verifier(source):
            return (origin_verifier(source) if source == self._origin_ref
                    else self.journal.verifier(source))
        self.store = ControlStore(self.root / 'control.sqlite', verifier=verifier,
                                  evidence=evidence, clock=self._clock)
        self.state = self.store.controller()
        self.judgment = self.store.judgment()
        self.trace = Trace(self.root / 'trace.sqlite', PublicationPolicy(release_check))
        self.connector = ConnectorGitHub(self._target, fetch_raw)
        self.gateway = HumanGateway(self.state, self.store.intake(), self.journal,
            self.connector, notifier, self.trace, target=self._target,
            approver_ids=self._approvers, publisher_id=self._publisher,
            isolation_guard=self.guard, clock=self._clock)

    def guard(self, approvers):
        """Fresh product-Worker absence; never an execution-protection receipt."""
        with self._lock:
            try:
                if (self._closed or self._claimed or type(approvers) is not frozenset
                        or approvers != self._approvers
                        or self._request is not None or self._native is not None
                        or self._read_marker() != self._marker('never_launched')
                        or not self._files_intact()):
                    return False
                run = self.state.get_run(self.run_id)
                return (not self.state.attempts(self.run_id)
                        and run.authenticated_origin_ref == self._origin_ref
                        and body_digest(create_run_body(self.run_id, run.original_intent)) == self._origin)
            except Exception:
                return False

    def _question(self, ref):
        if ref.run_id != self.run_id or ref.attempt_id is not None:
            raise UntrustedInput('only this Run pre-execution Human questions are supported')

    def stage_question(self, ref, request_id, context):
        with self._lock:
            self._question(ref)
            try:
                return self.gateway.publish(ref, request_id, context)
            except DeliveryUncertain:
                action = self.connector.take_question()
                if action is None: raise
                return action

    def reconcile(self, ref, request_id, comment_id):
        with self._lock:
            self._question(ref)
            return self.gateway.reconcile(ref, request_id, comment_id)

    def receive(self, ref, request_id, comment_id, *, expected_revision):
        with self._lock:
            self._question(ref)
            return self.gateway.receive(ref, request_id, comment_id,
                                        expected_revision=expected_revision)

    def notify(self, ref, request_id):
        with self._lock:
            self._question(ref)
            return self.gateway.notify(ref, request_id)

    def execute(self, request):
        """Sole lazy launch. Caller must already have reserved a judged Attempt."""
        with self._lock:
            if self._closed or self._claimed or request.ref.run_id != self.run_id:
                raise InvalidTransition('candidate launch is unavailable or already claimed')
            if (self._read_marker() != self._marker('never_launched')
                    or not self._files_intact()):
                raise UntrustedInput('candidate launch history changed')
            attempt = self.state.get_attempt(request.ref)
            run = self.state.get_run(self.run_id)
            if (self.state.attempts(self.run_id) != (attempt,)
                    or run.stop_requested or run.state in c.TERMINAL
                    or attempt.conditions != request.conditions
                    or self.state.get_job(self.run_id, request.ref.job_id) != request.job
                    or attempt.state is not c.State.PENDING or attempt.started_at is not None
                    or attempt.stop_reply is not None or attempt.result is not None
                    or self.state.execute_receipt(request.ref) is not None):
                raise InvalidTransition('exact newly reserved Attempt required')
            self._claimed = True  # Remains closed even when durable claim fails.
            self._write_marker('launch_claimed')  # fsync BEFORE factory or Native IO.
            self._request = request
            self._native = self._factory(request)
            return self._native.execute(request)

    def _delegate(self, name, ref, *args):
        with self._lock:
            if self._closed or self._native is None or ref != self._request.ref:
                raise InvalidTransition('exact owned Native Attempt required')
            return getattr(self._native, name)(ref, *args)

    def events(self, ref, after=None): return self._delegate('events', ref, after)
    def status(self, ref): return self._delegate('status', ref)
    def stop(self, ref): return self._delegate('stop', ref)

    def respond(self, response):
        with self._lock:
            if self._closed or self._native is None or response.ref != self._request.ref:
                raise InvalidTransition('exact owned Native Attempt required')
            return self._native.respond(response)

    def resume(self, state):
        with self._lock:
            if self._closed or self._native is None or state.ref != self._request.ref:
                raise InvalidTransition('exact owned Native Attempt required')
            return self._native.resume(state)

    def usage(self):
        with self._lock:
            return self._native.usage() if self._native is not None and not self._closed else ()

    def close(self):
        """Attempt bounded owned-Native cleanup, never invent confirmed cessation."""
        lock = getattr(self, '_lock', RLock())
        with lock:
            if getattr(self, '_closed', False): return
            self._closed = True
            failed = False
            native = getattr(self, '_native', None)
            if native is not None:
                try:
                    native.close()
                except Exception:
                    failed = True
            for name in ('store', 'journal', 'trace'):
                component = getattr(self, name, None)
                if component is not None:
                    try: component.close()
                    except Exception: failed = True
            if getattr(self, '_owner_fd', None) is not None:
                os.close(self._owner_fd)
                self._owner_fd = None
            if failed:
                raise RuntimeError('candidate cleanup unconfirmed; inspect owned resources') from None
