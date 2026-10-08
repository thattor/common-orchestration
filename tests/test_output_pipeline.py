"""0.4 output pipeline: persisted output -> bound AC -> single selection.

Adapters are synthetic; control state, blob storage and digest binding run
the production v4 code paths.
"""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest

from co_v4 import contracts as c
from co_v4.ac import Acceptance, CheckEvidence, Finding, JobGoal
from co_v4.adapter_capacity import (ADAPTERS, CHILD_LACKS_COLLECTOR,
    MAX_CONCURRENT, CapacityError, CapacityLedger, NativeAdapterPools,
    PooledAdapter)
from co_v4.catalog import Catalog, CatalogEntry, Verification
from co_v4.controller import Controller, JobPlan, POLICY_TERMINAL_REASONS
from co_v4.output_store import IntegrityError, OutputStore
from co_v4.state import (Conflict, ControlStore, DigestConflict, IngressReceipt,
                         InvalidTransition, NotFound, StoreUnavailable,
                         UntrustedInput, body_digest)
from co_v4.usage import UsageStore
from test_state import Harness
from test_adapter_capacity import Child
from fixture_e2e import Scenario, ArtifactAdapter, SYNTHETIC, USE


NOW = datetime(2026, 9, 28, tzinfo=timezone.utc)

# Independent golden vectors (evidence independent-output-vectors.json).
# Composed vs decomposed codepoints must NOT fold; empty items hash normally.
GOLDEN_VECTORS = (
    {'texts': ('A\né👘',),
     'blobs': (('sha256:1f3bb656863e7e6daca188f51d3f3ffd771fd3ccbbf8c0d2fbc4c4f259fdf94a', 8),),
     'manifest': '[{"blob_digest":"sha256:1f3bb656863e7e6daca188f51d3f3ffd771fd3ccbbf8c0d2fbc4c4f259fdf94a","index":0,"media_type":"text/plain","size":8}]',
     'digest': 'sha256:975e6de18edfb4f5b356db1578135a7d4083d6e15918840e531b011af2ce586b'},
    {'texts': ('A\né👘',),
     'blobs': (('sha256:a7584b396418c9e6604200f608bdea5e4c50e57cb1d93374d8653a6315d07d7f', 9),),
     'manifest': '[{"blob_digest":"sha256:a7584b396418c9e6604200f608bdea5e4c50e57cb1d93374d8653a6315d07d7f","index":0,"media_type":"text/plain","size":9}]',
     'digest': 'sha256:557df6cdf83c6f6dd35dab2ccec917860e9517391b00d387cf80cc80b30a94dc'},
    {'texts': ('日本語', ''),
     'blobs': (('sha256:77710aedc74ecfa33685e33a6c7df5cc83004da1bdcef7fb280f5c2b2e97e0a5', 9),
               ('sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 0)),
     'manifest': '[{"blob_digest":"sha256:77710aedc74ecfa33685e33a6c7df5cc83004da1bdcef7fb280f5c2b2e97e0a5","index":0,"media_type":"text/plain","size":9},{"blob_digest":"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","index":1,"media_type":"text/plain","size":0}]',
     'digest': 'sha256:ad27f128d7ac0200b4f939ddb6e5178a606b692596647f954865a9e6aeb55370'},
    {'texts': ('',),
     'blobs': (('sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 0),),
     'manifest': '[{"blob_digest":"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","index":0,"media_type":"text/plain","size":0}]',
     'digest': 'sha256:9981aee018f7bb4a0a9ee520deb29e8ab9f9b458cfdd6cbca2823bf461d28423'},
    {'texts': ('same text', 'second item'),
     'blobs': (('sha256:2e68a7bba11b90d1bae1daea2dd4951779cf45d5897c62539d01f44054bcb1e0', 9),
               ('sha256:e0414f5b3607b9512034e097f2ed074581cde127b56675eb88de5a85a27fb81e', 11)),
     'manifest': '[{"blob_digest":"sha256:2e68a7bba11b90d1bae1daea2dd4951779cf45d5897c62539d01f44054bcb1e0","index":0,"media_type":"text/plain","size":9},{"blob_digest":"sha256:e0414f5b3607b9512034e097f2ed074581cde127b56675eb88de5a85a27fb81e","index":1,"media_type":"text/plain","size":11}]',
     'digest': 'sha256:b4ca9ea80030a5e003bb429ed005c41ab278f3555ee30849944bbecfbf56a3bf'},
)


def profile(models=('fixture-a', 'fixture-b'), requires_output=True,
            effect_class='pure', routes=None):
    return c.TaskProfile(
        'fixture-task', 'sha256:' + '0' * 64, effect_class, requires_output,
        routes if routes is not None else tuple(
            (m, SYNTHETIC, 'fixture:environment') for m in models))


def output_run(directory, **kwargs):
    kwargs.setdefault('profile', profile())
    kwargs.setdefault('candidate_jobs', ('squares',))
    kwargs.setdefault('output_mode', 'collect')
    return Scenario(directory, **kwargs)


def drive_until(s, reason, limit=15):
    for _ in range(limit):
        progress = s.step()
        if progress.reason == reason:
            return progress
        if progress.state in c.TERMINAL:
            break
    raise AssertionError('reason %r not reached' % reason)


def authenticate_stop(scenario, source):
    """Bind an authenticated northbound stop receipt into the fixture journal."""
    body = {'operation': 'stop_run', 'run_id': 'run'}
    scenario.journal.bind(source, body, IngressReceipt(
        'fixture-human', source, body_digest(body), scenario.now))


def passing_acceptance(run_verdict='incomplete'):
    """Verifier independent of artifact bytes; isolates the selection gate."""
    def verify(request):
        if request.kind == 'job':
            return CheckEvidence(body_digest(request), Finding('pass', ('e',)),
                                 (Finding('pass', ('e',)),))
        refs = ('e',) if run_verdict == 'pass' else ()
        return CheckEvidence(body_digest(request), Finding(run_verdict, refs), ())
    return Acceptance(verify)


class NoCollector:
    """Registered adapter lacking OutputCollector; dispatch must reject it."""
    def __init__(self):
        self.requests = []
    def execute(self, request):
        self.requests.append(request)
        return c.OperationReply(request.ref, c.OperationStatus.ACCEPTED, 'unreached')
    def events(self, ref, after=None): return ()
    def respond(self, response):
        return c.OperationReply(response.ref, c.OperationStatus.UNSUPPORTED, 'unreached')
    def resume(self, state):
        return c.OperationReply(state.ref, c.OperationStatus.UNSUPPORTED, 'unreached')
    def stop(self, ref):
        return c.StopReply(ref, c.StopStatus.CONFIRMED, 'unreached', 'fixture:never-ran')
    def status(self, ref): raise ValueError('no attempt exists')
    def usage(self): return ()


class FlakyCollector(ArtifactAdapter):
    """Collector raises CollectionError for the first `fail_collect` calls."""
    def __init__(self, *args, fail_collect=1, **kwargs):
        super().__init__(*args, **kwargs)
        self.remaining = fail_collect
    def collect_output(self, ref):
        if self.remaining > 0:
            self.remaining -= 1
            raise c.CollectionError('synthetic collector unavailable')
        return super().collect_output(ref)


class BadShapeCollector(ArtifactAdapter):
    """Returns non-OutputItem output; a policy violation, never retryable."""
    def collect_output(self, ref):
        return (('text/plain', 'x'),)


class FixedOutput(ArtifactAdapter):
    """Collector returning a fixed item tuple, ignoring artifact bytes."""
    def __init__(self, *args, texts=(), **kwargs):
        super().__init__(*args, **kwargs)
        self._texts = texts
    def collect_output(self, ref):
        return tuple(c.OutputItem(index, 'text/plain', text)
                     for index, text in enumerate(self._texts))


class RefusingAdapter:
    """Terminal policy Result; synthetic, no artifact and no output."""
    def __init__(self, reason='content_filter', stop_status=c.StopStatus.CONFIRMED):
        self.reason, self.stop_status = reason, stop_status
        self.requests, self.stops = [], []
        self._events = {}
    def execute(self, request):
        self.requests.append(request)
        self._events[request.ref] = [c.ResultEvent(request.ref,
            'terminal:' + request.ref.attempt_id,
            c.Result(request.ref, c.State.FAILED, self.reason, 'synthetic refusal'))]
        return c.OperationReply(request.ref, c.OperationStatus.ACCEPTED, 'fixture')
    def events(self, ref, after=None):
        log = self._events[ref]
        if after is None:
            return tuple(log)
        index = next(i for i, e in enumerate(log) if e.event_id == after)
        return tuple(log[index + 1:])
    def respond(self, response):
        return c.OperationReply(response.ref, c.OperationStatus.UNSUPPORTED, 'no relay')
    def resume(self, state):
        return c.OperationReply(state.ref, c.OperationStatus.UNSUPPORTED, 'no resume')
    def stop(self, ref):
        self.stops.append(ref)
        return c.StopReply(ref, self.stop_status, 'fixture stop',
            'fixture:ceased:' + ref.attempt_id
            if self.stop_status == c.StopStatus.CONFIRMED else None)
    def status(self, ref): raise ValueError('no attempt exists')
    def usage(self): return ()
    def collect_output(self, ref):
        raise c.CollectionError('refused attempt has no output')


class CollectingChild(Child):
    """Pooled child with a verified collector; collected bytes are fixed."""
    def collect_output(self, ref):
        return (c.OutputItem(0, 'text/plain', 'collected text'),)


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def test_rejected_then_accepted_output_and_only_accepted_selected(self):
        s = output_run(self.dir / 'a', scripts={'squares': ['wrong', 'good']})
        try:
            final = s.drive()
            self.assertEqual((final.state, final.reason),
                             (c.State.COMPLETED, 'human_goal_verified'))
            selection = s.state.get_run('run').output_selection
            self.assertIsNotNone(selection)
            self.assertEqual(selection.job_id, 'squares')
            squares = [a for a in s.state.attempts('run') if a.ref.job_id == 'squares']
            self.assertEqual(len(squares), 2)
            first, second = squares
            self.assertEqual(first.ac.verdict, 'fail')
            self.assertIsNotNone(first.output)
            self.assertEqual(second.ac.verdict, 'pass')
            self.assertEqual(second.ac.output_digest, second.output.digest)
            self.assertEqual(selection.attempt_ref, second.ref)
            self.assertEqual(selection.output_digest, second.output.digest)
            # The first rejected digest is never committed as the Run output.
            self.assertNotEqual(selection.output_digest, first.output.digest)
            self.assertTrue(selection.output_digest.startswith('sha256:'))
        finally:
            s.close()

    def test_reopen_recovers_each_output_boundary(self):
        for index, boundary in enumerate(
                ('cessation_confirmed', 'output_persisted', 'job_goal_unmet')):
            s = output_run(self.dir / ('reopen' + str(index)),
                           scripts={'squares': ['wrong', 'good']})
            try:
                drive_until(s, boundary)
                s.controller = s.build()
                final = s.drive()
                self.assertEqual(final.state, c.State.COMPLETED, boundary)
                self.assertIsNotNone(
                    s.state.get_run('run').output_selection, boundary)
            finally:
                s.close()
        # Crash after the last Job Goal but before Run finalization.
        s = output_run(self.dir / 'reopen-final',
                       scripts={'squares': ['wrong', 'good']})
        try:
            seen = 0
            while True:
                progress = s.step()
                if progress.reason == 'job_goal_verified':
                    seen += 1
                    if seen == 2:
                        break
            s.controller = s.build()
            final = s.drive()
            self.assertEqual(final.state, c.State.COMPLETED)
            self.assertIsNotNone(s.state.get_run('run').output_selection)
        finally:
            s.close()

    def test_orphan_blobs_before_db_commit_recollect_safely(self):
        s = output_run(self.dir / 'orphan', scripts={'squares': ['good']})
        try:
            drive_until(s, 'cessation_confirmed')
            ref = s.controller._active
            # Crash window: blobs+manifest committed, DB reference never written.
            orphan = s.output_store.put(ref, s.adapter.collect_output(ref))
            s.controller = s.build()
            final = s.drive()
            self.assertEqual(final.state, c.State.COMPLETED)
            selection = s.state.get_run('run').output_selection
            self.assertEqual(selection.output_digest, orphan.digest)
        finally:
            s.close()

    def test_collect_failure_pure_retries_without_ac_fabrication(self):
        s = output_run(self.dir / 'flaky',
                       adapter=FlakyCollector(self.dir / 'flaky'),
                       scripts={'squares': ['good']})
        try:
            final = s.drive()
            self.assertEqual(final.state, c.State.COMPLETED)
            squares = [a for a in s.state.attempts('run') if a.ref.job_id == 'squares']
            self.assertEqual(len(squares), 2)
            failed, accepted = squares
            self.assertIsNone(failed.ac)  # no fabricated AC verdict
            self.assertIsNone(failed.output)
            self.assertEqual(failed.collection_failure.kind, 'collection_unavailable')
            failures = s.state.history('run', 'job_failures')
            self.assertEqual([f.kind for f in failures], ['collection_unavailable'])
            checked = {g.result.ref for g in s.state.history('run', 'job_goals')}
            self.assertNotIn(failed.ref, checked)
            self.assertEqual(s.state.get_run('run').output_selection.attempt_ref,
                             accepted.ref)
        finally:
            s.close()

    def test_collect_failure_effectful_fails_without_retry(self):
        s = output_run(self.dir / 'effectful',
                       adapter=FlakyCollector(self.dir / 'effectful', fail_collect=9),
                       profile=profile(effect_class='effectful'),
                       scripts={'squares': ['good']})
        try:
            final = s.drive()
            # Effectful collection loss is terminal approval_required after the
            # actual collection failure, never an automatic re-execution.
            self.assertEqual((final.state, final.reason),
                             (c.State.FAILED, 'approval_required'))
            self.assertEqual(len(s.adapter.requests), 1)  # effectful never re-executes
            attempt, = s.state.attempts('run')
            self.assertIsNotNone(attempt.collection_failure)
            self.assertEqual(attempt.collection_failure.kind, 'collection_unavailable')
            self.assertEqual([f.kind for f in s.state.history('run', 'job_failures')],
                             ['collection_unavailable'])
            self.assertIsNone(attempt.ac)       # collection loss is not an AC verdict
            self.assertIsNone(attempt.output)
            self.assertIsNone(s.state.get_run('run').output_selection)
        finally:
            s.close()

    def test_blob_corruption_is_integrity_failure_not_retry(self):
        s = output_run(self.dir / 'corrupt', scripts={'squares': ['good', 'good']})
        try:
            drive_until(s, 'output_persisted')
            attempt = s.state.get_attempt(s.controller._active)
            blob = (s.output_store.root / 'blobs'
                    / attempt.output.items[0].blob_digest[7:])
            blob.write_bytes(b'tampered bytes')
            final = s.drive()
            self.assertEqual((final.state, final.reason),
                             (c.State.FAILED, 'output_integrity_failure'))
            self.assertEqual(len(s.adapter.requests), 1)  # integrity never retries
            # The committed immutable output makes a JobFailure mutually
            # exclusive; corruption fails the Run without one.
            self.assertEqual(s.state.history('run', 'job_failures'), ())
            settled = s.state.get_attempt(attempt.ref)
            self.assertEqual(settled.output, attempt.output)  # immutable binding kept
            self.assertIsNone(settled.collection_failure)
            self.assertIsNone(settled.ac)
            self.assertIsNone(s.state.get_run('run').output_selection)
        finally:
            s.close()

    def test_invalid_collector_output_is_policy_failure_not_retry(self):
        s = output_run(self.dir / 'policy', adapter=BadShapeCollector(self.dir / 'policy'),
                       scripts={'squares': ['good', 'good']})
        try:
            final = s.drive()
            self.assertEqual((final.state, final.reason),
                             (c.State.FAILED, 'output_policy_failure'))
            self.assertEqual(len(s.adapter.requests), 1)
            self.assertEqual([f.kind for f in s.state.history('run', 'job_failures')],
                             ['policy_failure'])
            self.assertIsNone(s.state.get_run('run').output_selection)
        finally:
            s.close()

    def test_zero_or_multiple_accepted_candidates_fail_closed(self):
        for name, candidates in (('zero', ()), ('multiple', ('squares', 'total'))):
            s = output_run(self.dir / name, candidate_jobs=candidates)
            try:
                final = s.drive()
                self.assertEqual((final.state, final.reason),
                                 (c.State.FAILED, 'output_unavailable'), name)
                self.assertIsNone(s.state.get_run('run').output_selection)
            finally:
                s.close()

    def test_run_without_output_requirement_keeps_internal_semantics(self):
        s = output_run(self.dir / 'nooutput', profile=profile(requires_output=False),
                       candidate_jobs=())
        try:
            final = s.drive()
            self.assertEqual(final.state, c.State.COMPLETED)
            self.assertIsNone(s.state.get_run('run').output_selection)
        finally:
            s.close()

    def test_later_required_job_failure_blocks_publication(self):
        s = output_run(self.dir / 'latefail', scripts={'total': ['wrong'] * 6})
        try:
            final = s.drive()
            self.assertEqual(final.state, c.State.FAILED)
            self.assertIsNone(s.state.get_run('run').output_selection)
            squares = [a for a in s.state.attempts('run') if a.ref.job_id == 'squares']
            self.assertIsNotNone(squares[0].output)  # persisted but never selected
        finally:
            s.close()

    def test_candidate_never_routes_to_unverified_output_mode(self):
        s = output_run(self.dir / 'nocollection', output_mode='none')
        try:
            final = s.drive()
            self.assertEqual((final.state, final.reason),
                             (c.State.FAILED, 'output_unavailable'))
            self.assertEqual(s.adapter.requests, [])
        finally:
            s.close()

    def test_candidate_dispatch_rejects_adapter_without_collector(self):
        s = output_run(self.dir / 'nocollect', adapter=NoCollector())
        try:
            final = s.drive()
            self.assertEqual((final.state, final.reason),
                             (c.State.FAILED, 'output_unavailable'))
            self.assertEqual(s.adapter.requests, [])
        finally:
            s.close()

    def test_pure_profile_cannot_dispatch_outside_pinned_routes(self):
        s = output_run(self.dir / 'routes',
                       profile=profile(routes=(
                           ('fixture-a', SYNTHETIC, 'fixture:environment'),)))
        try:
            final = s.drive()
            self.assertEqual(final.state, c.State.COMPLETED)
            self.assertTrue(s.adapter.requests)
            self.assertEqual({r.conditions.model for r in s.adapter.requests},
                             {'fixture-a'})
        finally:
            s.close()
        denied = output_run(self.dir / 'noroutes', profile=profile(routes=()))
        try:
            final = denied.drive()
            self.assertEqual(final.state, c.State.FAILED)
            self.assertEqual(denied.adapter.requests, [])
        finally:
            denied.close()

    def test_policy_reasons_are_terminal_without_ac_failure_or_retry(self):
        # Exact canonical reasons only; none may be retried, rerouted or
        # converted into AC/JobFailure outcomes.
        self.assertEqual(sorted(POLICY_TERMINAL_REASONS),
                         ['content_filter', 'protocol_violation',
                          'provider_refusal'])
        for reason in sorted(POLICY_TERMINAL_REASONS):
            with self.subTest(reason=reason):
                s = output_run(self.dir / ('policy-' + reason),
                               adapter=RefusingAdapter(reason))
                try:
                    final = s.drive()
                    run = s.state.get_run('run')
                    self.assertEqual((final.state, final.reason),
                                     (c.State.FAILED, reason))
                    self.assertEqual(run.final_reason, reason)
                    self.assertTrue(run.cessation_confirmed)
                    attempts = s.state.attempts('run')
                    self.assertEqual(len(attempts), 1)       # exactly one Attempt
                    self.assertEqual(len(s.adapter.requests), 1)  # no reroute
                    attempt = attempts[0]
                    self.assertEqual((attempt.result.status, attempt.result.reason),
                                     (c.State.FAILED, reason))
                    self.assertIsNone(attempt.ac)            # zero AC records
                    self.assertIsNone(attempt.output)        # no collection
                    self.assertIsNone(attempt.collection_failure)
                    self.assertEqual(s.state.history('run', 'ac_history'), ())
                    self.assertEqual(s.state.history('run', 'job_goals'), ())
                    self.assertEqual(s.state.history('run', 'job_failures'), ())
                    self.assertEqual(s.checks, [])           # verifier never called
                    self.assertIsNone(run.output_selection)
                    # No sibling Job replan/dispatch after the policy terminal.
                    self.assertEqual(len(s.plan_calls), 1)
                    self.assertEqual(run.job_ids, ('squares',))
                finally:
                    s.close()

    def test_committed_stop_preempts_pending_policy_result(self):
        s = output_run(self.dir / 'stop-first',
                       adapter=RefusingAdapter('provider_refusal'))
        try:
            drive_until(s, 'execute_receipt')  # Result queued, not yet processed
            authenticate_stop(s, 'stop:before')
            s.store.intake().record_stop_request('run', 'stop:before')
            final = s.drive()
            run = s.state.get_run('run')
            # The already-committed stop owns the terminal transition.
            self.assertEqual((final.state, final.reason),
                             (c.State.FAILED, 'human_stop'))
            self.assertTrue(run.stop_requested)
            attempts = s.state.attempts('run')
            self.assertEqual(len(attempts), 1)
            self.assertEqual(len(s.adapter.requests), 1)
            # The policy Result stays as written; it is not re-labeled.
            self.assertEqual(attempts[0].result.reason, 'provider_refusal')
            self.assertEqual(s.state.history('run', 'job_goals'), ())
            self.assertEqual(s.state.history('run', 'job_failures'), ())
            self.assertIsNone(run.output_selection)
        finally:
            s.close()

    def test_policy_terminal_supersedes_later_authenticated_stop(self):
        s = output_run(self.dir / 'stop-after',
                       adapter=RefusingAdapter('content_filter'))
        try:
            final = s.drive()
            self.assertEqual((final.state, final.reason),
                             (c.State.FAILED, 'content_filter'))
            revision = s.state.get_run('run').revision
            authenticate_stop(s, 'stop:after')
            run = s.store.intake().record_stop_request('run', 'stop:after')
            # Terminal Run: stop intake replays without mutating state.
            self.assertEqual(run.revision, revision)
            self.assertEqual(run.final_reason, 'content_filter')
            self.assertFalse(run.stop_requested)
        finally:
            s.close()

    def test_policy_result_unconfirmed_cessation_holds_without_retry(self):
        s = output_run(self.dir / 'policy-unconfirmed',
                       adapter=RefusingAdapter('protocol_violation',
                                               c.StopStatus.UNCONFIRMED))
        try:
            progress = s.drive(lambda p: p.reason == 'terminal_cessation_unconfirmed')
            for _ in range(3):  # stable hold: no finalize, no new dispatch
                progress = s.step()
                self.assertEqual((progress.state, progress.reason),
                                 (c.State.RUNNING, 'terminal_cessation_unconfirmed'))
            run = s.state.get_run('run')
            self.assertNotIn(run.state, c.TERMINAL)
            self.assertEqual(len(s.adapter.requests), 1)
            self.assertEqual(len(s.state.attempts('run')), 1)
            self.assertEqual(s.state.history('run', 'job_goals'), ())
            self.assertEqual(s.state.history('run', 'job_failures'), ())
            self.assertIsNone(run.output_selection)
            self.assertGreaterEqual(len(s.adapter.stops), 1)
            attempt = s.state.attempts('run')[0]
            self.assertEqual(attempt.stop_reply.status, c.StopStatus.UNCONFIRMED)
        finally:
            s.close()

    def test_empty_output_is_persisted_but_never_selected(self):
        # Candidate selection requires at least one non-empty item; empty
        # output is never published as a COMPLETED Run output.
        for name, texts in (('empty-items', ()), ('empty-text', ('',))):
            with self.subTest(case=name):
                s = output_run(self.dir / name,
                               adapter=FixedOutput(self.dir / name, texts=texts))
                s.verify = passing_acceptance('pass')._verify
                s.controller = s.build()
                try:
                    final = s.drive()
                    run = s.state.get_run('run')
                    self.assertEqual((final.state, final.reason),
                                     (c.State.FAILED, 'output_unavailable'))
                    self.assertIsNone(run.output_selection)
                    squares = [a for a in s.state.attempts('run')
                               if a.ref.job_id == 'squares']
                    self.assertEqual(len(squares), 1)
                    self.assertIsNotNone(squares[0].output)  # persisted, not selectable
                    self.assertFalse(
                        any(i.size > 0 for i in squares[0].output.items))
                finally:
                    s.close()

    def test_output_with_one_nonempty_item_remains_selectable(self):
        s = output_run(self.dir / 'mixed',
                       adapter=FixedOutput(self.dir / 'mixed',
                                           texts=('nonempty', '')))
        s.verify = passing_acceptance('pass')._verify
        s.controller = s.build()
        try:
            final = s.drive()
            self.assertEqual((final.state, final.reason),
                             (c.State.COMPLETED, 'human_goal_verified'))
            run = s.state.get_run('run')
            self.assertIsNotNone(run.output_selection)
            squares = [a for a in s.state.attempts('run') if a.ref.job_id == 'squares']
            self.assertEqual(run.output_selection.output_digest,
                             squares[-1].output.digest)
        finally:
            s.close()


class StateBindingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.h = Harness(self.tmp.name)
        self.addCleanup(self.h.store.close)
        self.store = OutputStore(Path(self.tmp.name) / 'outputs')

    def _job(self):
        job = c.Job('r', 'j', 'create output', ('inspect output',),
                    output_candidate=True)
        d = self.h.judgment.judge(self.h.request(proposed=job))
        self.h.ctrl.add_job(job, d.decision_id, self.h.rev())
        return job

    def _ceased(self, name, model='m', output=None):
        a = self.h.begin(name, conditions=replace(self.h.conditions, model=model))
        self.h.finish(a.ref, c.State.COMPLETED)
        # finish() records the Result and bumps the Attempt revision; re-read
        # before recording cessation or a stale-revision Conflict results.
        a = self.h.ctrl.record_stop(
            c.StopReply(a.ref, c.StopStatus.CONFIRMED, 'fixture', 'ev:' + name),
            self.h.ctrl.get_attempt(a.ref).revision)
        if output is not None:
            out = self.store.put(a.ref, (c.OutputItem(0, 'text/plain', output),))
            a = self.h.ctrl.record_attempt_output(a.ref, out, a.revision)
        return a

    def test_output_and_failure_mutual_exclusion_and_digest_conflict(self):
        job = self._job()
        a = self._ceased('a', output='hello')
        different = c.AttemptOutput(a.ref, 'sha256:' + '1' * 64,
            (c.OutputItemMeta(0, 'text/plain', 'sha256:' + '2' * 64, 1),), 1)
        with self.assertRaises(DigestConflict):
            self.h.ctrl.record_attempt_output(a.ref, different, a.revision)
        # Same-digest replay is a no-op, even with a stale revision.
        replay = self.h.ctrl.record_attempt_output(
            a.ref, self.store.put(a.ref, (c.OutputItem(0, 'text/plain', 'hello'),)), -1)
        self.assertEqual(replay.output.digest, a.output.digest)
        failure = c.JobFailure(job, a.result, 'collection_unavailable',
                               ('output:collect:fixture',))
        with self.assertRaises(InvalidTransition):
            self.h.ctrl.record_job_failure(failure, a.revision)

    def test_failure_then_output_rejected_and_goal_binding_rules(self):
        job = self._job()
        a = self._ceased('a')
        failure = c.JobFailure(job, a.result, 'integrity_failure',
                               ('output:integrity:fixture',))
        self.h.ctrl.record_job_failure(failure, a.revision)
        with self.assertRaises(InvalidTransition):
            self.h.ctrl.record_attempt_output(
                a.ref, self.store.put(a.ref, (c.OutputItem(0, 'text/plain', 'x'),)),
                self.h.ctrl.get_attempt(a.ref).revision)
        b = self._ceased('b', model='m2', output='hello')
        mismatched = JobGoal(job, b.result,
            c.ACRecord(b.ref, 'pass', ('e',), 'sha256:' + '9' * 64),
            Finding('pass', ('e',)))
        with self.assertRaises(InvalidTransition):
            self.h.ctrl.record_job_goal(mismatched, self.h.rev())
        unbound = JobGoal(job, b.result, c.ACRecord(b.ref, 'pass', ('e',)),
                          Finding('pass', ('e',)))
        with self.assertRaises(InvalidTransition):
            self.h.ctrl.record_job_goal(unbound, self.h.rev())
        bound = JobGoal(job, b.result,
            c.ACRecord(b.ref, 'pass', ('e',), b.output.digest),
            Finding('pass', ('e',)))
        self.assertEqual(self.h.ctrl.record_job_goal(bound, self.h.rev()), bound)
        # Binding to output that was never persisted is rejected.
        d = self._ceased('c', model='m3')
        ghost = JobGoal(job, d.result,
            c.ACRecord(d.ref, 'pass', ('e',), 'sha256:' + '8' * 64),
            Finding('pass', ('e',)))
        with self.assertRaises(InvalidTransition):
            self.h.ctrl.record_job_goal(ghost, self.h.rev())

    def test_output_requires_successful_result_and_confirmed_cessation(self):
        job = self._job()
        a = self.h.begin('a')
        self.h.finish(a.ref, c.State.COMPLETED)
        out = self.store.put(a.ref, (c.OutputItem(0, 'text/plain', 'x'),))
        with self.assertRaises(InvalidTransition):  # no confirmed cessation yet
            self.h.ctrl.record_attempt_output(
                a.ref, out, self.h.ctrl.get_attempt(a.ref).revision)
        # Actual confirmed cessation settles 'a' so 'b' may be admitted.
        a = self.h.ctrl.record_stop(
            c.StopReply(a.ref, c.StopStatus.CONFIRMED, 'fixture', 'ev:a'),
            self.h.ctrl.get_attempt(a.ref).revision)
        b = self.h.begin('b', conditions=replace(self.h.conditions, model='m2'))
        self.h.finish(b.ref, c.State.FAILED)
        b = self.h.ctrl.record_stop(
            c.StopReply(b.ref, c.StopStatus.CONFIRMED, 'fixture', 'ev:b'),
            self.h.ctrl.get_attempt(b.ref).revision)
        with self.assertRaises(InvalidTransition):  # no output for failed Attempts
            self.h.ctrl.record_attempt_output(
                b.ref, self.store.put(b.ref, (c.OutputItem(0, 'text/plain', 'x'),)),
                b.revision)

    def test_latest_attempt_failure_rejects_older_accepted_output(self):
        job = self._job()
        first = self._ceased('a', output='first')
        accepted = JobGoal(job, first.result,
            c.ACRecord(first.ref, 'pass', ('e',), first.output.digest),
            Finding('pass', ('e',)))
        self.h.ctrl.record_job_goal(accepted, self.h.rev())
        # A later Attempt for the same Job supersedes the accepted candidate.
        second = self._ceased('b', model='m2', output='second')
        failed = JobGoal(job, second.result,
            c.ACRecord(second.ref, 'fail', ('e2',), second.output.digest),
            Finding('fail', ('e2',)))
        self.h.ctrl.record_job_goal(failed, self.h.rev())
        goals = self.h.ctrl.history('r', 'job_goals')
        self.assertEqual([g.ac.verdict for g in goals], ['pass', 'fail'])
        # The historical pass cannot complete the Run or seed its selection.
        with self.assertRaises(InvalidTransition):
            self.h.ctrl.finalize_run('r', c.State.COMPLETED,
                                     'human_goal_verified', self.h.rev(), True)
        run = self.h.ctrl.finalize_run('r', c.State.FAILED,
                                     'output_unavailable', self.h.rev(), True)
        self.assertEqual(run.state, c.State.FAILED)
        self.assertIsNone(run.output_selection)

    def test_wait_independent_authenticated_stop(self):
        h = self.h
        h.authenticate('stop:1', {'operation': 'stop_run', 'run_id': 'r'})
        run = h.intake.record_stop_request('r', 'stop:1')
        self.assertTrue(run.stop_requested)
        self.assertEqual(h.intake.record_stop_request('r', 'stop:1'), run)
        with self.assertRaises(UntrustedInput):
            h.intake.record_stop_request('r', 'stop:unauthenticated')
        with self.assertRaises(NotFound):
            h.intake.record_stop_request('missing', 'stop:1')
        with self.assertRaisesRegex(Conflict, 'stop_requested'):
            h.job('blocked')  # a stopped Run accepts no new Jobs
        revision = h.rev()
        h.ctrl.finalize_run('r', c.State.FAILED, 'fixture_cancelled', revision)
        h.authenticate('stop:2', {'operation': 'stop_run', 'run_id': 'r'})
        terminal = h.intake.record_stop_request('r', 'stop:2')
        self.assertEqual((terminal.state, terminal.revision),
                         (c.State.FAILED, revision + 1))


class PoolOutputTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name).resolve() / 'capacity.sqlite'
        self.ledger = CapacityLedger(self.path)
        self.children = {}
        self.factory_calls = []

    def _factory(self, make=None):
        def factory(request):
            self.factory_calls.append(request)
            child = make(request) if make else Child()
            self.children[request.ref] = child
            return child
        return factory

    def _pool(self, make=None, ledger=None, path=None):
        return PooledAdapter('codex.app-server', ledger=ledger or self.ledger,
            canonical_ledger=path or self.path, factory=self._factory(make))

    def _request(self, index=0, candidate=False):
        ref = c.AttemptRef('run-' + str(index), 'job', 'attempt')
        return c.ExecuteRequest(ref, c.Job(ref.run_id, ref.job_id, 'fixture', (),
            output_candidate=candidate),
            c.ExecutionConditions('a', 'codex.app-server', '/fixture', 'env:1',
                                  ('fixture:controls',)))

    def _catalog(self, routes):
        """routes: (model, adapter, environment_ref) triples; one entry per pair."""
        verifications = {}
        for model, adapter, env in routes:
            verifications.setdefault((model, adapter), []).append(
                Verification(model, adapter, USE, env, 'fixture:official',
                             'fixture:implementation', 'fixture:measurement',
                             'fixture:ac', output_mode='collect'))
        return Catalog(tuple(CatalogEntry(model, adapter, {USE: 2}, tuple(vs))
                             for (model, adapter), vs in verifications.items()))

    def _composition(self, name, plans, *, factories=None, fill=0):
        """Harness + pooled Controller; plans is ((job_id, routes), ...) in order."""
        base = Path(self.tmp.name).resolve()
        root = base / name
        root.mkdir(mode=0o700)
        h = Harness(root)
        self.addCleanup(h.store.close)
        ledger = CapacityLedger(base / (name + '-capacity.sqlite'))
        for index in range(fill):
            self.assertTrue(ledger.reserve(
                self._request(name + '-fill-%d' % index), 'occupied'))
        catalog = self._catalog(tuple(
            route for _, routes in plans for route in routes))
        queue = [JobPlan(c.Job('r', job_id, 'create output', ('checked',),
                               output_candidate=True),
                         h.action, 'write-output', USE,
                         tuple(c.ExecutionConditions(m, a, '/fixture', env,
                               ('fixture:controls',))
                               for m, a, env in routes))
                 for job_id, routes in plans]
        def planner(run, completed, goal):
            return queue[len(completed)] if len(completed) < len(queue) else None
        def build(pools):
            return Controller('r', state=h.ctrl, judgment=h.judgment,
                catalog=catalog, usage=UsageStore(), adapters=pools,
                acceptance=passing_acceptance('incomplete'), planner=planner,
                clock=lambda: NOW,
                output_store=OutputStore(base / (name + '-outputs')))
        pools = NativeAdapterPools(canonical_ledger=ledger.path,
            factories=factories or {key: self._factory() for key in ADAPTERS})
        return h, ledger, pools, build(pools), build

    def _drive(self, controller, until=None, limit=24):
        reasons = []
        for _ in range(limit):
            progress = controller.step()
            reasons.append(progress.reason)
            if progress.reason == 'execute_receipt' and progress.active is not None:
                child = self.children[progress.active]
                child.finish(progress.active)
                child.stop_status = c.StopStatus.CONFIRMED
            if progress.state in c.TERMINAL or progress.reason == until:
                return progress, reasons
        raise AssertionError('expected progress %r did not occur: %r'
                             % (until, reasons))

    def test_missing_child_collector_never_executes_and_releases_slot(self):
        pool = self._pool()
        request = self._request(candidate=True)
        reply = pool.execute(request)
        self.assertEqual(reply.status, c.OperationStatus.UNAVAILABLE)
        self.assertIsNotNone(reply.never_started)
        self.assertEqual(reply.never_started.evidence_ref, CHILD_LACKS_COLLECTOR)
        self.assertEqual(self.children[request.ref].requests, [])  # factory ran,
        self.assertEqual(self.ledger.count('codex.app-server'), 0)  # execute did not
        with self.assertRaises(CapacityError):  # mismatched child not retained
            pool.collect_output(request.ref)
        replay = pool.execute(request)  # stored receipt is not re-dispatched
        self.assertEqual(replay.status, c.OperationStatus.INVALID_STATE)
        self.assertEqual(self.ledger.count('codex.app-server'), 0)
        plain = self._request(1)  # non-candidate work is unaffected
        self.assertEqual(pool.execute(plain).status, c.OperationStatus.ACCEPTED)
        self.assertEqual(self.children[plain.ref].requests, [plain])

    def test_collect_forwards_to_child_retained_after_slot_release(self):
        pool = self._pool(lambda request: CollectingChild())
        request = self._request(candidate=True)
        self.assertEqual(pool.execute(request).status, c.OperationStatus.ACCEPTED)
        child = self.children[request.ref]
        child.finish(request.ref)
        child.stop_status = c.StopStatus.CONFIRMED
        self.assertEqual(pool.stop(request.ref).status, c.StopStatus.CONFIRMED)
        self.assertEqual(self.ledger.count('codex.app-server'), 0)  # slot released
        self.assertEqual(pool.collect_output(request.ref),
                         (c.OutputItem(0, 'text/plain', 'collected text'),))
        with self.assertRaises(CapacityError):  # exact ownership enforced
            pool.collect_output(self._request(2).ref)

    def test_restart_loses_retained_child_and_reports_unavailable(self):
        pool = self._pool()
        request = self._request()
        pool.execute(request)
        fresh = self._pool()  # same ledger, no in-memory children: post-restart
        with self.assertRaises(CapacityError):
            fresh.collect_output(request.ref)
        with self.assertRaises(CapacityError):
            pool.collect_output(self._request(9).ref)  # never owned by this pool

    def test_controller_child_without_collector_never_executes(self):
        # Accepted M1 rule: the missing-collector route is excluded after one
        # factory call; there is no second dispatch on the same Job/route.
        h, ledger, pools, controller, _ = self._composition(
            'nocollect', (('j', (('a', 'codex.app-server', 'env:1'),)),))
        final, reasons = self._drive(controller)
        self.assertEqual((final.state, final.reason),
                         (c.State.FAILED, 'no_eligible_route_or_pair_limit'))
        self.assertEqual(len(h.ctrl.attempts('r')), 1)
        self.assertEqual(len(self.factory_calls), 1)
        self.assertEqual(len(self.children), 1)
        self.assertTrue(all(child.requests == [] for child in
                            self.children.values()))  # execute never ran
        receipts = [r for r in h.ctrl.history('r', 'execute_history')
                    if r.never_started is not None]
        self.assertEqual([r.never_started.evidence_ref for r in receipts],
                         [CHILD_LACKS_COLLECTOR])
        self.assertEqual(ledger.count('codex.app-server'), 0)  # slot released

    def test_collector_route_exclusion_survives_restart(self):
        routes = (('a', 'codex.app-server', 'env:1'),
                  ('b', 'codex.app-server', 'env:1'))
        h, ledger, pools, controller, build = self._composition(
            'restart', (('j', routes),))
        self._drive(controller, until='execute_never_started')
        self.assertEqual([r.conditions.model for r in self.factory_calls], ['a'])
        self.assertEqual(ledger.count('codex.app-server'), 0)
        # Rebuilt Controller and fresh pools: exclusion comes from committed
        # execute_history receipts, not in-memory pool state.
        self.factory_calls.clear()
        restarted = NativeAdapterPools(canonical_ledger=ledger.path,
            factories={key: self._factory() for key in ADAPTERS})
        final, _ = self._drive(build(restarted))
        self.assertEqual((final.state, final.reason),
                         (c.State.FAILED, 'no_eligible_route_or_pair_limit'))
        # The denied exact route is not re-dispatched; the other model is.
        self.assertEqual([(r.job.job_id, r.conditions.model)
                          for r in self.factory_calls], [('j', 'b')])
        self.assertEqual(len(h.ctrl.attempts('r')), 2)
        denied = [r.never_started.request.conditions.model
                  for r in h.ctrl.history('r', 'execute_history')
                  if r.never_started is not None]
        self.assertEqual(denied, ['a', 'b'])
        self.assertTrue(all(child.requests == [] for child in
                            self.children.values()))

    def test_collector_exclusion_is_exact_route_per_job(self):
        # A CHILD_LACKS_COLLECTOR receipt excludes only that Job's exact
        # (model, adapter, environment_ref); other Jobs/routes stay eligible.
        for index, j2route in enumerate((('a', 'codex.app-server', 'env:2'),
                                         ('b', 'codex.app-server', 'env:1'),
                                         ('a', 'claude.print', 'env:1'))):
            with self.subTest(route=j2route):
                self.children, self.factory_calls = {}, []
                factories = {key: self._factory() for key in ADAPTERS}
                factories['claude.print'] = self._factory(
                    lambda request: CollectingChild()
                    if request.job.job_id == 'j1' else Child())
                h, ledger, pools, controller, _ = self._composition(
                    'isolate-%d' % index,
                    (('j1', (('a', 'codex.app-server', 'env:1'),
                             ('x', 'claude.print', 'env:1'))),
                     ('j2', (j2route,))),
                    factories=factories)
                final, _ = self._drive(controller)
                self.assertEqual((final.state, final.reason),
                                 (c.State.FAILED, 'no_eligible_route_or_pair_limit'))
                # j1's denied route did not exclude j2's different route: the
                # factory ran for j2, and child.execute still never ran there.
                self.assertEqual([r.job.job_id for r in self.factory_calls],
                                 ['j1', 'j1', 'j2'])
                executed = [ch for ch in self.children.values() if ch.requests]
                self.assertEqual(len(executed), 1)
                denied = {(r.never_started.request.job.job_id,
                           r.never_started.request.conditions.model,
                           r.never_started.request.conditions.adapter,
                           r.never_started.request.conditions.environment_ref)
                          for r in h.ctrl.history('r', 'execute_history')
                          if r.never_started is not None}
                self.assertEqual(denied, {('j1', 'a', 'codex.app-server', 'env:1'),
                                          ('j2',) + j2route})

    def test_capacity_full_is_transient_not_route_exclusion(self):
        # 'capacity:full-*' evidence never enters the exclusion ledger; while
        # full, dispatch waits without spending an Attempt.
        factories = {key: self._factory(lambda request: CollectingChild())
                     for key in ADAPTERS}
        h, ledger, pools, controller, _ = self._composition(
            'capfull', (('j', (('a', 'codex.app-server', 'env:1'),)),),
            factories=factories, fill=MAX_CONCURRENT)
        self._drive(controller, until='adapter_capacity_full')
        self._drive(controller, until='adapter_capacity_full')
        self.assertEqual(h.ctrl.attempts('r'), ())  # no Attempt spent while full
        self.assertTrue(ledger.release_reserved(
            self._request('capfull-fill-0'), 'occupied'))
        final, reasons = self._drive(controller)
        self.assertIn('execute_receipt', reasons)
        attempt, = h.ctrl.attempts('r')
        self.assertEqual(self.children[attempt.ref].requests[0].ref, attempt.ref)
        # The product Attempt's slot was released on confirmed cessation; the
        # other MAX_CONCURRENT-1 fixture reservations stay truthfully held
        # under their own identities until released.
        self.assertEqual(ledger.count('codex.app-server'), MAX_CONCURRENT - 1)
        self.assertEqual({snap.ref for snap in ledger.unresolved()},
                         {self._request('capfull-fill-%d' % i).ref
                          for i in range(1, MAX_CONCURRENT)})
        for index in range(1, MAX_CONCURRENT):
            self.assertTrue(ledger.release_reserved(
                self._request('capfull-fill-%d' % index), 'occupied'))
        self.assertEqual(ledger.count('codex.app-server'), 0)


class OutputStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def test_golden_output_vectors_match_independent_reference(self):
        store = OutputStore(self.dir / 'golden')
        ref = c.AttemptRef('r', 'j', 'a')
        digests = []
        for index, vector in enumerate(GOLDEN_VECTORS):
            with self.subTest(case=index):
                items = tuple(c.OutputItem(i, 'text/plain', text)
                              for i, text in enumerate(vector['texts']))
                out = store.put(ref, items)
                self.assertEqual(out.digest, vector['digest'])
                self.assertEqual(out.items, tuple(
                    c.OutputItemMeta(i, 'text/plain', blob, size)
                    for i, (blob, size) in enumerate(vector['blobs'])))
                self.assertEqual(out.total_bytes,
                                 sum(size for _, size in vector['blobs']))
                raw = (store.root / 'manifests'
                       / vector['digest'][7:]).read_bytes()
                self.assertEqual(raw, vector['manifest'].encode('utf-8'))
                self.assertEqual(store.manifest(vector['digest']), out.items)
                self.assertEqual(store.get(c.OutputRef(ref, out.digest), out),
                                 vector['texts'])
                digests.append(out.digest)
        # Composed/decomposed and empty items are distinct byte-exact contents;
        # no normalization or folding may collapse their identities.
        self.assertEqual(len(set(digests)), len(digests))
        self.assertNotEqual(digests[0], digests[1])

    def test_write_once_bytes_and_concurrent_publication(self):
        store = OutputStore(self.dir / 'store')
        ref = c.AttemptRef('r', 'j', 'a')
        # Public seam: identical content publishes idempotently.
        items = (c.OutputItem(0, 'text/plain', 'republished bytes'),)
        first = store.put(ref, items)
        second = store.put(ref, items)
        self.assertEqual((second.digest, second.items),
                         (first.digest, first.items))
        # Private write-once seam: public put() can never address one object
        # name with differing bytes, so _commit is exercised directly.
        name = 'ab' * 32
        store._commit('blobs', name, b'first-bytes')
        with self.assertRaises(IntegrityError):
            store._commit('blobs', name, b'different-bytes')
        self.assertEqual((store.root / 'blobs' / name).read_bytes(),
                         b'first-bytes')
        # Concurrent differing publication: exactly one wins, bytes retained.
        contested = 'cd' * 32
        barrier = threading.Barrier(2)
        def commit(data):
            barrier.wait(10)
            try:
                store._commit('blobs', contested, data)
                return 'published', data
            except IntegrityError:
                return 'conflict', data
        with ThreadPoolExecutor(2) as pool:
            outcomes = list(pool.map(commit, (b'alpha', b'beta')))
        self.assertEqual(sorted(k for k, _ in outcomes),
                         ['conflict', 'published'])
        winner = next(data for k, data in outcomes if k == 'published')
        self.assertEqual((store.root / 'blobs' / contested).read_bytes(), winner)

    def test_foreign_db_refusal_leaves_file_and_journal_mode_untouched(self):
        for name, contract in (('unmarked', None),
                               ('mismatched', 'other.contract/9')):
            with self.subTest(case=name):
                path = self.dir / (name + '.sqlite')
                db = sqlite3.connect(path)
                try:
                    db.execute('CREATE TABLE kept (id INTEGER PRIMARY KEY, v TEXT)')
                    db.execute("INSERT INTO kept VALUES (1, 'must-survive')")
                    if contract is not None:
                        db.execute('CREATE TABLE meta (id INTEGER PRIMARY KEY '
                                   'CHECK(id=1), contract TEXT NOT NULL)')
                        db.execute('INSERT INTO meta VALUES (1, ?)', (contract,))
                    db.commit()
                    mode = db.execute('PRAGMA journal_mode').fetchone()[0]
                finally:
                    db.close()
                before = path.read_bytes()
                with self.assertRaises(StoreUnavailable):
                    ControlStore(path, verifier=lambda *_: None,
                                 evidence=lambda *_: None)
                # Refusal happens before any write, WAL switch or pragma change.
                self.assertEqual(path.read_bytes(), before)
                for suffix in ('-wal', '-shm', '-journal'):
                    self.assertFalse(Path(str(path) + suffix).exists(), suffix)
                check = sqlite3.connect(path)
                try:
                    self.assertEqual(
                        check.execute('PRAGMA journal_mode').fetchone()[0], mode)
                    self.assertEqual(
                        check.execute('SELECT v FROM kept').fetchone(),
                        ('must-survive',))
                finally:
                    check.close()


if __name__ == '__main__': unittest.main()
