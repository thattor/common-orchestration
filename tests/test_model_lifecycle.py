"""Offline policy/admission proof; no Native availability qualification."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from co_v4 import contracts as c
from co_v4.ac import Acceptance
from co_v4.catalog import Catalog, CatalogEntry, Verification
from co_v4.controller import Controller, JobPlan
from co_v4.model_lifecycle import ModelLifecyclePolicy
from co_v4.routing import Assessment, select_route
from co_v4.usage import UsageStore
from test_controller import NativeFixture, catalog, USE
from test_state import Harness

CUT = datetime(2026, 10, 12, 15, tzinfo=timezone.utc)


def rule(**changes):
    value = dict(adapter='codex.app-server', model='gpt-5.5', auth_route='chatgpt',
        disable_from='2026-10-13T00:00:00+09:00', cutoff_timezone='Asia/Tokyo',
        cutoff_basis='maintainer', announcement_url='https://learn.chatgpt.com/docs/models',
        announced_on=None, retirement_on='2026-10-14', replacements=['gpt-6-sol', 'gpt-6-luna'])
    value.update(changes)
    return value


class ModelLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'policy.json'
        self.write([rule()])
        self.policy = ModelLifecyclePolicy.load(self.path)

    def write(self, rules):
        self.path.write_text(json.dumps(dict(version=1, rules=rules)))
        self.path.chmod(0o600)

    def reason(self, auth='chatgpt', now=CUT, model='gpt-5.5', adapter='codex.app-server'):
        return self.policy.admission_reason(model, adapter, auth, now=now)

    def route(self, auth='chatgpt', now=CUT, environment='env:1', extra=None):
        v = Verification('gpt-5.5', 'codex.app-server', USE, 'env:1',
            'fixture:o', 'fixture:i', 'fixture:m', 'fixture:ac', auth)
        entry = CatalogEntry(v.model, v.adapter, {USE: 2}, (v,), extra or {})
        job = c.Job('r', 'j', 'fixture', ('checked',))
        conditions = c.ExecutionConditions(v.model, v.adapter, '/fixture', environment, ('fixture:controls',))
        return select_route(Catalog((entry,), self.policy), job, USE,
            (Assessment(job, conditions, c.Decision.NORMAL, 'fixture:decision', True),), UsageStore(),
            now=now, max_usage_age=timedelta(minutes=1), explicit_model='gpt-5.5')

    def test_loaded_file_controls_inclusive_cutoff_and_real_routing(self):
        self.assertIsNone(self.reason(now=CUT-timedelta(microseconds=1)))
        self.assertIsNotNone(self.route(now=CUT-timedelta(microseconds=1)).selected)
        for now in (CUT, CUT+timedelta(days=1)):
            with self.subTest(now=now):
                result = self.route(now=now)
                self.assertIsNone(result.selected)
                self.assertEqual(result.eligible, ())  # Replacement metadata creates no route.
                self.assertEqual(result.excluded[0].reason, 'model_lifecycle_expired')

    def test_chatgpt_retirement_does_not_apply_to_api_or_unconfigured_models(self):
        self.assertIsNone(self.reason(auth='api-key'))
        self.assertIsNotNone(self.route(auth='api-key').selected)
        self.assertIsNone(self.reason(model='gpt-6-sol'))
        self.assertIsNone(self.reason(adapter='unconfigured'))

    def test_auth_is_verified_environment_metadata_not_worker_extra(self):
        self.assertEqual(self.route(auth=None, extra={'auth_route': 'api-key'}).excluded[0].reason,
                         'model_lifecycle_auth_unverified')
        self.assertEqual(self.route(environment='env:other').excluded[0].reason,
                         'use_or_environment_unverified')
        for auth in (None, 'unknown', 'ChatGPT', '', []):
            with self.subTest(auth=auth):
                self.assertEqual(self.reason(auth=auth), 'model_lifecycle_auth_unverified')

    def test_all_five_adapters_share_exact_policy_semantics(self):
        for adapter in ('codex.app-server', 'claude.print', 'devin.acp',
                        'antigravity.text.only', 't3code.orchestration-v2'):
            with self.subTest(adapter=adapter):
                self.write([rule(adapter=adapter, auth_route='subscription')])
                self.policy = ModelLifecyclePolicy.load(self.path)
                self.assertEqual(self.reason(adapter=adapter, auth='subscription'), 'model_lifecycle_expired')
                self.assertIsNone(self.reason(adapter=adapter, auth='api-key'))

    def test_malformed_unknown_and_ambiguous_policy_rejected(self):
        changes = [dict(disable_from='2026-10-14'), dict(disable_from='2026-10-14T00:00:00'),
            dict(disable_from='2026-10-14T00:00:00-00:00'), dict(disable_from='2026-02-30T00:00:00+09:00'),
            dict(cutoff_timezone='Unknown/Zone'), dict(cutoff_timezone='UTC'), dict(auth_route='unknown'),
            dict(auth_route=[]), dict(announced_on='2026-02-30'), dict(retirement_on='soon'),
            dict(cutoff_basis='inferred'), dict(expires_at='2026-10-14T00:00:00Z'), dict(fallback=True)]
        for change in changes:
            with self.subTest(change=change):
                self.write([rule(**change)])
                with self.assertRaises(ValueError):
                    ModelLifecyclePolicy.load(self.path)
        self.path.write_text('{"version":1,"version":1,"rules":[]}')
        with self.assertRaises(ValueError):
            ModelLifecyclePolicy.load(self.path)
        self.write([rule(), rule()])
        with self.assertRaises(ValueError):
            ModelLifecyclePolicy.load(self.path)

    def test_expires_at_alias_and_clock_validation(self):
        row = rule()
        row['expires_at'] = row.pop('disable_from')
        self.write([row])
        self.policy = ModelLifecyclePolicy.load(self.path)
        self.assertEqual(self.reason(), 'model_lifecycle_expired')
        self.assertEqual(self.reason(now=CUT.replace(tzinfo=None)), 'model_lifecycle_clock_invalid')

    def test_replacement_update_removal_and_unprotected_file_cannot_bypass(self):
        with self.assertRaises(ValueError):
            replace(self.policy, rules=())
        self.write([])
        self.assertEqual(self.reason(), 'model_lifecycle_policy_changed')
        self.path.unlink()
        self.assertEqual(self.reason(), 'model_lifecycle_policy_unavailable')
        self.write([rule()])
        self.path.chmod(0o666)
        self.assertEqual(self.reason(), 'model_lifecycle_policy_unavailable')
        with self.assertRaises(ValueError):
            ModelLifecyclePolicy.load(self.path)
        self.path.unlink()
        target = self.path.parent / 'target.json'
        target.write_text('{"version":1,"rules":[]}')
        self.path.symlink_to(target)
        self.assertEqual(self.reason(), 'model_lifecycle_policy_unavailable')


class LifecycleControllerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.h = Harness(self.tmp.name)
        self.addCleanup(self.h.store.close)
        self.native = NativeFixture()
        self.native.auto_complete = False
        self.path = Path(self.tmp.name) / 'policy.json'
        self.path.write_text(json.dumps(dict(version=1, rules=[rule(adapter='adapter', model='a')])))
        self.path.chmod(0o600)
        policy = ModelLifecyclePolicy.load(self.path)
        entry = catalog(models=('a',)).entries[0]
        entry = replace(entry, verifications=(replace(entry.verifications[0], auth_route='chatgpt'),))
        self.now = CUT-timedelta(seconds=1)
        plan = JobPlan(c.Job('r', 'j', 'fixture', ('checked',)), self.h.action, 'write-output', USE,
                       (replace(self.h.conditions, model='a'),))
        self.controller = Controller('r', state=self.h.ctrl, judgment=self.h.judgment,
            catalog=Catalog((entry,), policy), usage=UsageStore(), adapters={'adapter': self.native},
            acceptance=Acceptance(lambda _: None), planner=lambda *args: plan, clock=lambda: self.now)
        self.initial_checkpoint = self.h.ctrl.checkpoint('r')
        self.assertEqual(self.controller.step().reason, 'next_job')

    def assert_not_started(self):
        self.assertEqual(self.h.ctrl.attempts('r'), ())
        self.assertEqual(self.native.requests, [])

    def test_expiry_refuses_new_attempt_without_budget(self):
        self.now = CUT
        self.assertEqual(self.controller.step().state, c.State.FAILED)
        self.assert_not_started()

    def test_crossing_cutoff_during_dispatch_rejudgment_preserves_budget(self):
        original = self.h.judgment.judge
        def judge(request):
            if request.ref.attempt_id is not None:
                self.now = CUT
            return original(request)
        with patch.object(self.h.judgment, 'judge', side_effect=judge):
            self.assertEqual(self.controller.step().reason, 'model_lifecycle_expired')
        self.assert_not_started()

    def test_file_update_during_rejudgment_and_catalog_drop_cannot_bypass(self):
        original = self.h.judgment.judge
        def judge(request):
            if request.ref.attempt_id is not None:
                self.path.write_text('{"version":1,"rules":[]}')
            return original(request)
        with patch.object(self.h.judgment, 'judge', side_effect=judge):
            self.assertEqual(self.controller.step().reason, 'model_lifecycle_policy_changed')
        self.controller.catalog = Catalog(self.controller.catalog.entries)
        self.assertEqual(self.controller.step().reason, 'model_lifecycle_policy_changed')
        self.assert_not_started()

    def restart(self, catalog):
        # Recover through a new SQLite connection, not an in-memory snapshot.
        self.h.store.close()
        self.h.store = self.h.connect()
        self.addCleanup(self.h.store.close)
        self.h.refresh()
        self.controller = Controller('r', state=self.h.ctrl, judgment=self.h.judgment,
            catalog=catalog, usage=UsageStore(), adapters={'adapter': self.native},
            acceptance=Acceptance(lambda _: None), planner=lambda *args: None, clock=lambda: self.now)

    def test_checkpoint_pins_policy_across_restart_and_missing_or_replaced_composition(self):
        original = self.controller.catalog
        self.assertIsNone(self.initial_checkpoint.plan)
        self.assertEqual(self.initial_checkpoint.lifecycle_ref, original.lifecycle.ref)
        pinned = self.h.ctrl.checkpoint('r').lifecycle_ref
        self.assertEqual(pinned, original.lifecycle.ref)
        self.restart(Catalog(original.entries))
        self.assertEqual(self.controller.step().reason, 'model_lifecycle_policy_changed')
        self.assert_not_started()
        self.assertEqual(self.h.ctrl.checkpoint('r').lifecycle_ref, pinned)
        self.path.write_text('{"version":1,"rules":[]}')
        self.restart(Catalog(original.entries, ModelLifecyclePolicy.load(self.path)))
        self.assertEqual(self.controller.step().reason, 'model_lifecycle_policy_changed')
        self.assert_not_started()

    def test_restart_reloads_identical_policy_and_still_checks_expiry(self):
        original = self.controller.catalog
        self.restart(Catalog(original.entries, ModelLifecyclePolicy.load(self.path)))
        self.now = CUT
        self.assertEqual(self.controller.step().state, c.State.FAILED)
        self.assert_not_started()

    def test_restart_without_policy_still_allows_active_attempt_cleanup(self):
        self.assertEqual(self.controller.step().reason, 'execute_receipt')
        ref = self.native.requests[0].ref
        pinned = self.h.ctrl.checkpoint('r').lifecycle_ref
        self.restart(Catalog(self.controller.catalog.entries))
        self.now = CUT
        self.native.finish(ref, c.State.FAILED)
        for _ in range(5):
            self.controller.step()
            if self.native.stops:
                break
        self.assertEqual(self.native.stops, [ref])
        self.assertEqual(self.h.ctrl.checkpoint('r').lifecycle_ref, pinned)
        self.assertEqual(len(self.native.requests), 1)

    def test_expiry_and_policy_removal_never_block_existing_attempt_cleanup(self):
        self.assertEqual(self.controller.step().reason, 'execute_receipt')
        ref = self.native.requests[0].ref
        self.now = CUT
        self.path.unlink()
        self.native.finish(ref, c.State.FAILED)
        for _ in range(5):
            self.controller.step()
            if self.native.stops:
                break
        self.assertEqual(self.native.stops, [ref])
        self.assertEqual(len(self.native.requests), 1)


if __name__ == '__main__':
    unittest.main()
