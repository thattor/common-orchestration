"""#190 M3 ProfilePlanner: pinned single-Job derivation, fail-closed reparse.

Runs are created through the real Gateway.submit path, so original_intent is
the actual stored canonical str. No provider contact or qualification is
claimed; RouteConfig only proves shape, catalog evidence and bound headroom.
"""
from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest

from co_v4 import contracts as c
from co_v4.catalog import Catalog, CatalogEntry, UseCase, Verification
from co_v4.gateway_store import MAX_CANONICAL_BYTES, submit_body
from co_v4.openai_transport import Deadlines
from co_v4.profile_planner import ProfilePlanner
from co_v4.profile_registry import (RouteConfig, load_registry,
                                    revision_digest)
from co_v4.protocol_profile import RouteProtocolProfile, environment_ref
from co_v4.responses_input import (MAX_BODY_BYTES, RequestRejected, parse)
from co_v4.state import (ControlStore, IngressReceipt, IntegrityViolation,
                         body_digest)

NOW = '2026-10-06T00:00:00Z'
MODEL, ADAPTER = 'm', 'openai.responses'
ENDPOINT, AUTH_REF = 'https://provider.test/v1', 'cred-main'
ENDPOINT2 = 'https://provider2.test/v1'
WORKSPACE = '/profile-work'
MANIFEST = 'ab' * 32
ROUTE_PROFILE = RouteProtocolProfile('responses', 'present', 'present',
                                     {}, MODEL, MANIFEST)
ENV = environment_ref(ENDPOINT, AUTH_REF, ROUTE_PROFILE.profile_digest)
ENV2 = environment_ref(ENDPOINT2, AUTH_REF, ROUTE_PROFILE.profile_digest)
USE = UseCase('general')
BASE = ['ac:media_types', 'ac:max_bytes', 'ac:non_whitespace',
        'ac:no_forbidden_literals']
GOOD_AC = {'media_types': ['text/plain'], 'max_bytes': 4096,
           'non_whitespace': True,
           'forbidden_literals': ['</think>', '<think>']}


def wire_entry(**changes):
    entry = {'profile_id': 'co-text', 'effect_class': 'pure',
             'requires_output': True, 'routes': [[MODEL, ADAPTER, ENV]],
             'route_bounds': [{'route': [MODEL, ADAPTER, ENV],
                               'total_s': 120, 'max_drain_s': 30}],
             'unconfirmed_after_seconds': 180, 'use_case': 'general',
             'job_instructions': 'Produce the answer text.',
             'job_criteria': list(BASE), 'ac': dict(GOOD_AC)}
    entry.update(changes)
    return entry


def registry_doc(wires, aliases):
    return {'schema': 'co.task-profile-registry/1',
            'entries': [{'revision_digest': revision_digest(w), 'entry': w}
                        for w in wires],
            'aliases': aliases}


def one_doc(**changes):
    w = wire_entry(**changes)
    return registry_doc([w], [{'alias': 'co-text', 'profile_id': 'co-text',
                               'revision_digest': revision_digest(w)}])


class ProfilePlannerTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.receipts = {}
        self.catalog = Catalog((CatalogEntry(MODEL, ADAPTER, {USE: 2}, (
            Verification(MODEL, ADAPTER, USE, ENV, 'r:o', 'r:i', 'r:m',
                         'r:a', output_mode='collect'),)),))
        self.route = RouteConfig(MODEL, ADAPTER, ENV, ENDPOINT, AUTH_REF,
                                 Deadlines(total=100), 20, ROUTE_PROFILE)
        self.registry = load_registry(json.dumps(one_doc()),
                                      catalog=self.catalog,
                                      routes=(self.route,))
        self.store = ControlStore(
            Path(tmp.name) / 'control.sqlite',
            verifier=self.receipts.__getitem__,
            evidence=lambda *_: None, clock=lambda: NOW,
            profile_resolver=lambda alias: self.registry.resolve(alias))
        self.gateway = self.store.gateway()
        self.state = self.store.controller()
        self.planner = ProfilePlanner(self.registry, (self.route,), WORKSPACE)
        self.addCleanup(self.store.close)

    def submit(self, **request):
        """Real Gateway.submit; returns (RunSnapshot, TaskIntent)."""
        request.setdefault('model', 'co-text')
        intent = parse(json.dumps(request, ensure_ascii=False,
                                  separators=(',', ':')).encode('utf-8'))
        event = 'e%d' % len(self.receipts)
        self.receipts[event] = IngressReceipt(
            'p', event, body_digest(submit_body(intent.body_hash, None)), NOW)
        sub = self.gateway.submit(intent, None, event)
        return self.state.get_run(sub.run_id), intent

    def test_first_call_builds_fixed_single_job(self):
        run, intent = self.submit(
            input=[{'role': 'system', 'content': 'rules'},
                   {'role': 'user', 'content': [
                       {'type': 'input_text', 'text': 'a'},
                       {'type': 'input_text', 'text': 'b'}]},
                   {'role': 'assistant', 'content': 'prior'}],
            instructions='client tone', metadata={'k': 'v'},
            stream=False, tools=[])
        # The committed original_intent is the str canonical body.
        self.assertIs(type(run.original_intent), str)
        self.assertEqual(run.original_intent,
                         intent.canonical_body.decode('utf-8'))
        entry = self.registry.get('co-text', run.profile.revision_digest)
        plan = self.planner(run, (), None)
        self.assertEqual((plan.job.run_id, plan.job.job_id),
                         (run.run_id, 'job-1'))
        self.assertEqual(plan.job.instructions, entry.job_instructions)
        self.assertEqual(plan.job.acceptance_criteria, entry.job_criteria)
        self.assertTrue(plan.job.output_candidate)
        context = json.loads(plan.job.context_json)
        self.assertEqual(context, {'instructions': 'client tone', 'input': [
            {'type': 'message', 'role': 'system', 'content': 'rules'},
            {'type': 'message', 'role': 'user', 'content': [
                {'type': 'input_text', 'text': 'a'},
                {'type': 'input_text', 'text': 'b'}]},
            {'type': 'message', 'role': 'assistant', 'content': 'prior'}]})
        self.assertLessEqual(set(context), {'instructions', 'input'})
        self.assertEqual(plan.action.name, 'text.generate')
        self.assertEqual(plan.action.scope.dimensions, (
            ('profile', 'co-text'),
            ('profile_revision', entry.revision_digest),
            ('workspace', WORKSPACE)))
        self.assertTrue(plan.action.scope.known)
        self.assertEqual((plan.method, plan.use_case), ('text.generate', USE))
        self.assertEqual(plan.conditions, (c.ExecutionConditions(
            MODEL, ADAPTER, WORKSPACE, ENV,
            ('route-profile:' + ROUTE_PROFILE.profile_digest,)),))

    def test_exact_string_input_and_unicode_preserved(self):
        run, _ = self.submit(input='café — 你好')
        context = json.loads(self.planner(run, (), None).job.context_json)
        self.assertEqual(context['input'], 'café — 你好')
        self.assertIsNone(context['instructions'])

    def test_second_call_none_and_unknown_job_id_refused(self):
        run, _ = self.submit(input='x')
        self.assertIsNone(
            self.planner(replace(run, job_ids=('job-1',)), (), None))
        for bad in (('bogus',), ('job-1', 'job-2')):
            with self.subTest(bad=bad):
                with self.assertRaises(IntegrityViolation):
                    self.planner(replace(run, job_ids=bad), (), None)

    def test_restart_reentry_deterministic_same_plan(self):
        run, _ = self.submit(input='x')
        first = self.planner(run, (), None)
        again = ProfilePlanner(self.registry, (self.route,),
                               WORKSPACE)(run, (), None)
        self.assertEqual(first, again)

    def test_alias_remap_pins_old_run_new_submission_new_pin(self):
        run_old, _ = self.submit(input='x')
        w2 = wire_entry(job_instructions='Revised instructions.')
        d1, d2 = run_old.profile.revision_digest, revision_digest(w2)
        self.assertNotEqual(d1, d2)
        self.registry = load_registry(json.dumps(registry_doc([wire_entry(),
            w2], [{'alias': 'co-text', 'profile_id': 'co-text',
                   'revision_digest': d2}])), catalog=self.catalog,
            routes=(self.route,))
        run_new, _ = self.submit(input='x')
        self.assertEqual(run_new.profile.revision_digest, d2)
        # No alias lookup drives the old Run: only its pinned revision.
        self.assertEqual(self.registry.resolve('co-text').revision_digest, d2)
        remapped = ProfilePlanner(self.registry, (self.route,), WORKSPACE)
        old_plan = remapped(run_old, (), None)
        self.assertEqual(old_plan.job.instructions, 'Produce the answer text.')
        self.assertEqual(old_plan.action.scope.dimensions[1][1], d1)
        self.assertEqual(remapped(run_new, (), None).job.instructions,
                         'Revised instructions.')

    def test_missing_revision_and_corrupt_pin_fail_closed(self):
        run, _ = self.submit(input='x')
        ghost = c.TaskProfile('co-text', 'sha256:' + '9' * 64, 'pure', True,
                              run.profile.routes)
        # Runtime pin/entry absence is committed-state corruption:
        # IntegrityViolation, never the startup-only mismatch class.
        with self.assertRaises(IntegrityViolation):
            self.planner(replace(run, profile=ghost), (), None)
        for corrupt in (replace(run.profile, requires_output=False),
                        replace(run.profile,
                                routes=((MODEL, ADAPTER, 'env:x'),))):
            with self.subTest(corrupt=corrupt):
                with self.assertRaises(IntegrityViolation):
                    self.planner(replace(run, profile=corrupt), (), None)
        with self.assertRaises(IntegrityViolation):
            self.planner(replace(run, profile=None), (), None)

    def test_tampered_original_intent_fails_closed(self):
        run, _ = self.submit(input='x')
        with self.assertRaises(IntegrityViolation):
            self.planner(replace(run, original_intent='not json'), (), None)
        reserialized = json.dumps(json.loads(run.original_intent), indent=1)
        with self.assertRaises(IntegrityViolation):
            self.planner(replace(run, original_intent=reserialized), (), None)
        with self.assertRaises(IntegrityViolation):
            self.planner(replace(run, original_intent='x\ud800'), (), None)
        with self.assertRaises(IntegrityViolation):
            self.planner(replace(run, original_intent=b'{}'), (), None)

    def test_near_limit_canonical_expansion_accepted(self):
        # 64 items each gain "type":"message" in canonical form: a valid body
        # under MAX_BODY_BYTES normalizes past it but stays under the
        # Gateway bound; the planner must reparse under that larger limit.
        items = [{'role': 'user', 'content': 'x'} for _ in range(64)]
        base = json.dumps({'model': 'co-text', 'input': items},
                          separators=(',', ':')).encode()
        pad = MAX_BODY_BYTES - len(base) - 200
        items[-1] = {'role': 'user', 'content': 'y' * pad}
        intent = parse(json.dumps({'model': 'co-text', 'input': items},
                                  separators=(',', ':')).encode())
        self.assertGreater(len(intent.canonical_body), MAX_BODY_BYTES)
        self.assertLessEqual(len(intent.canonical_body), MAX_CANONICAL_BYTES)
        event = 'e%d' % len(self.receipts)
        self.receipts[event] = IngressReceipt(
            'p', event, body_digest(submit_body(intent.body_hash, None)), NOW)
        run = self.state.get_run(self.gateway.submit(intent, None, event).run_id)
        self.assertEqual(self.planner(run, (), None).job.job_id, 'job-1')

    def test_duplicate_model_adapter_routes_fail_no_silent_drop(self):
        catalog = Catalog((CatalogEntry(MODEL, ADAPTER, {USE: 2}, (
            Verification(MODEL, ADAPTER, USE, ENV, 'r:o', 'r:i', 'r:m',
                         'r:a', output_mode='collect'),
            Verification(MODEL, ADAPTER, USE, ENV2, 'r:o2', 'r:i2', 'r:m2',
                         'r:a2', output_mode='collect'))),))
        route2 = RouteConfig(MODEL, ADAPTER, ENV2, ENDPOINT2, AUTH_REF,
                             Deadlines(total=100), 20, ROUTE_PROFILE)
        routes = sorted([[MODEL, ADAPTER, ENV], [MODEL, ADAPTER, ENV2]])
        w = wire_entry(routes=routes, route_bounds=[
            {'route': r, 'total_s': 120, 'max_drain_s': 30}
            for r in routes])
        self.registry = load_registry(json.dumps(registry_doc([w],
            [{'alias': 'co-text', 'profile_id': 'co-text',
              'revision_digest': revision_digest(w)}])),
            catalog=catalog, routes=(self.route, route2))
        run, _ = self.submit(input='x')
        self.assertEqual(len(run.profile.routes), 2)
        planner = ProfilePlanner(self.registry, (self.route, route2),
                                 WORKSPACE)
        with self.assertRaises(IntegrityViolation):
            planner(run, (), None)


if __name__ == '__main__':
    unittest.main()
