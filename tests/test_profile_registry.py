# tests/test_profile_registry.py
"""#190 M3 profile registry: wire validation, digest pinning, startup check.

Real ControlStore + Gateway + ControllerState feed check_store; the route
profile and environment_ref are real derived objects. Nothing here claims
provider qualification — that remains QualifiedRouteGate's dispatch duty.
"""
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from co_v4 import contracts as c
from co_v4.catalog import Catalog, CatalogEntry, UseCase, Verification
from co_v4.openai_transport import Deadlines
from co_v4.gateway_store import submit_body
from co_v4.profile_registry import (ProfileRegistryInvalid,
    ProfileRegistryMismatch, RouteConfig, check_store, canonical,
    load_registry, revision_digest)
from co_v4.protocol_profile import RouteProtocolProfile, environment_ref
from co_v4.responses_input import parse
from co_v4.state import (ControlStore, IngressReceipt, body_digest,
                         create_run_body)

NOW = '2026-10-06T00:00:00Z'
MODEL, ADAPTER = 'm', 'openai.responses'
ENDPOINT, AUTH_REF = 'https://provider.test/v1', 'cred-main'
MANIFEST = 'ab' * 32
GOLDEN_ENV = 'env:sha256:' + '0' * 64
BASE = ['ac:media_types', 'ac:max_bytes', 'ac:non_whitespace',
        'ac:no_forbidden_literals']
ROUTE_PROFILE = RouteProtocolProfile('responses', 'present', 'present',
                                     {}, MODEL, MANIFEST)
ENV = environment_ref(ENDPOINT, AUTH_REF, ROUTE_PROFILE.profile_digest)
# Frozen canonical bytes of wire_entry(env=GOLDEN_ENV), domain-independent.
GOLDEN_CANONICAL = (
    b'{"ac":{"forbidden_literals":["</think>","<think>"],'
    b'"max_bytes":4096,"media_types":["text/plain"],'
    b'"non_whitespace":true},"effect_class":"pure",'
    b'"job_criteria":["ac:media_types","ac:max_bytes",'
    b'"ac:non_whitespace","ac:no_forbidden_literals"],'
    b'"job_instructions":"Produce the answer text.",'
    b'"profile_id":"co-text","requires_output":true,'
    b'"route_bounds":[{"max_drain_s":30,"route":["m","openai.responses",'
    b'"env:sha256:0000000000000000000000000000000000000000000000000000'
    b'000000000000"],"total_s":120}],"routes":[["m","openai.responses",'
    b'"env:sha256:0000000000000000000000000000000000000000000000000000'
    b'000000000000"]],"unconfirmed_after_seconds":180,'
    b'"use_case":"general"}')
# Domain-pinned digest of the frozen canonical bytes, stdlib only. NOTE:
# not executed here -- Root computes sha256(b'co.task-profile/1\n' +
# GOLDEN_CANONICAL) independently and may pin the literal hex in place.
GOLDEN_DIGEST = 'sha256:60563235a46701e82bb346850aabc4a1c3671b9f371e22852102820e70ddf165'
GOOD_AC = {'media_types': ['text/plain'], 'max_bytes': 4096,
           'non_whitespace': True,
           'forbidden_literals': ['</think>', '<think>']}


def wire_entry(env=ENV, **changes):
    entry = {'profile_id': 'co-text', 'effect_class': 'pure',
             'requires_output': True, 'routes': [[MODEL, ADAPTER, env]],
             'route_bounds': [{'route': [MODEL, ADAPTER, env],
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


class RegistryLoadTests(unittest.TestCase):
    def setUp(self):
        self.use = UseCase('general')
        self.catalog = Catalog((CatalogEntry(MODEL, ADAPTER, {self.use: 2}, (
            Verification(MODEL, ADAPTER, self.use, ENV, 'r:official',
                         'r:impl', 'r:measure', 'r:ac',
                         output_mode='collect'),)),))
        self.route = RouteConfig(MODEL, ADAPTER, ENV, ENDPOINT, AUTH_REF,
                                 Deadlines(total=100), 20, ROUTE_PROFILE)

    def load(self, doc, catalog='default', routes='default'):
        return load_registry(
            json.dumps(doc),
            catalog=self.catalog if catalog == 'default' else catalog,
            routes=(self.route,) if routes == 'default' else routes)

    def bad(self, doc=None, **kw):
        with self.assertRaises(ProfileRegistryInvalid):
            self.load(one_doc() if doc is None else doc, **kw)

    def test_golden_canonical_bytes_and_digest(self):
        wire = wire_entry(env=GOLDEN_ENV)
        self.assertEqual(canonical(wire), GOLDEN_CANONICAL)
        # Implementation digest vs stdlib-pinned digest on frozen bytes.
        self.assertEqual(revision_digest(wire), GOLDEN_DIGEST)
        changed = dict(wire, ac=dict(wire['ac'], max_bytes=4097))
        self.assertNotEqual(revision_digest(changed), GOLDEN_DIGEST)

    def test_load_resolves_alias_and_binds_revision(self):
        reg = self.load(one_doc())
        pinned = reg.resolve('co-text')
        entry = reg.get('co-text', pinned.revision_digest)
        self.assertIsNotNone(entry)
        self.assertEqual(pinned.routes, ((MODEL, ADAPTER, ENV),))
        self.assertEqual((pinned.effect_class, pinned.requires_output),
                         ('pure', True))
        self.assertEqual(reg.unconfirmed_after_seconds(
            'co-text', pinned.revision_digest), 180)
        self.assertEqual(reg.aliases, ('co-text',))
        self.assertIsNone(reg.resolve('missing'))
        self.assertIsNone(reg.get('co-text', 'sha256:' + '1' * 64))

    def test_exact_any_requires_exact_criterion(self):
        w = wire_entry(ac=dict(GOOD_AC, exact_any=['4']),
                       job_criteria=BASE + ['ac:exact'])
        reg = self.load(registry_doc([w], []))
        entry = reg.get('co-text', revision_digest(w))
        self.assertEqual(entry.ac.exact_any, ('4',))
        self.assertEqual(entry.job_criteria, tuple(BASE + ['ac:exact']))

    def test_document_rejections(self):
        for doc in (5, b'', 'not json', ' ' * (1024 * 1024 + 1),
                    '{"schema": "co.task-profile-registry/1", "schema": "x",'
                    ' "entries": [], "aliases": []}',
                    '{"schema": "co.task-profile-registry/1",'
                    ' "entries": NaN, "aliases": []}',
                    # Nested duplicate key inside a wire entry object.
                    '{"schema":"co.task-profile-registry/1","entries":'
                    '[{"revision_digest":"sha256:' + '0' * 64 + '",'
                    '"entry":{"profile_id":"a","profile_id":"a"}}],'
                    '"aliases":[]}'):
            with self.subTest(doc=type(doc)):
                with self.assertRaises(ProfileRegistryInvalid):
                    load_registry(doc, catalog=self.catalog,
                                  routes=(self.route,))
        self.bad({'schema': 'wrong', 'entries': [], 'aliases': []})
        self.bad({'schema': 'co.task-profile-registry/1', 'entries': []})
        self.bad({'schema': 'co.task-profile-registry/1', 'entries': {},
                  'aliases': []})

    def test_entry_field_rejections(self):
        cases = [
            dict(requires_output=False), dict(effect_class='effectful'),
            dict(profile_id=''), dict(routes=[]),
            dict(routes=[[MODEL, ADAPTER]]),
            dict(routes=[[MODEL, ADAPTER, ENV], [MODEL, ADAPTER, ENV]]),
            dict(routes=[['z', ADAPTER, ENV], [MODEL, ADAPTER, ENV]]),
            dict(routes=[[MODEL, 'openai.moderation', ENV]]),
            dict(route_bounds=[]),
            dict(route_bounds=[{'route': [MODEL, ADAPTER, 'env:x'],
                               'total_s': 120, 'max_drain_s': 30}]),
            dict(route_bounds=[{'route': [MODEL, ADAPTER, ENV],
                               'total_s': 120.0, 'max_drain_s': 30}]),
            dict(route_bounds=[{'route': [MODEL, ADAPTER, ENV],
                               'total_s': True, 'max_drain_s': 30}]),
            dict(route_bounds=[{'route': [MODEL, ADAPTER, ENV],
                               'total_s': 120, 'max_drain_s': 30,
                               'extra': 1}]),
            dict(unconfirmed_after_seconds=179),
            dict(unconfirmed_after_seconds=True),
            dict(unconfirmed_after_seconds=10 ** 30),
            dict(use_case='other'), dict(use_case='bogus'),
            dict(job_instructions=''), dict(job_criteria=list(reversed(BASE))),
        ]
        for changes in cases:
            with self.subTest(changes=changes):
                self.bad(one_doc(**changes))
        w = wire_entry()
        w['unknown'] = 1
        self.bad(registry_doc([w], []))


    def test_surrogate_wire_reaches_loader(self):
        # The fixture never canonicalizes the bad wire: a placeholder
        # declared digest stands in, and json.dumps ASCII-escapes the
        # surrogate so load_registry itself must reject it.
        w = wire_entry(job_instructions='bad\ud800text')
        doc = {'schema': 'co.task-profile-registry/1',
               'entries': [{'revision_digest': 'sha256:' + '0' * 64,
                            'entry': w}], 'aliases': []}
        self.assertTrue(json.dumps(doc).isascii())
        self.bad(doc)

    def test_count_limit_rejections(self):
        w = wire_entry()
        d = revision_digest(w)
        item = {'revision_digest': d, 'entry': w}
        routes65 = [[MODEL, ADAPTER, 'env:%03d' % i] for i in range(65)]
        docs = [
            {'schema': 'co.task-profile-registry/1',
             'entries': [item] * 257, 'aliases': []},
            registry_doc([w], [{'alias': 'a%d' % i, 'profile_id': 'co-text',
                                'revision_digest': d} for i in range(257)]),
            one_doc(routes=routes65,
                    route_bounds=[{'route': r, 'total_s': 120,
                                   'max_drain_s': 30} for r in routes65]),
        ]
        for doc in docs:
            with self.subTest(doc=doc.keys()):
                self.bad(doc)

    def test_ac_rejections(self):
        cases = [
            dict(GOOD_AC, non_whitespace=False),
            dict(GOOD_AC, forbidden_literals=['<think>']),
            dict(GOOD_AC, forbidden_literals=['<think>', '</think>']),
            dict(GOOD_AC, max_bytes=0), dict(GOOD_AC, max_bytes=262145),
            dict(GOOD_AC, max_bytes=4096.0), dict(GOOD_AC, media_types=[]),
            dict(GOOD_AC, media_types=['text/plain', 'text/plain']),
            dict(GOOD_AC, media_types=['bogus-type']),
            dict(GOOD_AC, unknown=1), dict(GOOD_AC, exact_any=[]),
            dict(GOOD_AC, exact_any=['b', 'a']),
            dict(GOOD_AC, exact_any=['4', '4']),
            dict(GOOD_AC, exact_any=list('123456789')),
            dict(GOOD_AC, exact_any=['4']),  # without ac:exact criterion
            {'max_bytes': 10, 'non_whitespace': True,
             'forbidden_literals': ['</think>', '<think>']},
        ]
        for ac in cases:
            with self.subTest(ac=ac):
                self.bad(one_doc(ac=ac))

    def test_digest_entry_and_alias_rejections(self):
        w = wire_entry()
        d = revision_digest(w)
        self.bad({'schema': 'co.task-profile-registry/1',
                  'entries': [{'revision_digest': 'sha256:' + '0' * 64,
                               'entry': w}], 'aliases': []})
        item = {'revision_digest': d, 'entry': w}
        self.bad({'schema': 'co.task-profile-registry/1',
                  'entries': [item, item], 'aliases': []})
        for alias in ('', 'has space', 'bad\nalias', 'x' * 129):
            self.bad(registry_doc([w], [{'alias': alias,
                'profile_id': 'co-text', 'revision_digest': d}]))
        self.bad(registry_doc([w], [
            {'alias': 'a1', 'profile_id': 'co-text', 'revision_digest': d},
            {'alias': 'a1', 'profile_id': 'co-text', 'revision_digest': d}]))
        self.bad(registry_doc([w], [{'alias': 'ghost',
            'profile_id': 'co-text',
            'revision_digest': 'sha256:' + '1' * 64}]))
        self.bad(registry_doc([w], [{'alias': 'a', 'profile_id': 'co-text',
                                     'revision_digest': d, 'x': 1}]))

    def test_catalog_and_route_config_rejections(self):
        self.bad(catalog=Catalog())
        self.bad(catalog=object())
        none_mode = Catalog((CatalogEntry(MODEL, ADAPTER, {self.use: 1}, (
            Verification(MODEL, ADAPTER, self.use, ENV, 'r:o', 'r:i',
                         'r:m', 'r:a', output_mode='none'),)),))
        self.bad(catalog=none_mode)
        coding = UseCase('coding')
        wrong_use = Catalog((CatalogEntry(MODEL, ADAPTER, {coding: 1}, (
            Verification(MODEL, ADAPTER, coding, ENV, 'r:o', 'r:i',
                         'r:m', 'r:a', output_mode='collect'),)),))
        self.bad(catalog=wrong_use)
        self.bad(routes=())
        self.bad(routes=(self.route, self.route))
        self.bad(routes=(object(),))
        variants = [
            replace(self.route, deadlines=Deadlines(total=121)),
            replace(self.route, max_drain_s=31),
            replace(self.route, endpoint='https://other.test/v1'),
            replace(self.route, auth_ref='cred-other'),
            replace(self.route, profile=RouteProtocolProfile(
                'chat', 'present', 'present', {}, MODEL, MANIFEST)),
            replace(self.route, profile=RouteProtocolProfile(
                'responses', 'present', 'present', {}, 'other', MANIFEST)),
        ]
        for route in variants:
            with self.subTest(route=route):
                self.bad(routes=(route,))

    def test_route_config_shape(self):
        base = dict(model=MODEL, adapter=ADAPTER, environment_ref=ENV,
                    endpoint=ENDPOINT, auth_ref=AUTH_REF,
                    deadlines=Deadlines(), max_drain_s=20,
                    profile=ROUTE_PROFILE)
        for kw in ({'profile': None}, {'profile': object()},
                   {'max_drain_s': 0}, {'max_drain_s': 601},
                   {'max_drain_s': 20.0}):
            with self.subTest(kw=kw):
                with self.assertRaises(ValueError):
                    RouteConfig(**dict(base, **kw))

    def test_alias_remap_keeps_pinned_revisions(self):
        w1 = wire_entry()
        w2 = wire_entry(job_instructions='Revised instructions.')
        d1, d2 = revision_digest(w1), revision_digest(w2)
        self.assertNotEqual(d1, d2)
        reg = self.load(registry_doc([w1, w2], [
            {'alias': 'co-text', 'profile_id': 'co-text',
             'revision_digest': d1}]))
        self.assertEqual(reg.resolve('co-text').revision_digest, d1)
        remapped = self.load(registry_doc([w1, w2], [
            {'alias': 'co-text', 'profile_id': 'co-text',
             'revision_digest': d2}]))
        self.assertEqual(remapped.resolve('co-text').revision_digest, d2)
        old = remapped.get('co-text', d1)   # pinned Runs unaffected
        self.assertEqual(old.job_instructions, 'Produce the answer text.')


class CheckStoreTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.receipts = {}
        use = UseCase('general')
        self.catalog = Catalog((CatalogEntry(MODEL, ADAPTER, {use: 2}, (
            Verification(MODEL, ADAPTER, use, ENV, 'r:o', 'r:i', 'r:m',
                         'r:a', output_mode='collect'),)),))
        self.route = RouteConfig(MODEL, ADAPTER, ENV, ENDPOINT, AUTH_REF,
                            Deadlines(total=100), 20, ROUTE_PROFILE)
        self.registry = load_registry(json.dumps(one_doc()),
                                      catalog=self.catalog,
                                      routes=(self.route,))
        self.pinned = self.registry.resolve('co-text')
        self.store = ControlStore(
            Path(tmp.name) / 'control.sqlite',
            verifier=self.receipts.__getitem__,
            evidence=lambda *_: None, clock=lambda: NOW,
            profile_resolver=lambda alias: self.registry.resolve(alias))
        self.gateway = self.store.gateway()
        self.state = self.store.controller()
        self.addCleanup(self.store.close)

    def add_run(self, run_id, profile, terminal=False):
        self.receipts[run_id] = IngressReceipt(
            'p', run_id, body_digest(create_run_body(run_id, 'i')), NOW)
        self.store.intake().create_run(run_id, 'i', run_id, profile=profile)
        self.store._db.execute(
            'INSERT INTO gateway_responses VALUES (?,?,?,?,?,?)',
            ('resp-' + run_id, 'p', run_id, body_digest('r'), 'co-text', NOW))
        self.store._db.execute('INSERT INTO gateway_work VALUES (?,?)',
                               (run_id, NOW))
        if terminal:
            with self.store._tx():
                data, before = self.store._load_locked(run_id)
                data['run'] = replace(data['run'], state=c.State.FAILED,
                                      final_reason='run_failed')
                self.store._store_locked(run_id, data, before)

    def ghost(self):
        return c.TaskProfile('co-text', 'sha256:' + '9' * 64, 'pure', True,
                             ((MODEL, ADAPTER, ENV),))

    def test_checker_requires_real_registry(self):
        with self.assertRaises(ProfileRegistryInvalid):
            check_store(object(), self.gateway, self.state)

    def test_missing_revision_nonterminal_refuses(self):
        self.add_run('run-missing', self.ghost())
        with self.assertRaises(ProfileRegistryMismatch):
            check_store(self.registry, self.gateway, self.state)

    def test_terminal_absent_revision_allowed(self):
        self.add_run('run-done', self.ghost(), terminal=True)
        self.assertEqual(
            check_store(self.registry, self.gateway, self.state),
            frozenset())

    def test_mismatch_and_none_quarantine_per_run(self):
        self.add_run('run-good', self.pinned)
        self.add_run('run-bad', replace(
            self.pinned, routes=((MODEL, ADAPTER, 'env:wrong'),)))
        self.add_run('run-none', None)
        before = self.store._db.total_changes
        result = check_store(self.registry, self.gateway, self.state)
        self.assertEqual(result, frozenset({'run-bad', 'run-none'}))
        self.assertIs(type(result), frozenset)
        self.assertEqual(self.store._db.total_changes, before)



    def test_live_alias_remap_pins_new_submissions_only(self):
        w1 = wire_entry()
        w2 = wire_entry(job_instructions='Revised instructions.')
        d1, d2 = self.pinned.revision_digest, revision_digest(w2)
        req = parse(json.dumps({'model': 'co-text', 'input': 'x'}).encode())
        self.receipts['e1'] = IngressReceipt(
            'p', 'e1', body_digest(submit_body(req.body_hash, None)), NOW)
        first = self.gateway.submit(req, None, 'e1')
        self.registry = load_registry(json.dumps(registry_doc([w1, w2], [
            {'alias': 'co-text', 'profile_id': 'co-text',
             'revision_digest': d2}])), catalog=self.catalog,
            routes=(self.route,))
        self.receipts['e2'] = IngressReceipt(
            'p', 'e2', body_digest(submit_body(req.body_hash, None)), NOW)
        second = self.gateway.submit(req, None, 'e2')
        self.assertNotEqual(first.run_id, second.run_id)
        self.assertEqual(
            self.state.get_run(first.run_id).profile.revision_digest, d1)
        self.assertEqual(
            self.state.get_run(second.run_id).profile.revision_digest, d2)

if __name__ == '__main__':
    unittest.main()
