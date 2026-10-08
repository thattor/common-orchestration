"""#190 M5: documented route-profile fields pin the actual measured
semantics — README, RUNBOOK and the example config must agree with the
fixed issued values.

Doc tables are compared field-for-field, and the negatives use the real
fixtures: spec-declared modes that differ from the RELEASED profile
while keeping the released digest/env are a route refusal with no
credential or gate construction; a re-moded profile under the original
request env is an environment_ref mismatch and that env is then
excluded for the gate's lifetime. Nothing claims a different profile
carrying its own fresh env is refused."""
import ast
from dataclasses import replace
import json
from pathlib import Path
import re
import unittest
from unittest.mock import patch

from co_v4 import host_routes as hr
from co_v4 import profile_registry as pr
from co_v4 import response_serializer as rs
from co_v4.catalog import (Catalog, CatalogEntry, UseCase,
                           Verification)
from co_v4.host_config import ProfileSpec, RouteSpec
from co_v4.launch_attestation import RouteUnqualified
from co_v4.openai_transport import Deadlines
from co_v4.protocol_profile import (RouteProtocolProfile,
                                    environment_ref, issue_profile,
                                    verify_manifest)
import test_host_routes as hrt
import test_profile_registry as prt
import test_qualified_route as qr

ROOT = Path(__file__).resolve().parents[1]

# The actual released values — fixed facts, not a re-qualification.
EXPECTED = {
    'openai.responses': {
        'protocol': 'responses', 'index_mode': 'absent_single_part',
        'sequence_mode': 'absent',
        'inert_fields': {'response.completed': ['timings']}},
    'openai.chat': {
        'protocol': 'chat', 'index_mode': 'present',
        'sequence_mode': 'present', 'inert_fields': {}}}

# The real per-protocol issuance arguments against a sealed manifest.
RELEASED_ARGS = {
    'openai.responses': dict(index_mode='absent_single_part',
                             sequence_mode='absent',
                             inert_fields={'response.completed':
                                           ('timings',)}),
    'openai.chat': {}}

# Fixed-format table rows. Leading horizontal indent is allowed — the
# RUNBOOK block is nested — but [ \t] never crosses a newline.
_ROW = re.compile(
    r'^[ \t]*\|[ \t]*`(openai\.responses|openai\.chat)`[ \t]*\|'
    r'[ \t]*`([^`]+)`[ \t]*\|[ \t]*`([^`]+)`[ \t]*\|'
    r'[ \t]*`([^`]+)`[ \t]*\|[ \t]*`([^`]+)`[ \t]*\|', re.M)


def _norm_inert(inert):
    """Doc tuple form and example list form compare as lists."""
    return {k: list(v) for k, v in inert.items()}


def doc_profiles(path):
    """Parse the fixed profile-table rows -> {adapter: field dict}."""
    rows = {}
    for adapter, proto, idx, seq, inert in _ROW.findall(
            path.read_text()):
        rows[adapter] = {'protocol': proto, 'index_mode': idx,
                         'sequence_mode': seq,
                         'inert_fields': _norm_inert(
                             ast.literal_eval(inert))}
    return rows


def released_spec(tmp, cred, mpath, adapter, *, profile=None):
    """RouteSpec wired to the ACTUAL released issuance of the sealed
    fixture manifest — the real digest and env, not generic defaults."""
    doc = json.loads(Path(mpath).read_text())
    protocol = adapter.rsplit('.', 1)[1]
    prof = issue_profile(verify_manifest(doc, hr.read_evidence),
                         protocol, **RELEASED_ARGS[adapter])
    launch = tmp / 'launch.json'
    if not launch.exists():
        hrt.write(launch, {})
    if profile is None:
        # Declared spec mirrors the issued profile exactly.
        profile = ProfileSpec(
            protocol, prof.index_mode, prof.sequence_mode,
            tuple(sorted((k, tuple(v))
                         for k, v in prof.inert_fields.items())))
    return RouteSpec(
        model=hrt.MODEL, adapter=adapter, endpoint=hrt.ENDPOINT,
        auth_ref=hrt.AUTH_REF, credential_file=str(cred),
        manifest_file=str(mpath), launch_record=str(launch),
        profile=profile,
        profile_digest='sha256:' + prof.profile_digest,
        environment_ref=environment_ref(hrt.ENDPOINT, hrt.AUTH_REF,
                                        prof.profile_digest),
        store_param='omit',
        deadlines=Deadlines(connect=5, first_byte=10, idle=30,
                            total=60),
        max_drain_s=30,
        verification=('general', 'r:o', 'r:i', 'r:m', 'r:a'))


class ProfileDocsTests(unittest.TestCase):
    def test_example_and_docs_match_measured_profiles(self):
        example = json.loads(
            (ROOT / 'examples' / 'host.example.json').read_text())
        doc_rows = {}
        for name in ('README.md', 'RUNBOOK.md'):
            rows = doc_profiles(ROOT / name)
            self.assertEqual(set(rows), set(EXPECTED), name)
            doc_rows[name] = rows
        self.assertEqual(len(example['routes']), 2)
        for route in example['routes']:
            with self.subTest(adapter=route['adapter']):
                self.assertEqual(route['profile'],
                                 EXPECTED[route['adapter']])
                for name in ('README.md', 'RUNBOOK.md'):
                    self.assertEqual(doc_rows[name][route['adapter']],
                                     EXPECTED[route['adapter']], name)


class PhaseBReleasedProfileTests(unittest.TestCase):
    """Spec-declared modes vs the released profile on the real Phase B
    path — real manifest/capture files, real verify/issue, real
    RouteUnqualified, and no credential or gate is ever constructed."""

    def setUp(self):
        self.fx = hrt.HostRoutesTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.tmp = self.fx._mk()
        self.cred = self.fx.cred(self.tmp)
        self.mpath = hrt.write(self.tmp / 'manifest.json',
                               hrt.manifest_dict(self.tmp, self.cred))

    def test_released_profiles_build_positive_control(self):
        for adapter in (hrt.RESPONSES, hrt.CHAT):
            spec = released_spec(self.tmp, self.cred, self.mpath,
                                 adapter)
            hr.build_routes(self.fx.config(self.tmp, (spec,),
                                           self.cred))

    def test_declared_mode_mutations_refused_no_credential_or_gate(self):
        cases = (
            # Released Responses is absent_single_part/absent/timings:
            # declared generic modes, and the dropped inert declaration,
            # each keeping the real released digest and env.
            (hrt.RESPONSES,
             ProfileSpec('responses', 'present', 'present', ())),
            (hrt.RESPONSES,
             ProfileSpec('responses', 'absent_single_part', 'absent',
                         ())),
            # Released Chat is present/present: declared sequence absent.
            (hrt.CHAT,
             ProfileSpec('chat', 'present', 'absent', ())),
        )
        for adapter, declared in cases:
            with self.subTest(adapter=adapter, declared=declared):
                spec = released_spec(self.tmp, self.cred, self.mpath,
                                     adapter, profile=declared)
                with patch.object(hr, 'CredentialSupplier') as creds, \
                        patch.object(hr, 'QualifiedRouteGate') as gates:
                    with self.assertRaises(RouteUnqualified):
                        hr.build_routes(
                            self.fx.config(self.tmp, (spec,),
                                           self.cred))
                creds.assert_not_called()
                gates.assert_not_called()


class GateReleasedProfileTests(unittest.TestCase):
    """Re-moded profiles under the ORIGINAL request env fail as
    environment_ref mismatch on the real gate — the gate re-issues with
    the profile's own modes, derives a different digest, and the env
    comparison is what fails. The env is then excluded for the gate's
    lifetime, so even the correct profile is refused as excluded."""

    def test_mode_mutants_env_mismatch_then_route_excluded(self):
        cases = []
        r_prof = qr.make_profile()      # real released Responses profile
        r_req = qr.request(qr.env_for(r_prof))
        cases.append(('responses-remoded',
                      replace(r_prof, index_mode='present',
                              sequence_mode='present',
                              inert_fields={}),
                      r_prof, r_req))
        cases.append(('responses-no-inert',
                      replace(r_prof, inert_fields={}),
                      r_prof, r_req))
        c_prof = issue_profile(verify_manifest(
            qr.manifest(), qr.BLOBS.__getitem__), 'chat')
        c_req = qr.request(qr.env_for(c_prof), adapter='openai.chat')
        cases.append(('chat-sequence-absent',
                      replace(c_prof, sequence_mode='absent',
                              inert_fields=dict(c_prof.inert_fields)),
                      c_prof, c_req))
        for name, mutant, good, req in cases:
            with self.subTest(name=name):
                g = qr.gate()
                qr.expect(g, mutant, 'environment_ref mismatch',
                          req=req)
                qr.expect(g, good, 'route excluded', req=req)


def _registry_snippet():
    """The RUNBOOK §3.5 fenced block, executed verbatim — the doc text
    itself is under test; a re-typed copy would pin nothing."""
    for block in re.findall(r'```python\n(.*?)```',
                            (ROOT / 'RUNBOOK.md').read_text(), re.S):
        if 'co-text-resp' in block \
                and 'co.task-profile-registry/1' in block:
            return block
    raise AssertionError('registry snippet not found in RUNBOOK')


class RegistrySnippetTests(unittest.TestCase):
    """The documented §3.5 registry document must load through the real
    load_registry and resolve each qualification alias to exactly its
    documented single actual route. Catalog Verifications carry the
    declared controlled fixture refs — fixture evidence, never a live
    or Native qualification claim."""

    USE = UseCase('general')
    PROFILES = {
        'openai.responses': RouteProtocolProfile(
            'responses', 'present', 'present', {}, prt.MODEL,
            prt.MANIFEST),
        'openai.chat': RouteProtocolProfile(
            'chat', 'present', 'present', {}, prt.MODEL, prt.MANIFEST)}
    ENVS = {a: environment_ref(prt.ENDPOINT, prt.AUTH_REF,
                               p.profile_digest)
            for a, p in PROFILES.items()}

    def setUp(self):
        self.catalog = Catalog(tuple(
            CatalogEntry(prt.MODEL, adapter, {self.USE: 2}, (
                Verification(prt.MODEL, adapter, self.USE, env,
                             'r:o', 'r:i', 'r:m', 'r:a',
                             output_mode='collect'),))
            for adapter, env in self.ENVS.items()))
        self.routes = tuple(pr.RouteConfig(
            model=prt.MODEL, adapter=adapter,
            environment_ref=env, endpoint=prt.ENDPOINT,
            auth_ref=prt.AUTH_REF, deadlines=Deadlines(total=100),
            max_drain_s=20, profile=self.PROFILES[adapter])
            for adapter, env in self.ENVS.items())

    def _ns(self):
        ns = {'model': prt.MODEL,
              'env_resp': self.ENVS['openai.responses'],
              'env_chat': self.ENVS['openai.chat']}
        exec(compile(_registry_snippet(), 'RUNBOOK.md §3.5', 'exec'), ns)
        return ns

    def _load(self, doc):
        return pr.load_registry(json.dumps(doc), catalog=self.catalog,
                                routes=self.routes)

    def test_snippet_loads_and_aliases_pin_exact_routes(self):
        ns = self._ns()
        reg = self._load(ns['doc'])
        self.assertEqual(reg.resolve('co-text-resp').routes,
            ((prt.MODEL, 'openai.responses',
              self.ENVS['openai.responses']),))
        self.assertEqual(reg.resolve('co-text-chat').routes,
            ((prt.MODEL, 'openai.chat', self.ENVS['openai.chat']),))
        self.assertEqual(reg.resolve('co-text').routes, (
            (prt.MODEL, 'openai.chat', self.ENVS['openai.chat']),
            (prt.MODEL, 'openai.responses',
             self.ENVS['openai.responses'])))
        base = tuple(pr.BASE_CRITERIA)
        for pid, digest in (('co-text-resp', ns['digest_resp']),
                            ('co-text-chat', ns['digest_chat'])):
            with self.subTest(profile_id=pid):
                entry = reg.get(pid, digest)
                self.assertEqual(entry.ac.exact_any, ('4',))
                self.assertEqual(entry.job_criteria,
                                 base + ('ac:exact',))
        general = reg.get('co-text', ns['digest'])
        self.assertIsNone(general.ac.exact_any)
        self.assertEqual(general.job_criteria, base)

    def test_exact_criterion_and_exact_any_move_together(self):
        ns = self._ns()
        base = list(pr.BASE_CRITERIA)
        cases = (
            ('exact_any without ac:exact',
             dict(ns['qual_resp'], job_criteria=base)),
            ('ac:exact without exact_any',
             dict(ns['entry'], job_criteria=base + ['ac:exact'])),
            ('exact_any on general without ac:exact',
             dict(ns['entry'],
                  ac=dict(ns['entry']['ac'], exact_any=['4']))))
        for label, wire in cases:
            with self.subTest(label=label):
                digest = pr.revision_digest(wire)
                doc = {'schema': pr.REGISTRY_SCHEMA,
                       'entries': [{'revision_digest': digest,
                                    'entry': wire}],
                       'aliases': [{'alias': wire['profile_id'],
                                    'profile_id': wire['profile_id'],
                                    'revision_digest': digest}]}
                with self.assertRaises(pr.ProfileRegistryInvalid):
                    self._load(doc)


class SerializerDocsTableTests(unittest.TestCase):
    """README's failed-Response table is pinned byte-equal to the
    serializer's own closed _MESSAGES table, which the module already
    asserts equals PROJECTION_CODES."""

    def test_nine_closed_codes_and_fixed_texts(self):
        self.assertEqual(len(rs._MESSAGES), 9)
        text = (ROOT / 'README.md').read_text()
        self.assertIn('error.code = "server_error"', text)
        self.assertIn('error.message = "<co_code>: <fixed text>"', text)
        rows = {code: tail for code, tail in re.findall(
            r'\| `([a-z_]+)` \| `([^`]+)` \|', text)
            if code in rs._MESSAGES}
        self.assertEqual(set(rows), set(rs._MESSAGES))
        for code, message in rs._MESSAGES.items():
            with self.subTest(code=code):
                self.assertEqual(message, code + ': ' + rows[code])


if __name__ == '__main__':
    unittest.main()
