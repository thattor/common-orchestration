"""Qualification-gate tests; injected readers/probes only, no real IO."""
import hashlib
import unittest

from co_v4.contracts import (AttemptRef, ExecutionConditions, ExecuteRequest,
    Job)
from co_v4.protocol_profile import (ASSERTIONS, MANIFEST_SCHEMA, ProfileError,
    RouteProtocolProfile, canonical, environment_ref, issue_profile,
    verify_manifest)
from co_v4.qualified_route import QualifiedRouteGate

BLOBS = {'/cap/responses.sse': b'data: r\n\n', '/cap/chat.sse': b'data: c\n\n',
         '/src/task.cpp': b'// serializer source\n'}
ENDPOINT, AUTH_REF = 'http://127.0.0.1:50353/v1', 'prov-key'
COMMIT = 'd81235049384534c167caea52b85a694f6103d14'


def manifest(**over):
    m = {'schema': MANIFEST_SCHEMA, 'provider_build': 'b11429',
         'provider_commit': COMMIT, 'model_sha256': '9' * 64,
         'model_id': 'co04-qwen3-06b',
         'launch': {'argv': ['llama-server', '--parallel', '1'],
                    'chat_template_sha256': 'a' * 64, 'slots': 1,
                    'threads': 2, 'bind': '127.0.0.1:50353'},
         'auth': {'mode': 'api_key_file', 'credential_ref': 'prov-key'},
         'qualification': {'sdk_version': '3.24.0',
             'auth_results': {'missing': 401, 'wrong': 401, 'valid': 200}},
         'captures': [{'protocol': 'responses', 'path': '/cap/responses.sse'},
                      {'protocol': 'chat', 'path': '/cap/chat.sse'}],
         'assertions': {name: {'passed': True} for name in ASSERTIONS},
         'multipart': {'kind': 'source_evidence',
                       'sha256': hashlib.sha256(BLOBS['/src/task.cpp'])
                       .hexdigest(), 'path': '/src/task.cpp',
                       'commit': COMMIT}}
    for cap in m['captures']:
        cap['sha256'] = hashlib.sha256(BLOBS[cap['path']]).hexdigest()
    m.update(over)
    m['manifest_sha256'] = hashlib.sha256(canonical(
        {k: v for k, v in m.items() if k != 'manifest_sha256'})).hexdigest()
    return m


def make_profile():
    return issue_profile(verify_manifest(manifest(), BLOBS.__getitem__),
        'responses', index_mode='absent_single_part', sequence_mode='absent',
        inert_fields={'response.completed': ('timings',)})


def env_for(prof, endpoint=ENDPOINT, auth_ref=AUTH_REF):
    return environment_ref(endpoint, auth_ref, prof.profile_digest)


def request(env, model='co04-qwen3-06b', adapter='openai.responses'):
    ref = AttemptRef('run', 'job', 'att')
    return ExecuteRequest(ref, Job('run', 'job', 'goal', ('ac',), '{}'),
        ExecutionConditions(model, adapter, '/w', env))


def gate(**kw):
    args = dict(read_evidence=BLOBS.__getitem__,
                probe_identity=lambda: {'model': 'co04-qwen3-06b'},
                launch_attested=lambda f, e, a: True)
    args.update(kw)
    return QualifiedRouteGate(**args)


def call(g, prof, m=None, endpoint=ENDPOINT, auth_ref=AUTH_REF, req=None):
    return g.qualify(profile=prof, manifest=m if m is not None else manifest(),
        endpoint=endpoint, auth_ref=auth_ref,
        request=req if req is not None else request(env_for(prof)))


def expect(g, prof, reason, **kw):
    try:
        call(g, prof, **kw)
    except ProfileError as exc:
        assert str(exc) == reason, (str(exc), reason)
        return
    raise AssertionError('expected ' + reason)


class QualifiedRouteGateTests(unittest.TestCase):
    def test_valid_passes_and_binds(self):
        seen = []
        prof = make_profile()
        g = gate(launch_attested=lambda f, e, a: seen.append(
            (f['provider_build'], e, a)) or True)
        binding = call(g, prof)
        # Attestation saw the manifest fields, endpoint and auth_ref.
        self.assertEqual(seen, [('b11429', ENDPOINT, AUTH_REF)])
        self.assertEqual(binding.environment_ref, env_for(prof))
        self.assertEqual(binding.profile.profile_digest, prof.profile_digest)
        self.assertEqual((binding.model, binding.auth_ref),
                         ('co04-qwen3-06b', 'prov-key'))
        self.assertNotIn('PRIVATE_CANARY', repr(binding))
        self.assertEqual(call(g, prof).environment_ref,
                         binding.environment_ref)

    def test_evidence_drift_exact_reasons(self):
        prof = make_profile()
        stale = manifest()
        stale['model_id'] = 'other-model'         # manifest_sha256 drift
        expect(gate(), prof, 'manifest_sha256 mismatch', m=stale)
        expect(gate(read_evidence=lambda p: b'tampered'), prof,
               'capture sha256 mismatch')
        expect(gate(read_evidence={}.__getitem__), prof, 'capture unreadable')
        def bad_source(path):
            return b'forged' if path == '/src/task.cpp' else BLOBS[path]
        expect(gate(read_evidence=bad_source), prof,
               'source evidence sha256 mismatch')
        # Forged direct profile: wrong manifest hash inside its digest.
        forged = RouteProtocolProfile(protocol='responses',
            model='co04-qwen3-06b', index_mode='absent_single_part',
            sequence_mode='absent', inert_fields={},
            provider_manifest_sha256='0' * 64)
        expect(gate(), forged, 'profile mismatch')
        # Chat profile against a manifest with no qualified chat capture.
        only_r = manifest(captures=[{'protocol': 'responses',
            'path': '/cap/responses.sse',
            'sha256': hashlib.sha256(BLOBS['/cap/responses.sse'])
            .hexdigest()}])
        chat_prof = RouteProtocolProfile(protocol='chat',
            model='co04-qwen3-06b', index_mode='present',
            sequence_mode='present', inert_fields={},
            provider_manifest_sha256=only_r['manifest_sha256'])
        expect(gate(), chat_prof, 'no qualified capture for protocol', m=only_r)
        # A pre-verified object is not authority: the gate verifies itself.
        expect(gate(), prof, 'manifest not serializable',
               m=verify_manifest(manifest(), BLOBS.__getitem__))

    def test_attestation_and_binding_exact_reasons(self):
        prof = make_profile()
        # auth_ref must equal manifest credential_ref even when the request
        # env was derived with the drifted ref.
        expect(gate(), prof, 'auth_ref mismatch', auth_ref='other-ref',
               req=request(env_for(prof, auth_ref='other-ref')))
        for attest in (lambda f, e, a: False, lambda f, e, a: 1,
                       lambda f, e, a: None, lambda f, e, a: 1 / 0):
            with self.subTest(attest=attest):
                expect(gate(launch_attested=attest), prof,
                       'launch attestation failed')
        # Correct served model but unattested launch (host never launched it).
        def hostile(fields, endpoint, auth_ref):
            fields['provider_build'] = 'b00000'   # move the comparison?
            return True
        expect(gate(launch_attested=hostile,
                    probe_identity=lambda: {'model': 'co04-qwen3-06b',
                                            'build': 'b00000'}),
               prof, 'observed identity mismatch')
        for model, adapter in (('m2', 'openai.responses'),
                               ('co04-qwen3-06b', 'openai.chat')):
            with self.subTest(binding=(model, adapter)):
                expect(gate(), prof, 'request binding mismatch',
                       req=request(env_for(prof), model=model,
                                   adapter=adapter))
        expect(gate(), prof, 'environment_ref mismatch',
               req=request('env:sha256:' + '0' * 64))

    def test_probe_cases_exact_reasons(self):
        prof = make_profile()
        cases = {
            'identity probe failed': [lambda: 1 / 0],
            'identity probe invalid': [lambda: 'x',
                lambda: {'build': 'b11429'},
                lambda: {'model': 'co04-qwen3-06b', 'extra': 'x'}],
            'observed identity mismatch': [lambda: {'model': 'other-model'},
                lambda: {'model': 'co04-qwen3-06b', 'build': 'b00000'},
                lambda: {'model': 'co04-qwen3-06b', 'commit': '0' * 40}],
        }
        for reason, probes in cases.items():
            for probe in probes:
                with self.subTest(reason=reason, probe=probe):
                    expect(gate(probe_identity=probe), prof, reason)

    def test_failure_excludes_for_lifetime(self):
        prof = make_profile()
        calls = []
        def flaky():
            calls.append(1)
            return {'model': 'other' if len(calls) == 1
                    else 'co04-qwen3-06b'}
        g = gate(probe_identity=flaky)
        req = request(env_for(prof))
        expect(g, prof, 'observed identity mismatch', req=req)
        expect(g, prof, 'route excluded', req=req)   # no requalification
        self.assertEqual(calls, [1])

    def test_gate_requires_host_callbacks(self):
        for kw in ({'launch_attested': None},
                   {'read_evidence': None}, {'probe_identity': None}):
            with self.subTest(kw=kw):
                args = dict(read_evidence=BLOBS.__getitem__,
                    probe_identity=lambda: {}, launch_attested=lambda: True)
                args.update(kw)
                with self.assertRaises(ProfileError) as ctx:
                    QualifiedRouteGate(**args)
                self.assertEqual(str(ctx.exception),
                                 'gate requires host readers')


if __name__ == '__main__':
    unittest.main()
