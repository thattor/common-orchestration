"""Qualification identity tests; pure bytes, no IO, network or secrets."""
import hashlib
import unittest

from co_v4.protocol_profile import (ASSERTIONS, ENV_PREFIX, MANIFEST_SCHEMA,
    ProfileError, RouteProtocolProfile, canonical, environment_ref,
    issue_profile, load_manifest, verify_manifest)

BLOBS = {'/cap/responses.sse': b'data: r\n\n', '/cap/chat.sse': b'data: c\n\n',
         '/src/task.cpp': b'// serializer source\n'}


def manifest(**over):
    m = {'schema': MANIFEST_SCHEMA, 'provider_build': 'b11429',
         'provider_commit': 'd81235049384534c167caea52b85a694f6103d14',
         'model_sha256': '9' * 64, 'model_id': 'co04-qwen3-06b',
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
                       'sha256': hashlib.sha256(BLOBS['/src/task.cpp']).hexdigest(),
                       'path': '/src/task.cpp',
                       'commit': 'd81235049384534c167caea52b85a694f6103d14'}}
    for cap in m['captures']:
        cap['sha256'] = hashlib.sha256(BLOBS[cap['path']]).hexdigest()
    m.update(over)
    m['manifest_sha256'] = hashlib.sha256(canonical(
        {k: v for k, v in m.items() if k != 'manifest_sha256'})).hexdigest()
    return m


def verified(**over):
    return verify_manifest(manifest(**over), BLOBS.__getitem__)


def rehashed(m):
    m['manifest_sha256'] = hashlib.sha256(canonical(
        {k: v for k, v in m.items() if k != 'manifest_sha256'})).hexdigest()
    return m


class ManifestTests(unittest.TestCase):
    def test_valid_manifest_verifies(self):
        self.assertEqual(len(verified().manifest_sha256), 64)

    def test_structure_rejects(self):
        mutations = (
            lambda m: m.update(schema='co.provider-manifest/0'),
            lambda m: m.pop('model_id'),
            lambda m: m.update(alien=1),
            lambda m: m.update(provider_commit='z' * 40),
            lambda m: m['launch'].pop('slots'),
            lambda m: m['launch']['argv'].append(1),
            lambda m: m['auth'].update(token='x'),
            lambda m: m['qualification']['auth_results'].update(valid=201),
            lambda m: m['captures'][0].pop('protocol'),
            lambda m: m['assertions']['terminal_byte_agreement'].update(
                passed=False),
            lambda m: m['assertions'].pop('no_defaulted_indices'),
            lambda m: m['assertions'].update(extra={'passed': True}),
            lambda m: m['multipart'].update(kind='vague'),
            lambda m: m['multipart'].update(kind='rejection_capture',
                                            sha256='f' * 64),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                m = manifest()
                mutate(m)
                # Rehash so the structural rule, not the hash, fails.
                with self.assertRaises(ProfileError):
                    verify_manifest(rehashed(m), BLOBS.__getitem__)

    def test_integrity_rejects(self):
        m = manifest()
        m['model_id'] = 'other-model'        # stale manifest_sha256
        with self.assertRaises(ProfileError):
            verify_manifest(m, BLOBS.__getitem__)
        with self.assertRaises(ProfileError):   # capture bytes tampered
            verify_manifest(manifest(), lambda p: b'tampered')
        with self.assertRaises(ProfileError):   # unreadable capture
            verify_manifest(manifest(), {}.__getitem__)

    def test_source_evidence_rehashed_and_commit_bound(self):
        verified()   # valid source evidence reads and hashes correctly
        m = manifest()
        m['multipart']['commit'] = '0' * 40    # drifted from provider_commit
        with self.assertRaises(ProfileError):
            verify_manifest(rehashed(m), BLOBS.__getitem__)
        m = manifest()
        m['multipart']['sha256'] = 'f' * 64    # stale declared hash
        with self.assertRaises(ProfileError):
            verify_manifest(rehashed(m), BLOBS.__getitem__)
        def missing(path):                     # source file absent
            if path == '/src/task.cpp':
                raise OSError('gone')
            return BLOBS[path]
        with self.assertRaises(ProfileError):
            verify_manifest(manifest(), missing)

    def test_detached_snapshot_blocks_midverify_mutation(self):
        # A hostile/concurrent caller mutating its own input during the
        # reader callback cannot remove evidence from the check set, and
        # forged second-capture bytes still reject.
        m = manifest()
        calls = []
        def hostile(path):
            calls.append(path)
            m['captures'][:] = []
            return (b'forged' if path == '/cap/chat.sse' else BLOBS[path])
        with self.assertRaises(ProfileError):
            verify_manifest(m, hostile)
        # Snapshot still iterated the removed second capture; fail-closed
        # stops there — the source-evidence read is never reached.
        self.assertEqual(calls, ['/cap/responses.sse', '/cap/chat.sse'])

    def test_postverify_input_mutation_cannot_move_proof(self):
        m = manifest()
        v = verify_manifest(m, BLOBS.__getitem__)
        m['model_id'] = 'forged'
        prof = issue_profile(v, 'responses')
        self.assertEqual(prof.model, 'co04-qwen3-06b')



class ProfileIssueTests(unittest.TestCase):
    def test_issue_requires_verified(self):
        for bad in (manifest(), object(), None):
            with self.subTest(bad=bad):
                with self.assertRaises(ProfileError):
                    issue_profile(bad, 'responses')

    def test_digest_determinism_and_invalidation_chain(self):
        kw = dict(index_mode='absent_single_part', sequence_mode='absent',
                  inert_fields={'response.completed': ('timings',)})
        prof = issue_profile(verified(), 'responses', **kw)
        self.assertEqual((prof.index_mode, prof.model),
                         ('absent_single_part', 'co04-qwen3-06b'))
        self.assertEqual(prof.profile_digest,
                         issue_profile(verified(), 'responses', **kw)
                         .profile_digest)
        other = issue_profile(verified(model_id='other-model'), 'responses')
        self.assertNotEqual(prof.profile_digest, other.profile_digest)
        ref = environment_ref('http://127.0.0.1:50353/v1', 'prov-key',
                              prof.profile_digest)
        self.assertTrue(ref.startswith(ENV_PREFIX))
        self.assertNotEqual(ref, environment_ref(
            'http://127.0.0.1:50353/v1', 'prov-key', other.profile_digest))
        self.assertNotEqual(ref, environment_ref(
            'http://127.0.0.1:1/v1', 'prov-key', prof.profile_digest))

    def test_sealed_proof_immutability(self):
        v = verified()
        prof = issue_profile(v, 'responses')
        # Mutating the reparsed manifest view cannot reach the sealed proof.
        v.manifest['model_id'] = 'forged-after-verification'
        again = issue_profile(v, 'responses')
        self.assertEqual(again.model, 'co04-qwen3-06b')
        self.assertEqual(again.profile_digest, prof.profile_digest)
        # inert_fields is deeply sealed: neither caller-dict mutation nor
        # attribute assignment can move the digest after issue.
        inert = {'response.completed': ('timings',)}
        q = issue_profile(v, 'responses', index_mode='absent_single_part',
                          sequence_mode='absent', inert_fields=inert)
        digest = q.profile_digest
        inert['response.failed'] = ('x',)
        with self.assertRaises(TypeError):
            q.inert_fields['response.created'] = ('y',)
        self.assertEqual(q.profile_digest, digest)
        self.assertNotEqual(prof.profile_digest, digest)

    def test_profile_guards(self):
        only_chat = manifest(captures=[{
            'protocol': 'chat', 'path': '/cap/chat.sse',
            'sha256': hashlib.sha256(BLOBS['/cap/chat.sse']).hexdigest()}])
        with self.assertRaises(ProfileError):   # protocol has no capture
            issue_profile(verify_manifest(only_chat, BLOBS.__getitem__),
                          'responses')
        with self.assertRaises(ProfileError):   # single-part: responses only
            issue_profile(verified(), 'chat', index_mode='absent_single_part',
                          sequence_mode='absent')
        with self.assertRaises(ProfileError):   # single-part needs absent seq
            issue_profile(verified(), 'responses',
                          index_mode='absent_single_part')
        for bad in ({'index_mode': 'optional'}, {'sequence_mode': 'mixed'},
                    {'protocol': 'alien'}, {'model': ''},
                    {'provider_manifest_sha256': 'zz'},
                    {'inert_fields': {'e': ['list']}},
                    {'inert_fields': {'e': ('b', 'a')}},
                    {'inert_fields': {'e': ('has space',)}},
                    {'inert_fields': {'e': ('a', ['b'])}},
                    {'index_mode': 'absent_single_part'},
                    {'protocol': 'chat', 'index_mode': 'absent_single_part',
                     'sequence_mode': 'absent'},
                    {'protocol': ['responses']},
                    {'index_mode': {'x': 1}}):
            with self.subTest(bad=bad):
                kw = dict(protocol='responses', index_mode='present',
                    sequence_mode='present', inert_fields={}, model='m',
                    provider_manifest_sha256='0' * 64)
                kw.update(bad)
                with self.assertRaises(ProfileError):
                    RouteProtocolProfile(**kw)

    def test_environment_ref_inputs(self):
        digest = issue_profile(verified(), 'responses').profile_digest
        for bad in (('', 'prov-key', digest),
                    ('http://x', 'has space', digest),
                    ('http://x', 'prov-key', 'zz')):
            with self.subTest(bad=bad):
                with self.assertRaises(ProfileError):
                    environment_ref(*bad)


if __name__ == '__main__':
    unittest.main()
