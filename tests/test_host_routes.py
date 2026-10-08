"""#190 M3 host_routes: Phase B ordering, catalog merge, refusal factory.

Real manifest/capture/credential temp files drive the real
verify_manifest -> issue_profile path. The dispatch-mechanics test mocks
attestation/probe and fakes the transport -- it tests gate/loader/adapter
mechanics only and is NOT Provider qualification."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import tempfile
import unittest
from unittest.mock import patch

from co_v4 import contracts as c
from co_v4 import host_routes as hr
from co_v4.adapter_capacity import (CapacityError, CapacityLedger,
                                    PooledAdapter)
from co_v4.adapters.openai_chat import OpenAIChatAdapter
from co_v4.adapters.openai_responses import OpenAIResponsesAdapter
from co_v4.catalog import UseCase
from co_v4.host_config import HostConfig, ProfileSpec, RouteSpec
from co_v4.launch_attestation import RouteUnqualified
from co_v4.openai_transport import (Deadlines, OpenAIRoute, StreamEnded,
    StreamFailed, StreamStarted, payload_digest)
from test_openai_adapters import FakeTransport
from co_v4.protocol_profile import (ASSERTIONS, ProfileError, canonical,
    environment_ref, issue_profile, verify_manifest)
from co_v4.qualified_route import QualifiedRouteGate

COMMIT = 'd81235049384534c167caea52b85a694f6103d14'
MODEL = 'co04-qwen3-06b'
RESPONSES, CHAT = 'openai.responses', 'openai.chat'
ENDPOINT, AUTH_REF = 'http://127.0.0.1:50353/v1', 'prov-key'


def write(path, data, mode=0o600):
    path.write_bytes(data if type(data) is bytes else json.dumps(data).encode())
    os.chmod(path, mode)
    return path


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def manifest_dict(tmp, cred, **over):
    r_cap, c_cap, src = tmp / 'cap.sse', tmp / 'chat.sse', tmp / 'task.cpp'
    r_cap.write_bytes(b'data: r\n\n')
    c_cap.write_bytes(b'data: c\n\n')
    src.write_bytes(b'// serializer source\n')
    m = {'schema': 'co.provider-manifest/1', 'provider_build': 'b11429',
         'provider_commit': COMMIT, 'model_sha256': '9' * 64,
         'model_id': MODEL,
         'launch': {'argv': ['llama-server', '-m', '/m/m.gguf',
            '--chat-template-file', '/t/t.jinja',
            '--api-key-file', str(cred)], 'chat_template_sha256': 'a' * 64,
            'slots': 1, 'threads': 2, 'bind': '127.0.0.1:50353'},
         'auth': {'mode': 'api_key_file', 'credential_ref': AUTH_REF},
         'qualification': {'sdk_version': '3.24.0',
            'auth_results': {'missing': 401, 'wrong': 401, 'valid': 200}},
         'captures': [
            {'protocol': 'responses', 'path': str(r_cap),
             'sha256': _sha(r_cap)},
            {'protocol': 'chat', 'path': str(c_cap),
             'sha256': _sha(c_cap)}],
         'assertions': {n: {'passed': True} for n in ASSERTIONS},
         'multipart': {'kind': 'source_evidence', 'sha256': _sha(src),
                       'path': str(src), 'commit': COMMIT}}
    m.update(over)
    m['manifest_sha256'] = hashlib.sha256(canonical(
        {k: v for k, v in m.items() if k != 'manifest_sha256'})).hexdigest()
    return m


class HostRoutesTests(unittest.TestCase):
    def test_factory_route_no_confirmed_statuses_and_slot_held(self):
        """Q3: the production factory wires confirmed_statuses=() —
        400/401/429/500 classify http_status, pool stop stays UNCONFIRMED
        and the capacity slot remains held. Gate is a declared mock; the
        fake transport carries the child's own auth supplier identity."""
        cfg, spec, _ = self.world()
        bundle = hr.build_routes(cfg)
        ledger = CapacityLedger(str(self.base / 'ledger.db'))
        made = []

        def factory(req):
            child = bundle.factories[RESPONSES](req)
            child._gate = QualifiedRouteGate(
                read_evidence=hr.read_evidence,
                probe_identity=lambda: {'model': MODEL},
                launch_attested=lambda f, e, a: True)
            made.append(child)
            return child

        pool = PooledAdapter(RESPONSES, ledger=ledger,
                             canonical_ledger=ledger.path, factory=factory)
        for i, status in enumerate((400, 401, 429, 500)):
            with self.subTest(status=status):
                req = self.req(spec)

                def make_fake(*a, **k):
                    fake = FakeTransport([[StreamStarted(status),
                        StreamFailed('http_status', 'sent')]])
                    fake.auth_supplier = made[-1]._auth_supplier
                    return fake

                with patch.object(hr, 'HttpSseTransport',
                                  side_effect=make_fake):
                    self.assertEqual(pool.execute(req).status,
                                     c.OperationStatus.ACCEPTED)
                child = made[-1]
                self.assertEqual(child._route.confirmed_statuses, ())
                state = None
                for _ in range(10):
                    state = child.status(req.ref).state
                    if state in c.TERMINAL:
                        break
                self.assertEqual(state, c.State.FAILED
                                 if status in (400, 401, 429) else c.State.ERROR)
                outcome = next(e.result for e in pool.events(req.ref)
                               if type(e) is c.ResultEvent)
                self.assertEqual(outcome.reason, 'http_status')
                self.assertEqual(ledger.count(RESPONSES), i + 1)
                self.assertEqual(pool.stop(req.ref).status,
                                 c.StopStatus.UNCONFIRMED)
                self.assertEqual(ledger.count(RESPONSES), i + 1)

    def test_own_env_preflight_exclusion_other_gate_refuser_clean(self):
        """Q4: real QualifiedRouteGate objects with declared mock probe/
        attestation. A failing probe latches ONLY that env's exclusion; the
        other env's gate still qualifies and dispatches; a context-miss
        request is the NeverStarted refuser and adds zero exclusions."""
        tmp = self._mk()
        cred = self.cred(tmp)
        mpath = write(tmp / 'manifest.json', manifest_dict(tmp, cred))
        s1 = self.spec_for(tmp, cred, mpath)
        s2 = self.spec_for(tmp, cred, mpath,
                           endpoint='http://127.0.0.1:50354/v1')
        bundle = hr.build_routes(self.config(tmp, (s1, s2), cred))
        good = QualifiedRouteGate(
            read_evidence=hr.read_evidence,
            probe_identity=lambda: {'model': MODEL},
            launch_attested=lambda f, e, a: True)

        def fail_probe():
            raise RouteUnqualified('route_unqualified')

        bad = QualifiedRouteGate(
            read_evidence=hr.read_evidence, probe_identity=fail_probe,
            launch_attested=lambda f, e, a: True)
        # Own-env preflight failure: env1's child never reaches the wire and
        # env1 alone is latched on its gate.
        req1 = self.req(s1)
        child1 = bundle.factories[RESPONSES](req1)
        child1._gate = bad
        self.assertEqual(child1._route.confirmed_statuses, ())
        reply = child1.execute(req1)
        self.assertEqual(reply.status, c.OperationStatus.UNSUPPORTED)
        self.assertIs(reply.never_started.request, req1)
        self.assertIn(s1.environment_ref, bad._excluded)
        self.assertNotIn(s2.environment_ref, bad._excluded)
        # Other gate keeps qualifying its own env: real dispatch mechanics.
        req2 = self.req(s2)
        child2 = bundle.factories[RESPONSES](req2)
        child2._gate = good
        fake = FakeTransport([[StreamStarted(200), StreamEnded()]])
        fake.auth_supplier = child2._auth_supplier
        with patch.object(hr, 'HttpSseTransport', return_value=fake):
            self.assertEqual(child2.execute(req2).status,
                             c.OperationStatus.ACCEPTED)
        self.assertFalse(good._excluded)
        # No matching context: refusing child, request-bound receipt, and
        # zero new exclusions on either gate.
        orphan = self.req(s1, environment_ref='env:sha256:' + '0' * 64)
        reply = bundle.factories[RESPONSES](orphan).execute(orphan)
        self.assertEqual(reply.status, c.OperationStatus.UNSUPPORTED)
        self.assertIs(reply.never_started.request, orphan)
        self.assertEqual(reply.never_started.evidence_ref,
                         'route:unconfigured')
        self.assertFalse(good._excluded)
        self.assertNotIn(orphan.conditions.environment_ref, bad._excluded)

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.base = Path(self._tmp.name).resolve()   # Darwin realpath
        self._seq = 0

    def _mk(self):
        return Path(tempfile.mkdtemp(dir=str(self.base)))

    def cred(self, tmp):
        return write(tmp / 'cred', secrets.token_hex(32).encode())

    def spec_for(self, tmp, cred, mpath, endpoint=ENDPOINT,
                 auth_ref=AUTH_REF, adapter=RESPONSES, **over):
        doc = json.loads(Path(mpath).read_text())
        protocol = adapter.rsplit('.', 1)[1]
        prof = issue_profile(verify_manifest(doc, hr.read_evidence),
                             protocol)
        launch = tmp / 'launch.json'
        if not launch.exists():
            write(launch, {})
        kw = dict(model=MODEL, adapter=adapter, endpoint=endpoint,
            auth_ref=auth_ref, credential_file=str(cred),
            manifest_file=str(mpath), launch_record=str(launch),
            profile=ProfileSpec(protocol, 'present', 'present', ()),
            profile_digest='sha256:' + prof.profile_digest,
            environment_ref=environment_ref(endpoint, auth_ref,
                                            prof.profile_digest),
            store_param='omit', deadlines=Deadlines(
                connect=5, first_byte=10, idle=30, total=60),
            max_drain_s=30,
            verification=('general', 'r:o', 'r:i', 'r:m', 'r:a'))
        kw.update(over)
        return RouteSpec(**kw)

    def config(self, tmp, routes, cred):
        return HostConfig(str(tmp), str(tmp / 'cap.db'), '127.0.0.1',
                          18000, str(cred), str(cred), 4096, 5, routes)

    def world(self, manifest_over=None, **over):
        tmp = self._mk()
        cred = self.cred(tmp)
        mpath = write(tmp / 'manifest.json',
                      manifest_dict(tmp, cred, **(manifest_over or {})))
        spec = self.spec_for(tmp, cred, mpath, **over)
        return self.config(tmp, (spec,), cred), spec, cred

    def req(self, spec, **cond):
        self._seq += 1
        kw = dict(model=MODEL, adapter=RESPONSES,
                  workspace=hr.TEXT_WORKSPACE,
                  environment_ref=spec.environment_ref)
        kw.update(cond)
        ref = c.AttemptRef('run', 'job', 'att-%d' % self._seq)
        return c.ExecuteRequest(ref, c.Job(
            'run', 'job', 'goal', ('ac',), '{}', True),
            c.ExecutionConditions(**kw))

    def test_duplicate_route_key_refused_before_phase_b(self):
        # Opus F3: a directly constructed HostConfig whose routes share a
        # (model, adapter, environment_ref) key is refused before any
        # Phase B work — no manifest read, no credential supplier, even
        # when the specs differ only in non-key fields (store_param).
        tmp = self._mk()
        cred = self.cred(tmp)
        mpath = write(tmp / 'manifest.json', manifest_dict(tmp, cred))
        s1 = self.spec_for(tmp, cred, mpath)
        s2 = self.spec_for(tmp, cred, mpath, store_param='send_false')
        self.assertEqual(s1.environment_ref, s2.environment_ref)
        self.assertNotEqual(s1.store_param, s2.store_param)
        cfg = self.config(tmp, (s1, s2), cred)
        with patch.object(hr, '_protected_doc') as docs, \
                patch.object(hr, 'CredentialSupplier') as trap:
            with self.assertRaises(RouteUnqualified):
                hr.build_routes(cfg)
        docs.assert_not_called()
        trap.assert_not_called()

    def test_positive_bundle_and_api_key_kind(self):
        cfg, spec, _ = self.world()
        b = hr.build_routes(cfg)
        ctx = b.contexts[(MODEL, RESPONSES, spec.environment_ref)]
        v = b.catalog.entries[0].verifications[0]
        self.assertEqual((v.auth_route, v.output_mode),
                         ('api-key', 'collect'))
        self.assertEqual(v.environment_ref, spec.environment_ref)
        self.assertEqual(b.catalog.entries[0].recommended_for,
                         {UseCase('general'): hr.TEXT_ROUTE_RECOMMENDATION})
        rc = b.route_configs[0]
        self.assertEqual((rc.endpoint, rc.auth_ref, rc.max_drain_s),
                         (ENDPOINT, AUTH_REF, 30))
        self.assertIs(rc.profile, ctx.profile)
        self.assertEqual(spec.profile_digest,
                         'sha256:' + ctx.profile.profile_digest)
        self.assertEqual(ctx.manifest_sha256,
                         ctx.profile.provider_manifest_sha256)

    def test_catalog_merges_envs_and_supplier_dedup(self):
        tmp = self._mk()
        cred = self.cred(tmp)
        mpath = write(tmp / 'manifest.json', manifest_dict(tmp, cred))
        s1 = self.spec_for(tmp, cred, mpath)
        s2 = self.spec_for(tmp, cred, mpath,
                           endpoint='http://127.0.0.1:50354/v1')
        b = hr.build_routes(self.config(tmp, (s1, s2), cred))
        entry = b.catalog.entries[0]
        self.assertEqual({v.environment_ref for v in entry.verifications},
                         {s1.environment_ref, s2.environment_ref})
        ctx1 = b.contexts[(MODEL, RESPONSES, s1.environment_ref)]
        ctx2 = b.contexts[(MODEL, RESPONSES, s2.environment_ref)]
        self.assertIs(ctx1.supplier, ctx2.supplier)   # one object per file
        self.assertIsNot(ctx1.gate, ctx2.gate)        # one gate per env

    def test_divergent_ref_same_file_and_kind_refusal(self):
        tmp = self._mk()
        cred = self.cred(tmp)
        mpath = write(tmp / 'manifest.json', manifest_dict(tmp, cred))
        mpath2 = write(tmp / 'm2.json', manifest_dict(tmp, cred, auth={
            'mode': 'api_key_file', 'credential_ref': 'other-ref'}))
        s1 = self.spec_for(tmp, cred, mpath)
        s2 = self.spec_for(tmp, cred, mpath2, auth_ref='other-ref')
        with self.assertRaises(RouteUnqualified):
            hr.build_routes(self.config(tmp, (s1, s2), cred))
        cfg, spec, _ = self.world()
        for kind in ('oauth', AUTH_REF, ''):
            with self.subTest(kind=kind):
                with patch.object(hr, 'AUTH_KIND', kind):
                    with self.assertRaises(RouteUnqualified):
                        hr.build_routes(cfg)

    def test_phase_b_never_opens_credential(self):
        """Order proof: CredentialSupplier is trapped and must never be
        constructed on any independently invalid manifest/digest/model/
        auth/env/key-argv route."""
        launch = {'chat_template_sha256': 'a' * 64, 'slots': 1,
                  'threads': 2, 'bind': '127.0.0.1:50353'}
        cfgs = []
        cfg, spec, _ = self.world()             # capture tampered post-write
        Path(json.loads(Path(spec.manifest_file).read_text())
             ['captures'][0]['path']).write_bytes(b'tampered')
        cfgs.append(cfg)
        cfgs.append(self.world(
            profile_digest='sha256:' + '0' * 64)[0])
        cfgs.append(self.world(model='other-model')[0])
        cfgs.append(self.world(auth_ref='other-ref')[0])
        cfgs.append(self.world(
            environment_ref='env:sha256:' + '0' * 64)[0])
        for argv in (['llama-server', '-m', '/m/m.gguf'],
                     ['llama-server', '--api-key-file', 'a',
                      '--api-key-file', 'b'],
                     ['llama-server', '--api-key-file', '/other/key']):
            cfgs.append(self.world(manifest_over={
                'launch': dict(launch, argv=argv)})[0])
        with patch.object(hr, 'CredentialSupplier') as trap:
            for cfg in cfgs:
                with self.assertRaises(RouteUnqualified):
                    hr.build_routes(cfg)
        trap.assert_not_called()

    def test_loader_declared_digest_and_reread(self):
        cfg, spec, cred = self.world()
        ctx = hr.build_routes(cfg).contexts[
            (MODEL, RESPONSES, spec.environment_ref)]
        digest = ctx.profile.provider_manifest_sha256
        doc = ctx.loader(digest)
        self.assertEqual(doc['manifest_sha256'], digest)  # preserved field
        with self.assertRaises(ProfileError):             # declared != asked
            ctx.loader('0' * 64)
        Path(spec.manifest_file).write_bytes(b'not json')
        with self.assertRaises(RouteUnqualified):         # _protected_doc
            ctx.loader(digest)
        m = manifest_dict(Path(spec.manifest_file).parent, cred)
        m['manifest_sha256'] = 'f' * 64                   # forged declared
        write(Path(spec.manifest_file), m)
        with self.assertRaises(ProfileError):
            ctx.loader(digest)

    def test_readers_modes_nofollow_boundaries(self):
        cfg, spec, _ = self.world()
        mpath = Path(spec.manifest_file)
        self.assertTrue(hr.read_protected(str(mpath)))
        os.chmod(mpath, 0o664)
        with self.assertRaises(RouteUnqualified):
            hr.read_protected(str(mpath))
        os.chmod(mpath, 0o600)          # restore for independent cases
        link = self.base / 'link.json'
        os.symlink(mpath, link)
        for path in (str(link), str(self.base / 'absent'),
                     str(mpath) + '\x00x', str(self.base)):
            with self.subTest(path=path[-14:]):
                with self.assertRaises(RouteUnqualified):
                    hr.read_protected(path)
        for maximum in (0, -1, True, 1.5, 'x', 1 << 21):
            with self.subTest(maximum=maximum):
                with self.assertRaises(RouteUnqualified):
                    hr.read_protected(str(mpath), maximum=maximum)
        cap = Path(json.loads(mpath.read_text())['captures'][0]['path'])
        os.chmod(cap, 0o664)                            # not forced for evidence
        self.assertEqual(hr.read_evidence(str(cap)), b'data: r\n\n')
        os.mkfifo(self.base / 'cap.fifo')               # NONBLOCK: no hang
        with self.assertRaises(RouteUnqualified):
            hr.read_evidence(str(self.base / 'cap.fifo'))
        with self.assertRaises(RouteUnqualified):
            hr.read_evidence(str(cap) + '\x00x')

    def test_factory_miss_releases_lease_no_post(self):
        cfg, spec, _ = self.world()
        b = hr.build_routes(cfg)
        ledger = CapacityLedger(str(self.base / 'ledger.db'))
        pool = PooledAdapter(RESPONSES, ledger=ledger,
                             canonical_ledger=ledger.path,
                             factory=b.factories[RESPONSES])
        with patch.object(hr, 'HttpSseTransport') as trap:
            for miss in ({'environment_ref': 'env:sha256:' + '0' * 64},
                         {'workspace': '/other'},
                         {'model': 'ghost-model'}):
                with self.subTest(miss=miss):
                    req = self.req(spec, **miss)
                    reply = pool.execute(req)
                    self.assertEqual(reply.status,
                                     c.OperationStatus.UNSUPPORTED)
                    self.assertIs(reply.never_started.request, req)
                    self.assertEqual(reply.never_started.evidence_ref,
                                     'route:unconfigured')
                    row = ledger.row(req.ref, RESPONSES)
                    self.assertEqual(row[2:],
                                     ('released', 'route:unconfigured'))
        trap.assert_not_called()                        # zero POST/transport
        self.assertEqual(ledger.count(RESPONSES), 0)
        with self.assertRaises(CapacityError):          # real reserve rule
            pool.execute(self.req(spec, adapter=CHAT))

    def test_factory_positive_children_both_protocols(self):
        tmp = self._mk()
        cred = self.cred(tmp)
        mpath = write(tmp / 'manifest.json', manifest_dict(tmp, cred))
        s_r = self.spec_for(tmp, cred, mpath)
        s_c = self.spec_for(tmp, cred, mpath, adapter=CHAT)
        b = hr.build_routes(self.config(tmp, (s_r, s_c), cred))
        for spec, adapter, cls, path in (
                (s_r, RESPONSES, OpenAIResponsesAdapter, '/v1/responses'),
                (s_c, CHAT, OpenAIChatAdapter, '/v1/chat/completions')):
            with self.subTest(adapter=adapter):
                ctx = b.contexts[(MODEL, adapter, spec.environment_ref)]
                req = self.req(spec, adapter=adapter)
                child = b.factories[adapter](req)
                self.assertIs(type(child), cls)
                self.assertIs(child._gate, ctx.gate)
                self.assertIs(child._auth_supplier, ctx.supplier)
                self.assertIs(child._route.profile, ctx.profile)
                self.assertIs(child._route.request, req)
                transport = ctx.transport(req, b'{}', child._route)
                self.assertIs(transport.auth_supplier, ctx.supplier)
                self.assertEqual(transport._path, path)
                self.assertIs(transport._deadlines, ctx.deadlines)

    def test_execute_isolated_mechanics_not_provider_proof(self):
        """Gate+loader+adapter mechanics on real files and the real
        verify/issue/binding path; attestation/probe are LABELED MOCKS and
        the transport fake never opens a socket."""
        cfg, spec, _ = self.world()
        ctx = hr.build_routes(cfg).contexts[
            (MODEL, RESPONSES, spec.environment_ref)]
        req = self.req(spec)

        class FakeTransport:
            def __init__(self):
                self.auth_supplier = ctx.supplier
                self.sent_state, self.opened = 'not_sent', 0
            def open(self):
                self.opened += 1
                self.sent_state = 'sent'
            def close(self):
                pass

        fake = FakeTransport()
        gate = QualifiedRouteGate(
            read_evidence=hr.read_evidence,
            probe_identity=lambda: {'model': MODEL},
            launch_attested=lambda fields, e, a: True)
        child = OpenAIResponsesAdapter(
            verify_host=ctx.verify,
            transport_factory=lambda r, body, rt: fake,
            route=OpenAIRoute(request=req, endpoint=ENDPOINT,
                model=MODEL, store_param='omit',
                payload_sha256=payload_digest(req),
                sequence='required', profile=ctx.profile,
                auth_ref=AUTH_REF),
            max_drain=30, qualification_gate=gate,
            manifest_loader=ctx.loader, auth_supplier=ctx.supplier)
        reply = child.execute(req)
        self.assertEqual(reply.status, c.OperationStatus.ACCEPTED)
        self.assertEqual(fake.opened, 1)

    def test_refuser_identity_and_collector(self):
        self.assertEqual(hr.UnconfiguredResponsesAdapter.ADAPTER_ID,
                         RESPONSES)
        self.assertEqual(hr.UnconfiguredChatAdapter.ADAPTER_ID, CHAT)
        refuser = hr.UnconfiguredResponsesAdapter()
        self.assertIsInstance(refuser, c.OutputCollector)
        with self.assertRaises(c.CollectionError):
            refuser.collect_output(None)


if __name__ == '__main__':
    unittest.main()
