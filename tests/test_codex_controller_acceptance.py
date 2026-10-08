"""Product Controller/Adapter with local synthetic stdio; no provider calls."""
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from co_v4 import contracts as c
from co_v4.catalog import Catalog, CatalogEntry, Verification
from co_v4.judgment import TrustedEvidence
from co_v4.state import IngressReceipt, body_digest, create_run_body
from probes import codex_controller_acceptance as probe

SCRIPT = '''#!{python}
import sys,json
if '--version' in sys.argv:
 print('codex-cli 0.159.2');sys.exit(0)
def emit(x): print(json.dumps(x),flush=True)
for line in sys.stdin:
 m=json.loads(line);p=m.get('params',{{}});method=m.get('method');i=m.get('id')
 if method=='initialize': emit({{'id':i,'result':{{'userAgent':'fixture'}}}})
 elif method=='thread/start':
  emit({{'id':i,'result':{{'thread':{{'id':'t'}},'model':p['model'],'modelProvider':'openai','cwd':p['cwd'],'approvalPolicy':'on-request','approvalsReviewer':'user','activePermissionProfile':{{'id':p['permissions']}},'reasoningEffort':'medium','serviceTier':('default' if 'service_tier="default"' in sys.argv else 'priority')}}}})
 elif method=='turn/start':
  emit({{'id':i,'result':{{'turn':{{'id':'u','status':'inProgress'}}}}}})
  emit({{'method':'item/started','params':{{'threadId':'t','turnId':'u','startedAtMs':1,'item':{{'id':'i','type':'agentMessage','text':''}}}}}})
  emit({{'method':'item/completed','params':{{'threadId':'t','turnId':'u','completedAtMs':2,'item':{{'id':'i','type':'agentMessage','text':{output!r}}}}}}})
  emit({{'method':'turn/completed','params':{{'threadId':'t','turn':{{'id':'u','status':'completed','error':None,'itemsView':'notLoaded','items':[]}}}}}})
'''


class ControllerTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.executable = self.root / 'synthetic-native'
        self.executable.write_text(SCRIPT.format(python=probe.sys.executable, output=probe.EXPECTED))
        self.executable.chmod(0o700)
        self.home = self.root / 'home'; (self.home / '.codex').mkdir(parents=True)
        (self.home / '.codex/auth.json').write_text('SYNTHETIC-NOT-A-CREDENTIAL')
        self.environment, self.descriptor = 'fixture:sol', {'synthetic': True}
        self.sessions = []
        self.protection, self.deny, self.origin = True, False, True
        self.usage_allowed, self.tier, self.source_valid = True, 'fast', True
        self.fast_feature = True
        outer = self
        self.addCleanup(patch.stopall)
        class FixtureHost:
            def __init__(self, config):
                self.config = config; self._profile_name = 'co_readonly_' + 'a' * 32
                self._request = None; self._admitted = False
                self.observation = {'native_handoff_verified': False}
            def verify(self, request, phase, native):
                self.config.delegation.validate(request, 'codex.readonly.local')
                if phase == 'launch': self._request = request
                elif phase == 'turn':
                    if request != self._request: raise ValueError('fixture binding')
                    self._admitted = True; self._native_thread_id = native['thread']['id']
                    self.observation = {'native_handoff_verified': True}
                    if self.config.mode is not None:
                        self.observation['subscription_precondition'] = probe.subscription_gate(
                            self._rpc('account/read', {}), self._rpc('account/rateLimits/read', {}),
                            api_environment_absent=True)
                        self.observation['service_tier_observation'] = probe.verify_service_tier(
                            self.config.mode, self._rpc('config/read', {})['config'], native)
            def transport(self, request):
                import co_v4.codex_host as host_module
                return host_module.StdioTransport(str(self.config.executable), request.conditions.workspace,
                    config_overrides=probe.service_tier_overrides(self.config.mode) if self.config.mode else (), env={}, required_version='codex-cli 0.159.2')
            def _rpc(self, method, params):
                if method == 'account/read': return {'account': {'type': 'chatgpt', 'planType': 'pro'}, 'requiresOpenaiAuth': True}
                if method == 'account/rateLimits/read': return {'ordinaryUsageAllowed': outer.usage_allowed, 'rateLimits': {}}
                if method == 'config/read': return {'config': {'service_tier': outer.tier, 'features': {'fast_mode': outer.fast_feature}}}
                raise AssertionError('unexpected fixture RPC')
        real_session = probe.ProfileTextSession
        class CapturedSession(real_session):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs); outer.sessions.append(self)
        patch.object(probe, 'CodexReadOnlyHost', FixtureHost).start()
        patch.object(probe, 'ProfileTextSession', CapturedSession).start()
        patch.object(probe, 'environment_definition', return_value=(self.environment, self.descriptor)).start()
        patch.object(probe, 'configured_launch_inventory', return_value=((), ())).start()
        patch.object(Path, 'home', return_value=self.home).start()

    def inputs(self):
        run, intent, source = 'fixture-run', 'Fixture authorizes one fixed-text response.', 'fixture:platform'
        received = datetime.now(timezone.utc).isoformat()
        def origin(ref):
            if ref != source or not self.origin: raise ValueError('fixture origin refused')
            return IngressReceipt('fixture-owner', source, body_digest(create_run_body(run, intent)), received)
        def evidence(snapshot, request, admission):
            refs = ('fixture:owned-source',)
            valid = admission is not None and admission.request_digest == body_digest(request)
            if admission is not None:
                self.assertFalse(admission.native_handoff_verified)
                self.assertEqual(admission.state_revision, snapshot.revision)
                refs += (admission.evidence_ref,)
            return TrustedEvidence(body_digest(request), 'fixture:policy', refs, body_digest(request.action),
                hard_deny=self.deny, intent_contained=True, intent_authorizes=True,
                conditions_verified=valid, protection_verified=valid and self.protection)
        def source_check():
            if not self.source_valid: raise ValueError('fixture source drift')
        catalog = Catalog((CatalogEntry(probe.MODEL, probe.ADAPTER, {}, (
            Verification(probe.MODEL, probe.ADAPTER, probe.USE, self.environment,
                'fixture:official', 'fixture:implementation', 'fixture:prior-measurement', 'fixture:prior-ac'),)),))
        return dict(run_id=run, human_intent=intent, human_intent_ref=source,
            origin_verifier=origin, evidence_resolver=evidence, executable=self.executable,
            catalog=catalog, environment_ref=self.environment, check_source=source_check,
            service_tier='fast', timeout=1)

    def test_explicit_modes_use_host_gate_and_canonical_reports(self):
        for mode in ('fast', 'tibo', 'normal'):
            with self.subTest(mode=mode):
                self.tier = 'default' if mode == 'normal' else 'fast'
                self.fast_feature = mode != 'normal'
                inputs = self.inputs()
                inputs.pop('service_tier')
                report = probe.run(self.root / mode, mode=mode, **inputs)
                self.assertTrue(report['accepted'], report)
                self.assertEqual(report['mode'], 'fast' if mode == 'tibo' else mode)
                session = self.sessions[-1]
                self.assertEqual(session.config.mode, report['mode'])
                self.assertEqual(report['observation']['service_tier']['requested'], report['mode'])

    def test_product_controller_fixed_text_job_and_run_ac(self):
        report = probe.run(self.root / 'run', **self.inputs())
        self.assertTrue(report['accepted'], report)
        self.assertEqual((report['attempts'], report['routing_records'], report['job_goal_count'], report['run_goal_count']), (1, 1, 1, 1))
        self.assertEqual(report['check_verdicts'], ['pass', 'pass'])
        for key in ('generic_stop_qualified', 'sol_llm_planner_qualified', 'human_gateway_exercised', 'catalog_promoted'):
            self.assertFalse(report[key])
        self.assertNotIn(probe.EXPECTED, (self.root / 'run/control/observation.json').read_text())
        session = self.sessions[0]
        self.assertEqual(session.stop(session.request.ref).status, c.StopStatus.CONFIRMED)
        self.assertEqual(session.adapter.stop(session.request.ref).status, c.StopStatus.UNCONFIRMED)

    def test_normal_stop_never_comes_from_cleanup_or_partial_observation(self):
        self.assertTrue(probe.run(self.root / 'run', **self.inputs())['accepted'])
        session = self.sessions[0]
        for field, value in (('turn_rpc_confirmed', False), ('terminal', None), ('eof_validated', False),
                ('wait_exit', None), ('cleanup_terminated', True), ('error', 'fixture-error'), ('turn_submissions', 0), ('thread', 'other'), ('turn', None)):
            with self.subTest(field=field):
                old = getattr(session.wire, field); setattr(session.wire, field, value)
                try: self.assertNotEqual(session.stop(session.request.ref).status, c.StopStatus.CONFIRMED)
                finally: setattr(session.wire, field, old)
        with self.assertRaisesRegex(ValueError, 'cross Attempt'):
            session.stop(replace(session.request.ref, attempt_id='other'))
        self.source_valid = False
        with self.assertRaises(ValueError): session.stop(session.request.ref)

    def test_unbound_or_second_dispatch_refused(self):
        self.assertTrue(probe.run(self.root / 'run', **self.inputs())['accepted'])
        session = self.sessions[0]
        with self.assertRaises(ValueError): session.execute(session.request)
        with self.assertRaises(ValueError): session.events(replace(session.request.ref, attempt_id='other'))
        with self.assertRaises(FileExistsError): probe.run(self.root / 'run', **self.inputs())

    def test_usage_or_tier_mismatch_never_sends_model_turn(self):
        for name, value in (('usage_allowed', False), ('tier', 'default')):
            old = getattr(self, name); setattr(self, name, value)
            try:
                report = probe.run(self.root / name, **self.inputs())
                self.assertFalse(report['accepted'])
                self.assertEqual(report['observation']['native']['turn_submissions'], 0)
                self.assertFalse(report['observation']['native']['scoped_completion_evidence_complete'])
            finally: setattr(self, name, old)

    def test_origin_deny_or_unknown_protection_never_launches_worker(self):
        for name, value in (('origin', False), ('deny', True), ('protection', False)):
            old = getattr(self, name); setattr(self, name, value)
            try:
                report = probe.run(self.root / name, **self.inputs())
                self.assertFalse(report['accepted']); self.assertFalse(report['submission_claimed'])
                self.assertEqual(len(self.sessions), 0)
            finally: setattr(self, name, old)

    def test_other_model_or_environment_catalog_not_reused(self):
        for model, environment in (('gpt-6-astra', self.environment), ('gpt-6.1-sol', self.environment), (probe.MODEL, 'other')):
            inputs = self.inputs()
            inputs['catalog'] = Catalog((CatalogEntry(model, probe.ADAPTER, {}, (
                Verification(model, probe.ADAPTER, probe.USE, environment, 'o', 'i', 'm', 'a'),)),))
            with self.assertRaisesRegex(ValueError, 'reviewed exact-use'):
                probe.run(self.root / 'must-not-exist', **inputs)
            self.assertFalse((self.root / 'must-not-exist').exists())


if __name__ == '__main__': unittest.main()
