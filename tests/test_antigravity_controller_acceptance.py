"""Synthetic authority/transport fixtures; actual Controller/Adapter/AC, Native 0."""
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from co_v4.antigravity_profiles import CANDIDATE_ROUTES
from co_v4.adapters.antigravity import AntigravityTextAdapter, TextProfile, payload_digest
from co_v4.catalog import Catalog, CatalogEntry, Verification
from co_v4.judgment import TrustedEvidence
from co_v4.state import IngressReceipt, body_digest, create_run_body
from probes import antigravity_controller_acceptance as probe
from test_antigravity import Transport, frames


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name).resolve();self.workspace=self.root/'approved';self.workspace.mkdir(mode=0o700)
        self.environment='fixture:qualified';self.descriptor={'fixture':True}
        self.output=probe.EXPECTED;self.normal=True;self.launches=[];self.checks=[]
        outer=self
        class FixtureHost:
            def __init__(self,config,request,*,verify_launch_policy):
                self.config,self.request,self.policy=config,request,verify_launch_policy
                self.profile=TextProfile(request,payload_digest(request))
                self.observation={'native_handoff_verified':False,'cessation':'unconfirmed'}
            def verify(self,request,profile):
                self.config.delegation.validate(request,probe.CAPABILITY)
                return self.policy(request,profile,('fixture',),frozenset())
            def make_adapter(self):
                def factory(request,payload,profile):
                    self.verify(request,profile);outer.launches.append(request)
                    f=frames();f[0]['init']['cwd']=str(outer.workspace)
                    f[2]['step_update']['text_delta']=outer.output;f[-1]['result']['response']=outer.output
                    return Transport(f)
                def completion(*args):
                    if not outer.normal:raise ValueError('fixture unconfirmed')
                    self.observation.update(native_handoff_verified=True,cessation='confirmed')
                    return 'fixture:normal'
                return AntigravityTextAdapter(profile=self.profile,verify_host=self.verify,
                    transport_factory=factory,verify_completion=completion)
            def verified_native_stream(self, expected):
                if not outer.normal or outer.output != expected:raise ValueError('fixture AC')
                return b'fixture:verified-original-stream-not-native'
            def structural_observation(self):return ()
            def process_facts(self):
                return {'streams_eof':outer.normal,'normal_exit_zero':outer.normal,'owned_process_reaped':True}
        self.addCleanup(patch.stopall)
        patch.object(probe,'AntigravityTextHost',FixtureHost).start()
        patch.object(probe,'environment_definition',return_value=(self.environment,self.descriptor)).start()
        patch('subprocess.Popen',side_effect=AssertionError('Native forbidden')).start()

    def inputs(self,*,deny=False,origin=True,protection=True):
        run='fixture-run';intent='Fixture authorized bounded text';source='fixture:origin'
        received_at=datetime.now(timezone.utc).isoformat()
        def provenance(ref):
            if not origin or ref!=source:raise ValueError('fixture origin')
            return IngressReceipt('fixture-owner',source,body_digest(create_run_body(run,intent)),received_at)
        def evidence(snapshot,request,admission):
            refs=('fixture:state',)
            valid=admission is not None and admission.request_digest==body_digest(request)
            if admission is not None:
                self.assertFalse(admission.native_handoff_verified);refs+=(admission.evidence_ref,)
            return TrustedEvidence(body_digest(request),'fixture:policy',refs,body_digest(request.action),
                hard_deny=deny,intent_contained=True,intent_authorizes=True,
                conditions_verified=valid,protection_verified=valid and protection)
        def policy_factory(execution):
            def verify(request,*args):
                if request!=execution:raise ValueError('changed request')
                self.checks.append(request)
            return verify
        catalog=Catalog((CatalogEntry(probe.MODEL,probe.ADAPTER,{},(
            Verification(probe.MODEL,probe.ADAPTER,probe.USE,self.environment,
                'fixture:official','fixture:implementation','fixture:prior-native','fixture:prior-ac'),)),))
        return dict(workspace=self.workspace,run_id=run,human_intent=intent,human_intent_ref=source,
            origin_verifier=provenance,evidence_resolver=evidence,policy_factory=policy_factory,
            executable=self.root/'fixture-cli',hook_source=self.root/'hook.sh',skill_source=self.root/'SKILL.md',
            catalog=catalog,environment_ref=self.environment,timeout=2)

    def test_controller_independent_job_and_run_ac(self):
        report=probe.run(self.root/'run',**self.inputs())
        self.assertTrue(report['accepted'],report)
        self.assertEqual((report['attempts'],report['job_goal_count'],report['run_goal_count']),(1,1,1))
        self.assertEqual(report['check_verdicts'],['pass','pass'])
        self.assertEqual(len(self.launches),1)
        self.assertEqual(self.launches[0].conditions.workspace,str(self.workspace))
        self.assertEqual(list(self.workspace.iterdir()),[])
        self.assertGreaterEqual(len(self.checks),3)
        self.assertFalse(report['catalog_promoted']);self.assertFalse(report['human_gateway_exercised'])
        self.assertNotIn(probe.EXPECTED,(self.root/'run/control/observation.json').read_text())
        with self.assertRaises(FileExistsError):probe.run(self.root/'run',**self.inputs())
        self.assertEqual(len(self.launches),1)

    def test_wrong_output_and_unconfirmed_never_goal(self):
        self.output='WRONG'
        r=probe.run(self.root/'wrong',**self.inputs());self.assertFalse(r['accepted']);self.assertEqual(r['check_verdicts'],['fail'])
        self.normal=False
        r=probe.run(self.root/'unconfirmed',**self.inputs());self.assertFalse(r['accepted']);self.assertEqual(r['check_verdicts'],[])

    def test_no_authority_or_catalog_no_submission(self):
        for name,kwargs in [('deny',{'deny':True}),('origin',{'origin':False}),('protection',{'protection':False})]:
            r=probe.run(self.root/name,**self.inputs(**kwargs));self.assertFalse(r['accepted']);self.assertFalse(r['submission_claimed'])
        for key,value in [('catalog',Catalog()),('environment_ref','other')]:
            args=self.inputs();args[key]=value
            with self.assertRaises(ValueError):probe.run(self.root/key,**args)
        self.assertEqual(self.launches,[])

    def test_candidate_cannot_reuse_legacy_model_qualification(self):
        args = self.inputs()
        args['route_profile'] = CANDIDATE_ROUTES[0]
        with self.assertRaisesRegex(ValueError, 'exact-use qualification required'):
            probe.run(self.root / 'candidate', **args)
        self.assertEqual(self.launches, [])
        self.assertFalse((self.root / 'candidate').exists())

    def test_policy_failure_and_environment_drift_no_factory(self):
        args=self.inputs()
        def factory(_):
            def deny(*_):raise ValueError('actual usage expired')
            return deny
        args['policy_factory']=factory
        r=probe.run(self.root/'policy',**args);self.assertFalse(r['accepted']);self.assertEqual(self.launches,[])
        with patch.object(probe,'environment_definition',side_effect=[(self.environment,self.descriptor),('drift',self.descriptor)]):
            r=probe.run(self.root/'drift',**self.inputs());self.assertFalse(r['accepted'])
        self.assertEqual(self.launches,[])
