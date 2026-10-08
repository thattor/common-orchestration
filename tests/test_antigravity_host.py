"""Owned pipe fixtures only: no Native process, model, auth or hook runs."""
from dataclasses import replace
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from co_v4 import antigravity_host as h
from co_v4.contracts import OperationStatus, State, StopStatus
from co_v4.delegation import DelegatedScope
from probes import antigravity_text_worker as p
from test_antigravity import frames


class Process:
    def __init__(self, wire, error=b'', code=0):
        self.code=code
        streams=[]
        for data in (wire,error):
            r,w=os.pipe();os.write(w,data);os.close(w);streams.append(os.fdopen(r,'rb'))
        self.stdout,self.stderr=streams
    def poll(self):return self.code
    def wait(self,timeout=None):return self.code


class HostTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name).resolve();self.worker=self.root/'worker';self.worker.mkdir(mode=0o700)
        self.req=p.make_request(self.worker,'fixture:environment')
        self.config=h.AntigravityHostConfig(self.req.conditions,self.root/'agy',
            DelegatedScope('fixture:human',self.req.ref,str(self.worker),h.CAPABILITY),
            self.root/'hook.sh',self.root/'SKILL.md')
        def source(path,**_):
            return {self.config.executable:h.BINARY_SHA,self.config.hook_source:h.HOOK_SHA,self.config.skill_source:h.SKILL_SHA}[path]
        self.addCleanup(patch.stopall)
        patch.object(h,'_ordinary',side_effect=source).start()
        patch.dict(os.environ,{key:'' for key in h.ORCA_KEYS}).start()

    def wire(self,text=p.EXPECTED,**kwargs):
        fs=frames();fs[0]['init']['cwd']=str(self.worker);fs[0]['init']['agent']='jetski'
        fs[0]['init']['tools']=['view_file','run_command']
        fs[2]['step_update']['text_delta']=text+'\n';fs[-1]['result']['response']=text+'\n'
        return Process(b''.join(json.dumps(f).encode()+b'\n' for f in fs),**kwargs)

    def pump(self,a):
        for _ in range(10):
            state=a.status(self.req.ref).state
            if state in (State.COMPLETED,State.ERROR):return state
        self.fail('fixture did not terminate')

    def test_default_and_changed_effect_refuse_before_factory(self):
        for policy in (None,lambda *args:True):
            host=h.AntigravityTextHost(self.config,self.req,**({'verify_launch_policy':policy} if policy else {}))
            with patch.object(h.subprocess,'Popen') as factory:
                self.assertEqual(host.make_adapter().execute(self.req).status,OperationStatus.UNSUPPORTED)
                factory.assert_not_called()
        host=h.AntigravityTextHost(self.config,self.req,verify_launch_policy=lambda *args:None)
        with patch.dict(os.environ,{'ORCA_PANE_KEY':'fixture'}),patch.object(h.subprocess,'Popen') as factory:
            self.assertEqual(host.make_adapter().execute(self.req).status,OperationStatus.UNSUPPORTED)
            factory.assert_not_called()
        with patch.object(h,'_ordinary',return_value='bad'),patch.object(h.subprocess,'Popen') as factory:
            self.assertEqual(host.make_adapter().execute(self.req).status,OperationStatus.UNSUPPORTED)
            factory.assert_not_called()

    def test_owned_result_eof_wait_bound_prompt_and_once(self):
        checks=[];host=h.AntigravityTextHost(self.config,self.req,verify_launch_policy=lambda *args:checks.append(args))
        a=host.make_adapter()
        with patch.object(h.subprocess,'Popen',return_value=self.wire()) as factory:
            self.assertEqual(a.execute(self.req).status,OperationStatus.ACCEPTED)
            self.assertEqual(self.pump(a),State.COMPLETED)
            self.assertEqual(a.text_output(self.req.ref),p.EXPECTED)
            self.assertEqual(a.stop(self.req.ref).status,StopStatus.CONFIRMED)
            self.assertEqual(a.execute(self.req).status,OperationStatus.INVALID_STATE)
            self.assertEqual(factory.call_count,1)
            argv=factory.call_args.args[0]
            self.assertEqual(argv[-2],'--print')
            self.assertEqual(json.loads(argv[-1])['instructions'],self.req.job.instructions)
            self.assertEqual(json.loads(argv[-1])['delegation']['workspace'],'.')
            self.assertNotIn(str(self.worker),argv[-1])
            self.assertEqual(host.config.delegation.workspace,str(self.worker))
            self.assertEqual(argv[argv.index('--print-timeout')+1],'120s')
            self.assertEqual(factory.call_args.kwargs['stdin'],h.subprocess.DEVNULL)
        self.assertEqual(len(checks),2)
        self.assertTrue(host.process_facts()['streams_eof'])
        self.assertEqual(host.observation['effective_effort'],'unmeasured')

    def test_stderr_bad_exit_and_unowned_completion_fail(self):
        for opts in ({'error':b'PRIVATE_CANARY'},{'code':1}):
            host=h.AntigravityTextHost(self.config,self.req,verify_launch_policy=lambda *args:None);a=host.make_adapter()
            with patch.object(h.subprocess,'Popen',return_value=self.wire(**opts)):
                a.execute(self.req);self.assertEqual(self.pump(a),State.ERROR)
            self.assertEqual(a.stop(self.req.ref).status,StopStatus.UNCONFIRMED)
            self.assertNotIn('PRIVATE_CANARY',repr(host.process_facts()))
        with self.assertRaises(ValueError):
            host.verify_completion(self.req,Mock(),'session',None,{},host.profile)

    def test_probe_independent_ac_and_same_output_refusal(self):
        for text,expect in ((p.EXPECTED,True),(p.EXPECTED+'\n',False)):
            output=self.root/('pass' if expect else 'fail')
            with patch.object(h.subprocess,'Popen',return_value=self.wire(text)):
                report=p.run(output,self.req,self.config,verify_launch_policy=lambda *args:None)
            self.assertEqual(report['accepted'],expect)
            self.assertTrue(report['process']['normal_exit_zero'])
            self.assertEqual(report['actual_bytes'],20 if expect else 21)
            if not expect:
                self.assertEqual(report['actual_sha256'],'66dc44686c65521cda1fa1cfc7e42043267b7654128cdf25b78d11a93ceda65d')
                self.assertFalse(report['ac_passed'])
            self.assertEqual((output/'verified-native.ndjson').exists(),expect)
            if expect:self.assertEqual((output/'verified-native.ndjson').stat().st_mode & 0o777,0o600)
            self.assertTrue((output/'submission-claim.json').exists())
            with patch.object(h.subprocess,'Popen') as factory:
                with self.assertRaises(FileExistsError):
                    p.run(output,self.req,self.config,verify_launch_policy=lambda *args:None)
                factory.assert_not_called()
        self.assertNotEqual(p.make_request(self.worker,'fixture').ref,p.make_request(self.worker,'fixture').ref)
