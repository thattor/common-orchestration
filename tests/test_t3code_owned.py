"""Owned synthetic children only; these tests never invoke Codex or T3."""
from dataclasses import replace
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from co_v4 import contracts as c
from co_v4.t3code_owned import OwnedCodexBroker, _same_birth
from co_v4.codex_host import DISABLED_FEATURES

PEER = '''import json,sys,time,signal,subprocess
if sys.argv[1] == '--version':
 print('fixture 1.0',flush=True); raise SystemExit
for raw in sys.stdin:
 m=json.loads(raw); p=m.get('params',{})
 with open('received-methods','a') as audit: audit.write(str(m.get('method'))+'\\n')
 if m.get('method')=='config/read':
  config={'features':{k:False for k in ['apps','plugins','hooks','memories','multi_agent','remote_plugin','skill_mcp_dependency_install','remote_control','shell_snapshot']},'mcp_servers':{},'notify':[],'web_search':'disabled','shell_environment_policy':{'inherit':'none','include_only':[],'set':{}}}
  if '--mcp-collision' in sys.argv: config['mcp_servers']={'t3-code':{'enabled':False}}
  if '--inherited-mcp' in sys.argv: config['mcp_servers']={'fixture-helper':{'enabled':False}}
  if '--cleared-env' in sys.argv: config['shell_environment_policy']['set']={'FIXTURE_SETTING':''}
  if '--active-env' in sys.argv: config['shell_environment_policy']['set']={'FIXTURE_SETTING':' '}
  if '--baseurl' in sys.argv: config['openai_base_url']='https://private.invalid'
  if '--chatgpturl' in sys.argv: config['chatgpt_base_url']='https://private.invalid'
  if '--provider' in sys.argv: config['model_provider']='custom'
  if '--openai-override' in sys.argv: config['model_providers']={'openai':{'base_url':'https://private.invalid'}}
  if '--unused-provider' in sys.argv: config['model_providers']={'unused':{'base_url':'https://private.invalid'}}
  if '--snapshot' in sys.argv: config['features']['shell_snapshot']=True
  if '--badconfig' in sys.argv: config['mcp_servers']={'inherited':{'enabled':True}}
  print(json.dumps({'id':m['id'],'result':{'config':config}}),flush=True)
 elif m.get('method')=='initialize':
  print(json.dumps({'id':m['id'],'result':{}}),flush=True)
 elif m.get('method')=='account/read':
  print(json.dumps({'id':m['id'],'result':{'requiresOpenaiAuth':True,'account':{'type':'apiKey' if '--api' in sys.argv else 'chatgpt','planType':'pro','email':'secret@example.invalid'}}}),flush=True)
 elif m.get('method')=='account/rateLimits/read':
  print(json.dumps({'id':m['id'],'result':{'rateLimits':{},'ordinaryUsageAllowed':'--noquota' not in sys.argv}}),flush=True)
 elif m.get('method')=='initialized': pass
 elif m.get('method')=='thread/start':
  if '--inherited-mcp' in sys.argv and p['config'].get('mcp_servers',{}).get('fixture-helper') != {'enabled':False}:
   print(json.dumps({'method':'mcpServer/startupStatus/updated','params':{'name':'fixture-helper'}}),flush=True)
  if '--startup-escape' in sys.argv:
   detached=subprocess.Popen([sys.executable,'-c','import time;time.sleep(.6)'],start_new_session=True,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
   detached.wait()
  if '--inherited-mcp' in sys.argv:
   assert p['config']['mcp_servers']=={'fixture-helper':{'enabled':False},'t3-code':{'url':'http://127.0.0.1:49999/mcp','http_headers':{'Authorization':'Bearer private-fixture-token'}}}
  print(json.dumps({'id':m['id'],'result':{'thread':{'id':'native-thread'},'model':p['model'],'cwd':p['cwd'],'modelProvider':'custom' if '--thread-provider' in sys.argv else 'openai'}}),flush=True)
 elif m.get('method')=='turn/start':
  if '--escape' in sys.argv:
   detached=subprocess.Popen([sys.executable,'-c','import time;time.sleep(1)'],start_new_session=True,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
   time.sleep(.3)
   detached.wait()
  if '--orphan' in sys.argv:
   subprocess.Popen([sys.executable,'-c','import time;time.sleep(2)'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
   time.sleep(.3)
  print(json.dumps({'id':m['id'],'result':{'turn':{'id':'native-turn'}}}),flush=True)
  print(json.dumps({'method':'turn/completed','params':{'threadId':'native-thread','turn':{'id':'native-turn','status':'completed','error':None}}}),flush=True)
if '--hang' in sys.argv:
 signal.signal(signal.SIGTERM,signal.SIG_IGN)
 while True: time.sleep(.1)
'''

class OwnedBrokerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='t3o-',dir='/tmp')
        self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name).resolve()
        self.peer=self.base/'peer'
        self.peer.write_text('#!'+sys.executable+'\n'+PEER);self.peer.chmod(0o700)
        self.request=c.ExecuteRequest(c.AttemptRef('r','j','a'), c.Job('r','j','text',('exact',)),
            c.ExecutionConditions('fixture-model','t3code.orchestration-v2',str(self.base),'fixture-env'))

    def owner(self,args=('app-server',),**options):
        owner=OwnedCodexBroker(self.base/'owner',executable=self.peer,argv_allowlist=[args,('--version',)],
                              env={'PATH':os.defpath},cwd=self.base,**options)
        self.addCleanup(owner.close)
        owner.arm(self.request,prompt='exact private prompt',effort='low',service_tier='default')
        return owner

    def client(self,owner,args=('app-server',)):
        p=subprocess.Popen([str(owner.wrapper_path),*args],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        def cleanup():
            if p.poll() is None: p.kill()
            p.wait()
            for stream in (p.stdin,p.stdout,p.stderr): stream.close()
        self.addCleanup(cleanup)
        return p

    def send(self,p,value):
        p.stdin.write((json.dumps(value)+'\n').encode());p.stdin.flush()

    def start(self,p):
        self.send(p,{'id':1,'method':'thread/start','params':{'model':'fixture-model','cwd':str(self.base),'config':{'tools.update_plan.enabled':True}}})
        self.assertEqual(json.loads(p.stdout.readline())['result']['thread']['id'],'native-thread')

    def turn(self,p,**changes):
        params={'threadId':'native-thread','model':'fixture-model','cwd':str(self.base),'effort':'low',
                'serviceTier':'default','approvalPolicy':'untrusted','sandboxPolicy':{'type':'readOnly'},
                'input':[{'type':'text','text':'exact private prompt'}]}
        params.update(changes);self.send(p,{'id':2,'method':'turn/start','params':params})

    def finish(self,owner,**changes):
        return owner.finish(self.request,native_thread_id=changes.get('thread','native-thread'),
                            native_turn_id=changes.get('turn','native-turn'),timeout=5)

    def completed(self,p):
        self.assertIn(b'native-turn',p.stdout.readline());self.assertIn(b'turn/completed',p.stdout.readline())

    def test_pinned_null_metadata_forwarded_without_turn(self):
        owner=self.owner();p=self.client(owner)
        self.send(p,{'method':'initialized','params':None})
        self.send(p,{'id':9,'method':'account/rateLimits/read','params':None})
        self.assertIn('rateLimits',json.loads(p.stdout.readline())['result'])
        p.stdin.close();p.wait(3)
        self.assertFalse(owner.observation()['children'][0]['failed'])
        self.assertIsNone(owner._selected)

    def reject_input(self, value, expected):
        owner=self.owner();p=self.client(owner);self.send(p,value);p.stdin.close();p.wait(3)
        self.assertEqual(p.stdout.read(), b'')
        self.assertEqual(owner.observation()['children'][0]['failure_code'], expected)
        self.assertIsNone(owner._selected)
        self.assertFalse((self.base/'received-methods').exists())

    def test_unreviewed_thread_config_layer_rejected_before_native(self):
        self.reject_input({'id':1,'method':'thread/start','params':{'model':'fixture-model',
            'cwd':str(self.base),'config':{'tools.update_plan.enabled':True,
            'sandbox_mode':'danger-full-access'}}}, 'thread_config_layer')

    def test_config_write_rejected_before_native(self):
        self.reject_input({'id':1,'method':'config/value/write','params':{
            'keyPath':'sandbox_mode','value':'danger-full-access','mergeStrategy':'replace'}}, 'unknown_rpc')

    def test_approval_response_rejected_before_native(self):
        self.reject_input({'id':1,'result':{'decision':'accept'}}, 'rpc_or_approval_response')

    def test_thread_mcp_redirect_rejected_before_native(self):
        self.reject_input({'id':1,'method':'thread/start','params':{'model':'fixture-model',
            'cwd':str(self.base),'config':{'tools.update_plan.enabled':True,'mcp_servers':{
            't3-code':{'url':'http://127.0.0.1:9999/mcp','http_headers':{'Authorization':'Bearer fixture'}}}}}},
            'thread_mcp_binding')

    def test_pinned_thread_mcp_layer_and_initialize_permit_normal_completion(self):
        url='http://127.0.0.1:49999/mcp'
        owner=self.owner(t3_mcp_url=url);p=self.client(owner)
        self.send(p,{'id':7,'method':'initialize','params':{
            'clientInfo':{'name':'T3 Code','title':'T3 Code','version':'0.0.45'},
            'capabilities':{'experimentalApi':True,'optOutNotificationMethods':['turn/diff/updated']}}})
        self.assertEqual(json.loads(p.stdout.readline())['result'],{})
        self.send(p,{'id':1,'method':'thread/start','params':{'model':'fixture-model',
            'cwd':str(self.base),'config':{'tools.update_plan.enabled':True,'mcp_servers':{
            't3-code':{'url':url,'http_headers':{'Authorization':'Bearer private-fixture-token'}}}}}})
        self.assertIn(b'native-thread',p.stdout.readline())
        self.turn(p);self.completed(p)
        proof=self.finish(owner)
        self.assertIsNotNone(proof,owner.observation());self.assertTrue(proof.normal_completion)
        self.assertNotIn('private-fixture-token',json.dumps(owner.observation()))
        self.assertNotIn('private-fixture-token',repr(proof))

    def test_endpoint_mutation_creates_no_native_child(self):
        owner=self.owner(t3_mcp_url='http://127.0.0.1:49999/mcp')
        owner.t3_mcp_url='http://127.0.0.1:49998/mcp'
        p=self.client(owner);p.stdin.close();p.wait(3)
        self.assertEqual(owner.observation()['children'],[])

    def test_normal_completion_exact_proof_and_metadata_children(self):
        owner=self.owner()
        self.assertEqual(subprocess.check_output([str(owner.wrapper_path),'--version']),b'fixture 1.0\n')
        p=self.client(owner);self.start(p);self.turn(p);self.completed(p)
        proof=self.finish(owner);self.assertIsNotNone(proof, owner.observation());self.assertTrue(proof.normal_completion)
        self.assertTrue(owner.verify_proof(proof,self.request))
        self.assertFalse(owner.verify_proof(replace(proof),self.request))
        self.assertFalse(owner.verify_proof(proof,replace(self.request,ref=c.AttemptRef('r','j','other'))))
        p.wait(3);self.assertEqual(p.returncode,0)
        self.assertNotIn('exact private prompt',repr(proof))

    def test_client_killed_owner_still_drains_original_native(self):
        owner=self.owner();p=self.client(owner);self.start(p);self.turn(p);self.completed(p)
        p.kill();p.wait(3)
        proof=self.finish(owner);self.assertIsNotNone(proof, owner.observation());self.assertTrue(proof.normal_completion)

    def test_force_reap_is_not_normal_completion(self):
        args=('app-server','--hang');owner=self.owner(args);p=self.client(owner,args)
        self.start(p);self.turn(p);self.completed(p)
        proof=self.finish(owner);self.assertIsNotNone(proof, owner.observation());self.assertTrue(proof.forced)
        self.assertFalse(proof.normal_completion);self.assertLess(proof.exit_code,0)

    def test_wrong_prompt_refused_before_native_turn(self):
        owner=self.owner();p=self.client(owner);self.start(p)
        self.turn(p,input=[{'type':'text','text':'wrong'}]);p.stdin.close();p.wait(3)
        self.assertIsNone(self.finish(owner));self.assertIsNone(owner._selected)

    def test_wrong_native_identity_cannot_mint_proof(self):
        owner=self.owner();p=self.client(owner);self.start(p);self.turn(p);self.completed(p)
        self.assertIsNone(self.finish(owner,turn='other'))

    def test_cross_request_finalization_rejected(self):
        owner=self.owner()
        with self.assertRaisesRegex(ValueError,'cross-request'):
            owner.finish(replace(self.request,ref=c.AttemptRef('r','j','other')),native_thread_id='n',native_turn_id='t')

    def test_enabled_inherited_mcp_refuses_turn_before_forward(self):
        args=('app-server','--badconfig');owner=self.owner(args);p=self.client(owner,args)
        self.send(p,{'id':1,'method':'thread/start','params':{'model':'fixture-model','cwd':str(self.base),'config':{'tools.update_plan.enabled':True}}})
        p.stdin.close();p.wait(3)
        self.assertEqual(p.stdout.read(), b'')  # Owned config response is suppressed.
        self.assertIsNone(owner._selected)
        self.assertIsNone(self.finish(owner))

    def test_snapshot_enabled_fails_before_thread_and_redacts_input_shape(self):
        args=('app-server','--snapshot');owner=self.owner(args);p=self.client(owner,args)
        self.send(p,{'id':1,'method':'thread/start','params':{'model':'fixture-model','cwd':str(self.base),
            'config':{'tools.update_plan.enabled':True}}})
        p.stdin.close();p.wait(3)
        row=owner.observation()['children'][0]
        self.assertEqual(row['failure_code'],'config_feature_shell_snapshot')
        self.assertEqual(row['registered_thread_count'],0)
        self.assertEqual(row['input_shape']['method'],'thread/start')
        self.assertNotIn(str(self.base),json.dumps(row['input_shape']))
        self.assertEqual((self.base/'received-methods').read_text().splitlines(),['config/read'])

    def test_unknown_input_names_and_values_are_not_diagnostics(self):
        owner=self.owner();p=self.client(owner)
        self.send(p,{'id':1,'method':'private-method-secret','params':{'private-key-secret':'private-value-secret'}})
        p.stdin.close();p.wait(3)
        row=owner.observation()['children'][0]
        self.assertEqual(row['failure_code'],'unknown_rpc')
        self.assertEqual(row['input_shape'],{'method':'unknown','params_type':'dict',
            'known_fields':{},'unknown_field_count':1})
        self.assertNotIn('secret',json.dumps(row))

    def test_provider_or_subscription_refusal_before_thread(self):
        for option,code in (('--provider','config_selected_provider_route'),
                            ('--baseurl','config_selected_provider_route'),
                            ('--chatgpturl','config_selected_provider_route'),
                            ('--openai-override','config_selected_provider_route'),
                            ('--api','included_subscription_usage_unverified'),
                            ('--noquota','included_subscription_usage_unverified')):
            with self.subTest(option=option):
                self.peer.write_text('#!'+sys.executable+'\n'+PEER);self.peer.chmod(0o700)
                args=('app-server',option)
                owner=OwnedCodexBroker(self.base/option[2:],executable=self.peer,argv_allowlist=[args],
                    env={'PATH':os.defpath},cwd=self.base)
                self.addCleanup(owner.close)
                owner.arm(self.request,prompt='exact private prompt',effort='low',service_tier='default')
                p=self.client(owner,args)
                self.send(p,{'id':1,'method':'thread/start','params':{'model':'fixture-model','cwd':str(self.base),
                    'config':{'tools.update_plan.enabled':True}}})
                p.stdin.close();p.wait(3)
                row=owner.observation()['children'][0]
                self.assertEqual(row['failure_code'],code)
                self.assertEqual(row['registered_thread_count'],0)
                self.assertNotIn('secret@example.invalid',json.dumps(row))
                self.assertNotIn('thread/start',(self.base/'received-methods').read_text().splitlines())
                (self.base/'received-methods').unlink()

    def test_dormant_other_provider_does_not_change_stock_route(self):
        args=('app-server','--unused-provider');owner=self.owner(args);p=self.client(owner,args)
        self.start(p);self.turn(p);self.completed(p)
        self.assertTrue(self.finish(owner).normal_completion)
        self.assertTrue(owner.observation()['children'][0]['subscription_verified'])
        self.assertNotIn('secret@example.invalid',json.dumps(owner.observation()))

    def test_effective_thread_provider_mismatch_rejected_before_turn(self):
        args=('app-server','--thread-provider');owner=self.owner(args);p=self.client(owner,args)
        self.send(p,{'id':1,'method':'thread/start','params':{'model':'fixture-model','cwd':str(self.base),
            'config':{'tools.update_plan.enabled':True}}})
        p.stdin.close();p.wait(3)
        self.assertEqual(p.stdout.read(),b'')
        self.assertEqual(owner.observation()['children'][0]['failure_code'],'thread_selected_provider')
        self.assertIsNone(owner._selected)

    def test_provider_environment_is_refused_before_launch(self):
        for key in ('OPENAI_API_KEY','OPENAI_BASE_URL','HTTP_PROXY','OPENAI_PROJECT','CODEX_API_KEY'):
            with self.subTest(key=key), self.assertRaisesRegex(ValueError,'scoped Native environment'):
                OwnedCodexBroker(self.base/key,executable=self.peer,argv_allowlist=[('app-server',)],
                    env={'PATH':os.defpath,key:'private-value'},cwd=self.base)

    def test_explicit_cleared_environment_allows_normal_completion(self):
        args=('app-server','--cleared-env')
        owner=self.owner(args,cleared_environment_keys=('FIXTURE_SETTING',));p=self.client(owner,args)
        self.start(p);self.turn(p);self.completed(p)
        self.assertTrue(self.finish(owner).normal_completion)

    def test_environment_clear_keeps_unknown_nonempty_and_bad_types_refused(self):
        owner=self.owner(cleared_environment_keys=('FIXTURE_SETTING',))
        from co_v4.t3code_owned import _Child
        from types import SimpleNamespace
        child=SimpleNamespace(owner=owner)
        for value in (None, {}, {'FIXTURE_SETTING':''}):
            self.assertTrue(_Child.empty_environment(child,value))
        for value in ({'UNKNOWN':''},{'FIXTURE_SETTING':' '},{'FIXTURE_SETTING':'active'},
                      {'FIXTURE_SETTING':None},{'FIXTURE_SETTING':False},[]):
            self.assertFalse(_Child.empty_environment(child,value))

    def test_nonempty_cleared_environment_fails_before_thread(self):
        args=('app-server','--active-env')
        owner=self.owner(args,cleared_environment_keys=('FIXTURE_SETTING',));p=self.client(owner,args)
        self.send(p,{'id':1,'method':'thread/start','params':{'model':'fixture-model','cwd':str(self.base),
            'config':{'tools.update_plan.enabled':True}}})
        p.stdin.close();p.wait(3)
        row=owner.observation()['children'][0]
        self.assertEqual(row['failure_code'],'config_shell_environment')
        self.assertEqual(row['registered_thread_count'],0)

    def test_cleared_key_inventory_is_bound_and_names_are_safe(self):
        for keys in (['NAME'],('NAME','NAME'),('bad.name',),('bad"key',),('SPACE KEY',),(None,),([],)):
            with self.subTest(keys=keys),self.assertRaisesRegex(ValueError,'exact cleared environment'):
                OwnedCodexBroker(self.base/'bad',executable=self.peer,argv_allowlist=[('app-server',)],
                    env={'PATH':os.defpath},cwd=self.base,cleared_environment_keys=keys)
        owner=self.owner(cleared_environment_keys=('FIXTURE_SETTING',))
        owner.cleared_environment_keys=('OTHER',)
        p=self.client(owner);p.stdin.close();p.wait(3)
        self.assertEqual(owner.observation()['children'],[])

    def test_startup_escape_reports_owned_metadata_and_refuses_turn(self):
        args=('app-server','--startup-escape');owner=self.owner(args);p=self.client(owner,args)
        self.start(p);self.turn(p);p.stdin.close();p.wait(3)
        row=owner.observation()['children'][0]
        self.assertEqual(row['failure_code'],'owned_process_group_escape')
        self.assertTrue(row['escaped_group']);self.assertIsNone(owner._selected)
        self.assertIsNone(self.finish(owner))
        self.assertEqual(len(row['descendant_metadata']),1)
        pid,metadata=next(iter(row['descendant_metadata'].items()))
        self.assertEqual(metadata['pgid'],pid)
        self.assertEqual(metadata['ppid'],row['pid'])
        self.assertEqual(metadata['birth'],row['descendants'][pid])
        self.assertEqual(metadata['input_method'],'thread/start')
        self.assertNotIn('/',metadata['executable'])
        self.assertNotIn('time.sleep',json.dumps(metadata))

    def test_process_identity_survives_missing_or_split_executable_name(self):
        from co_v4.t3code_owned import _processes
        from unittest.mock import patch
        from types import SimpleNamespace
        data='123 1 123 Mon Oct  5 06:00:22 2026\nextra-name-line\n'
        with patch('co_v4.t3code_owned.subprocess.run',return_value=SimpleNamespace(stdout=data)):
            rows=_processes()
        self.assertEqual(rows[123],(1,123,'Mon Oct  5 06:00:22 2026','unknown'))

    def test_thread_mcp_overlay_preserves_local_entry_and_inherited_denies(self):
        args=('app-server','--inherited-mcp')
        owner=self.owner(args,t3_mcp_url='http://127.0.0.1:49999/mcp',disabled_mcp_servers=('fixture-helper',))
        p=self.client(owner,args)
        self.send(p,{'id':1,'method':'thread/start','params':{'model':'fixture-model','cwd':str(self.base),
            'config':{'tools.update_plan.enabled':True,'mcp_servers':{'t3-code':{
                'url':'http://127.0.0.1:49999/mcp','http_headers':{'Authorization':'Bearer private-fixture-token'}}}}}})
        self.assertIn(b'native-thread',p.stdout.readline())
        self.turn(p);self.completed(p)
        self.assertTrue(self.finish(owner).normal_completion)
        row=owner.observation()['children'][0]
        self.assertEqual(row['thread_mcp_denies_count'],1)
        self.assertFalse(row['escaped_group'])
        self.assertNotIn('private-fixture-token',json.dumps(row))

    def test_same_child_mcp_inventory_must_match(self):
        args=('app-server','--inherited-mcp');owner=self.owner(args);p=self.client(owner,args)
        self.send(p,{'id':1,'method':'thread/start','params':{'model':'fixture-model','cwd':str(self.base),
            'config':{'tools.update_plan.enabled':True}}})
        p.stdin.close();p.wait(3)
        self.assertEqual(owner.observation()['children'][0]['failure_code'],'config_mcp_inventory_mismatch')
        self.assertEqual((self.base/'received-methods').read_text().splitlines(),['config/read'])

    def test_original_t3_input_cannot_add_or_reenable_server(self):
        self.reject_input({'id':1,'method':'thread/start','params':{'model':'fixture-model',
            'cwd':str(self.base),'config':{'tools.update_plan.enabled':True,'mcp_servers':{
                'fixture-helper':{'enabled':True}}}}},'thread_mcp_binding')

    def test_disabled_mcp_inventory_is_safe_and_immutable(self):
        for names in (['name'],('t3-code',),('bad.name',),('name','name'),([],)):
            with self.subTest(names=names),self.assertRaisesRegex(ValueError,'exact disabled MCP'):
                OwnedCodexBroker(self.base/'bad',executable=self.peer,argv_allowlist=[('app-server',)],
                    env={'PATH':os.defpath},cwd=self.base,disabled_mcp_servers=names)
        owner=self.owner();owner.disabled_mcp_servers=('unreviewed',)
        p=self.client(owner);p.stdin.close();p.wait(3)
        self.assertEqual(owner.observation()['children'],[])

    def test_inherited_reserved_t3_server_collision_is_refused(self):
        args=('app-server','--mcp-collision');owner=self.owner(args);p=self.client(owner,args)
        self.send(p,{'id':1,'method':'thread/start','params':{'model':'fixture-model','cwd':str(self.base),
            'config':{'tools.update_plan.enabled':True}}})
        p.stdin.close();p.wait(3)
        self.assertEqual(owner.observation()['children'][0]['failure_code'],'config_mcp_inventory_mismatch')
        self.assertEqual((self.base/'received-methods').read_text().splitlines(),['config/read'])

    def test_augmented_thread_wire_retains_frame_bound(self):
        from co_v4.t3code_owned import _Child
        from unittest.mock import patch
        from types import SimpleNamespace
        owner=self.owner(disabled_mcp_servers=tuple('helper'+str(i) for i in range(10)))
        message={'id':1,'method':'thread/start','params':{'model':'fixture-model','cwd':str(self.base),
            'config':{'tools.update_plan.enabled':True,'mcp_servers':{'t3-code':{
                'url':'http://127.0.0.1:49999/mcp','http_headers':{'Authorization':'Bearer private-token'}}}}}}
        def reject(code): raise ValueError(code)
        child=SimpleNamespace(owner=owner,reject=reject,thread_mcp_denies_count=0)
        with patch('co_v4.t3code_owned.MAX_FRAME',len(json.dumps(message).encode())+1):
            with self.assertRaisesRegex(ValueError,'thread_forward_frame_limit'):
                _Child.prepare_thread_wire(child,message)
        self.assertEqual(set(message['params']['config']['mcp_servers']),{'t3-code'})
        self.assertEqual(owner.observation()['children'],[])

    def test_second_turn_refused_before_forward(self):
        owner=self.owner();p=self.client(owner);self.start(p);self.turn(p);self.completed(p)
        self.turn(p);p.stdin.close();p.wait(3)
        self.assertEqual(p.stdout.read(), b'')
        self.assertIsNone(self.finish(owner))

    def test_reaped_parent_with_live_group_descendant_is_unconfirmed(self):
        args=('app-server','--orphan');owner=self.owner(args);p=self.client(owner,args)
        self.start(p);self.turn(p);self.completed(p)
        proof=self.finish(owner)
        self.assertIsNone(proof)
        self.assertTrue(owner.observation()['children'][0]['reaped'])
        self.assertTrue(owner.observation()['children'][0]['descendants'])
        # The owned fixture child exits on its own bounded timer. Do not leave it behind.
        time.sleep(2)

    def test_owner_lifetime_expires_without_client_cooperation(self):
        owner=OwnedCodexBroker(self.base/'owner',executable=self.peer,
            argv_allowlist=[('app-server',)],env={'PATH':os.defpath},cwd=self.base,timeout_seconds=1)
        self.addCleanup(owner.close)
        p=self.client(owner)
        p.wait(4)
        owner.close()
        row=owner.observation()['children'][0]
        self.assertTrue(row['reaped']);self.assertTrue(row['forced']);self.assertTrue(row['failed'])

    def test_incomplete_native_frame_never_counts_as_drained_proof(self):
        self.peer.write_text(self.peer.read_text().replace(
            "if '--hang' in sys.argv:", "print('{partial',end='',flush=True)\nif '--hang' in sys.argv:"))
        owner=self.owner();p=self.client(owner);self.start(p);self.turn(p);self.completed(p)
        self.assertIsNone(self.finish(owner))

    def test_launch_environment_mutation_creates_no_native_child(self):
        owner=self.owner();owner.env['UNREVIEWED']='changed'
        p=self.client(owner);p.stdin.close();p.wait(3)
        self.assertEqual(owner.observation()['children'], [])

    def test_nonallowlisted_launch_creates_no_child(self):
        owner=self.owner();p=self.client(owner,('login',));p.stdin.close();p.wait(3)
        self.assertEqual(owner.observation()['children'], [])
        self.assertTrue(owner.observation()['failed'])

    def test_reparenting_is_not_process_absence(self):
        self.assertTrue(_same_birth((123,456,'same birth'),'same birth'))
        self.assertFalse(_same_birth(None,'same birth'))
        self.assertFalse(_same_birth((123,456,'new birth'),'same birth'))

    def test_escaped_child_never_proves_cessation(self):
        args=('app-server','--escape');owner=self.owner(args);p=self.client(owner,args)
        self.start(p);self.turn(p);self.completed(p)
        self.assertTrue(owner.observation()['children'][0]['escaped_group'])
        self.assertIsNone(self.finish(owner))

if __name__=='__main__': unittest.main()
