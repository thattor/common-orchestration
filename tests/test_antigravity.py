"""Offline fixtures only; no native process or provider is invoked."""
import copy
import json
import unittest
from co_v4.adapters.antigravity import ADAPTER, AntigravityTextAdapter, TextProfile, payload_digest
from co_v4.contracts import (AttemptRef, Job, ExecutionConditions, ExecuteRequest,
    OperationStatus, State, StopStatus, ResumeState)


def request():
    ref = AttemptRef('public-run', 'review', 'one')
    return ExecuteRequest(ref, Job(ref.run_id, ref.job_id, 'Review public references',
        ('Keep unknowns unknown',), '{"public_packet_sha256":"fixture"}'),
        ExecutionConditions('gemini-3.8-flash-high', ADAPTER, '/owned/public', 'fixture'))


def frames():
    usage = dict.fromkeys(('input_tokens', 'output_tokens', 'thinking_tokens',
                          'cache_read_tokens', 'total_tokens'), 0)
    return [
        {'event': 'init', 'conversation_id': 'fixture-session', 'init': {
            'cwd': '/owned/public', 'tools': [], 'permission_mode': 'request-review',
            'model': 'gemini-3.8-flash-high'}},
        {'event': 'step_update', 'step_update': {'conversation_id': 'fixture-session',
            'step_index': 0, 'state': 'DONE', 'step_type': 'user_input'}},
        {'event': 'step_update', 'step_update': {'conversation_id': 'fixture-session',
            'step_index': 1, 'state': 'DONE', 'step_type': 'agent_response', 'text_delta': 'review'}},
        {'event': 'result', 'result': {'conversation_id': 'fixture-session',
            'status': 'SUCCESS', 'response': 'review', 'duration_seconds': 1,
            'num_turns': 1, 'usage': usage}}]


class Transport:
    def __init__(self, values, *, drained=True, code=0):
        self.data = b''.join(json.dumps(f).encode() + b'\n' for f in values)
        self.done, self.code, self.closed = drained, code, False
    def poll(self):
        data, self.data = self.data, b''
        return (data,) if data else ()
    def drained(self): return self.done
    def wait_owned(self): return self.code
    def close(self): self.closed = True


class AntigravityTests(unittest.TestCase):
    def adapter(self, values=None, **kw):
        t = Transport(frames() if values is None else values, **kw)
        self.payloads = []
        def factory(req, payload, profile):
            self.payloads.append(payload)
            return t
        a = AntigravityTextAdapter(verify_host=lambda *args: None,
            transport_factory=factory, profile=TextProfile(request(), payload_digest(request()), ()), verify_completion=lambda *args: 'fixture:owned-normal')
        return a, t

    def test_default_refuses_before_factory_and_boolean_not_attestation(self):
        req = request()
        for options in ({}, {'verify_host': lambda *args: True,
                            'transport_factory': lambda *args: self.fail('must not launch'), 'profile': TextProfile(req,payload_digest(req))}):
            a = AntigravityTextAdapter(**options)
            reply = a.execute(req)
            self.assertEqual(reply.status, OperationStatus.UNSUPPORTED)
            self.assertEqual(reply.never_started.request, req)

    def test_success_requires_eof_wait_and_separate_proof(self):
        req = request(); a, t = self.adapter(drained=False)
        self.assertEqual(a.execute(req).status, OperationStatus.ACCEPTED)
        self.assertNotEqual(a.status(req.ref).state, State.COMPLETED)
        t.done = True; t.code = None
        self.assertNotEqual(a.status(req.ref).state, State.COMPLETED)
        t.code = 0
        self.assertEqual(a.status(req.ref).state, State.COMPLETED)
        self.assertEqual(a.text_output(req.ref), 'review')
        self.assertEqual(self.payloads[0]['context'], {'public_packet_sha256': 'fixture'})
        self.assertEqual(a.stop(req.ref).status, StopStatus.CONFIRMED)
        self.assertTrue(t.closed)
        self.assertEqual(a.execute(req).status, OperationStatus.INVALID_STATE)
        self.assertEqual(a.usage(), ())

    def test_source_bound_plan_expansion_only(self):
        from dataclasses import replace
        good = [{'name': 'plan', 'type': 'system'}]
        for value, permit, expected in [(good, True, State.COMPLETED),
                ([], False, State.COMPLETED), (good, False, State.ERROR),
                ([{'name': 'plan', 'type': 'skill'}], True, State.ERROR),
                ([{'name': 'other', 'type': 'system'}], True, State.ERROR),
                (good * 2, True, State.ERROR), (None, True, State.ERROR),
                ([{'name': 'plan', 'type': 'system', 'extra': 1}], True, State.ERROR)]:
            with self.subTest(value=value, permit=permit):
                f=frames(); f[0]['init']['expanded_commands']=value
                a,t=self.adapter(f); a._profile=replace(a._profile,plan_expansion=permit)
                req=request();a.execute(req)
                self.assertEqual(a.status(req.ref).state,expected)
        for schema, expected in [(None, State.COMPLETED), ({},State.ERROR), ('',State.ERROR)]:
            f=frames();f[0]['init']['json_schema']=schema
            a,t=self.adapter(f);req=request();a.execute(req)
            self.assertEqual(a.status(req.ref).state,expected)

    def test_pinned_done_formatting_preserves_model_bytes(self):
        from dataclasses import replace
        for payload in ('review', 'review\n', 'review\r\n', 'review '):
            f=frames();f[2]['step_update']['text_delta']=payload+'\n'
            f[-1]['result']['response']=payload+'\n'
            a,t=self.adapter(f);a._profile=replace(a._profile,native_done_lf=True)
            req=request();a.execute(req);self.assertEqual(a.status(req.ref).state,State.COMPLETED)
            self.assertEqual(a.text_output(req.ref),payload)
            self.assertEqual(a.diagnostic(req.ref)['native_done_lfs_decoded'],1)
        f=frames();f[2]['step_update'].update(state='ACTIVE',text_delta='review')
        done=copy.deepcopy(f[2]);done['step_update'].update(state='DONE',text_delta='\n')
        f.insert(3,done);f[-1]['result']['response']='review\n'
        a,t=self.adapter(f);a._profile=replace(a._profile,native_done_lf=True)
        req=request();a.execute(req);self.assertEqual(a.status(req.ref).state,State.COMPLETED)
        self.assertEqual(a.text_output(req.ref),'review')
        # Streaming ACTIVE body followed by DONE framing; two distinct DONE steps.
        f=frames();f[2]['step_update'].update(state='ACTIVE',text_delta='re')
        done=copy.deepcopy(f[2]);done['step_update'].update(state='DONE',text_delta='view\n')
        second=copy.deepcopy(done);second['step_update'].update(step_index=2,text_delta='two\n')
        f[3:3]=[done,second];f[-1]['result']['response']='review\ntwo\n'
        a,t=self.adapter(f);a._profile=replace(a._profile,native_done_lf=True)
        req=request();a.execute(req);self.assertEqual(a.status(req.ref).state,State.COMPLETED)
        self.assertEqual(a.text_output(req.ref),'reviewtwo')
        self.assertEqual(a.diagnostic(req.ref)['native_done_lfs_decoded'],2)
        for f in (frames(),frames()[:-1],frames()[0:2]+[frames()[-1]]):
            a,t=self.adapter(f);a._profile=replace(a._profile,native_done_lf=True)
            req=request();a.execute(req);self.assertEqual(a.status(req.ref).state,State.ERROR)
        # Default profile never applies a formatting transform.
        f=frames();f[2]['step_update']['text_delta']='review\n';f[-1]['result']['response']='review\n'
        a,t=self.adapter(f);req=request();a.execute(req)
        self.assertEqual(a.status(req.ref).state,State.COMPLETED)
        self.assertEqual(a.text_output(req.ref),'review\n')

    def test_bad_protocol_and_permissions_fail_closed(self):
        variants = []
        for key, value in [('model','other'), ('cwd','/other'), ('tools',['view_file']),
                           ('permission_mode','always-proceed')]:
            f=frames(); f[0]['init'][key]=value; variants.append(f)
        for key,value in [('status','ERROR'), ('num_turns',True),
                          ('response','contradiction'), ('conversation_id','other')]:
            f=frames(); f[-1]['result'][key]=value; variants.append(f)
        for key,value in [('step_type','tool'), ('tool_info', {'canary':'DO_NOT_LEAK'}),
                          ('subagent_info',{}), ('state','UNKNOWN')]:
            f=frames(); f[2]['step_update'][key]=value; variants.append(f)
        f=frames(); f[-1]['result']['usage']['input_tokens']=True; variants.append(f)
        variants += [frames()[1:], frames()[:-1], frames()+[frames()[-1]], frames()+[frames()[2]]]
        for f in variants:
            with self.subTest(f=f):
                a,t=self.adapter(f); req=request(); a.execute(req)
                self.assertEqual(a.status(req.ref).state, State.ERROR)
                self.assertNotIn('DO_NOT_LEAK', repr(a.events(req.ref)))
                self.assertEqual(a.stop(req.ref).status, StopStatus.UNCONFIRMED)

    def test_bad_exit_and_unverified_completion(self):
        for code in (1, True):
            a,t=self.adapter(code=code); req=request(); a.execute(req)
            self.assertEqual(a.status(req.ref).state, State.ERROR)
        a,t=self.adapter(); a._completion=lambda *args: False
        req=request(); a.execute(req)
        self.assertEqual(a.status(req.ref).state, State.ERROR)

    def test_factory_ambiguous_and_cancel_never_confirmed(self):
        req=request()
        def broken(*args): raise RuntimeError('PRIVATE_CANARY')
        a=AntigravityTextAdapter(verify_host=lambda *args: None, transport_factory=broken, profile=TextProfile(req,payload_digest(req)))
        reply=a.execute(req)
        self.assertEqual(reply.status, OperationStatus.ERROR)
        self.assertIsNone(reply.never_started)
        self.assertNotIn('PRIVATE_CANARY',repr(a.events(req.ref)))
        self.assertEqual(a.stop(req.ref).status, StopStatus.UNCONFIRMED)
        self.assertEqual(a.resume(ResumeState(ADAPTER,req.ref,b'opaque')).status,
                         OperationStatus.INVALID_STATE)

    def test_duplicate_keys_truncation_and_timeout(self):
        for data in (b'{"event":"init","event":"result"}\n', b'{', b'NaN\n'):
            a,t=self.adapter(); t.data=data; req=request(); a.execute(req)
            self.assertEqual(a.status(req.ref).state, State.ERROR)
        a,t=self.adapter(drained=False); a._clock=lambda: 0; req=request(); a.execute(req)
        a._clock=lambda: 121
        self.assertEqual(a.status(req.ref).state, State.ERROR)
        self.assertEqual(a.stop(req.ref).status, StopStatus.UNCONFIRMED)

    def test_real_defaults_never_admit_or_certify(self):
        req=request(); calls=[]; profile=TextProfile(req,payload_digest(req))
        a=AntigravityTextAdapter(profile=profile,
            transport_factory=lambda *args: calls.append(args))
        self.assertEqual(a.execute(req).status, OperationStatus.UNSUPPORTED)
        self.assertEqual(calls, [])
        t=Transport(frames())
        a=AntigravityTextAdapter(profile=profile, verify_host=lambda *args: None,
            transport_factory=lambda *args: t)
        a.execute(req)
        self.assertEqual(a.status(req.ref).state, State.ERROR)
        self.assertEqual(a.stop(req.ref).status, StopStatus.UNCONFIRMED)

    def test_trailing_later_batch_cannot_certify_result(self):
        a,t=self.adapter(drained=False); req=request(); a.execute(req)
        self.assertNotEqual(a.status(req.ref).state,State.COMPLETED)
        t.data=b'{"event":"unknown","canary":"PRIVATE_CANARY"}\n'; t.done=True
        self.assertEqual(a.status(req.ref).state,State.ERROR)
        self.assertEqual(a.stop(req.ref).status,StopStatus.UNCONFIRMED)
        self.assertNotIn('PRIVATE_CANARY',repr(a.events(req.ref)))

    def test_profile_binds_request_payload_inventory_and_effort(self):
        req=request(); a,t=self.adapter()
        a._profile=TextProfile(req,'0'*64)
        self.assertEqual(a.execute(req).status,OperationStatus.UNSUPPORTED)
        self.assertEqual(self.payloads,[])
        f=frames(); f[0]['init']['tools']=['view_file']
        a,t=self.adapter(f)
        a._profile=TextProfile(req,payload_digest(req),('view_file',),'high')
        captured=[]
        def verify(actual, profile):
            captured.append((actual,profile))  # fixture proof only
        a._verify=verify
        a.execute(req)
        self.assertEqual(a.status(req.ref).state,State.COMPLETED)
        self.assertEqual(captured,[(req,a._profile)])
        # A registered but denied tool is not a grant to execute it.
        f=frames(); f[0]['init']['tools']=['view_file']
        f[2]['step_update']['step_type']='tool'
        a,t=self.adapter(f)
        a._profile=TextProfile(req,payload_digest(req),('view_file',))
        a.execute(req)
        self.assertEqual(a.status(req.ref).state,State.ERROR)
        with self.assertRaises(ValueError):
            TextProfile(req,payload_digest(req),['view_file'])


if __name__ == '__main__': unittest.main()
