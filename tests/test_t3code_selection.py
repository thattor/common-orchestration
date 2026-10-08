"""Selection metadata is not Native qualification; synthetic pure tests only."""
from copy import deepcopy
from dataclasses import replace
import unittest
from co_v4.t3code_selection import advertised_models, resolve_selection
from co_v4.contracts import AttemptRef, ExecuteRequest, ExecutionConditions, Job
from co_v4.adapters.t3code import ADAPTER


def config():
    def model(name, preferred):
        return {'slug': name, 'isDefault': preferred, 'capabilities': {'optionDescriptors': [
            {'id': 'reasoningEffort', 'type': 'select', 'currentValue': 'medium',
                'options': [{'id': 'low'}, {'id': 'medium', 'isDefault': True}]},
            {'id': 'serviceTier', 'type': 'select', 'currentValue': 'default',
                'options': [{'id': 'default', 'isDefault': True}, {'id': 'priority'}]}]}}
    return {'providers': [{'instanceId': 'codex', 'driver': 'codex', 'enabled': True,
        'status': 'ready', 'auth': {'secret': 'PRIVATE'},
        'models': [model('fixture-model', True), model('another-model', False)]}]}


class SelectionTests(unittest.TestCase):
    def test_default_resolves_actual_advertisement_not_hardcoded_model(self):
        selected = resolve_selection(config())
        self.assertEqual((selected.mode, selected.model, selected.effort, selected.service_tier),
            ('default', 'fixture-model', 'medium', 'default'))
        selected.verify_current(config())
        self.assertNotIn('PRIVATE', repr(advertised_models(config())))

    def test_explicit_exact_selection_keeps_mode_and_no_fallback(self):
        selected = resolve_selection(config(), mode='explicit', model='another-model', effort='low')
        self.assertEqual((selected.model, selected.effort), ('another-model', 'low'))
        for model, effort in [('another', 'low'), ('Another-model', 'low'), ('another-model', 'normal'),
                              ('another-model', None), ('auto', 'medium')]:
            with self.assertRaises(ValueError): resolve_selection(config(), mode='explicit', model=model, effort=effort)
        with self.assertRaises(ValueError): resolve_selection(config(), model='fixture-model')
        with self.assertRaises(ValueError): resolve_selection(config(), mode='auto')

    def test_missing_duplicate_and_contradictory_defaults_fail(self):
        for change in ('missing', 'duplicate', 'effort_missing', 'effort_conflict'):
            value = config(); models = value['providers'][0]['models']
            if change == 'missing': models[0]['isDefault'] = False
            elif change == 'duplicate': models[1]['isDefault'] = True
            else:
                d = models[0]['capabilities']['optionDescriptors'][0]
                if change == 'effort_conflict': d['currentValue'] = 'low'
                else:
                    d.pop('currentValue'); d['options'][1].pop('isDefault')
            with self.subTest(change=change), self.assertRaises(ValueError): resolve_selection(value)

    def test_default_and_explicit_drift_are_refused(self):
        for mode in ('default', 'explicit'):
            selected = resolve_selection(config(), mode=mode,
                **({'model':'fixture-model','effort':'medium'} if mode == 'explicit' else {}))
            value=config(); value['providers'][0]['models'][0]['capabilities']['optionDescriptors'][0]['options'].append({'id':'high'})
            with self.assertRaises(ValueError): selected.verify_current(value)
        value=config(); value['providers'][0]['models'][0]['isDefault']=False
        value['providers'][0]['models'][1]['isDefault']=True
        with self.assertRaises(ValueError): resolve_selection(config()).verify_current(value)

    def test_duplicate_id_and_bad_types_refused(self):
        for kind in ('provider','model','descriptor','option','default_type','option_type','disabled'):
            value=config(); p=value['providers'][0]; m=p['models'][0]; d=m['capabilities']['optionDescriptors'][0]
            if kind=='provider':value['providers'].append(deepcopy(p))
            elif kind=='model':p['models'].append(deepcopy(m))
            elif kind=='descriptor':m['capabilities']['optionDescriptors'].append(deepcopy(d))
            elif kind=='option':d['options'].append(deepcopy(d['options'][0]))
            elif kind=='default_type':m['isDefault']=1
            elif kind=='option_type':d['type']='text'
            else:p['enabled']=False
            with self.subTest(kind=kind),self.assertRaises(ValueError):advertised_models(value)

    def test_profile_binds_resolved_request_and_mode(self):
        selected=resolve_selection(config());ref=AttemptRef('run','job','attempt')
        request=ExecuteRequest(ref,Job('run','job','Return OK',('OK',),'{}'),
            ExecutionConditions(selected.model,ADAPTER,'/worker','selection:'+selected.catalog_sha256))
        profile=selected.profile(request,'project','trusted-host')
        self.assertEqual(profile.selection_mode,'default')
        self.assertEqual(profile.selection_ref,selected.catalog_sha256)
        self.assertEqual(profile.model_selection()['options'][0]['value'],'medium')
        with self.assertRaises(ValueError):selected.profile(replace(request,
            conditions=replace(request.conditions,model='different')),'project','trusted-host')
        with self.assertRaises(ValueError):replace(profile,selection_ref='')
        with self.assertRaises(ValueError):replace(profile,selection_mode='auto')

    def test_generic_profile_keeps_legacy_explicit_fixtures(self):
        selected=resolve_selection(config());ref=AttemptRef('run','job','attempt')
        request=ExecuteRequest(ref,Job('run','job','Return OK',('OK',),'{}'),
            ExecutionConditions(selected.model,ADAPTER,'/worker','fixture'))
        profile=selected.profile(request,'project','trusted-host')
        legacy=replace(profile,selection_mode='explicit',selection_ref='',options_json='[]')
        self.assertEqual(legacy.model_selection()['model'],'fixture-model')

    def test_tier_default_not_advertised_does_not_enable_priority(self):
        value=config();d=value['providers'][0]['models'][0]['capabilities']['optionDescriptors'][1]
        d.update(currentValue='priority',options=[{'id':'priority','isDefault':True}])
        with self.assertRaises(ValueError):resolve_selection(value)


    def test_real_resolved_profile_and_host_share_single_source_pin(self):
        from co_v4.t3code_host import T3CodeHost, T3CodeHostConfig, SOURCE_REVISION
        from co_v4.adapters.t3code import SOURCE_REVISION as ADAPTER_SOURCE
        selected=resolve_selection(config());ref=AttemptRef('run','job','attempt')
        request=ExecuteRequest(ref,Job('run','job','Return OK',('OK',),'{}'),
            ExecutionConditions(selected.model,ADAPTER,'/worker','fixture'))
        profile=selected.profile(request,'project','trusted-host')
        seen=[]
        def verify(req, actual, endpoint):
            selected.verify_current(config());seen.append(actual)
            return req == request and actual == profile
        host=T3CodeHost(T3CodeHostConfig('http://127.0.0.1:12345',lambda:'private',verify))
        self.assertEqual(SOURCE_REVISION,ADAPTER_SOURCE)
        self.assertEqual(profile.source_revision,SOURCE_REVISION)
        self.assertIsNone(host.verify_host(request,profile))
        self.assertEqual(seen,[profile])
