"""Synthetic selection tests; model/list availability is not live qualification."""
from dataclasses import replace
from pathlib import Path
import unittest
from unittest.mock import Mock

from co_v4.codex_errors import HostUnverified
from co_v4.codex_host import CodexReadOnlyHost
from co_v4.codex_model_selection import model_choices, verify_selection, NATIVE_VERSION
from probes.codex_profile_acceptance import qualification_request
from probes.codex_controller_acceptance import environment_definition
from tests import test_codex_named_profile as fixture
from co_v4.codex_permissions import ProfileError


def row(model, efforts):
    return {"model": model, "defaultReasoningEffort": efforts[0],
            "supportedReasoningEfforts": [{"reasoningEffort": e} for e in efforts]}


class SelectionTests(unittest.TestCase):
    def verify(self, rows, model='gpt-6-luna', effort='high', effective='high', **kwargs):
        return verify_selection(Mock(return_value={"data": rows}), model=model,
            effort=effort, effective_effort=effective, native_version=kwargs.get('version', NATIVE_VERSION),
            request_digest='a' * 64)

    def test_per_model_support_and_inherited_effective_value(self):
        rows = [row('gpt-6-luna', ['medium', 'high', 'max']), row('gpt-6-astra', ['medium', 'ultra'])]
        self.assertEqual(self.verify(rows)['effective_effort'], 'high')
        self.assertIsNone(self.verify(rows, effort=None)['requested_effort'])
        inherited = self.verify(rows, effort=None, effective=None)
        self.assertIsNone(inherited['effective_effort'])
        self.assertFalse(inherited['effective_effort_reported'])
        self.assertEqual(self.verify(rows, model='gpt-6-astra', effort='ultra', effective='ultra')['requested_effort'], 'ultra')
        for model, effort, effective in [('unknown', 'high', 'high'), ('gpt-6-luna', 'ultra', 'ultra'),
                                         ('gpt-6-luna', None, 'ultra'), ('gpt-6-luna', 'high', 'medium'), ('gpt-6-luna', 'high', None)]:
            with self.subTest(model=model, effort=effort, effective=effective), self.assertRaises(HostUnverified):
                self.verify(rows, model=model, effort=effort, effective=effective)
        with self.assertRaises(HostUnverified): self.verify(rows, version='codex-cli 0.159.3')

    def test_pagination_duplicate_and_malformed_fail_closed(self):
        first, last = row('gpt-6-astra', ['medium']), row('gpt-6-luna', ['high'])
        rpc = Mock(side_effect=[{'data': [first], 'nextCursor': 'next'}, {'data': [last]}])
        self.assertEqual(set(model_choices(rpc)), {'gpt-6-astra', 'gpt-6-luna'})
        self.assertEqual(rpc.call_args.args[1]['cursor'], 'next')
        invalid = [{'data': None}, {'data': [first, first]}, {'data': [None]},
                   {'data': [dict(first, defaultReasoningEffort='missing')]},
                   {'data': [dict(first, supportedReasoningEfforts=[{}])]},
                   {'data': [], 'nextCursor': ''}, {'data': [], 'nextCursor': 1}]
        for page in invalid:
            with self.subTest(page=page), self.assertRaises(HostUnverified):
                model_choices(Mock(return_value=page))
        with self.assertRaisesRegex(HostUnverified, 'pagination_invalid'):
            model_choices(Mock(return_value={'data': [], 'nextCursor': 'loop'}))
        with self.assertRaisesRegex(HostUnverified, 'page_limit'):
            model_choices(Mock(side_effect=[{'data': [], 'nextCursor': str(i)} for i in range(16)]))

    def test_selected_effort_binds_authorization_and_environment(self):
        root = Path('/private/tmp')
        one = qualification_request(root, 'a' * 32, model='gpt-6.1-sol', effort='high')
        two = qualification_request(root, 'a' * 32, model='gpt-6.1-sol', effort='max')
        self.assertNotEqual(one, two)
        self.assertEqual(one.conditions.model, 'gpt-6.1-sol')
        self.assertIn('reasoning-effort:high', one.conditions.control_evidence_refs)
        refs = [environment_definition(Path(__file__).resolve(), model=model, effort=effort)[0]
                for model, effort in [('gpt-6-astra', 'high'), ('gpt-6-astra', 'max'), ('gpt-6-luna', 'high'), ('gpt-6-astra', None)]]
        self.assertEqual(len(set(refs)), 4)


class ProductSelectionTests(unittest.TestCase):
    setUp = fixture.NamedProfileHostTests.setUp
    prepare = fixture.NamedProfileHostTests.prepare
    run_gate = fixture.NamedProfileHostTests.run_gate
    methods = fixture.NamedProfileHostTests.methods

    def test_unsupported_native_selection_refuses_before_model_turn(self):
        for rows, code in [([], 'qualification_model_unsupported'),
                           ([row('gpt-6-astra', ['high'])], 'qualification_effort_unsupported'),
                           ([row('gpt-6-astra', ['medium']), row('gpt-6-astra', ['medium'])], 'model_metadata_invalid')]:
            with self.subTest(code=code):
                self.prepare(); self.wire.model_rows = rows; self.run_gate()
                self.assertEqual(self.host.observation['status'], code)
                self.assertNotIn('turn/start', self.methods())
                self.assertNotIn('command/exec', self.methods())

    def test_model_and_effort_selection_reaches_same_attempt_turn(self):
        self.prepare()
        conditions = replace(self.conditions, model='gpt-6-luna')
        self.request = replace(self.request, conditions=conditions)
        self.host = CodexReadOnlyHost(replace(self.host.config, conditions=conditions, reasoning_effort='high'))
        self.wire.model_rows = [row('gpt-6-luna', ['medium', 'high', 'max'])]
        self.adapter = self.host.make_adapter(); self.addCleanup(self.adapter.close)
        self.run_gate()
        self.assertTrue(self.host.observation['native_handoff_verified'])
        sent = {message['method']: message['params'] for message in self.wire.sent if 'params' in message}
        self.assertEqual(sent['thread/start']['model'], 'gpt-6-luna')
        self.assertEqual(sent['turn/start']['effort'], 'high')
        self.assertEqual(self.host.observation['model_selection']['effective_effort'], 'high')

    def test_selection_evidence_binds_actual_request_version_and_native(self):
        self.prepare(); self.run_gate()
        observation = self.host.observation['model_selection']
        self.assertEqual(observation['request_binding_sha256'], self.host._request_digest)
        self.assertEqual(observation['native_version'], NATIVE_VERSION)
        self.assertEqual(observation['model'], self.request.conditions.model)
        self.assertFalse(observation['live_inference_qualified'])
        self.assertLess(self.methods().index('model/list'), self.methods().index('turn/start'))

    def test_inherited_effort_is_not_overridden(self):
        self.prepare()
        self.host = CodexReadOnlyHost(replace(self.host.config, reasoning_effort=None))
        self.adapter = self.host.make_adapter(); self.addCleanup(self.adapter.close)
        self.run_gate()
        self.assertTrue(self.host.observation['native_handoff_verified'])
        turn = next(m for m in self.wire.sent if m.get('method') == 'turn/start')
        self.assertNotIn('effort', turn['params'])
        self.assertIsNone(self.host.observation['model_selection']['requested_effort'])

    def test_inherited_native_null_is_distinct_from_missing_field(self):
        for missing in (False, True):
            with self.subTest(missing=missing):
                self.prepare()
                self.host = CodexReadOnlyHost(replace(self.host.config, reasoning_effort=None))
                self.adapter = self.host.make_adapter(); self.addCleanup(self.adapter.close)
                original = self.wire.send
                def send(message):
                    original(message)
                    if message.get('method') == 'thread/start':
                        native = self.wire.incoming[-1]['result']
                        if missing: native.pop('reasoningEffort')
                        else: native['reasoningEffort'] = None
                self.wire.send = send
                self.run_gate()
                if missing:
                    self.assertNotIn('turn/start', self.methods())
                    self.assertEqual(self.host.observation['status'], 'native_reasoning_effort_missing')
                else:
                    self.assertIn('turn/start', self.methods())
                    selected = self.host.observation['model_selection']
                    self.assertIsNone(selected['effective_effort'])
                    self.assertFalse(selected['effective_effort_reported'])

    def test_metadata_requests_cannot_be_injected_after_turn(self):
        self.prepare(); self.run_gate()
        with self.assertRaisesRegex(ProfileError, 'model_metadata_request_unbound'):
            self.host._transport.inner.send({'id': 'other', 'method': 'model/list',
                'params': {'includeHidden': False, 'limit': 100}})
