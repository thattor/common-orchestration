"""Exact selection and adversarial model advertisements, offline only."""
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from co_v4.adapters.devin import DevinAdapter
from co_v4.contracts import State
from co_v4.devin_host import DevinTextHost, check_launch_template
from co_v4.devin_selection import EXACT_MODELS, ModelObservation, resolve_model
import test_devin
import test_devin_host


def models(current="swe-2-high", ids=None):
    return {"currentModelId": current, "availableModels": [
        {"modelId": uid} for uid in (ids if ids is not None else [current])]}


class SelectionTests(unittest.TestCase):
    def test_exact_and_family_effort_resolution(self):
        for uid in EXACT_MODELS:
            self.assertEqual(resolve_model(uid), uid)
        for effort in ("medium", "high", "max"):
            self.assertEqual(resolve_model("swe-2", effort), "swe-2-" + effort)
            self.assertEqual(resolve_model("swe-2-" + effort, effort), "swe-2-" + effort)

    def test_swe17_labels_select_exact_variants_without_effective_effort_claim(self):
        for family, exact in (("swe-1.7", "swe-1-7"), ("swe-1.7-lightning", "swe-1-7-lightning")):
            self.assertEqual(resolve_model(family, "max"), exact)
            self.assertEqual(resolve_model(family, "medium"), exact + "-medium")
            self.assertEqual(resolve_model(exact, "max"), exact)
            self.assertFalse(ModelObservation(exact).evidence()['effective_effort_verified'])
            with self.assertRaises(ValueError): resolve_model(family, "high")

    def test_unknown_alias_non_swe_and_contradiction_rejected(self):
        for model, effort in (("swe-2", None), ("swe-1.6", None), ("SWE-2 High", None),
                              ("swe-3", None), ("claude-opus-5-5", None),
                              ("swe-2-high", "max"), ("swe-2", "low"),
                              ("swe-1-6", "high"), ("swe-1-7", "high")):
            with self.subTest(model=model, effort=effort), self.assertRaises(ValueError):
                resolve_model(model, effort)

    def test_bad_probe_selection_precedes_files_or_processes(self):
        from probes.devin_cessation import run
        from probes.devin_host_preflight import run as preflight
        from probes.devin_text_smoke import run as smoke
        from probes.devin_controller_acceptance import run as controller
        from probes.devin_live_control import probe
        with tempfile.TemporaryDirectory() as root:
            target = Path(root) / 'must-not-exist'
            for operation in (run, preflight, smoke):
                with self.subTest(operation=operation.__module__), patch('subprocess.Popen') as launch:
                    with self.assertRaises(ValueError):
                        operation(target, executable=Path('/invalid'), native_version='fixture',
                                  model='swe-2-high', effort='max', credential_files=(), human_intent_ref='intent')
                    launch.assert_not_called()
                    self.assertFalse(target.exists())
            with self.assertRaises(ValueError):
                probe(target, model='claude')
            with self.assertRaises(ValueError):
                controller(target, run_id='r', human_intent='i', human_intent_ref='h', origin_verifier=None,
                           evidence_resolver=None, executable=Path('/invalid'), native_version='fixture',
                           model='swe-2', credential_files=(), catalog=None, environment_ref=None,
                           control_evidence_refs=(), policy_ref='p')
            self.assertFalse(target.exists())

    def test_host_rejects_before_launch_check_or_transport(self):
        f = test_devin_host.DevinHostTests(); f.setUp(); self.addCleanup(f.doCleanups)
        for model, effort in (("swe-2", "high"), ("normal", None), ("swe-2-high", "max")):
            config = replace(f.host.config, conditions=replace(f.request.conditions, model=model), effort=effort)
            with patch('co_v4.devin_host.check_launch_template') as check:
                with self.assertRaises((ValueError, RuntimeError)):
                    DevinTextHost(config)
                check.assert_not_called()
            with self.assertRaises(RuntimeError): check_launch_template(config)
        f.factory.assert_not_called()

    def test_generic_synthetic_adapter_model_still_supported(self):
        f = test_devin.DevinTests(); f.setUp(); self.addCleanup(f.doCleanups)
        f.request = replace(f.request, conditions=replace(f.request.conditions, model='fixture-model'))
        f.running()
        self.assertEqual(f.adapter.status(f.ref).state, State.RUNNING)

    def test_malformed_advertisements_never_become_effective(self):
        invalid = [None, {}, {"currentModelId": None}, models(""),
                   {"availableModels": [{"modelId": "swe-2-high"}]},
                   {"currentModelId": "swe-2-high", "availableModels": None},
                   models(ids=[]), models(ids=["swe-2-high", "swe-2-high"]),
                   models(ids=["swe-2-medium"]), models(ids=[None]), models("swe-2-medium")]
        for advertisement in invalid:
            with self.subTest(advertisement=advertisement), self.assertRaises(ValueError):
                ModelObservation('swe-2-high').observe({'models': advertisement})
        with self.assertRaises(ValueError):
            ModelObservation('swe-2-high').observe({'models': models(), **models('swe-2-medium')})


class ProtocolSelectionTests(unittest.TestCase):
    def fixture(self):
        f = test_devin.DevinTests(); f.setUp(); self.addCleanup(f.doCleanups); f.launch()
        return f

    @staticmethod
    def update(f, uid='swe-2-high', session='sess-private', **fields):
        f.wire.incoming.append({'jsonrpc': '2.0', 'method': 'session/update', 'params': {
            'sessionId': session, 'update': {'sessionUpdate': 'current_model_update',
                                          'currentModelId': uid, **fields}}})

    def test_session_exact_advertisement_and_omission(self):
        for advertisement in ({}, {'models': models()}):
            f = self.fixture()
            f.wire.reply('session/new', {**f.session_result(), **advertisement})
            self.assertEqual(f.adapter.status(f.ref).state, State.RUNNING)
            observation = f.adapter._get(f.ref).models.evidence()
            self.assertEqual(observation['effective_model_verified'], bool(advertisement))
            self.assertEqual(observation['effective_model'], 'swe-2-high' if advertisement else None)

    def test_bad_queued_advertisement_cannot_be_overwritten_by_good_reply(self):
        for uid, session in (('swe-2-medium', 'sess-private'), ('swe-2-high', 'different')):
            f = self.fixture(); self.update(f, uid, session)
            f.wire.reply('session/new', {**f.session_result(), 'models': models()})
            self.assertEqual(f.adapter.status(f.ref).state, State.ERROR)
            self.assertFalse(any(m.get('method') == 'session/prompt' for m in f.wire.sent))

    def test_good_queued_update_cannot_mask_bad_reply(self):
        f = self.fixture(); self.update(f)
        f.wire.reply('session/new', {**f.session_result(), 'models': models('swe-2-medium')})
        self.assertEqual(f.adapter.status(f.ref).state, State.ERROR)
        self.assertFalse(any(m.get('method') == 'session/prompt' for m in f.wire.sent))

    def test_model_mismatch_after_completion_response_invalidates_result(self):
        f = self.fixture()
        f.wire.reply('session/new', {**f.session_result(), 'models': models()})
        self.assertEqual(f.adapter.status(f.ref).state, State.RUNNING)
        f.wire.reply('session/prompt', {'stopReason': 'end_turn'})
        self.update(f, 'swe-2-max')
        self.assertEqual(f.adapter.status(f.ref).state, State.ERROR)
        self.assertEqual(f.adapter.protocol_diagnostic(f.ref)['category'], 'native_model_mismatch')

    def test_updates_validate_missing_null_empty_duplicate_and_cross_session(self):
        for fields in ({'currentModelId': None}, {'currentModelId': ''},
                       {'models': models(ids=[])}, {'models': models(ids=['swe-2-high'] * 2)},
                       {'models': models('swe-2-max')}):
            f = self.fixture(); f.wire.reply('session/new', f.session_result())
            self.assertEqual(f.adapter.status(f.ref).state, State.RUNNING)
            self.update(f, **fields)
            self.assertEqual(f.adapter.status(f.ref).state, State.ERROR)
        f = self.fixture(); f.wire.reply('session/new', f.session_result())
        self.assertEqual(f.adapter.status(f.ref).state, State.RUNNING)
        self.update(f, session='other')
        self.assertEqual(f.adapter.status(f.ref).state, State.ERROR)

    def test_matching_current_update_without_full_advertisement_is_observed(self):
        f = self.fixture(); self.update(f)
        f.wire.reply('session/new', f.session_result())
        self.assertEqual(f.adapter.status(f.ref).state, State.RUNNING)
        self.assertEqual(f.adapter._get(f.ref).models.current, 'swe-2-high')


if __name__ == '__main__': unittest.main()
