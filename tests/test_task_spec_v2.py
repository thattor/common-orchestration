"""Tests for co.task/2 and co.task-plan/2 validation in co_v4.task.spec.

The v1 wire contracts keep their exact results; v2 adds spec-level
selection/announcement/focus, a required per-step focus enum, and
fixed-mode target coverage checks. Planner remains the initial call only.
"""
import unittest

from co_v4.task import spec as m
from co_v4.task.common import TaskError

SHA = 'a' * 40
CLAUDE = {'route': 'claude', 'model': 'claude-opus-5-5'}
DEVIN = {'route': 'devin', 'model': 'swe-2-high'}


def _code(exc):
    return getattr(exc, 'code', exc.args[0] if exc.args else None)


def v1_spec(**over):
    s = {'schema': 'co.task/1', 'goal': 'ship it', 'repo': '/tmp/repo',
         'base_sha': SHA, 'readable': ['README.md'], 'writable': ['src/x.py'],
         'verify': ['/usr/bin/true']}
    s.update(over)
    return s


def v2_spec(**over):
    s = v1_spec()
    s['schema'] = 'co.task/2'
    s.update(over)
    return s


def v1_step(i, role='implement', **over):
    st = {'id': f's{i}', 'role': role, 'instructions': 'do it', 'inputs': []}
    st.update(over)
    return st


def v2_step(i, role='implement', focus='coding', **over):
    st = {'id': f's{i}', 'role': role, 'instructions': 'do it',
          'inputs': [], 'focus': focus}
    st.update(over)
    return st


def v2_plan(*steps):
    return {'schema': 'co.task-plan/2', 'steps': list(steps)}


class Case(unittest.TestCase):
    def assert_err(self, code, fn, *args):
        with self.assertRaises(TaskError) as ctx:
            fn(*args)
        self.assertEqual(_code(ctx.exception), code)


class SpecV2(Case):
    def test_v1_spec_still_accepted_without_v2_keys(self):
        out = m.validate_spec(v1_spec())
        self.assertEqual(out['schema'], 'co.task/1')
        for key in ('selection', 'announcement', 'focus'):
            self.assertNotIn(key, out)

    def test_v2_spec_defaults(self):
        out = m.validate_spec(v2_spec())
        self.assertEqual(out['schema'], 'co.task/2')
        self.assertEqual(out['selection'],
                         {'mode': 'suitability', 'targets': {}})
        self.assertEqual(out['announcement'], 'standard')
        self.assertEqual(out['focus'], 'architecture_planning')

    def test_v2_spec_validated_output_revalidates(self):
        sel = {'mode': 'fixed',
               'targets': {'planner': dict(CLAUDE), 'implement': dict(DEVIN)}}
        out = m.validate_spec(v2_spec(selection=sel, announcement='quiet',
                                      focus='coding'))
        self.assertEqual(m.validate_spec(out), out)

    def test_v2_rejects_unknown_keys_nulls_and_bad_enums(self):
        self.assert_err('spec_invalid', m.validate_spec, v2_spec(extra=1))
        self.assert_err('spec_invalid', m.validate_spec, v2_spec(focus=None))
        self.assert_err('spec_invalid', m.validate_spec,
                        v2_spec(focus='chatting'))
        self.assert_err('spec_invalid', m.validate_spec,
                        v2_spec(announcement='loud'))
        self.assert_err('spec_invalid', m.validate_spec,
                        v2_spec(selection=[]))
        self.assert_err('spec_invalid', m.validate_spec, v2_spec(
            selection={'mode': 'suitability', 'bogus': 1}))

    def test_fixed_requires_planner_and_implement_at_creation(self):
        self.assert_err('spec_invalid', m.validate_spec, v2_spec(
            selection={'mode': 'fixed', 'targets': {}}))
        self.assert_err('spec_invalid', m.validate_spec, v2_spec(selection={
            'mode': 'fixed', 'targets': {'planner': dict(CLAUDE)}}))
        out = m.validate_spec(v2_spec(selection={
            'mode': 'fixed',
            'targets': {'planner': dict(CLAUDE), 'implement': dict(DEVIN)}}))
        self.assertEqual(out['selection']['mode'], 'fixed')

    def test_targets_bounded_typed_and_role_scoped(self):
        def sel(**target_over):
            t = dict(DEVIN)
            t.update(target_over)
            return {'mode': 'usage',
                    'targets': {'planner': dict(CLAUDE), 'implement': t}}
        self.assert_err('spec_invalid', m.validate_spec,
                        v2_spec(selection=sel(model='has space')))
        self.assert_err('spec_invalid', m.validate_spec,
                        v2_spec(selection=sel(model='m' * 129)))
        self.assert_err('spec_invalid', m.validate_spec,
                        v2_spec(selection=sel(model='tab\there')))
        self.assert_err('spec_invalid', m.validate_spec,
                        v2_spec(selection=sel(model=7)))
        self.assert_err('spec_invalid', m.validate_spec,
                        v2_spec(selection=sel(route='openai')))
        self.assert_err('spec_invalid', m.validate_spec, v2_spec(selection={
            'mode': 'usage', 'targets': {'bogus': dict(CLAUDE)}}))
        self.assert_err('spec_invalid', m.validate_spec, v2_spec(selection={
            'mode': 'usage', 'targets': {'planner': {'route': 'claude'}}}))
        self.assert_err('spec_invalid', m.validate_spec, v2_spec(selection={
            'mode': 'usage',
            'targets': {'planner': dict(CLAUDE, extra='x')}}))
        out = m.validate_spec(v2_spec(selection=sel(model='m' * 128)))
        self.assertEqual(out['selection']['targets']['implement']['model'],
                         'm' * 128)


class PlanV2(Case):
    def test_v1_plan_unchanged(self):
        spec = m.validate_spec(v1_spec())
        plan = {'schema': 'co.task-plan/1', 'steps': [v1_step(1)]}
        self.assertEqual(m.validate_plan(plan, spec)['schema'],
                         'co.task-plan/1')
        self.assert_err('plan_invalid', m.validate_plan,
                        {'schema': 'co.task-plan/1',
                         'steps': [v1_step(1, focus='coding')]}, spec)
        self.assert_err('plan_invalid', m.validate_plan,
                        {'schema': 'co.task-plan/1',
                         'steps': [v1_step(1, role='planner'), v1_step(2)]},
                        spec)

    def test_v2_plan_requires_focus_enum(self):
        spec = m.validate_spec(v2_spec())
        step = v2_step(1)
        del step['focus']
        self.assert_err('plan_invalid', m.validate_plan, v2_plan(step), spec)
        self.assert_err('plan_invalid', m.validate_plan,
                        v2_plan(v2_step(1, focus='nope')), spec)
        out = m.validate_plan(v2_plan(v2_step(1, focus='reasoning')), spec)
        self.assertEqual(out['steps'][0]['focus'], 'reasoning')

    def test_v2_plan_schema_must_match_spec(self):
        plan = v2_plan(v2_step(1))
        self.assert_err('plan_invalid', m.validate_plan, plan,
                        m.validate_spec(v1_spec()))
        out = m.validate_plan(plan, m.validate_spec(v2_spec()))
        self.assertEqual(out['schema'], 'co.task-plan/2')
        self.assert_err('plan_invalid', m.validate_plan,
                        {'schema': 'co.task-plan/1', 'steps': [v1_step(1)]},
                        m.validate_spec(v2_spec()))
        self.assert_err('plan_invalid', m.validate_plan,
                        v2_plan(v2_step(1, role='planner'),
                                v2_step(2, inputs=['s1'])),
                        m.validate_spec(v2_spec()))

    def test_v2_order_rules_and_design_consumer(self):
        spec = m.validate_spec(v2_spec())
        self.assert_err('plan_invalid', m.validate_plan,
                        v2_plan(v2_step(1, role='review', focus='review'),
                                v2_step(2)), spec)
        self.assert_err('plan_invalid', m.validate_plan,
                        v2_plan(v2_step(1),
                                v2_step(2, role='review', focus='review'),
                                v2_step(3)), spec)
        self.assert_err('plan_invalid', m.validate_plan,
                        v2_plan(v2_step(1), v2_step(2, role='planner')), spec)
        self.assert_err('plan_invalid', m.validate_plan,
                        v2_plan(v2_step(1, role='planner', focus='reasoning'),
                                v2_step(2)), spec)
        good = v2_plan(v2_step(1, role='design', focus='reasoning'),
                       v2_step(2, inputs=['s1']),
                       v2_step(3, role='review', focus='review',
                               inputs=['s2']))
        self.assertEqual(len(m.validate_plan(good, spec)['steps']), 3)

    def test_fixed_plan_requires_target_for_every_used_role(self):
        spec = m.validate_spec(v2_spec(selection={
            'mode': 'fixed',
            'targets': {'planner': dict(CLAUDE), 'implement': dict(DEVIN)}}))
        # only implement used and targeted: accepted despite dormant planner
        out = m.validate_plan(v2_plan(v2_step(1)), spec)
        self.assertEqual(out['schema'], 'co.task-plan/2')
        # review used but untargeted: refused
        self.assert_err('plan_invalid', m.validate_plan,
                        v2_plan(v2_step(1),
                                v2_step(2, role='review', focus='review',
                                        inputs=['s1'])), spec)
        # design used but untargeted: refused
        self.assert_err('plan_invalid', m.validate_plan,
                        v2_plan(v2_step(1, role='design'),
                                v2_step(2, inputs=['s1'])), spec)
        # configuring a review target clears the refusal
        spec2 = m.validate_spec(v2_spec(selection={
            'mode': 'fixed',
            'targets': {'planner': dict(CLAUDE), 'implement': dict(DEVIN),
                        'review': dict(CLAUDE)}}))
        out = m.validate_plan(
            v2_plan(v2_step(1),
                    v2_step(2, role='review', focus='review', inputs=['s1'])),
            spec2)
        self.assertEqual(out['steps'][1]['role'], 'review')


class Compat(Case):
    def test_schema_constants_and_dispatch(self):
        self.assertEqual((m.SCHEMA, m.PLAN_SCHEMA),
                         ('co.task/1', 'co.task-plan/1'))
        self.assertEqual((m.SCHEMA_V2, m.PLAN_SCHEMA_V2),
                         ('co.task/2', 'co.task-plan/2'))
        self.assert_err('spec_invalid', m.validate_spec,
                        v1_spec(schema='co.task/9'))
        self.assert_err('plan_invalid', m.validate_plan,
                        {'schema': 'co.task-plan/9', 'steps': []},
                        m.validate_spec(v2_spec()))


if __name__ == '__main__':
    unittest.main()
