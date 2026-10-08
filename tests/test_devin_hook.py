"""Offline hook-seam regressions: documented stdin/stdout contract only.

Contract under test: `allow` is unsupported — no trusted host binds this
hook to the call's actual target, so every allow resolution defers to the
Native permission prompt and never prints an approval, whatever Scope it
claims and however the decision file is spelled. `deny`/`cancel` still
relay as the documented block output, bound to the exact request and spent
exactly once via a canonical-path `.consumed` marker.
"""
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from probes import devin_permission_hook as hook

FIXTURES = Path(__file__).parent / 'fixtures'
HOOK_SCRIPT = Path(hook.__file__).resolve()
PERMISSION = (FIXTURES / 'devin_permission_request.json').read_text()
PRETOOL = (FIXTURES / 'devin_pretooluse.json').read_text()
PERMISSION_EVENT = json.loads(PERMISSION)
PRETOOL_EVENT = json.loads(PRETOOL)
HEAD_A = 'a' * 40
HEAD_B = 'b' * 40


def run_hook(stdin_text, argv):
    out = io.StringIO()
    with patch('sys.stdin', io.StringIO(stdin_text)), \
            patch('sys.stdout', out):
        code = hook.main(argv)
    return code, out.getvalue()


def write_decision(root, resolution, reason='judgment:1', event=PERMISSION_EVENT,
                   scope=None, name='decision.json', **binding):
    """Bound decision for `event`; binding overrides simulate foreign/stale ones."""
    target = {field: binding.get(field, event.get(field))
              for field in ('session_id', 'prompt_id', 'tool_name', 'tool_input')}
    body = {'resolution': resolution, 'reason': reason, **target}
    if scope is not None:
        body['scope'] = scope
    path = Path(root) / name
    path.write_text(json.dumps(body))
    return path


def make_repo(root, branch='feature', head=HEAD_A, name='repo'):
    """Minimal hand-built .git work tree used to stage the reviewed drift
    scenarios. The hook never reads it: an allow defers on any target."""
    repo = Path(root) / name
    gitdir = repo / '.git'
    gitdir.mkdir(parents=True)
    (gitdir / 'HEAD').write_text(f'ref: refs/heads/{branch}\n')
    ref = gitdir / 'refs' / 'heads' / branch
    ref.parent.mkdir(parents=True)
    ref.write_text(head + '\n')
    return repo


def switch_branch(repo, branch, head=HEAD_B):
    """Move the hand-built repo to another branch (the reviewed drift)."""
    gitdir = repo / '.git'
    (gitdir / 'HEAD').write_text(f'ref: refs/heads/{branch}\n')
    ref = gitdir / 'refs' / 'heads' / branch
    ref.parent.mkdir(parents=True, exist_ok=True)
    ref.write_text(head + '\n')


def push_event(workdir):
    """The reviewed call: `git push origin HEAD` with an explicit workdir."""
    event = dict(PERMISSION_EVENT)
    event['tool_input'] = {'command': 'git push origin HEAD',
                           'workdir': str(workdir)}
    return json.dumps(event)


class DevinHookTests(unittest.TestCase):
    def test_allow_defers_and_records_the_unsupported_relay(self):
        # Contract: `allow` is unsupported — the hook is not a trusted target
        # authority — so a bound, unspent allow still exits 0 with no output,
        # and the audit records the explicit defer reason.
        with tempfile.TemporaryDirectory() as root:
            spool = Path(root) / 'capture.jsonl'
            code, out = run_hook(PERMISSION, [
                '--decision-file', str(write_decision(root, 'allow')),
                '--record', str(spool)])
            self.assertEqual((code, out), (0, ''))
            captured = json.loads(spool.read_text().splitlines()[0])
        self.assertEqual(captured['outcome'], 'defer')
        self.assertEqual(captured['decision']['resolution'], 'allow')
        self.assertTrue(captured['decision']['bound'])
        self.assertEqual(captured['decision']['defer_reason'],
                         'allow_relay_unsupported')

    def test_deny_and_cancel_map_to_block(self):
        for resolution, reason in (('deny', 'judgment:1'),
                                   ('cancel', 'cancel: judgment:1')):
            with self.subTest(resolution=resolution), \
                    tempfile.TemporaryDirectory() as root:
                code, out = run_hook(PRETOOL, [
                    '--decision-file',
                    str(write_decision(root, resolution, event=PRETOOL_EVENT))])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(out),
                             {'decision': 'block', 'reason': reason})

    def test_defer_without_decision_and_capture_records_call(self):
        with tempfile.TemporaryDirectory() as root:
            spool = Path(root) / 'capture.jsonl'
            code, out = run_hook(PERMISSION, ['--record', str(spool)])
            self.assertEqual(code, 0)
            self.assertEqual(out, '')
            lines = spool.read_text().splitlines()
        self.assertEqual(len(lines), 1)
        captured = json.loads(lines[0])
        self.assertEqual(captured['tool_name'], 'exec')
        self.assertEqual(captured['tool_input']['command'],
                         'git push origin HEAD')
        self.assertEqual(captured['session_id'], 'fixture-session-0000')
        self.assertEqual(captured['outcome'], 'defer')
        self.assertIsNone(captured['decision'])

    def test_never_approves_on_malformed_or_missing_inputs(self):
        events = ('', '{', '[]', '{}',
                  json.dumps({'hook_event_name': 'PostToolUse',
                              'tool_name': 'exec', 'tool_input': {},
                              'session_id': 's'}),
                  json.dumps({'hook_event_name': 'PermissionRequest',
                              'tool_name': 'exec', 'tool_input': {}}),
                  json.dumps({'hook_event_name': 'PermissionRequest',
                              'tool_name': '', 'tool_input': {},
                              'session_id': 's'}),
                  json.dumps({'hook_event_name': 'PermissionRequest',
                              'tool_name': 'exec', 'tool_input': 'x',
                              'session_id': 's'}))
        for event in events:
            with self.subTest(event=event), \
                    tempfile.TemporaryDirectory() as root:
                code, out = run_hook(
                    event, ['--decision-file',
                            str(write_decision(root, 'allow'))])
            self.assertEqual((code, out), (0, ''))
        decisions = ('not json', '{}', '{"resolution": "maybe"}',
                     '{"resolution": "allow", "reason": 5}',
                     '{"resolution": "allow", "reason": "unbound"}',
                     '{"resolution": "allow", "reason": "r", "session_id": "s",'
                     ' "prompt_id": "p", "tool_name": "exec",'
                     ' "tool_input": {}, "scope": "not-a-dict"}')
        for body in decisions:
            with self.subTest(decision=body), \
                    tempfile.TemporaryDirectory() as root:
                path = Path(root) / 'd.json'
                path.write_text(body)
                code, out = run_hook(PERMISSION,
                                     ['--decision-file', str(path)])
            self.assertEqual((code, out), (0, ''))
        with tempfile.TemporaryDirectory() as root:
            code, out = run_hook(PERMISSION, [
                '--decision-file', str(Path(root) / 'missing.json')])
        self.assertEqual((code, out), (0, ''))

    def test_bound_decision_must_match_session_target_and_turn(self):
        mismatches = (
            {'session_id': 'other-session'},
            {'prompt_id': 'fixture-prompt-9999'},  # stale: rotated per turn
            {'tool_name': 'edit'},
            {'tool_input': {'command': 'git status', 'shell_id': 'main'}},
            {'tool_input': {'command': 'git push origin HEAD'}},  # partial input
        )
        for resolution in ('allow', 'deny', 'cancel'):
            for binding in mismatches:
                with self.subTest(resolution=resolution, binding=binding), \
                        tempfile.TemporaryDirectory() as root:
                    spool = Path(root) / 'capture.jsonl'
                    code, out = run_hook(PERMISSION, [
                        '--decision-file',
                        str(write_decision(root, resolution, **binding)),
                        '--record', str(spool)])
                    self.assertEqual((code, out), (0, ''))
                    captured = json.loads(spool.read_text().splitlines()[0])
                    self.assertEqual(captured['outcome'], 'defer')
                    self.assertFalse(captured['decision']['bound'])
                    self.assertEqual(captured['decision']['resolution'],
                                     resolution)
                    self.assertTrue(captured['decision']['mismatched_fields'])
                    self.assertIn('claimed_target', captured['decision'])

    def test_cross_session_allow_cannot_approve_this_request(self):
        # An allow issued for session A's `git status` must never approve
        # session B's `git push origin HEAD` — it defers like everything else.
        with tempfile.TemporaryDirectory() as root:
            foreign = dict(PERMISSION_EVENT)
            foreign.update(session_id='session-A',
                           tool_input={'command': 'git status',
                                       'shell_id': 'main'})
            code, out = run_hook(PERMISSION, [
                '--decision-file',
                str(write_decision(root, 'allow', event=foreign))])
        self.assertEqual((code, out), (0, ''))

    def test_bound_deny_is_blocked_and_audited(self):
        with tempfile.TemporaryDirectory() as root:
            spool = Path(root) / 'capture.jsonl'
            code, out = run_hook(PERMISSION, [
                '--decision-file', str(write_decision(root, 'deny')),
                '--record', str(spool)])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(out),
                             {'decision': 'block', 'reason': 'judgment:1'})
            captured = json.loads(spool.read_text().splitlines()[0])
        self.assertEqual(captured['outcome'], 'block')
        self.assertEqual(captured['decision'],
                         {'resolution': 'deny', 'bound': True,
                          'mismatched_fields': []})

    def test_missing_prompt_id_on_event_cannot_be_bound(self):
        event = dict(PERMISSION_EVENT)
        del event['prompt_id']
        with tempfile.TemporaryDirectory() as root:
            code, out = run_hook(json.dumps(event), [
                '--decision-file', str(write_decision(root, 'allow'))])
        self.assertEqual((code, out), (0, ''))


class DevinHookConsumptionTests(unittest.TestCase):
    """P2 regression: a bound decision is spent once per call, not per turn,
    and the claim anchors to the decision's canonical path, not its spelling."""

    def test_allow_is_spent_once_and_never_approves(self):
        # First presentation of a bound allow: deferred but consumed. The
        # byte-identical retry audits as a duplicate claim of the same
        # decision rather than re-evaluating it.
        with tempfile.TemporaryDirectory() as root:
            decision = write_decision(root, 'allow')
            code, out = run_hook(PERMISSION,
                                 ['--decision-file', str(decision)])
            self.assertEqual((code, out), (0, ''))
            self.assertTrue(Path(str(decision) + '.consumed').exists())
            spool = Path(root) / 'capture.jsonl'
            code, out = run_hook(PERMISSION, [
                '--decision-file', str(decision), '--record', str(spool)])
            self.assertEqual((code, out), (0, ''))
            captured = json.loads(spool.read_text().splitlines()[0])
        self.assertEqual(captured['outcome'], 'defer')
        self.assertTrue(captured['decision']['bound'])
        consumed = captured['decision']['consumed']
        self.assertTrue(consumed['duplicate'])
        self.assertEqual(consumed['prior_claim']['session_id'],
                         'fixture-session-0000')
        self.assertEqual(consumed['prior_claim']['tool_input']['command'],
                         'git push origin HEAD')

    def test_deny_is_single_use_too(self):
        # A bound block answers one request; the retry defers to the Native
        # prompt instead of silently re-applying a spent decision.
        with tempfile.TemporaryDirectory() as root:
            decision = write_decision(root, 'deny')
            code, out = run_hook(PERMISSION,
                                 ['--decision-file', str(decision)])
            self.assertEqual(json.loads(out)['decision'], 'block')
            code, out = run_hook(PERMISSION,
                                 ['--decision-file', str(decision)])
            self.assertEqual((code, out), (0, ''))

    def test_concurrent_calls_claim_the_decision_once(self):
        # Real hook invocations are separate processes; only one may claim the
        # decision, and under fail-closed allow none may relay an approval.
        with tempfile.TemporaryDirectory() as root:
            decision = write_decision(root, 'allow')
            records = [Path(root) / f'cap-{index}.jsonl' for index in range(8)]
            procs = [subprocess.Popen(
                [sys.executable, str(HOOK_SCRIPT),
                 '--decision-file', str(decision),
                 '--record', str(records[index])],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True)
                for index in range(8)]
            results = [proc.communicate(input=PERMISSION) for proc in procs]
            outcomes = [json.loads(record.read_text().splitlines()[0])
                        for record in records]
        for stdout, stderr in results:
            self.assertEqual(stderr, '')
            self.assertEqual(stdout, '')
        duplicates = [entry for entry in outcomes
                      if entry['decision'].get('consumed', {}).get('duplicate')]
        self.assertEqual(len(duplicates), 7)
        winners = [entry for entry in outcomes
                   if 'consumed' not in entry['decision']]
        self.assertEqual(len(winners), 1)
        self.assertEqual(winners[0]['decision']['defer_reason'],
                         'allow_relay_unsupported')

    def test_mismatched_decision_is_not_consumed(self):
        # A foreign decision stays unspent: it still belongs to its own
        # pending request, so no .consumed marker may appear.
        with tempfile.TemporaryDirectory() as root:
            decision = write_decision(root, 'allow', session_id='other')
            code, out = run_hook(PERMISSION,
                                 ['--decision-file', str(decision)])
            self.assertEqual((code, out), (0, ''))
            self.assertFalse(
                Path(str(decision) + '.consumed').exists())

    def test_bound_allow_is_spent_even_though_it_defers(self):
        # An allow can never apply, and it is still consumed on first
        # presentation: a retry audits as spent rather than re-evaluated.
        with tempfile.TemporaryDirectory() as root:
            repo = make_repo(root, branch='feature')
            decision = write_decision(
                root, 'allow', event=json.loads(push_event(repo)),
                scope={'git_branch': 'other'})
            code, out = run_hook(push_event(repo),
                                 ['--decision-file', str(decision)])
            self.assertEqual((code, out), (0, ''))
            self.assertTrue(Path(str(decision) + '.consumed').exists())


class DevinHookFailClosedAllowTests(unittest.TestCase):
    """Astra residual-P2 repros: every allow path must end in defer, never
    approve — the hook has no trusted host binding the exact actual target."""

    def test_symlink_retargeted_actual_target_never_approves(self):
        # Reviewed path 1: `git -C target` runs in a symlinked directory the
        # Worker can retarget between decision and call, so the workdir the
        # hook sees is not the repo the command pushes. Both presentations —
        # before and after the retarget — must defer.
        with tempfile.TemporaryDirectory() as root:
            approved = make_repo(root, branch='feature', name='approved')
            other = make_repo(root, branch='main', name='other')
            link = Path(root) / 'target'
            link.symlink_to(approved)
            event = dict(PERMISSION_EVENT)
            event['tool_input'] = {
                'command': 'git -C target push origin HEAD',
                'workdir': str(root)}
            event_text = json.dumps(event)
            decision = write_decision(root, 'allow', event=event)
            spool = Path(root) / 'capture.jsonl'
            code, out = run_hook(event_text, [
                '--decision-file', str(decision), '--record', str(spool)])
            self.assertEqual((code, out), (0, ''))
            link.unlink()
            link.symlink_to(other)
            code, out = run_hook(event_text, [
                '--decision-file', str(decision), '--record', str(spool)])
            self.assertEqual((code, out), (0, ''))
            first, second = (json.loads(line)
                             for line in spool.read_text().splitlines())
            self.assertEqual(first['outcome'], 'defer')
            self.assertEqual(first['decision']['defer_reason'],
                             'allow_relay_unsupported')
            self.assertEqual(second['outcome'], 'defer')
            self.assertTrue(second['decision']['consumed']['duplicate'])
            # A file_path reached through the same retargeted symlink is an
            # equally unverifiable target: it defers too.
            edit_event = dict(PERMISSION_EVENT)
            edit_event['tool_input'] = {
                'file_path': str(link / 'AGENTS.md'),
                'old_string': 'alpha', 'new_string': 'beta'}
            edit_decision = write_decision(root, 'allow', event=edit_event,
                                           name='edit.json')
            code, out = run_hook(json.dumps(edit_event),
                                 ['--decision-file', str(edit_decision)])
            self.assertEqual((code, out), (0, ''))

    def test_scope_omitted_stale_allow_never_approves(self):
        # Reviewed path 2: an unspent allow issued while the repo was on
        # `feature` is presented for the first time after the branch moved to
        # `main`. Scope omitted, empty or stale-matching all defer.
        with tempfile.TemporaryDirectory() as root:
            repo = make_repo(root, branch='feature')
            event = push_event(repo)
            decisions = (
                write_decision(root, 'allow', event=json.loads(event),
                               name='no-scope.json'),
                write_decision(root, 'allow', event=json.loads(event),
                               scope={}, name='empty-scope.json'),
                write_decision(root, 'allow', event=json.loads(event),
                               scope={'git_branch': 'feature'},
                               name='stale-scope.json'),
            )
            switch_branch(repo, 'main')
            for decision in decisions:
                with self.subTest(decision=decision.name):
                    code, out = run_hook(
                        event, ['--decision-file', str(decision)])
                    self.assertEqual((code, out), (0, ''))
                    self.assertTrue(
                        Path(str(decision) + '.consumed').exists())

    def test_alias_decision_path_cannot_spend_the_same_decision_twice(self):
        # Reviewed path 3: the same decision file reached through a symlink
        # alias is the same claim. The marker anchors to the canonical path,
        # so the second spelling audits as a duplicate — never a fresh relay.
        with tempfile.TemporaryDirectory() as root:
            decision = write_decision(root, 'allow', name='decision.json')
            alias = Path(root) / 'alias.json'
            os.symlink(decision.name, alias)
            code, out = run_hook(PERMISSION,
                                 ['--decision-file', str(decision)])
            self.assertEqual((code, out), (0, ''))
            spool = Path(root) / 'capture.jsonl'
            code, out = run_hook(PERMISSION, [
                '--decision-file', str(alias), '--record', str(spool)])
            self.assertEqual((code, out), (0, ''))
            captured = json.loads(spool.read_text().splitlines()[0])
            self.assertEqual(captured['outcome'], 'defer')
            consumed = captured['decision']['consumed']
            self.assertTrue(consumed['duplicate'])
            self.assertEqual(consumed['prior_claim']['session_id'],
                             'fixture-session-0000')
            self.assertTrue(Path(str(decision) + '.consumed').exists())
            self.assertFalse(Path(str(alias) + '.consumed').exists())

    def test_claimed_scope_is_recorded_but_never_gates(self):
        # The decision's Scope claims survive verbatim in the audit record as
        # evidence of what was approved; they cannot promote a defer to an
        # approve, matching or not.
        with tempfile.TemporaryDirectory() as root:
            repo = make_repo(root)
            scope = {'cwd': str(repo), 'git_toplevel': str(repo),
                     'git_branch': 'feature', 'git_head': HEAD_A}
            decision = write_decision(
                root, 'allow', event=json.loads(push_event(repo)),
                scope=scope)
            spool = Path(root) / 'capture.jsonl'
            code, out = run_hook(push_event(repo), [
                '--decision-file', str(decision), '--record', str(spool)])
            self.assertEqual((code, out), (0, ''))
            captured = json.loads(spool.read_text().splitlines()[0])
        self.assertEqual(captured['outcome'], 'defer')
        self.assertEqual(captured['decision']['claimed_scope'], scope)
        self.assertEqual(captured['decision']['defer_reason'],
                         'allow_relay_unsupported')

    def test_unverifiable_or_unknown_scope_claims_still_defer(self):
        with tempfile.TemporaryDirectory() as root:
            bare = Path(root) / 'bare'
            bare.mkdir()
            cases = ((push_event(bare), {'git_branch': 'feature'}),
                     (PERMISSION, {'git_branch': 'feature'}),
                     (push_event(bare), {'cwd': str(bare),
                                         'unknown_key': 'x'}),
                     (push_event(bare), {'cwd': str(bare),
                                         'git_branch': 5}))
            for index, (event_text, scope) in enumerate(cases):
                with self.subTest(scope=scope):
                    decision = write_decision(
                        root, 'allow', event=json.loads(event_text),
                        scope=scope, name=f'scope-{index}.json')
                    code, out = run_hook(
                        event_text, ['--decision-file', str(decision)])
                    self.assertEqual((code, out), (0, ''))

    def test_no_allow_combination_ever_outputs_approve(self):
        # Blanket invariant: for every decision shape carrying `allow` —
        # bound or foreign, Scope omitted/empty/matching/mismatched — and for
        # both hook event types, stdout never contains an approve decision.
        variants = (
            {},                                          # scope omitted
            {'scope': {}},                               # scope empty
            {'scope': {'git_branch': 'main'}},
            {'scope': {'cwd': '/does/not/exist'}},
        )
        for event_text, event in ((PERMISSION, PERMISSION_EVENT),
                                  (PRETOOL, PRETOOL_EVENT)):
            for index, extra in enumerate(variants):
                with self.subTest(tool=event['tool_name'], variant=index), \
                        tempfile.TemporaryDirectory() as root:
                    decision = write_decision(root, 'allow', event=event,
                                              name=f'a-{index}.json', **extra)
                    code, out = run_hook(
                        event_text, ['--decision-file', str(decision)])
                    self.assertEqual(code, 0)
                    self.assertNotIn('approve', out)
                    self.assertEqual(out, '')


if __name__ == '__main__':
    unittest.main()
