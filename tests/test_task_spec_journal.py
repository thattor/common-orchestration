"""Deterministic invariants for co_v4.task spec validation and the journal."""
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from co_v4.task import common
from co_v4.task import spec as spec_mod
from co_v4.task.common import TaskError, parse_json
from co_v4.task.journal import Journal
from co_v4.task import journal as journal_mod


def spec_dict(**over):
    s = {'schema': 'co.task/1', 'goal': 'add feature', 'repo': '/abs/repo',
         'base_sha': 'a' * 40, 'readable': ['src/a.py', 'tests/test_a.py'],
         'writable': ['src/a.py', 'src/new.py'],
         'verify': ['/usr/bin/env', 'python3', '-m', 'pytest']}
    s.update(over)
    return s


def code_of(fn, *a, **k):
    try:
        fn(*a, **k)
    except TaskError as exc:
        return exc.code
    raise AssertionError('expected TaskError')


class SpecTests(unittest.TestCase):
    def test_valid_defaults_and_deepcopy(self):
        out = spec_mod.validate_spec(spec_dict())
        self.assertEqual((out['max_steps'], out['max_repairs'],
                          out['call_timeout']), (6, 1, 900))
        src = spec_dict()
        out2 = spec_mod.validate_spec(src)
        out2['readable'].append('x')
        self.assertNotIn('x', src['readable'])

    def test_rejections(self):
        cases = [('schema', 'x'), ('goal', ''), ('goal', 'x\ud800'),
                 ('repo', 'rel'), ('repo', 5),
                 ('base_sha', 'a' * 39), ('base_sha', 'A' * 40),
                 ('readable', 'x'), ('readable', ['a', 'a']),
                 ('readable', ['../e']), ('readable', ['/a']),
                 ('readable', ['a//b']), ('readable', ['a/./b']),
                 ('readable', ['.git/config']), ('readable', ['sub/.git/x']),
                 ('readable', ['x/.co-verify-tmp/y']),
                 ('readable', ['x/.co-verify-tmp-stale/y']),
                 ('readable', ['.GIT/config']),
                 ('readable', ['a', 'a/b']),      # ancestor/file collision
                 ('readable', ['test.py', 'TEST.py']),
                 ('readable', ['café.py', 'cafe\u0301.py']),
                 ('readable', ['APP', 'app/file.py']),
                 ('readable', ['a\nb']), ('readable', ['a\tb']),
                 ('writable', []),                # dev task needs writes
                 ('writable', ['ok', 'ok/sub']),  # ancestor collision
                 ('verify', []), ('verify', ['pytest']),
                 ('verify', ['/bin/']), ('max_steps', 0), ('max_steps', 7),
                 ('max_steps', True), ('max_repairs', 2), ('call_timeout', 0),
                 ('call_timeout', 901), ('nope', 1)]
        for key, val in cases:
            with self.subTest(key=key, val=str(val)[:40]):
                s = spec_dict()
                s[key] = val
                self.assertEqual(code_of(spec_mod.validate_spec, s),
                                 'spec_invalid')

    def test_missing_required(self):
        for key in ('verify', 'base_sha', 'goal'):
            s = spec_dict()
            del s[key]
            self.assertEqual(code_of(spec_mod.validate_spec, s),
                             'spec_invalid')


class PlanTests(unittest.TestCase):
    def setUp(self):
        self.spec = spec_mod.validate_spec(spec_dict())

    def step(self, n, role='implement', inputs=None, instr='do it'):
        return {'id': f's{n}', 'role': role, 'instructions': instr,
                'inputs': inputs or []}

    def plan(self, steps):
        return {'schema': 'co.task-plan/1', 'steps': steps}

    def test_valid_shapes(self):
        p = spec_mod.validate_plan(self.plan([self.step(1)]), self.spec)
        self.assertEqual(p['steps'][0]['id'], 's1')
        p = self.plan([self.step(1, 'design'),
                       self.step(2, 'implement', ['s1']),
                       self.step(3, 'review', ['s2'])])
        self.assertEqual(len(spec_mod.validate_plan(p, self.spec)['steps']), 3)

    def test_scope_and_order_invariants(self):
        bad = [self.plan([]),
               self.plan([self.step(1, 'design')]),              # no impl
               self.plan([self.step(1, 'review')]),             # rev first
               self.plan([self.step(1), self.step(2, 'design', ['s1'])]),  # last=design
               self.plan([self.step(1), self.step(2, 'review', ['s1']),
                          self.step(3, 'implement', ['s1'])]),  # impl after rev
               self.plan([self.step(1, 'implement', ['s1'])]),
               self.plan([self.step(1, 'implement', ['s9'])]),
               self.plan([self.step(1), self.step(2, 'implement', ['s1', 's1'])]),
               self.plan([dict(self.step(1), id='s2')]),
               self.plan([dict(self.step(1), extra=1)]),
               self.plan([self.step(1, 'bogus')]),
               self.plan([dict(self.step(1), role=['implement'])]),  # unhashable
               self.plan([dict(self.step(1), inputs={'s1': 1})]),
               self.plan([self.step(1, instr='  ')]),
               self.plan([self.step(1, instr='x' * 5000)]),      # >4096 bytes
               self.plan([self.step(1, instr='x\ud800')]),      # surrogate
               {'schema': 'wrong', 'steps': [self.step(1)]},
               {'schema': 'co.task-plan/1', 'steps': [self.step(1)],
                'route': 'x'},
               'notadict']
        for p in bad:
            with self.subTest(p=str(p)[:70]):
                self.assertEqual(code_of(spec_mod.validate_plan, p, self.spec),
                                 'plan_invalid')

    def test_max_steps_bound(self):
        spec = spec_mod.validate_spec(spec_dict(max_steps=2))
        p = self.plan([self.step(i) for i in (1, 2, 3)])
        self.assertEqual(code_of(spec_mod.validate_plan, p, spec),
                         'plan_invalid')


class ParseJsonTests(unittest.TestCase):
    def test_strict_and_sole_fence(self):
        self.assertEqual(parse_json('{"a":1}'), {'a': 1})
        self.assertEqual(parse_json('```json\n{"a":1}\n```'), {'a': 1})
        content = '## Examples\n```python\nprint(1)\n```\n'
        replacement = {'files': [{'path': 'guide.md', 'content': content}]}
        encoded = json.dumps(replacement)
        self.assertEqual(parse_json(encoded), replacement)
        self.assertEqual(parse_json('```json\n' + encoded + '\n```'),
                         replacement)

    def test_rejections(self):
        for text in ('', '[]', '5', '{"a":1} trailing',
                     '```json\n{"a":1}', '```json\n{}\n``` extra',
                     '```\n{}\n```\n```',
                     'x ```json\n{}\n```', '{"a":1,"a":2}', '{"a":NaN}',
                     '{"a":1}\n```json\n{}\n```'):
            with self.subTest(text=text[:30]):
                self.assertEqual(code_of(parse_json, text), 'json_invalid')


class ChangesReviewTests(unittest.TestCase):
    def setUp(self):
        self.spec = spec_mod.validate_spec(spec_dict())

    def body(self, files, summary='s'):
        return json.dumps({'files': files, 'summary': summary})

    def test_changes_roundtrip(self):
        out = spec_mod.validate_changes(
            self.body([{'path': 'src/a.py', 'content': 'x=1'},
                       {'path': 'src/new.py', 'content': ''}]), self.spec)
        self.assertEqual([c['path'] for c in out], ['src/a.py', 'src/new.py'])

    def test_changes_scope_limits_and_wire(self):
        cases = [
            self.body([{'path': 'tests/test_a.py', 'content': 'x'}]),
            self.body([{'path': 'etc/passwd', 'content': 'x'}]),
            self.body([{'path': 'src/a.py', 'content': 'a'},
                       {'path': 'src/a.py', 'content': 'b'}]),
            self.body([{'path': 'src/a.py', 'content': 'y' * 65537}]),
            self.body([{'path': 'src/a.py', 'content': 'x', 'extra': 1}]),
            self.body([{'path': 'src/a.py'}]),
            self.body([{'path': 'src/a.py', 'content': 5}]),
            self.body([{'path': 'src/a.py', 'content': 'x\ud800'}]),
            self.body([{'path': {'p': 1}, 'content': 'x'}]),
            self.body([]),                                   # empty proposal
            json.dumps({'files': [{'path': 'src/a.py', 'content': 'x'}]}),
            json.dumps({'files': [], 'summary': 's', 'extra': 1}),
            json.dumps({'files': [{'path': 'src/a.py', 'content': 'x'}],
                        'summary': 5}),
            'not json', '{"files":']
        for text in cases:
            with self.subTest(text=str(text)[:60]):
                self.assertEqual(code_of(spec_mod.validate_changes, text,
                                         self.spec), 'changes_invalid')

    def test_review_wire_and_bad(self):
        for v in ('approve', 'request_changes'):
            r = spec_mod.validate_review(json.dumps(
                {'verdict': v, 'findings': ['f1']}))
            self.assertEqual((r['verdict'], set(r)), (v, {'verdict', 'findings'}))
        bad = ['not json',
               json.dumps({'verdict': 'lgtm', 'findings': []}),
               json.dumps({'verdict': ['approve'], 'findings': []}),
               json.dumps({'verdict': {'v': 1}, 'findings': []}),
               json.dumps({'verdict': 'approve', 'findings': {}}),
               json.dumps({'verdict': 'approve', 'findings': [{'f': 1}]}),
               json.dumps({'verdict': 'approve', 'findings': ['x\ud800']}),
               json.dumps({'verdict': 'approve', 'findings': [],
                           'schema': 'x'})]
        for text in bad:
            with self.subTest(text=text[:50]):
                self.assertEqual(code_of(spec_mod.validate_review, text),
                                 'review_invalid')


class JournalTests(unittest.TestCase):
    _n = 0

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        JournalTests._n += 1
        self.dir = Path(self.tmp.name) / f'task-{JournalTests._n}'

    def corrupt(self, mutate):
        j = Journal(self.dir, create=True)
        j.append('a', x=1)
        j.append('b', y=2)
        j.close()
        mutate(self.dir / 'journal.jsonl')
        return code_of(Journal, self.dir)

    def test_create_append_reopen(self):
        j = Journal(self.dir, create=True)
        self.assertEqual(stat.S_IMODE(self.dir.stat().st_mode), 0o700)
        e1 = j.append('task_opened', spec={'a': 1})
        self.assertEqual((e1['seq'], e1['kind']), (1, 'task_opened'))
        j.append('call_started', step='s1')
        j.close()
        with Journal(self.dir) as j2:
            self.assertEqual([e['seq'] for e in j2.events], [1, 2])
            self.assertEqual(j2.events[0]['data'], {'spec': {'a': 1}})
            self.assertEqual(j2.append('done')['seq'], 3)

    def test_failed_lock_does_not_close_reused_descriptor(self):
        with Journal(self.dir, create=True):
            failed = Journal.__new__(Journal)
            with self.assertRaises(TaskError):
                failed.__init__(self.dir)
            replacement = os.open('/dev/null', os.O_RDONLY)
            try:
                failed.__del__()
                os.fstat(replacement)
            finally:
                os.close(replacement)

    def test_read_missing_state_is_nonmutating(self):
        with self.assertRaises(TaskError):
            Journal(self.dir)
        self.assertFalse(self.dir.exists())
        with Journal(self.dir, create=True) as j:
            record = j.put_text('s1', 'c1', 'text')
        missing = self.dir / 'out' / 'tmp'
        missing.rmdir()
        with Journal(self.dir) as j:
            with self.assertRaises(TaskError):
                j.get_text(record)
        self.assertFalse(missing.exists())

    def test_append_cap_is_checked_before_mutation(self):
        with Journal(self.dir, create=True) as j:
            before = (self.dir / 'journal.jsonl').read_bytes()
            with mock.patch.object(journal_mod, '_MAX_BYTES', 80):
                with self.assertRaises(TaskError):
                    j.append('too_big', text='x' * 80)
            self.assertEqual((self.dir / 'journal.jsonl').read_bytes(), before)

    def test_nonserializable_data_rejected(self):
        j = Journal(self.dir, create=True)
        self.assertEqual(code_of(j.append, 'bad', nan=float('nan')),
                         'journal_data_invalid')
        j.close()

    def test_torn_and_bad_lines_rejected(self):
        def torn(p):
            with open(p, 'ab') as f:
                f.write(b'{"seq')
        self.assertEqual(self.corrupt(torn), 'journal_corrupt')
        JournalTests._n += 1
        self.dir = Path(self.tmp.name) / f'task-{JournalTests._n}'

        def garbage(p):
            with open(p, 'ab') as f:
                f.write(b'not json\n')
        self.assertEqual(self.corrupt(garbage), 'journal_corrupt')

    def test_seq_gap_and_noncanonical_rejected(self):
        self.assertEqual(self.corrupt(
            lambda p: p.write_text(p.read_text().split('\n', 1)[1])),
            'journal_corrupt')
        JournalTests._n += 1
        self.dir = Path(self.tmp.name) / f'task-{JournalTests._n}'
        self.assertEqual(self.corrupt(
            lambda p: p.write_text(p.read_text().replace('"x":1', '"x" : 1'))),
            'journal_corrupt')

    def test_lock_exclusive(self):
        # Child must retain the Journal: a temporary loses its lock via __del__.
        script = (
            'import sys,time\n'
            f'sys.path.insert(0, {str(Path(__file__).resolve().parents[1])!r})\n'
            'from co_v4.task.journal import Journal\n'
            'j = Journal(sys.argv[1], create=True)\n'
            "print('OPEN', flush=True)\n"
            'time.sleep(20)\n'
            'j.close()\n')
        proc = subprocess.Popen([sys.executable, '-c', script, str(self.dir)],
                                stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual(proc.stdout.readline().strip(), 'OPEN')
            self.assertEqual(code_of(Journal, self.dir), 'journal_locked')
        finally:
            proc.kill()
            proc.wait()
            proc.stdout.close()

    def test_put_text_journal_roundtrip(self):
        j = Journal(self.dir, create=True)
        rec = j.put_text('s1', 'c1', 'final answer')
        j.append('call_done', output=rec)   # record must be journal-safe JSON
        j.close()
        with Journal(self.dir) as j2:
            stored = j2.events[-1]['data']['output']
            self.assertEqual(stored, rec)
            self.assertIs(type(stored['items']), list)
            self.assertEqual(j2.get_text(stored), 'final answer')
            bad = json.loads(json.dumps(stored))
            bad['attempt_ref']['run_id'] = 'other-task'
            self.assertEqual(code_of(j2.get_text, bad), 'output_ref_invalid')

    def test_output_integrity(self):
        j = Journal(self.dir, create=True)
        rec = j.put_text('s1', 'c1', 'hello\nworld')
        blob = self.dir / 'out' / 'blobs' / rec['items'][0]['blob_digest'][7:]
        blob.write_bytes(b'tampered')
        self.assertEqual(code_of(j.get_text, rec), 'output_corrupt')
        rec2 = j.put_text('s1', 'c2', 'fresh')
        bad = json.loads(json.dumps(rec2))
        bad['digest'] = 'sha256:' + '0' * 64
        self.assertEqual(code_of(j.get_text, bad), 'output_corrupt')
        j.close()

    def test_read_creates_no_out_store(self):
        j = Journal(self.dir, create=True)
        rec = {'attempt_ref': {'run_id': self.dir.name, 'job_id': 's1',
                               'attempt_id': 'c1'},
               'digest': 'sha256:' + '0' * 64,
               'items': [{'index': 0, 'media_type': 'text/plain',
                          'blob_digest': 'sha256:' + '1' * 64, 'size': 1}],
               'total_bytes': 1, 'created_at': None}
        self.assertEqual(code_of(j.get_text, rec), 'output_corrupt')
        self.assertFalse((self.dir / 'out').exists())
        j.close()

    def test_symlinked_state_refused(self):
        j = Journal(self.dir, create=True)
        rec = j.put_text('s1', 'c1', 'x')
        j.close()
        elsewhere = Path(self.tmp.name) / 'elsewhere.jsonl'
        elsewhere.write_text('')
        (self.dir / 'journal.jsonl').unlink()
        os.symlink(elsewhere, self.dir / 'journal.jsonl')
        self.assertEqual(code_of(Journal, self.dir), 'path_invalid')
        JournalTests._n += 1
        self.dir = Path(self.tmp.name) / f'task-{JournalTests._n}'
        j = Journal(self.dir, create=True)
        rec = j.put_text('s1', 'c1', 'x')
        j.close()
        victim = Path(self.tmp.name) / 'victim'
        victim.mkdir()
        shutil.rmtree(self.dir / 'out')
        os.symlink(victim, self.dir / 'out')
        j2 = Journal(self.dir)
        self.assertEqual(code_of(j2.get_text, rec), 'output_corrupt')
        j2.close()

    def test_missing_journal(self):
        common.private_dir(self.dir)
        self.assertEqual(code_of(Journal, self.dir), 'journal_missing')


if __name__ == '__main__':
    unittest.main()
