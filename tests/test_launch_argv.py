"""Closed argv allowlist parser tests for validate_launch_argv (#190 M3).

Pure grammar/value checks of the public validator — no kernel, record,
launch or provider-qualification claims. Fixture paths are plain
canonical strings; nothing is opened, spawned or hashed. The flag/arity
map below is the expected contract spelled out in this fixture, not the
implementation table."""
import unittest

from co_v4.launch_attestation import (RouteUnqualified,
                                      validate_launch_argv)

EXE = '/opt/llama/bin/llama-server'
MODEL = '/models/qwen3.gguf'
TEMPLATE = '/templates/chat.jinja'
CRED = '/keys/provider.key'
ALIAS = 'co04-qwen3-06b'
BASE = (EXE, '-m', MODEL, '--chat-template-file', TEMPLATE,
        '--api-key-file', CRED, '--host', '127.0.0.1', '--port', '8000',
        '--alias', ALIAS, '--threads', '2', '--parallel', '1',
        '--device', 'none', '--n-gpu-layers', '0', '--reasoning', 'off',
        '--reasoning-budget', '0', '--temp', '0',
        '--no-webui', '--no-ui-mcp-proxy')
FULL = (EXE, '--jinja', '-m', MODEL, '--chat-template-file', TEMPLATE,
        '--api-key-file', CRED, '--host', '127.0.0.1', '--port', '8000',
        '--alias', ALIAS, '--threads', '2', '--threads-batch', '2',
        '--threads-http', '4', '--parallel', '1', '--device', 'none',
        '--n-gpu-layers', '0', '--reasoning', 'off',
        '--reasoning-format', 'auto', '--reasoning-budget', '0',
        '--temp', '0',
        '--cors-origins', 'http://127.0.0.1', '--timeout', '30',
        '--ctx-size', '4096', '--no-warmup', '--no-webui',
        '--no-ui-mcp-proxy')
# Expected contract: every allowed flag with its valid value tokens.
FULL_FLAGS = (('-m', MODEL), ('--model', MODEL),
              ('--chat-template-file', TEMPLATE),
              ('--api-key-file', CRED), ('--host', '127.0.0.1'),
              ('--port', '8000'), ('--alias', ALIAS), ('--threads', '2'),
              ('--threads-batch', '2'), ('--threads-http', '4'),
              ('--parallel', '1'), ('--device', 'none'),
              ('--n-gpu-layers', '0'), ('--reasoning', 'off'),
              ('--reasoning-format', 'auto'),
              ('--reasoning-budget', '0'),
              ('--temp', '0'),
              ('--cors-origins', 'http://127.0.0.1'), ('--timeout', '30'),
              ('--ctx-size', '4096'), ('--no-warmup',), ('--no-webui',),
              ('--no-ui-mcp-proxy',), ('--jinja',))
ARITY = {g[0]: len(g) - 1 for g in FULL_FLAGS}
REQUIRED = ('-m', '--chat-template-file', '--api-key-file', '--host',
            '--port', '--alias', '--threads', '--parallel', '--device',
            '--n-gpu-layers', '--reasoning', '--reasoning-budget',
            '--temp',
            '--no-webui', '--no-ui-mcp-proxy')
KW = dict(executable_path=EXE, model_path=MODEL, template_path=TEMPLATE,
          credential_file=CRED, model_id=ALIAS, threads=2, slots=1,
          host='127.0.0.1', port=8000)


def check(argv, **over):
    kw = dict(KW)
    kw.update(over)
    return validate_launch_argv(tuple(argv), **kw)


class ArgvTests(unittest.TestCase):
    def bad(self, argv, **over):
        with self.assertRaises(RouteUnqualified):
            check(argv, **over)

    def _idx(self, argv, flag):
        idxs = [i for i, t in enumerate(argv) if t == flag]
        self.assertEqual(len(idxs), 1)   # non-vacuous: flag present once
        return idxs[0]

    def replace_val(self, flag, value, argv=BASE):
        argv = list(argv)
        i = self._idx(argv, flag)
        self.assertNotEqual(argv[i + 1], value)   # mutation is real
        argv[i + 1] = value
        return tuple(argv)

    def drop(self, flag, argv=BASE):
        argv = list(argv)
        i = self._idx(argv, flag)
        del argv[i:i + 1 + ARITY[flag]]
        self.assertNotIn(flag, argv)               # mutation is real
        return tuple(argv)

    def test_positive_variants(self):
        self.assertIsNone(check(BASE))
        self.assertIsNone(check(FULL))
        alt = tuple('--model' if t == '-m' else t for t in BASE)
        self.assertIsNone(check(alt))
        j = list(BASE)
        j.insert(j.index('--chat-template-file'), '--jinja')
        self.assertIsNone(check(j))
        v6 = list(BASE)
        v6[v6.index('--host') + 1] = '::1'
        v6[v6.index('--port') + 1] = '9000'
        v6 += ['--cors-origins', 'http://[::1]']
        self.assertIsNone(check(v6, host='::1', port=9000))
        self.assertIsNone(check(
            self.replace_val('--alias', 'Z9._-x'), model_id='Z9._-x'))
        self.assertIsNone(check(
            self.replace_val('--alias', 'a' * 128), model_id='a' * 128))

    def test_every_required_missing(self):
        self.assertIsNone(check(BASE))
        for flag in REQUIRED:
            with self.subTest(flag=flag):
                self.bad(self.drop(flag))

    def test_every_flag_repeated(self):
        self.assertIsNone(check(FULL))
        for group in FULL_FLAGS:
            flag = group[0]
            if flag == '--model':
                continue
            dup = tuple(FULL) + (flag,) + tuple(group[1:])
            self.assertEqual(dup.count(flag), 2)
            with self.subTest(flag=flag):
                self.bad(dup)
        alt = tuple('--model' if t == '-m' else t for t in FULL)
        self.assertIsNone(check(alt))
        dup = alt + ('--model', MODEL)
        self.assertEqual(dup.count('--model'), 2)
        self.bad(dup)
        both = tuple(FULL) + ('--model', MODEL)     # -m + --model
        self.assertEqual(both.count('-m'), 1)
        self.assertEqual(both.count('--model'), 1)
        self.bad(both)

    def test_every_constrained_value_wrong(self):
        for flag, val in (('-m', '/other/m.gguf'),
                ('--chat-template-file', '/other/t.jinja'),
                ('--api-key-file', '/other/k'), ('--host', '0.0.0.0'),
                ('--port', '8001'), ('--alias', 'wrong-id'),
                ('--threads', '3'), ('--parallel', '2'),
                ('--device', 'cpu'), ('--n-gpu-layers', '1'),
                ('--reasoning', 'auto'), ('--reasoning-budget', '5'),
                ('--temp', '0.0'), ('--temp', '00'), ('--temp', '-0'),
                ('--temp', '0.1'), ('--temp', '1')):
            with self.subTest(flag=flag):
                self.bad(self.replace_val(flag, val))
        for flag, vals in (('--threads-batch', ('1', '3', 'x')),
                ('--threads-http', ('0', '17', 'x')),
                ('--ctx-size', ('0', '32769', 'x')),
                ('--reasoning-format', ('on', 'off')),
                ('--cors-origins', ('http://127.0.0.1:8000',
                                    'http://[::1]', 'x')),
                ('--timeout', ('0', '3601', 'x'))):
            for v in vals:
                with self.subTest(flag=flag, wrong=v[:8]):
                    self.bad(self.replace_val(flag, v, FULL))

    def test_optional_bounds_min_max(self):
        self.assertIsNone(check(FULL))
        for flag, v in (('--threads-http', '1'), ('--threads-http', '16'),
                        ('--ctx-size', '1'), ('--ctx-size', '32768'),
                        ('--timeout', '1'), ('--timeout', '3600')):
            with self.subTest(flag=flag, v=v):
                self.assertIsNone(check(self.replace_val(flag, v, FULL)))

    def test_integer_tokens(self):
        for v in ('08', '+2', '-2', '', ' 2', '2.0', '0x2', '２'):
            with self.subTest(v=v):
                self.bad(self.replace_val('--threads', v, FULL))
        huge = '9' * 5000
        for flag in ('--threads', '--threads-http', '--ctx-size',
                     '--timeout'):
            with self.subTest(flag=flag, kind='huge-decimal'):
                self.bad(self.replace_val(flag, huge, FULL))
        self.bad(self.replace_val('--port', '08000'))
        self.bad(self.replace_val('--port', '0'))
        self.bad(self.replace_val('--port', '65536'))

    def test_premises_fail_closed(self):
        for kw in ({'host': 'localhost'}, {'host': '10.0.0.1'},
                   {'host': ''}, {'host': None}, {'host': True},
                   {'port': 0}, {'port': 65536}, {'port': True},
                   {'port': '8000'}, {'port': None},
                   {'threads': 0}, {'threads': -1}, {'threads': True},
                   {'threads': '2'}, {'slots': 0}, {'slots': -1},
                   {'slots': None}, {'slots': False},
                   {'model_id': ''}, {'model_id': 'a,b'},
                   {'model_id': 'x' * 129}, {'model_id': None},
                   {'executable_path': '/other/exe'},
                   {'model_path': '/other/m'},
                   {'template_path': '/other/t'},
                   {'credential_file': '/other/k'}):
            with self.subTest(kw=kw):
                self.bad(FULL, **kw)

    def test_unlisted_separated_and_joined(self):
        denies = ('-a', '-dev', '-ngl', '-rea', '-tb', '-to', '-mu',
                  '-dr', '-hf', '-hfr', '-hft', '-hfd', '-hfrd', '-md',
                  '-mm', '-mmu', '--spec-draft-model', '--models-dir',
                  '--models-preset', '--models-default', '--ssl-key-file',
                  '--ssl-cert-file', '--log-file', '--webui',
                  '--ui-mcp-proxy', '--tools', '--mcp-servers-json',
                  '--agent', '--reasoning-effort',
                  '--reasoning-budget-message', '--reasoning-preserve',
                  '--chat-template', '--chat-template-kwargs',
                  '--api-key', '--cpu-mask', '--split-mode',
                  '--embedding', '--api-prefix', '--hf-repo',
                  '--hf-file', '--hf-repo-draft', '--model-url',
                  '--model-draft', '--lora', '--lora-scaled',
                  '--lora-base', '--control-vector',
                  '--control-vector-scaled', '--mmproj', '--mmproj-url',
                  '--no-jinja',
                  '--temperature', '--seed', '--top-p', '--top-k',
                  '--min-p')
        for tok in denies:
            with self.subTest(tok=tok):
                self.bad(FULL + (tok,))
                self.bad(FULL + (tok, 'x'))
            if tok.startswith('--'):
                self.bad(FULL + (tok + '=x',))

    def test_grammar_forms(self):
        self.bad(BASE + ('--model=' + MODEL,))
        self.bad(BASE + ('-m' + MODEL,))
        self.bad(BASE + ('--host=127.0.0.1',))
        self.bad(BASE + ('--threads=2',))
        self.bad(BASE + ('--temp=0',))
        self.bad(BASE + ('positional',))
        self.bad(BASE + ('--timeout',))                # missing arg
        self.bad(BASE + ('--timeout', '--threads'))    # flag as value
        self.bad(BASE + ('--jinja',))                  # after template
        self.bad(('sh',) + BASE[1:])                   # argv0 mismatch
        self.bad(())
        with self.assertRaises(RouteUnqualified):      # non-tuple argv
            validate_launch_argv(list(BASE), **KW)


if __name__ == '__main__':
    unittest.main()
