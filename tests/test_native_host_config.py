import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from co_v4 import host_config
from co_v4.task import admission
from co_v4.task.common import TaskError

DIG = 'sha256:' + 'c' * 64
VERIFY = {'use_case': 'general', 'official_ref': 'r:o',
          'implementation_ref': 'r:i', 'measurement_ref': 'r:m',
          'ac_ref': 'r:a', 'output_mode': 'collect'}


class NativeLoadTests(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name).resolve()
        for name in ('state', 'work', 'ms'):
            (self.dir / name).mkdir(mode=0o700)
        self.state, self.cwd, self.mdir = map(str, (
            self.dir / 'state', self.dir / 'work', self.dir / 'ms'))
        self.root = self.dir / 'hostroot'
        self.root.mkdir(mode=0o700)
        self.ledger = self.root / 'capacity.db'
        self.files = {}
        for n in ('principals', 'registry', 'cred', 'manifest', 'launch'):
            p = self.dir / n
            p.write_bytes(b'x')
            p.chmod(0o600)
            self.files[n] = str(p)
        self.cfg = self.dir / 'host.json'
        self.enterContext(mock.patch.object(admission, '_host_root',
                                            lambda: self.root))

    def nroute(self, **kw):
        r = {'kind': 'native', 'model': 'm1', 'adapter': 'codex.app-server',
             'environment_ref': 'native:' + DIG, 'measurement_digest': DIG,
             'measurement_state_dir': self.mdir, 'native_cwd': self.cwd,
             'measurement_key': 'codex/m1', 'effort': 'high', 'total_s': 60,
             'max_drain_s': 3, 'max_output_bytes': 1024,
             'verification': dict(VERIFY)}
        r.update(kw)
        return r

    def wroute(self, **kw):
        r = {'model': 'm', 'adapter': 'openai.responses',
             'endpoint': 'http://127.0.0.1:8081/v1', 'auth_ref': 'cred-a',
             'credential_file': self.files['cred'],
             'manifest_file': self.files['manifest'],
             'launch_record': self.files['launch'],
             'profile': {'protocol': 'responses', 'index_mode': 'present',
                         'sequence_mode': 'present', 'inert_fields': {}},
             'profile_digest': 'sha256:' + 'a' * 64,
             'environment_ref': 'env:sha256:' + 'b' * 64,
             'store_param': 'send_false',
             'deadlines': {'connect_s': 5, 'first_byte_s': 10,
                           'idle_s': 30, 'total_s': 60},
             'max_drain_s': 20, 'verification': dict(VERIFY)}
        r.update(kw)
        return r

    def doc(self, **kw):
        d = {'schema': 'co.service-host/1', 'state_root': self.state,
             'ledger_path': str(self.ledger), 'max_body_bytes': 65536,
             'sync_wait_s': 10, 'bind': {'host': '127.0.0.1', 'port': 8080},
             'principals_file': self.files['principals'],
             'registry_file': self.files['registry'],
             'routes': [self.nroute()]}
        d.update(kw)
        return d

    def load(self, doc):
        self.cfg.write_text(json.dumps(doc))
        self.cfg.chmod(0o600)
        return host_config.load_host_config(str(self.cfg))

    def test_native_loads_creates_nothing(self):
        cfg = self.load(self.doc())
        self.assertEqual(cfg.routes[0].kind, 'native')
        self.assertFalse(self.ledger.exists())

    def test_mixed_order_and_duplicates(self):
        r2 = self.nroute(model='m2', measurement_key='codex/m2')
        cfg = self.load(self.doc(routes=[self.nroute(), self.wroute(), r2]))
        self.assertEqual([getattr(r, 'kind', 'wire') for r in cfg.routes],
                         ['native', 'wire', 'native'])
        with self.assertRaises(host_config.HostConfigInvalid):
            self.load(self.doc(routes=[self.nroute(), self.nroute()]))

    def test_ledger_pin_and_unsafe_metadata(self):
        (self.dir / 'o').mkdir()
        with self.assertRaises(host_config.HostConfigInvalid):
            self.load(self.doc(
                ledger_path=str(self.dir / 'o' / 'capacity.db')))
        self.ledger.symlink_to(self.files['cred'])
        with self.assertRaises(host_config.HostConfigInvalid):
            self.load(self.doc())
        self.ledger.unlink()
        self.ledger.write_bytes(b'x')
        self.ledger.chmod(0o644)
        with self.assertRaises(host_config.HostConfigInvalid):
            self.load(self.doc())

    def test_wire_never_resolves(self):
        m = self.enterContext(mock.patch.object(
            admission, 'canonical_ledger_path', side_effect=AssertionError))
        self.load(self.doc(routes=[self.wroute()],
                           ledger_path=str(self.dir / 'cap.db')))
        m.assert_not_called()

    def test_resolver_errors_refused(self):
        for exc in (TaskError('capacity_invalid'), ValueError('x'),
                    OSError('x')):
            with mock.patch.object(admission, 'canonical_ledger_path',
                                   side_effect=exc):
                with self.assertRaises(host_config.HostConfigInvalid):
                    self.load(self.doc())

    def test_unknown_kind_and_bad_keys(self):
        for r in (self.wroute(kind='mystery'), self.nroute(extra=1),
                  self.wroute(kind='native')):
            with self.assertRaises(host_config.HostConfigInvalid):
                self.load(self.doc(routes=[r]))
