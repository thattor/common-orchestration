"""Manifest body binding tests for LaunchAttestor (#190 M3).

The gate hands the sealed manifest BODY (no manifest_sha256 key); the
attestor recomputes its canonical sha256 and binds the record to it.
A standalone full document is accepted only when a present declared
digest equals the recompute — null, non-hex or wrong is rejected.
Process identity is stubbed: these pin record/binding behavior only."""
import hashlib
import os
import tempfile
import unittest
from dataclasses import asdict

from co_v4.launch_attestation import (LaunchAttestor, RouteUnqualified,
                                      file_descriptor)
from co_v4.process_identity import ProcessIdentity
from co_v4.protocol_profile import canonical

ENDPOINT, AUTH, UID = 'http://127.0.0.1:8000/v1', 'env:prov', os.getuid()


class BodyBindingTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = os.path.realpath(tmp.name)
        j = lambda n: os.path.join(base, n)
        self.exe, self.model, self.tmpl, self.cred = (
            j('srv'), j('m.gguf'), j('t.jinja'), j('key'))
        for p, data in ((self.exe, b'x'), (self.model, b'y'),
                        (self.tmpl, b'z'), (self.cred, b'')):
            with open(p, 'wb') as f:
                f.write(data)
        self.argv = [self.exe, '-m', self.model,
            '--chat-template-file', self.tmpl, '--api-key-file',
            self.cred, '--host', '127.0.0.1', '--port', '8000',
            '--alias', 'co04-qwen3-06b', '--threads', '2',
            '--parallel', '1', '--device', 'none', '--n-gpu-layers',
            '0', '--reasoning', 'off', '--reasoning-budget', '0', '--temp', '0',
            '--no-webui', '--no-ui-mcp-proxy']
        self.descs = {n: file_descriptor(p) for n, p in (
            ('executable', self.exe), ('model', self.model),
            ('template', self.tmpl))}
        self.body = {'model_id': 'co04-qwen3-06b',
            'model_sha256': self.descs['model'].sha256,
            'auth': {'credential_ref': AUTH},
            'launch': {'argv': self.argv, 'threads': 2, 'slots': 1,
                'chat_template_sha256': self.descs['template'].sha256}}
        self.sha = hashlib.sha256(canonical(self.body)).hexdigest()
        self.record_path = j('launch.json')
        rec = {'schema': 'co.provider-launch/1',
               'manifest_sha256': self.sha, 'pid': os.getpid(),
               'start_time': {'sec': 1, 'usec': 2}, 'uid': UID,
               'executable': asdict(self.descs['executable']),
               'argv': self.argv,
               'model': asdict(self.descs['model']),
               'template': asdict(self.descs['template']),
               'endpoint': ENDPOINT, 'credential_ref': AUTH}
        fd = os.open(self.record_path,
                     os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'wb') as f:
            f.write(canonical(rec))
        self.attest = LaunchAttestor(self.record_path, self.cred,
                                     read_process=self._reader)

    def _reader(self, pid, uid, start_time):
        return ProcessIdentity(pid=pid, uid=uid, start_sec=1,
            start_usec=2, executable=self.exe, argv=tuple(self.argv))

    def test_sealed_body_accepted(self):
        self.assertIs(self.attest(dict(self.body), ENDPOINT, AUTH), True)

    def test_full_document_matching_declared(self):
        doc = dict(self.body, manifest_sha256=self.sha)
        self.assertIs(self.attest(doc, ENDPOINT, AUTH), True)

    def test_present_declared_wrong_rejected(self):
        for bad in (None, 'x' * 64, '0' * 64):
            doc = dict(self.body, manifest_sha256=bad)
            with self.subTest(kind=type(bad).__name__):
                with self.assertRaises(RouteUnqualified):
                    self.attest(doc, ENDPOINT, AUTH)

    def test_auth_ref_bound_to_argument_and_manifest(self):
        with self.assertRaises(RouteUnqualified):
            self.attest(dict(self.body), ENDPOINT, 'env:other')
        doc = dict(self.body, auth={'credential_ref': 'env:other'})
        with self.assertRaises(RouteUnqualified):
            self.attest(doc, ENDPOINT, AUTH)
        doc = dict(self.body)
        del doc['auth']
        with self.assertRaises(RouteUnqualified):
            self.attest(doc, ENDPOINT, AUTH)


if __name__ == '__main__':
    unittest.main()
