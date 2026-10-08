"""Explicit audit linkage and release checks, not host isolation evidence."""
from pathlib import Path
import tempfile
import unittest
from co_v4 import contracts as c
from co_v4.trace import DiagnosisTrigger, Link, PublicationBlocked, PublicationPolicy, Trace


class TraceTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.path=Path(self.tmp.name)/'trace.sqlite'
        self.allowed=True
        self.trace=Trace(self.path,PublicationPolicy(lambda value:self.allowed))
        self.ref=c.QuestionRef('r','j','a'); self.at='2026-09-28T00:00:00Z'

    def tearDown(self):
        self.trace.close(); self.tmp.cleanup()

    def test_linked_records_preserve_failed_history_result_and_ac(self):
        records=[('intent','i',{},()),('routing','route',{'selected':'fixture'},(Link('intent','i'),Link('catalog','catalog:1'),Link('usage','usage:1'))),
                 ('judgment','d',{'decision':'normal'},(Link('routing','route'),Link('approval','approval:1'))),
                 ('rejection','rejected',{'reason':'human_rejected'},(Link('human_response','answer:1'),)),
                 ('timeout','timed-out',{'reason':'human_confirmation_timeout'},(Link('waiting','q:1'),)),
                 ('result','result',{'status':'completed'},(Link('attempt','a'),Link('judgment','d'))),
                 ('ac','ac',{'verdict':'fail'},(Link('result','result'),))]
        for kind,key,summary,links in records:
            self.trace.append(key,kind,self.ref,at=self.at,summary=summary,links=links)
        self.trace.close(); self.trace=Trace(self.path,PublicationPolicy(lambda _:True))
        self.assertEqual(len(self.trace.records()),7)
        result=next(r for r in self.trace.records() if r['kind']=='result')
        self.assertEqual(result['summary']['status'],'completed')
        with self.assertRaises(ValueError): self.trace.append('result','result',self.ref,at=self.at,summary={'status':'failed'})
        self.assertEqual(len(self.trace.jsonl().splitlines()),7)

    def test_diagnosis_entry_does_not_claim_remediation(self):
        for trigger in DiagnosisTrigger:
            record=self.trace.diagnose(trigger.value,self.ref,trigger,at=self.at,
                observation='Investigate repeated waiting',links=(Link('waiting','q'),))
            self.assertEqual(record['summary']['state'],'investigation_requested')
        with self.assertRaises(ValueError):
            self.trace.diagnose('bad',self.ref,'unknown',at=self.at,observation='x',links=())

    def test_resume_credentials_pii_raw_data_never_serialized(self):
        inputs=[{'resume_state':b'opaque'}, {'raw':c.ResumeState('a',c.AttemptRef('r','j','a'),b'opaque')},
                {'credential':'value'}, {'detail':'user@example.invalid'}, {'detail':'Bearer abcd'},
                {'detail':'ghp_synthetic'}, {'detail':'token=hidden'}, {'detail':'\x1b[31m'},
                {'secret':'not-for-publication'}, {'detail':'-----BEGIN RSA PRIVATE KEY-----'}]
        for value in inputs:
            with self.assertRaises(PublicationBlocked):
                self.trace.append('bad','native',self.ref,at=self.at,summary=value)
        self.assertEqual(self.trace.records(),())

    def test_host_release_checker_is_required_and_rechecked(self):
        self.trace.append('safe','job',self.ref,at=self.at,summary={'evidence':'Readable fixture observation'})
        self.allowed=False
        with self.assertRaises(PublicationBlocked): self.trace.jsonl()
        with self.assertRaises(PublicationBlocked): self.trace.append('other','job',self.ref,at=self.at,summary={})
        with self.assertRaises(PublicationBlocked): PublicationPolicy(lambda _:1).check('arbitrary')
        with self.assertRaises(ValueError): Link('raw_secret','anything').wire()


if __name__ == '__main__': unittest.main()
