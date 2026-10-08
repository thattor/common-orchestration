"""Explicit, sanitized audit records. Never serialize arbitrary state or Native data.

Construct in the protected host. The release checker must classify each complete
outbound value; regexes are only defense in depth, not a PII classifier. Records
contain readable evidence and typed links, not just unrecoverable digests.
"""
from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import math
import re
import sqlite3
from typing import Callable


class PublicationBlocked(Exception):
    """A fixed message deliberately excludes the rejected input."""


def canonical(value) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'), allow_nan=False)


def digest(value) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


class PublicationPolicy:
    def __init__(self, release_check: Callable[[object], bool]):
        self._release_check = release_check

    @staticmethod
    def check_content(value):
        """Structural/secret screening only; this grants no publication clearance."""
        # Byte/blob/opaque objects are unsupported even if a host checker errs.
        def visit(obj):
            if obj is None or type(obj) in (bool, int):
                return
            if type(obj) is float and math.isfinite(obj):
                return
            if type(obj) is str:
                if len(obj) > 32000 or re.search(
                    r'(?i)(-----BEGIN .*PRIVATE KEY|\b(?:gh[pousr]_[A-Za-z0-9]+|github_pat_[A-Za-z0-9_]+)|'
                    r'\bBearer\s+\S+|\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}|'
                    r'(?:password|secret|token|authorization|resume[_ -]?(?:state|opaque))\s*[:=])', obj):
                    raise PublicationBlocked('publication requires safe content')
                if any(ord(ch) < 32 and ch not in '\n\t' for ch in obj):
                    raise PublicationBlocked('publication contains control characters')
                return
            if type(obj) in (list, tuple):
                for child in obj: visit(child)
                return
            if type(obj) is dict and all(type(key) is str for key in obj):
                for key, child in obj.items():
                    if re.search(r'(?i)(secret|password|credential|opaque|resume|token|authorization)', key):
                        raise PublicationBlocked('sensitive field cannot be published')
                    visit(key); visit(child)
                return
            raise PublicationBlocked('unsupported publication type')
        visit(value)
        return value

    def check(self, value):
        self.check_content(value)
        try:
            allowed = self._release_check(value) is True
        except Exception:
            allowed = False
        if not allowed:
            raise PublicationBlocked('trusted publication clearance required')
        return value


KINDS = frozenset({'intent', 'run', 'job', 'attempt', 'routing', 'catalog', 'usage',
    'judgment', 'human_response', 'approval', 'rejection', 'timeout', 'waiting',
    'result', 'ac', 'native', 'notification', 'diagnosis', 'instruction', 'stop'})


@dataclass(frozen=True)
class Link:
    kind: str
    record_id: str

    def wire(self):
        if self.kind not in KINDS or not self.record_id:
            raise ValueError('typed audit reference required')
        return {'kind': self.kind, 'record_id': self.record_id}


class DiagnosisTrigger(str, Enum):
    DAILY_BRIEFING = 'daily_briefing'
    CONTROLLER = 'controller'
    HUMAN = 'human'
    CHANGE_VALIDATION_FAILED = 'change_validation_failed'


class Trace:
    """Append-only SQLite records, exportable as JSONL; trusted writer only.

    Links address retained records in this trace or canonical stores. The host
    must retain those stores and provide the corresponding read resolver. File
    placement and this Python interface alone do not prove Worker isolation.
    """
    def __init__(self, path, policy: PublicationPolicy):
        self._db = sqlite3.connect(path, isolation_level=None)
        self._db.execute('CREATE TABLE IF NOT EXISTS trace (id TEXT PRIMARY KEY, body TEXT NOT NULL)')
        self.policy = policy

    def close(self):
        self._db.close()

    def append(self, record_id: str, kind: str, ref, *, at: str,
               summary: dict, links: tuple[Link, ...] = ()) -> dict:
        if kind not in KINDS or not record_id:
            raise ValueError('typed audit record required')
        record = {'record_id': record_id, 'kind': kind, 'at': at,
                  'run_id': ref.run_id, 'job_id': ref.job_id,
                  'attempt_id': ref.attempt_id, 'summary': summary,
                  'links': [link.wire() for link in links]}
        encoded = canonical(self.policy.check(record))
        self._db.execute('BEGIN IMMEDIATE')
        try:
            previous = self._db.execute('SELECT body FROM trace WHERE id=?', (record_id,)).fetchone()
            if previous and previous[0] != encoded:
                raise ValueError('audit identity already has different content')
            self._db.execute('INSERT OR IGNORE INTO trace VALUES (?,?)', (record_id, encoded))
            self._db.execute('COMMIT')
        except BaseException:
            self._db.execute('ROLLBACK')
            raise
        return json.loads(encoded)

    def records(self) -> tuple[dict, ...]:
        return tuple(json.loads(row[0]) for row in self._db.execute('SELECT body FROM trace ORDER BY rowid'))

    def jsonl(self) -> str:
        # Recheck clearance when exporting, including changes to release policy.
        return ''.join(canonical(self.policy.check(record)) + '\n' for record in self.records())

    def diagnose(self, record_id, ref, trigger: DiagnosisTrigger, *, at, observation, links):
        if type(trigger) is not DiagnosisTrigger or not links:
            raise ValueError('diagnosis requires a trigger and retained evidence')
        return self.append(record_id, 'diagnosis', ref, at=at,
            summary={'trigger': trigger.value, 'observation': observation,
                     'state': 'investigation_requested'}, links=links)

    def record_result(self, record_id, result, *, at, links):
        """Project a retained Result without Native raw output or free-text detail."""
        return self.append(record_id, 'result', result.ref, at=at,
            summary={'status': result.status.value, 'reason': result.reason,
                     'artifact_refs': list(result.artifact_refs)}, links=links)

    def record_ac(self, record_id, ac, *, at, result_ref):
        return self.append(record_id, 'ac', ac.ref, at=at,
            summary={'verdict': ac.verdict, 'evidence_refs': list(ac.evidence_refs)},
            links=(Link('result', result_ref),))

    def record_judgment(self, judgment, *, at, links):
        from .contracts import approval_target
        return self.append(judgment.decision_id, 'judgment', judgment.ref, at=at,
            summary={'decision': judgment.decision.value, 'reason': judgment.reason,
                     'target': approval_target(judgment.ref.run_id, judgment.action),
                     'evidence_refs': list(judgment.evidence_refs),
                     'state_revision': judgment.state_revision}, links=links)

    def record_routing(self, routing):
        """Project a retained Controller routing record, including after restart.

        State owns the canonical evidence. Publication still requires this
        Trace's trusted release checker; local retention never grants clearance.
        The same retained record can be projected again idempotently.
        """
        summary = json.loads(routing.summary_json)
        summary['state_revision'] = routing.state_revision
        links = [Link('job', routing.ref.job_id)]
        links.extend(Link('judgment', option['judgment_ref'])
                     for option in summary['assessments'])
        if routing.execution_decision_ref is not None:
            summary['execution_judgment_ref'] = routing.execution_decision_ref
            links.append(Link('judgment', routing.execution_decision_ref))
        if routing.ref.attempt_id is not None:
            links.append(Link('attempt', routing.ref.attempt_id))
        return self.append(routing.record_id, 'routing', routing.ref,
                           at=routing.at, summary=summary, links=tuple(links))
