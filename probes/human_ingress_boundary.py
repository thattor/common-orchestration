"""Read-only snapshot observation and negative ingress probe; no live acceptance.

The trusted operator fetches the Issue and comment through an existing authorized
GitHub read-only connector. A JSON file cannot attest its own provenance: verify
that acquisition separately. Expected IDs are independent operator inputs, not
inferred from the snapshot. No body is parsed as an answer or emitted in reports.
Run with: python -m probes.human_ingress_boundary SNAPSHOT --repository OWNER/REPO
  --issue NUMBER --comment ID --actor ID --observed-at UTC_TIMESTAMP
Snapshot shape: {"issue": <GitHub Issue object>, "comment": <comment object>}.
"""
import argparse
import json
from pathlib import Path

from co_v4.human_gateway import HumanGateway, IssueTarget
from co_v4.state import UntrustedInput
from co_v4.waiting import utc

LIMIT = 262144


class _Forbidden:
    """Tripwire: the probe never provisions a control store or outbound handle."""
    def __init__(self):
        self.touched = False

    def __getattr__(self, name):
        self.touched = True
        raise AssertionError('probe crossed its read-only boundary')


def probe(snapshot, *, target, comment_id, actor_id, observed_at):
    """Check source bindings, then exercise real receive with isolation absent.

    This is deliberately incapable of a positive ingress result. It establishes
    neither human response authentication nor Native containment. A normal Issue
    comment suffices; do not request or manufacture a human approval to run it.
    """
    if type(comment_id) is not int or comment_id < 1:
        raise ValueError('exact comment ID required')
    if type(actor_id) is not int or actor_id < 1:
        raise ValueError('exact actor ID required')
    utc(observed_at)
    forbidden = _Forbidden()
    guard_calls = []

    def unverified_isolation(approvers):
        guard_calls.append(approvers)
        return False  # No host isolation evidence is provisioned by this probe.

    gateway = HumanGateway(forbidden, forbidden, forbidden, forbidden, forbidden,
        forbidden, target=target, approver_ids=frozenset({actor_id}),
        publisher_id=actor_id, isolation_guard=unverified_isolation,
        clock=lambda: observed_at)
    source_matches = False
    try:
        issue = snapshot['issue']
        # Read-only injection reuses production source validation without a REST
        # token, HTTP client, write method, journal, or approval receipt.
        class IssueSnapshot:
            def issue(self, requested):
                if requested != target:
                    raise AssertionError('unexpected Issue target')
                return issue
        gateway.github = IssueSnapshot()
        gateway._issue()
        comment = gateway._comment(snapshot['comment'], comment_id,
                                   user_ids=frozenset({actor_id}))
        source_matches = comment['user']['type'] == 'User'
    except (UntrustedInput, KeyError, TypeError, AttributeError):
        pass
    finally:
        gateway.github = forbidden

    blocked = False
    try:
        # No fabricated Wait, publication, response, or receipt is needed: the
        # isolation boundary must reject before any of those are accessed.
        gateway.receive(None, 'negative-probe', comment_id, expected_revision=0)
    except UntrustedInput:
        blocked = True
    if not blocked or forbidden.touched or guard_calls != [frozenset({actor_id})]:
        raise AssertionError('ingress isolation boundary did not fail closed')
    return {
        'schema': 'co.human-ingress-boundary-probe.v1',
        'source_binding': 'matched' if source_matches else 'rejected',
        'snapshot_provenance': 'requires_independent_connector_evidence',
        'ingress': 'blocked_isolation_unverified',
        'approval_created': False,
        'waiting_lifecycle': 'not_exercised',
        'live_acceptance': 'not_established',
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot', type=Path)
    parser.add_argument('--repository', required=True)
    for name in ('issue', 'comment', 'actor'):
        parser.add_argument('--' + name, required=True, type=int)
    parser.add_argument('--observed-at', required=True)
    args = parser.parse_args()
    try:
        with args.snapshot.open('rb') as source:
            raw = source.read(LIMIT + 1)
        if len(raw) > LIMIT:
            raise ValueError('snapshot too large')
        report = probe(json.loads(raw), target=IssueTarget(args.repository, args.issue),
                       comment_id=args.comment, actor_id=args.actor,
                       observed_at=args.observed_at)
    except Exception:
        # Never print snapshot bodies, filesystem paths, or provider diagnostics.
        parser.exit(2, 'Human ingress probe failed; no acceptance established.\n')
    print(json.dumps(report, sort_keys=True))
    return 0 if report['source_binding'] == 'matched' else 1


if __name__ == '__main__':
    raise SystemExit(main())
