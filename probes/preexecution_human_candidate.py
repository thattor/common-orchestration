"""Programmatic pre-execution candidate stage; no snapshot-authentication CLI.

The operator supplies a PreExecutionHumanDriver whose origin verifier and raw
GitHub fetch callback are bound to actual authorized host inputs. This helper
does not create them, manufacture a Human answer, or launch Native execution.

prepare(...) returns the durable WaitingHuman and the exact QuestionPost for
one authorized host connector publication. The person replies on GitHub. Fresh
raw GET callbacks plus driver.reconcile/receive complete the source cycle.
After restart use the existing wait and reconcile; never call prepare to resend.
An approved response still requires independent execution Judgment/HostVerifier,
exact Attempt reservation, then driver.execute with the sole lazy Native factory.
"""
from datetime import timedelta

from co_v4 import contracts as c
from co_v4.judgment import JudgmentRequest
from co_v4.state import InvalidTransition, UntrustedInput
from co_v4.waiting import timestamp, utc


def prepare(driver, *, job, action, conditions, method, request_id, context):
    """One new question using existing policy decisions and the default 24h."""
    # Host code serializes planning with the driver operations. This helper
    # does not turn Worker absence into Native execution-protection evidence.
    ref = c.QuestionRef(job.run_id, job.job_id)
    if job.run_id != driver.run_id:
        raise UntrustedInput('candidate Job belongs to another Run')
    decision = driver.judgment.judge(JudgmentRequest(ref, action, method, conditions,
                                                    proposed_job=job))
    if decision.decision is not c.Decision.NORMAL:
        raise InvalidTransition('Job containment requires its own trusted evidence')
    driver.state.add_job(job, decision.decision_id, decision.state_revision)
    decision = driver.judgment.judge(JudgmentRequest(ref, action, method, conditions))
    if decision.decision not in (c.Decision.CONFIRM, c.Decision.UNDETERMINED):
        raise InvalidTransition('current Judgment does not require a Human question')
    deadline = timestamp(utc(driver.store.now()) + timedelta(hours=24))
    wait = c.WaitingHuman(ref, request_id, action, decision.decision, decision.reason, deadline)
    driver.state.open_wait(wait, method, decision.state_revision, decision.decision_id)
    post = driver.stage_question(ref, request_id, context)
    return wait, post
