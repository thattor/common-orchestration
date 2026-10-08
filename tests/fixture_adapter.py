"""Deterministic SUT for Contract integration only; never registered for routing."""
from co_v4.contracts import (
    Action, Confirmation, ConfirmationEvent, Decision, OperationReply,
    OperationStatus, Resolution, ResumeState, Result, ResultEvent, State,
    StatusEvent, StopReply, StopStatus, TERMINAL, validate_response,
)


class FixtureAdapter:
    def __init__(self, action: Action):
        self.action = action
        self.request = None
        self.confirmation = None
        self.log = []
        self.state = State.PENDING
        self.effects = []
        self.stopping = False
        self.resume_state = None

    def _status(self, state):
        self.state = state
        self.log.append(StatusEvent(self.request.ref, str(len(self.log)), state))

    def execute(self, request):
        if self.request is not None:
            return OperationReply(request.ref, OperationStatus.INVALID_STATE, "already started")
        self.request = request
        self.resume_state = ResumeState(request.conditions.adapter, request.ref, b"fixture-secret")
        self._status(State.RUNNING)
        self.confirmation = Confirmation(request.ref, "confirmation-1", Decision.CONFIRM,
                                         self.action, "fixture requires confirmation", "fixture.native", True)
        self._status(State.WAITING_HUMAN)
        self.log.append(ConfirmationEvent(request.ref, str(len(self.log)), self.confirmation))
        return OperationReply(request.ref, OperationStatus.ACCEPTED, "started", self.resume_state)

    def _ref(self, ref):
        if self.request is None or self.request.ref != ref:
            raise ValueError("unknown attempt")

    def events(self, ref, after=None):
        self._ref(ref)
        if after is None:
            return tuple(self.log)
        for index, event in enumerate(self.log):
            if event.event_id == after:
                return tuple(self.log[index + 1:])
        raise ValueError("unknown cursor")

    def respond(self, response):
        self._ref(response.ref)
        if self.state != State.WAITING_HUMAN or self.stopping:
            return OperationReply(response.ref, OperationStatus.INVALID_STATE, "not answerable")
        validate_response(self.confirmation, response)
        if response.resolution == Resolution.ALLOW:
            self.effects.append(self.action)
            self._finish(State.COMPLETED)
        else:
            self._finish(State.FAILED, "human_rejected" if response.resolution == Resolution.DENY else "other")
        return OperationReply(response.ref, OperationStatus.ACCEPTED, "relayed")

    def _finish(self, state, reason=None):
        self._status(state)
        result = Result(self.request.ref, state, reason)
        self.log.append(ResultEvent(self.request.ref, str(len(self.log)), result))

    def resume(self, state):
        if state != self.resume_state or self.state in TERMINAL or self.stopping:
            return OperationReply(state.ref, OperationStatus.INVALID_STATE, "not resumable")
        return OperationReply(state.ref, OperationStatus.ACCEPTED, "same paused attempt", state)

    def stop(self, ref):
        self._ref(ref)
        self.stopping = True
        return StopReply(ref, StopStatus.REQUESTED, "receipt only")

    def observe_stopped(self):
        self._finish(State.FAILED, "other")
        return StopReply(self.request.ref, StopStatus.CONFIRMED, "fixture ceased", "fixture:stop-event")

    def status(self, ref):
        self._ref(ref)
        return next(event for event in reversed(self.log) if isinstance(event, StatusEvent))

    def usage(self):
        return ()
