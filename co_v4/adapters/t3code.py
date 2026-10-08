"""Source-pinned T3 Code orchestration-v2 single-Job text adapter.

An authenticated T3 projection is a T3 result, never Native cessation evidence.
No server, provider, authentication or configuration is created by this module.
"""
from dataclasses import dataclass, field
import json
import math
import time
from uuid import uuid4
from urllib.parse import quote

from ..contracts import (CollectionError, ExecuteRequest, NeverStarted, OperationReply, OperationStatus,
    OutputItem, Result, ResultEvent, State, StatusEvent, StopReply, StopStatus)
from ..delegation import job_payload

ADAPTER = 't3code.orchestration-v2'
# Minor bump marks the co.controller/4 compatibility change; v3 baseline
# was 0.1.0-dev (runtime_v3 co_v3/adapters/t3code.py uses this constant).
# The -dev suffix honestly marks this adapter unqualified.
ADAPTER_VERSION = '0.2.0-dev'
SOURCE_REVISION = '4ee6bfd50ef4a089440d5c3662db2298da9cc50e'
MAX_BATCH = 64
MAX_FRAME = 1048576
MAX_TOTAL = 16777216
MAX_ROWS = 256
MAX_TEXT = 262144
_DIAGNOSTIC_ERRORS = frozenset({
    'invalid bounded projection', 'thread binding changed', 'unsupported control activity',
    'run identity changed', 'activity without run', 'run binding changed', 'unknown run status',
    'unexpected continuation', 'recovered provider attempt unsupported', 'unsupported execution node',
    'unsupported turn item', 'unbound message', 'changed initial message', 'unexpected message role',
    'interactive waiting unsupported', 'terminal timestamp missing', 'T3 terminal projection inconsistent',
    'invalid text output', 'unexpected RPC envelope', 'RPC did not succeed', 'invalid interrupt receipt',
    'fresh thread not established', 'invalid poll', 'frame limit or trailing activity',
    'invalid liveness', 'terminal with unresolved RPC', 'disconnected before result',
})
PROJECTION_ARRAYS = frozenset(('runs', 'attempts', 'nodes', 'subagents',
    'providerSessions', 'providerThreads', 'providerTurns', 'runtimeRequests',
    'messages', 'plans', 'turnItems', 'checkpointScopes', 'checkpoints',
    'contextHandoffs', 'contextTransfers', 'visibleTurnItems'))


def _refuse(*args):
    raise ValueError('unverified host')


def _string(value, limit=256):
    return type(value) is str and 0 < len(value.encode('utf-8')) <= limit


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate key')
        result[key] = value
    return result


def _root_preparation(row, run):
    """Pinned T3 bookkeeping, not a provider command or setup-script permit."""
    return (run.get('workspacePreparation') == {'type': 'root'}
            and _string(run.get('rootNodeId'))
            and row.get('id') == 'turn-item:provider:codex:native-item:' +
                quote('workspace-preparation:' + run['id'], safe="~()*!.'-")
            and row.get('type') == 'command_execution'
            and row.get('nodeId') == run['rootNodeId']
            and row.get('nativeItemRef') is None and row.get('providerTurnId') is None
            and row.get('parentItemId') is None
            and row.get('input') == 'Preparing workspace'
            and ((row.get('status') == 'running' and row.get('title') == 'Preparing workspace'
                  and row.get('completedAt') is None and 'output' not in row and 'exitCode' not in row)
                 or (row.get('status') == 'completed' and row.get('title') == 'Workspace ready'
                     and row.get('output', 'Workspace preparation completed.') == 'Workspace preparation completed.'
                     and type(row.get('exitCode')) is int and row['exitCode'] == 0
                     and _string(row.get('completedAt')))))


def _empty_root_checkpoint(row, run, value, workspace):
    """Accept only the root checkpoint bookkeeping of an unchanged text Job."""
    if (not _string(run.get('rootNodeId')) or not _string(row.get('checkpointId'))
            or not _string(row.get('scopeId'))):
        return False
    checkpoints = [c for c in value['checkpoints'] if c.get('id') == row.get('checkpointId')]
    scopes = [s for s in value['checkpointScopes'] if s.get('id') == row.get('scopeId')]
    if len(checkpoints) != 1 or len(scopes) != 1:
        return False
    checkpoint, scope = checkpoints[0], scopes[0]
    return (row.get('type') == 'checkpoint' and row.get('files') == []
            and row.get('id') == 'turn-item:provider:codex:native-item:' +
                quote('checkpoint:' + checkpoint['id'], safe="~()*!.'-")
            and row.get('nodeId') == run.get('rootNodeId')
            and row.get('nativeItemRef') is None and row.get('providerTurnId') is None
            and row.get('parentItemId') is None and row.get('status') == 'completed'
            and _string(row.get('completedAt'))
            and checkpoint.get('threadId') == run.get('threadId')
            and checkpoint.get('runId') == run['id']
            and checkpoint.get('nodeId') == run.get('rootNodeId')
            and checkpoint.get('scopeId') == scope['id'] and checkpoint.get('files') == []
            and checkpoint.get('status') in {'ready', 'missing'}
            and scope.get('threadId') == run.get('threadId') and scope.get('runId') == run['id']
            and scope.get('nodeId') == run.get('rootNodeId')
            and scope.get('kind') == 'root_run' and scope.get('parentScopeId') is None
            and scope.get('cwd') == workspace)


def _checkpoint_pending(run, value, workspace):
    """Pinned RunExecutionService: provider finished, root capture not committed.

    This permits another bounded projection poll, never a result or Human wait.
    Runtime requests, extra runs and unsupported activities were already rejected.
    """
    if (run.get('workspacePreparation') != {'type': 'root'} or run.get('completedAt') is not None
            or run.get('checkpointId') is not None
            or any(len(value[key]) != 1 for key in ('attempts', 'providerThreads', 'providerTurns', 'checkpointScopes'))):
        return False
    attempt, provider, turn, scope = (value[key][0] for key in
        ('attempts', 'providerThreads', 'providerTurns', 'checkpointScopes'))
    roots = [n for n in value['nodes'] if n.get('id') == run.get('rootNodeId')]
    if len(roots) != 1 or not _string(run.get('rootNodeId')):
        return False
    root = roots[0]
    if (len(value['checkpoints']) > 1 or any(c.get('files') != []
            or c.get('threadId') != run['threadId'] or c.get('runId') is not None
            or c.get('nodeId') != root['id'] or c.get('scopeId') != scope.get('id')
            or c.get('status') not in {'ready', 'missing'} for c in value['checkpoints'])):
        return False
    native_refs = (provider.get('nativeThreadRef'), turn.get('nativeTurnRef'))
    if any(type(ref) is not dict or ref.get('driver') != 'codex'
            or ref.get('strength') != 'strong' or not _string(ref.get('nativeId')) for ref in native_refs):
        return False
    return (root.get('kind') == 'root_turn' and root.get('status') == 'waiting'
        and root.get('completedAt') is None and root.get('runtimeRequestId') is None
        and root.get('checkpointScopeId') == scope.get('id') and _string(scope.get('id'))
        and scope.get('threadId') == run['threadId'] and scope.get('runId') == run['id']
        and scope.get('nodeId') == root['id'] and scope.get('kind') == 'root_run'
        and scope.get('parentScopeId') is None and scope.get('cwd') == workspace
        and attempt.get('status') == 'completed' and _string(attempt.get('completedAt'))
        and attempt.get('rootNodeId') == root['id'] and _string(attempt.get('id'))
        and run.get('activeAttemptId') == attempt['id'] and run.get('providerThreadId') == provider.get('id')
        and attempt.get('providerThreadId') == provider.get('id') and _string(provider.get('id'))
        # Pinned finalization retains the initial nullable attempt.providerTurnId;
        # the completed turn's runAttemptId below is the authoritative reverse binding.
        and attempt.get('providerTurnId') in (None, turn.get('id')) and _string(turn.get('id'))
        and provider.get('appThreadId') == run['threadId']
        and provider.get('providerInstanceId') == run['providerInstanceId']
        and provider.get('pendingBackgroundTasks', []) == [] and provider.get('handoffIds') == []
        and turn.get('providerThreadId') == provider['id'] and turn.get('nodeId') == root['id']
        and turn.get('runAttemptId') == attempt['id'] and turn.get('status') == 'completed'
        and _string(turn.get('completedAt'))
        and all(n.get('status') == 'completed' and n.get('runtimeRequestId') is None
                for n in value['nodes'] if n['id'] != root['id']))


@dataclass(frozen=True)
class T3Profile:
    """Trusted exact selection; references alone do not attest authorization.

    verify_host must bind the existing authenticated server/project root and
    provider instance/configuration, current fee policy, and advertised options
    to this request. In particular serviceTier=fast is not inferred support.
    """
    request: ExecuteRequest
    project_id: str
    provider_instance_id: str
    human_intent_ref: str
    options_json: str = '[]'
    runtime_mode: str = 'approval-required'
    interaction_mode: str = 'default'
    source_revision: str = SOURCE_REVISION
    selection_mode: str = 'explicit'
    selection_ref: str = ''

    def __post_init__(self):
        if (type(self.request) is not ExecuteRequest
                or not all(_string(x) for x in (self.project_id, self.provider_instance_id,
                                               self.human_intent_ref))
                or self.runtime_mode != 'approval-required'
                or self.interaction_mode not in ('default', 'plan')
                or self.source_revision != SOURCE_REVISION
                or self.selection_mode not in ('explicit', 'default')
                or type(self.selection_ref) is not str
                or (self.selection_ref and (len(self.selection_ref) != 64
                    or any(c not in '0123456789abcdef' for c in self.selection_ref)))
                or (self.selection_mode == 'default' and not self.selection_ref)
                or type(self.options_json) is not str or len(self.options_json) > 4096):
            raise ValueError('invalid trusted T3 profile')
        options = json.loads(self.options_json, object_pairs_hook=_pairs)
        # Known native option IDs from the pinned CodexProvider wire descriptors. Availability
        # still requires the actual model descriptor, not this static set.
        allowed = {'serviceTier': {'default', 'priority', 'fast'}, 'reasoningEffort': {
            'none', 'minimal', 'low', 'medium', 'high', 'xhigh', 'max', 'ultra'}}
        if (type(options) is not list or len(options) > 2
                or any(type(o) is not dict or set(o) != {'id', 'value'}
                    or type(o['id']) is not str or o['id'] not in allowed
                    or type(o['value']) is not str or o['value'] not in allowed[o['id']]
                    for o in options)
                or len({o['id'] for o in options}) != len(options)):
            raise ValueError('unsupported T3 model options')

    def model_selection(self):
        return {'instanceId': self.provider_instance_id,
                'model': self.request.conditions.model,
                'options': json.loads(self.options_json)}


@dataclass
class _Attempt:
    request: ExecuteRequest
    started: float
    thread: str
    message: str
    prompt: str
    transport: object = None
    events: list = field(default_factory=list)
    pending: dict = field(default_factory=dict)
    next_id: int = 1
    received: int = 0
    run: str | None = None
    launched: bool = False
    terminal: bool = False
    closed: bool = False
    text: str | None = None
    stop_sent: bool = False
    stop_ack: bool = False
    stop_failed: bool = False
    last_poll: float = float('-inf')
    projection: dict | None = None
    cessation: StopReply | None = None
    diagnostic: str | None = None


class T3CodeAdapter:
    """Nonblocking fixed Adapter Protocol over genuine T3 Effect RPC.

    transport_factory(request, launch_payload) opens a client only. The adapter
    sends RPC Requests, consumes bounded tuples of decoded RPC frames via poll,
    checks alive(), and closes only its owned client. The transport/host must
    reject duplicate JSON keys, limit raw frames and bind authorization before
    any launch send. None-returning host verification attests or raises.
    """
    def __init__(self, *, profile=None, verify_host=_refuse, transport_factory=None,
                 verify_cessation=None, clock=time.monotonic, timeout=120, poll_interval=0.25):
        if any(type(x) not in (int, float) or not math.isfinite(x)
               for x in (timeout, poll_interval)) or not 0 < timeout <= 600 or not 0 <= poll_interval <= 60:
            raise ValueError('bounded polling required')
        self._profile, self._verify, self._factory = profile, verify_host, transport_factory
        self._verify_cessation = verify_cessation
        self._clock, self._timeout, self._interval = clock, timeout, poll_interval
        self._attempts, self._closed = {}, False

    def execute(self, request):
        ref = request.ref
        if self._closed or ref in self._attempts:
            return OperationReply(ref, OperationStatus.INVALID_STATE, 'Adapter closed or Attempt used')
        try:
            if (type(self._profile) is not T3Profile or self._profile.request != request
                    or request.conditions.adapter != ADAPTER or self._factory is None
                    or not _string(request.conditions.model)
                    or not _string(request.conditions.workspace, 4096)):
                raise ValueError('unbound route')
            if self._verify(request, self._profile) is not None:
                raise ValueError('host must attest or raise')
            prompt = _json({**job_payload(request), 'delegation': {
                'human_intent_ref': self._profile.human_intent_ref,
                'run_id': ref.run_id, 'job_id': ref.job_id, 'attempt_id': ref.attempt_id,
                'workspace': request.conditions.workspace, 'capability': 't3code.text.only',
                'constraints': ['Only carry out this Job using its supplied context.',
                    'Use no tools or subagents; return the requested text.',
                    'Do not inspect credentials, change CO state or other Attempts.',
                    'Return out-of-scope needs to Controller; do not expand permissions.']}})
            if len(prompt.encode('utf-8')) > MAX_TEXT:
                raise ValueError('input limit')
        except Exception:
            return OperationReply(ref, OperationStatus.UNSUPPORTED, 'T3 host preflight refused',
                never_started=NeverStarted(request, ADAPTER + ':never-started:' + uuid4().hex))
        attempt = _Attempt(request, self._clock(), str(uuid4()), str(uuid4()), prompt)
        self._attempts[ref] = attempt  # Reserve before any transport creation.
        self._status(attempt, State.PENDING)
        launch = {'commandId': str(uuid4()), 'threadId': attempt.thread,
            'projectId': self._profile.project_id, 'title': 'CO delegated Job',
            'generateTitle': False, 'reuseExistingThread': False,
            'modelSelection': self._profile.model_selection(),
            'runtimeMode': self._profile.runtime_mode,
            'interactionMode': self._profile.interaction_mode,
            'workspaceStrategy': {'type': 'root'},
            'initialMessage': {'messageId': attempt.message, 'text': prompt, 'attachments': []}}
        try:
            # Pass a copy: the host cannot accidentally mutate the sent binding.
            attempt.transport = self._factory(request, json.loads(_json(launch)))
            self._send(attempt, 'launch', 'orchestration.launchThread', launch)
        except Exception:
            self._finish(attempt, State.ERROR, 't3_launch_or_submission_unknown')
            return OperationReply(ref, OperationStatus.ERROR, 'T3 submission outcome unknown')
        return OperationReply(ref, OperationStatus.ACCEPTED, 'T3 launch submitted; outcome unverified')

    def _send(self, attempt, kind, method, payload):
        request_id = str(attempt.next_id)
        attempt.next_id += 1
        attempt.pending[request_id] = kind
        attempt.transport.send({'_tag': 'Request', 'id': request_id, 'tag': method,
                                'payload': payload, 'headers': []})

    def _status(self, attempt, state):
        previous = next((e for e in reversed(attempt.events) if isinstance(e, StatusEvent)), None)
        if previous is None or previous.state != state:
            attempt.events.append(StatusEvent(attempt.request.ref, uuid4().hex, state))

    def _finish(self, attempt, state, reason=None):
        if attempt.terminal:
            return
        attempt.terminal = True
        if state != State.COMPLETED:
            attempt.text = None
        self._status(attempt, state)
        attempt.events.append(ResultEvent(attempt.request.ref, uuid4().hex,
            Result(attempt.request.ref, state, reason,
                   detail='T3 projection only; Native cessation unverified' if state == State.COMPLETED else '')))
        self._close(attempt)

    def _close(self, attempt):
        if not attempt.closed:
            attempt.closed = True
            if attempt.transport is not None:
                try:
                    attempt.transport.close()
                except Exception:
                    pass

    def _projection(self, attempt, value):
        if (type(value) is not dict or set(value) != PROJECTION_ARRAYS | {'thread', 'updatedAt'}
                or not _string(value['updatedAt'])
                or any(type(value[k]) is not list or len(value[k]) > MAX_ROWS
                       or any(type(row) is not dict for row in value[k]) for k in PROJECTION_ARRAYS)):
            raise ValueError('invalid bounded projection')
        thread = value['thread']
        if (type(thread) is not dict or thread.get('id') != attempt.thread
                or thread.get('projectId') != self._profile.project_id
                or thread.get('providerInstanceId') != self._profile.provider_instance_id
                or thread.get('modelSelection') != self._profile.model_selection()
                or thread.get('runtimeMode') != 'approval-required'
                or thread.get('interactionMode') != self._profile.interaction_mode
                or thread.get('worktreePath') is not None):
            raise ValueError('thread binding changed')
        # Any interactive request is unsupported, including externally resolved
        # requests: a different UI must not silently authorize this delegation.
        if any(value[k] for k in ('runtimeRequests', 'subagents', 'contextHandoffs', 'contextTransfers')):
            raise ValueError('unsupported control activity')
        runs = value['runs']
        if len(runs) > 1 or (attempt.run is not None and not runs):
            raise ValueError('run identity changed')
        if not runs:
            if any(value[k] for k in PROJECTION_ARRAYS - {'messages'}):
                raise ValueError('activity without run')
            return None
        run = runs[0]
        if (not _string(run.get('id')) or run.get('threadId') != attempt.thread
                or run.get('userMessageId') != attempt.message
                or run.get('providerInstanceId') != self._profile.provider_instance_id
                or run.get('modelSelection') != self._profile.model_selection()
                or (attempt.run is not None and attempt.run != run['id'])
                or any(k in run for k in ('restartContinuationOfRunId', 'usageLimitContinuationOfRunId',
                                         'manualContinuationOfRunId'))):
            raise ValueError('run binding changed')
        attempt.run = run['id']
        statuses = {'preparing', 'queued', 'starting', 'running', 'waiting',
                    'completed', 'interrupted', 'failed', 'cancelled', 'rolled_back'}
        state = run.get('status')
        if state not in statuses:
            raise ValueError('unknown run status')
        for row in value['attempts']:
            if (row.get('runId') != attempt.run or row.get('reason') != 'initial'
                    or row.get('providerInstanceId') != self._profile.provider_instance_id):
                raise ValueError('unexpected continuation')
        if len(value['attempts']) > 1:
            raise ValueError('recovered provider attempt unsupported')
        for row in value['nodes']:
            if (row.get('threadId') != attempt.thread or row.get('runId') != attempt.run
                    or row.get('kind') not in {'root_turn', 'assistant_message', 'reasoning', 'plan', 'todo_list'}):
                raise ValueError('unsupported execution node')
        for row in value['turnItems']:
            own_interrupt = (attempt.stop_sent and row.get('type') in
                             {'run_interrupt_request', 'run_interrupt_result'}
                             and type(row.get('message')) is str)
            if (row.get('threadId') != attempt.thread or row.get('runId') != attempt.run
                    or (not own_interrupt and not _root_preparation(row, run)
                        and not _empty_root_checkpoint(row, run, value, attempt.request.conditions.workspace)
                        and row.get('type') not in
                        {'user_message', 'assistant_message', 'reasoning', 'proposed_plan', 'todo_list'})):
                raise ValueError('unsupported turn item')
        texts, user_seen, message_ids = [], False, set()
        for row in value['messages']:
            if (not _string(row.get('id')) or row['id'] in message_ids
                    or row.get('threadId') != attempt.thread or row.get('runId') != attempt.run
                    or type(row.get('text')) is not str or len(row['text'].encode('utf-8')) > MAX_TEXT
                    or type(row.get('streaming')) is not bool or row.get('attachments') != []
                    or any(k in row for k in ('notification', 'delegatedCompletion', 'senderThreadId', 'scheduledTaskId'))):
                raise ValueError('unbound message')
            message_ids.add(row['id'])
            if row.get('role') == 'user':
                if user_seen or row['id'] != attempt.message or row['text'] != attempt.prompt or row['streaming']:
                    raise ValueError('changed initial message')
                user_seen = True
            elif row.get('role') == 'assistant':
                texts.append(row)
            else:
                raise ValueError('unexpected message role')
        if state == 'waiting':
            if (not user_seen or not texts or any(row['streaming'] for row in texts)
                    or not _checkpoint_pending(run, value, attempt.request.conditions.workspace)):
                raise ValueError('interactive waiting unsupported')
            self._status(attempt, State.RUNNING)
            return None
        if state in {'running', 'starting'}:
            self._status(attempt, State.RUNNING)
        if state in {'completed', 'interrupted', 'failed', 'cancelled', 'rolled_back'}:
            if not _string(run.get('completedAt')):
                raise ValueError('terminal timestamp missing')
            if state != 'completed':
                return (State.FAILED, 't3_run_' + state, None)
            if (not user_seen or not texts or any(row['streaming'] for row in texts)
                    or any(row.get('status') not in {'completed', 'cancelled', 'interrupted', 'failed'}
                           for key in ('nodes', 'attempts', 'providerTurns') for row in value[key])):
                raise ValueError('T3 terminal projection inconsistent')
            text = '\n'.join(row['text'] for row in texts)
            if not text or len(text.encode('utf-8')) > MAX_TEXT:
                raise ValueError('invalid text output')
            return (State.COMPLETED, None, text)
        return None

    def _frame(self, attempt, frame):
        if (type(frame) is not dict or set(frame) != {'_tag', 'requestId', 'exit'}
                or frame['_tag'] != 'Exit' or type(frame['requestId']) is not str
                or frame['requestId'] not in attempt.pending):
            raise ValueError('unexpected RPC envelope')
        kind = attempt.pending.pop(frame['requestId'])
        result = frame['exit']
        if (type(result) is not dict or set(result) != {'_tag', 'value'}
                or result['_tag'] != 'Success'):
            if kind == 'stop':
                attempt.stop_failed = True
            raise ValueError('RPC did not succeed')
        value = result['value']
        if kind == 'stop':
            if (type(value) is not dict or set(value) != {'sequence'}
                    or type(value['sequence']) is not int or value['sequence'] < 0):
                raise ValueError('invalid interrupt receipt')
            attempt.stop_ack = True
            return None
        if kind == 'launch':
            if (type(value) is not dict or set(value) != {'threadId', 'projection', 'resumed'}
                    or value['threadId'] != attempt.thread or value['resumed'] is not False):
                raise ValueError('fresh thread not established')
            attempt.launched = True
            value = value['projection']
        result = self._projection(attempt, value)
        attempt.projection = json.loads(_json(value))
        return result

    def _pump(self, attempt):
        if attempt.terminal:
            return
        if self._clock() - attempt.started >= self._timeout:
            self._finish(attempt, State.ERROR, 't3_poll_timeout_cessation_unconfirmed')
            return
        try:
            batch = attempt.transport.poll()
            if type(batch) is not tuple or len(batch) > MAX_BATCH:
                raise ValueError('invalid poll')
            candidate = None
            for frame in batch:
                size = len(_json(frame).encode('utf-8'))
                attempt.received += size
                if size > MAX_FRAME or attempt.received > MAX_TOTAL or candidate is not None:
                    raise ValueError('frame limit or trailing activity')
                candidate = self._frame(attempt, frame)
            alive = attempt.transport.alive()
            if type(alive) is not bool:
                raise ValueError('invalid liveness')
            if candidate is not None:
                if attempt.pending:
                    # A pending interrupt is not silently dropped as completed.
                    raise ValueError('terminal with unresolved RPC')
                state, reason, attempt.text = candidate
                self._finish(attempt, state, reason)
                return
            if not alive:
                raise ValueError('disconnected before result')
            if attempt.launched and not attempt.pending and self._clock() - attempt.last_poll >= self._interval:
                attempt.last_poll = self._clock()
                self._send(attempt, 'projection', 'orchestration.getThreadProjection',
                           {'threadId': attempt.thread})
        except Exception as error:
            message = str(error)
            attempt.diagnostic = message if message in _DIAGNOSTIC_ERRORS else 'unclassified protocol or transport failure'
            self._finish(attempt, State.ERROR, 't3_protocol_or_connection_unverified')

    def _get(self, ref):
        if ref not in self._attempts:
            raise ValueError('unknown Attempt')
        return self._attempts[ref]

    def diagnostic(self, ref):
        return self._get(ref).diagnostic

    def events(self, ref, after=None):
        attempt, start = self._get(ref), 0
        if after is not None:
            ids = [event.event_id for event in attempt.events]
            if after not in ids:
                raise ValueError('unknown event cursor')
            start = ids.index(after) + 1
        self._pump(attempt)
        return tuple(attempt.events[start:])

    def status(self, ref):
        attempt = self._get(ref)
        self._pump(attempt)
        return next(e for e in reversed(attempt.events) if isinstance(e, StatusEvent))

    def stop(self, ref):
        if ref not in self._attempts:
            return StopReply(ref, StopStatus.ERROR, 'unknown Attempt')
        attempt = self._get(ref)
        if attempt.cessation is not None:
            return attempt.cessation
        if (attempt.terminal and attempt.projection is not None
                and self._verify_cessation is not None):
            try:
                proof = self._verify_cessation(attempt.request, self._profile,
                    attempt.thread, attempt.run, json.loads(_json(attempt.projection)))
                if (type(proof) is StopReply and proof.ref == ref
                        and proof.status == StopStatus.CONFIRMED and _string(proof.evidence_ref, 4096)):
                    attempt.cessation = proof
                    return proof
            except Exception:
                pass  # A missing/failed owner receipt never confirms cessation.
        if attempt.terminal or attempt.closed:
            return StopReply(ref, StopStatus.UNCONFIRMED, 'T3 result/client close is not Native cessation evidence')
        if attempt.stop_ack:
            return StopReply(ref, StopStatus.REQUESTED, 'T3 acknowledged interrupt; cessation unverified')
        if attempt.stop_sent:
            return StopReply(ref, StopStatus.UNCONFIRMED, 'interrupt outcome pending; cessation unverified')
        if attempt.run is None:
            return StopReply(ref, StopStatus.UNCONFIRMED, 'no bound T3 run available to interrupt')
        attempt.stop_sent = True  # Reserve before send; never resend ambiguous interrupts.
        try:
            self._send(attempt, 'stop', 'orchestration.dispatchCommand', {
                'type': 'run.interrupt', 'commandId': str(uuid4()), 'threadId': attempt.thread,
                'runId': attempt.run, 'holdQueue': True})
        except Exception:
            attempt.stop_failed = True
            self._finish(attempt, State.ERROR, 't3_interrupt_submission_unknown')
        return StopReply(ref, StopStatus.UNCONFIRMED, 'interrupt submitted; acknowledgment and cessation unverified')

    def resume(self, state):
        if state.adapter != ADAPTER or state.ref not in self._attempts or self._get(state.ref).terminal:
            return OperationReply(state.ref, OperationStatus.INVALID_STATE, 'unknown or terminal resume identity')
        return OperationReply(state.ref, OperationStatus.UNSUPPORTED, 'same-Attempt Resume unsupported')

    def respond(self, response):
        if response.ref not in self._attempts or self._get(response.ref).terminal:
            return OperationReply(response.ref, OperationStatus.INVALID_STATE, 'unknown or terminal Attempt')
        return OperationReply(response.ref, OperationStatus.UNSUPPORTED, 'T3 Human relay unsupported')

    def usage(self):
        return ()

    def text_output(self, ref):
        attempt = self._get(ref)
        if not attempt.terminal or attempt.text is None:
            raise ValueError('successful T3 text output unavailable')
        return attempt.text

    def collect_output(self, ref):
        """Optional public collector for a verified output_mode=collect route.

        Wraps the audited private text_output: exactly one verbatim UTF-8
        text item exists only for an internally proven COMPLETED Attempt.
        Failed, stopped or unfinished Attempts keep the fixed ValueError
        refusal; an unknown ref is a CollectionError — no projection, tool,
        error or diagnostic material. Storage, digests and verdicts remain
        Controller-owned.
        """
        if ref not in self._attempts:
            raise CollectionError('attempt unavailable in this adapter instance')
        return (OutputItem(0, 'text/plain', self.text_output(ref)),)

    def close(self):
        self._closed = True
        for attempt in self._attempts.values():
            self._finish(attempt, State.ERROR, 'adapter_closed_cessation_unconfirmed')
