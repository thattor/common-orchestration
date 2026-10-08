"""Trusted one-shot AGY text host. No default authorization or settings changes."""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import stat
import subprocess
from uuid import uuid4

from .adapters.antigravity import AntigravityTextAdapter, TextProfile, payload_digest, MAX_BYTES
from .delegation import DelegatedScope, job_payload
from .antigravity_profiles import AntigravityRouteProfile, LEGACY_ROUTE, LEGACY_BINARY_SHA, LEGACY_MODEL

BINARY_SHA = LEGACY_BINARY_SHA
HOOK_SHA = '7e0d31809d25521c08a5a209c463fe5efbb3a76541957ee59d5b8b7ad0fafd46'
SKILL_SHA = '2bc797a6e9f42ce18430c4c47fa425606001cb6aa2616d858820e2ff7a9deba9'
MODEL = LEGACY_MODEL
CAPABILITY = 'antigravity.text.only'
ORCA_KEYS = ('ORCA_AGENT_HOOK_ENDPOINT', 'ORCA_AGENT_HOOK_PORT', 'ORCA_AGENT_HOOK_TOKEN', 'ORCA_PANE_KEY')


def _reject(*args):
    raise ValueError('trusted actual launch policy required')


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _json(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False)


def _ordinary(path, *, maximum=268435456):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('absolute bound source required')
    for item in (path, *path.parents):
        if item.is_symlink():
            raise ValueError('source symlink refused')
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_size > maximum:
        raise ValueError('source ownership or bounds changed')
    return _sha(path.read_bytes())


def invocation(executable, prompt, route_profile=LEGACY_ROUTE):
    if type(route_profile) is not AntigravityRouteProfile:
        raise ValueError('exact AGY route profile required')
    return (str(executable), '--mode', 'plan', '--sandbox', '--model', route_profile.model,
            '--effort', route_profile.effort, '--output-format', 'stream-json', '--print-timeout', '120s', '--print', prompt)


@dataclass(frozen=True)
class AntigravityHostConfig:
    conditions: object
    executable: Path
    delegation: DelegatedScope
    hook_source: Path
    skill_source: Path
    route_profile: AntigravityRouteProfile = LEGACY_ROUTE


class PrintTransport:
    """One argv prompt, no stdin, both pipes bounded/drained; never retries."""
    def __init__(self, argv, workspace, env):
        self.process = None
        self._streams = {}
        self._wire = bytearray()
        self._stderr_bytes = 0
        self._total = 0
        self._closed = False
        self._normal_exit = None
        self._cleanup_reaped = False
        self.process = subprocess.Popen(argv, cwd=workspace, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        self._streams = {self.process.stdout.fileno(): 'stdout', self.process.stderr.fileno(): 'stderr'}

    def poll(self):
        chunks = []
        for fd in select.select(list(self._streams), [], [], 0)[0]:
            data = os.read(fd, 65536)
            if not data:
                del self._streams[fd]
                continue
            self._total += len(data)
            if self._total > MAX_BYTES:
                raise ValueError('output bound exceeded')
            if self._streams[fd] == 'stdout':
                self._wire.extend(data)
                chunks.append(data)
            else:
                self._stderr_bytes += len(data)
        return tuple(chunks)

    def drained(self):
        return not self._streams

    def wait_owned(self):
        if not self.drained():
            return None
        self._normal_exit = self.process.poll()
        if self._normal_exit is not None:
            self.process.wait(timeout=1)
        return self._normal_exit

    def observed_terminal(self, session, result):
        if (not self.drained() or self._normal_exit != 0 or self._stderr_bytes
                or not self._wire.endswith(b'\n')):
            return False
        lines = self._wire.splitlines()
        if not lines:
            return False
        try:
            terminal = json.loads(lines[-1])
            initial = json.loads(lines[0])
            return (initial.get('event') == 'init' and initial.get('conversation_id') == session
                    and terminal == {'event': 'result', 'result': result})
        except (ValueError, TypeError):
            return False

    def structural_observation(self, request):
        """Only fixed vocabulary/types/counts on rejection; no arbitrary fields."""
        observed=[]
        for raw in self._wire.splitlines()[:256]:
            try:
                frame=json.loads(raw)
                if type(frame) is not dict:
                    raise ValueError()
            except (ValueError, TypeError):
                observed.append({'event':'invalid_json_or_shape'});continue
            event=frame.get('event')
            item={'event':event if event in ('init','step_update','result','error') else 'unknown',
                  'top_field_count':len(frame)}
            if event=='init' and type(frame.get('init')) is dict:
                info=frame['init'];known={'cwd','model','agent','tools','permission_mode','json_schema','expanded_commands'}
                item.update(known_fields=sorted(set(info)&known),unknown_field_count=len(set(info)-known),
                    model_matches=info.get('model')==request.conditions.model,
                    cwd_matches=info.get('cwd')==request.conditions.workspace,
                    tools_count=len(info['tools']) if type(info.get('tools')) is list else None,
                    permission_mode=info.get('permission_mode') if info.get('permission_mode') in ('request-review','always-proceed') else 'unknown')
            elif event=='step_update' and type(frame.get('step_update')) is dict:
                info=frame['step_update'];kind=info.get('step_type');state=info.get('state')
                item.update(step_type=kind if kind in ('user_input','agent_response','checkpoint','tool','subagent') else 'unknown',
                    state=state if state in ('ACTIVE','DONE') else 'unknown',field_count=len(info))
            elif event=='result' and type(frame.get('result')) is dict:
                info=frame['result'];status=info.get('status')
                item.update(status=status if status in ('SUCCESS','ERROR','CANCELED','INTERRUPTED','INVALID','WAITING','RUNNING') else 'unknown',
                            field_count=len(info))
            observed.append(item)
        return tuple(observed)

    def verified_wire(self):
        return bytes(self._wire)

    def facts(self):
        return {'streams_eof': self.drained(), 'normal_exit_zero': self._normal_exit == 0,
                'stderr_bytes': self._stderr_bytes, 'stream_sha256': _sha(self._wire),
                'owned_process_reaped': self._cleanup_reaped or self._normal_exit is not None}

    def close(self):
        if self._closed:
            return
        self._closed = True
        if self.process is not None:
            if self.process.poll() is None:
                os.killpg(self.process.pid, signal.SIGTERM)
                try:
                    self.process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(self.process.pid, signal.SIGKILL)
                    self.process.wait(timeout=3)
            else:
                self.process.wait(timeout=1)
            self._cleanup_reaped = True
            for stream in (self.process.stdout, self.process.stderr):
                stream.close()


class AntigravityTextHost:
    def __init__(self, config, request, *, verify_launch_policy=_reject):
        self.config, self.request, self._policy = config, request, verify_launch_policy
        if type(config.route_profile) is not AntigravityRouteProfile:
            raise ValueError('exact AGY route profile required')
        self.profile = TextProfile(request, payload_digest(request), effort=config.route_profile.effort,
            plan_expansion=config.route_profile.plan_expansion,
            native_done_lf=config.route_profile.native_done_lf)
        self._transport = None
        self._adapter = None
        self._reserved = False
        self._completed_response = None
        self.observation = {'native_handoff_verified': False, 'cessation': 'unconfirmed',
                            'requested_effort': config.route_profile.effort, 'effective_effort': 'unmeasured',
                            'native_version': config.route_profile.native_version,
                            'provider_turn_effort_verified': False, 'fast_qualified': False,
                            'requested_mode': 'plan', 'sandbox_flag': True}

    def prompt(self):
        envelope = self.config.delegation.envelope()
        envelope['workspace'] = '.'  # exact absolute binding stays exclusively host-side
        envelope['constraints'].append('Use no tools, skills, research or subagents. Return only the requested text.')
        return _json({**job_payload(self.request), 'delegation': envelope})

    def _check(self, request, profile):
        if request != self.request or profile != self.profile or self.config.conditions != request.conditions:
            raise ValueError('bound request changed')
        self.config.delegation.validate(request, CAPABILITY)
        if request.conditions.model != self.config.route_profile.model or request.conditions.adapter != CAPABILITY:
            raise ValueError('unsupported exact route')
        if _ordinary(self.config.executable) != self.config.route_profile.binary_sha256:
            raise ValueError('executable changed')
        if (_ordinary(self.config.hook_source, maximum=65536) != HOOK_SHA
                or _ordinary(self.config.skill_source, maximum=65536) != SKILL_SHA):
            raise ValueError('reviewed customization changed')
        if any(os.environ.get(key) for key in ORCA_KEYS):
            raise ValueError('Orca hook effect predicate changed')
        workspace = Path(request.conditions.workspace)
        if not workspace.is_absolute() or '..' in workspace.parts or any(p.is_symlink() for p in (workspace,*workspace.parents)):
            raise ValueError('workspace binding invalid')
        info = workspace.stat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700 or any(workspace.iterdir())):
            raise ValueError('approved empty workspace changed')
        env = dict(os.environ)
        argv = invocation(self.config.executable, self.prompt(), self.config.route_profile)
        if self._policy(request, profile, argv, frozenset(env)) is not None:
            raise ValueError('launch policy must attest or raise')
        return argv, env

    def verify(self, request, profile):
        self._check(request, profile)

    def transport(self, request, payload, profile):
        if self._reserved or payload != job_payload(self.request):
            raise ValueError('duplicate or changed submission')
        argv, env = self._check(request, profile)
        self._reserved = True
        self._transport = PrintTransport(argv, request.conditions.workspace, env)
        return self._transport

    def verify_completion(self, request, transport, session, last_step, result, profile):
        if (request != self.request or profile != self.profile or transport is not self._transport
                or type(transport) is not PrintTransport or not transport.observed_terminal(session, result)):
            raise ValueError('owned original normal terminal unverified')
        self._completed_response = result['response']
        self.observation.update(native_handoff_verified=True, cessation='confirmed',
                                conversation_sha256=_sha(session.encode()))
        return 'agy:owned-normal:' + _sha(_json({'request':payload_digest(request),
            'session':session, 'result':result, 'stream':transport.facts()['stream_sha256']}).encode())

    def make_adapter(self):
        self._adapter = AntigravityTextAdapter(profile=self.profile, verify_host=self.verify,
            transport_factory=self.transport, verify_completion=self.verify_completion, timeout=120)
        return self._adapter

    def process_facts(self):
        return self._transport.facts() if self._transport else {'owned_process_started': False}

    def verified_native_stream(self, expected_text):
        """Immutable private export only after owned success and independent body AC."""
        if (self.observation['cessation'] != 'confirmed' or self._transport is None
                or type(expected_text) is not str or self._adapter is None
                or self._adapter.text_output(self.request.ref) != expected_text):
            raise ValueError('original stream export requires verified exact text')
        return self._transport.verified_wire()

    def structural_observation(self):
        return self._transport.structural_observation(self.request) if self._transport else ()
