"""Fail-closed host for an externally running, authenticated T3 Code server.

The trusted verifier must attest the pinned running server, existing project/root,
provider/model and advertised options against the exact request and profile.
It must not create grants, start servers or invoke providers. No default trust.
"""
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import select
import shutil
import subprocess
from urllib.parse import urlsplit

from .contracts import StopReply, StopStatus
from .t3code_owned import OwnedCodexBroker

from .adapters.t3code import SOURCE_REVISION
MAX_BYTES = 2 * 1024 * 1024


def _reject(*args):
    raise ValueError('trusted T3 server binding verifier required')


def _endpoint(value):
    parts = urlsplit(value)
    if (parts.scheme != 'http' or parts.hostname not in ('127.0.0.1', '[::1]', '::1')
            or parts.username is not None or parts.password is not None
            or parts.path not in ('', '/') or parts.query or parts.fragment
            or parts.port is None):
        raise ValueError('explicit loopback HTTP origin required')
    return value.rstrip('/')


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate wire key')
        result[key] = value
    return result


def _encode(value):
    raw = json.dumps(value, separators=(',', ':'), allow_nan=False).encode()
    if len(raw) > MAX_BYTES:
        raise ValueError('T3 input bound exceeded')
    return raw + b'\n'


@dataclass(frozen=True)
class T3CodeHostConfig:
    endpoint: str
    bearer_supplier: object = field(repr=False)
    verify_binding: object = field(default=_reject, repr=False)
    node_executable: str = 'node'
    timeout_seconds: float = 30.0
    owned_codex: object = field(default=None, repr=False)


class T3CodeHost:
    def __init__(self, config):
        self.config = config
        self._verified = None
        self._owned_binding = None
        _endpoint(config.endpoint)
        if config.owned_codex is not None and type(config.owned_codex) is not OwnedCodexBroker:
            raise ValueError('exclusive Native owner required')

    def verify_host(self, request, profile):
        self._verified = None
        if (profile.request != request or profile.source_revision != SOURCE_REVISION
                or profile.runtime_mode != 'approval-required'):
            raise ValueError('T3 profile binding mismatch')
        # Callback success is explicit True; absence/None never grants trust.
        if self.config.verify_binding(request, profile, self.config.endpoint) is not True:
            raise ValueError('T3 server binding not attested')
        self._verified = (request, profile)

    def open_transport(self, request, launch_payload):
        verified = self._verified
        self._verified = None
        if verified is None or verified[0] != request:
            raise ValueError('T3 host verification required')
        profile = verified[1]
        if self.config.verify_binding(request, profile, self.config.endpoint) is not True:
            raise ValueError('T3 server binding changed')
        if (launch_payload.get('projectId') != profile.project_id
                or launch_payload.get('modelSelection') != profile.model_selection()
                or launch_payload.get('runtimeMode') != profile.runtime_mode
                or launch_payload.get('interactionMode') != profile.interaction_mode
                or launch_payload.get('workspaceStrategy') != {'type': 'root'}
                or launch_payload.get('reuseExistingThread') is not False
                or launch_payload.get('generateTitle') is not False):
            raise ValueError('T3 launch differs from attested profile')
        if self.config.owned_codex is not None:
            options = {o['id']: o['value'] for o in profile.model_selection()['options']}
            self.config.owned_codex.arm(request, prompt=launch_payload['initialMessage']['text'],
                effort=options.get('reasoningEffort'), service_tier=options.get('serviceTier'))
            self._owned_binding = (request, profile, launch_payload['threadId'])
        return T3CodeTransport(self.config, launch_payload)

    def confirm_cessation(self, request, profile, thread_id, run_id, projection):
        """Only an exclusive broker's original-child receipt may confirm stop."""
        owner = self.config.owned_codex
        if owner is None or self._owned_binding != (request, profile, thread_id):
            return None
        runs = projection.get('runs', [])
        threads = projection.get('providerThreads', [])
        turns = projection.get('providerTurns', [])
        if (projection.get('thread', {}).get('id') != thread_id or len(runs) != 1
                or runs[0].get('id') != run_id or runs[0].get('threadId') != thread_id
                or runs[0].get('providerInstanceId') != profile.provider_instance_id
                or runs[0].get('modelSelection') != profile.model_selection()
                or len(threads) != 1 or len(turns) != 1
                or threads[0].get('id') != runs[0].get('providerThreadId')
                or threads[0].get('appThreadId') != thread_id
                or threads[0].get('providerInstanceId') != profile.provider_instance_id
                or turns[0].get('providerThreadId') != threads[0].get('id')
                or turns[0].get('runAttemptId') != runs[0].get('activeAttemptId')
                or turns[0].get('nodeId') != runs[0].get('rootNodeId')):
            return None
        native_thread = threads[0].get('nativeThreadRef', {})
        native_turn = turns[0].get('nativeTurnRef', {})
        if any(not isinstance(x, dict) or x.get('driver') != 'codex'
               or x.get('strength') != 'strong' or not isinstance(x.get('nativeId'), str)
               or not x['nativeId'] for x in (native_thread, native_turn)):
            return None
        proof = owner.finish(request, native_thread_id=native_thread['nativeId'],
                             native_turn_id=native_turn['nativeId'])
        if proof is None or not owner.verify_proof(proof, request):
            return None
        reason = ('owned Native forced teardown after observed result' if proof.forced else
                  'owned Native EOF and reaped exit after observed result')
        return StopReply(request.ref, StopStatus.CONFIRMED, reason, proof.evidence_ref)


class T3CodeTransport:
    """Bounded private stdio bridge. Close reaps only this owned helper."""
    def __init__(self, config, launch_payload):
        self._closed = False
        self._buffer = bytearray()
        self._total = 0
        self._ids = set()
        self._received = set()
        self._outbound = bytearray()
        self._launch = json.loads(_encode(launch_payload))
        self._launched = False
        self._thread = self._launch.get('threadId')
        if not isinstance(self._thread, str) or not self._thread:
            raise ValueError('bound launch thread required')
        endpoint = _endpoint(config.endpoint)
        if not 0 < config.timeout_seconds <= 120:
            raise ValueError('invalid T3 deadline')
        node = shutil.which(config.node_executable)
        if node is None:
            raise ValueError('Node runtime unavailable')
        bearer = config.bearer_supplier()
        if not isinstance(bearer, str) or not bearer or len(bearer) > 8192 or any(c.isspace() for c in bearer):
            raise ValueError('existing T3 bearer required')
        self.process = subprocess.Popen(
            [node, str(Path(__file__).with_name('t3code_rpc.mjs'))],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env={'PATH': os.defpath}, start_new_session=True)
        os.set_blocking(self.process.stdout.fileno(), False)
        os.set_blocking(self.process.stdin.fileno(), False)
        try:
            self._write({'endpoint': endpoint, 'bearer': bearer,
                         'timeoutMs': int(config.timeout_seconds * 1000)})
        except Exception:
            self.close()
            raise ValueError('T3 bridge initialization failed') from None

    def _write(self, value):
        data = _encode(value)
        if len(self._outbound) + len(data) > 4 * MAX_BYTES:
            raise ValueError('T3 outbound bound exceeded')
        self._outbound.extend(data)
        self._flush()

    def _flush(self):
        if self._outbound and select.select([], [self.process.stdin], [], 0)[1]:
            try:
                sent = os.write(self.process.stdin.fileno(), self._outbound)
                del self._outbound[:sent]
            except BlockingIOError:
                pass

    def send(self, message):
        if self._closed or not self.alive():
            raise ValueError('T3 bridge unavailable')
        if (not isinstance(message, dict) or set(message) != {'_tag', 'id', 'tag', 'payload', 'headers'}
                or message['_tag'] != 'Request' or message['headers'] != []
                or not isinstance(message['id'], str) or not message['id']
                or len(message['id']) > 128 or message['id'] in self._ids):
            raise ValueError('invalid T3 request envelope')
        tag, payload = message['tag'], message['payload']
        if not self._launched:
            valid = tag == 'orchestration.launchThread' and payload == self._launch
        elif tag == 'orchestration.getThreadProjection':
            valid = payload == {'threadId': self._thread}
        elif tag == 'orchestration.dispatchCommand':
            valid = (isinstance(payload, dict) and set(payload) == {'type', 'commandId', 'threadId', 'runId', 'holdQueue'}
                     and payload['type'] == 'run.interrupt' and payload['threadId'] == self._thread
                     and payload['holdQueue'] is True and all(isinstance(payload[k], str) and payload[k]
                     for k in ('commandId', 'runId')))
        else:
            valid = False
        if not valid or len(self._ids) >= 4096:
            raise ValueError('T3 request outside bound scope')
        self._write(message)
        self._ids.add(message['id'])
        self._launched = True

    def poll(self):
        frames = []
        if self._closed:
            return ()
        self._flush()
        for _ in range(64):
            if not select.select([self.process.stdout], [], [], 0)[0]:
                break
            data = os.read(self.process.stdout.fileno(), 65536)
            if not data:
                break
            self._total += len(data)
            self._buffer.extend(data)
            if self._total > 32 * MAX_BYTES or len(self._buffer) > MAX_BYTES:
                self.close()
                raise ValueError('T3 output bound exceeded')
        while b'\n' in self._buffer and len(frames) < 64:
            raw, _, rest = self._buffer.partition(b'\n')
            self._buffer = bytearray(rest)
            try:
                frame = json.loads(raw, object_pairs_hook=_pairs,
                                   parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
                if (not isinstance(frame, dict) or frame.get('_tag') != 'Exit'
                        or frame.get('requestId') not in self._ids
                        or frame.get('requestId') in self._received):
                    raise ValueError()
            except (ValueError, TypeError):
                self.close()
                raise ValueError('invalid T3 bridge output') from None
            self._received.add(frame['requestId'])
            frames.append(frame)
        return tuple(frames)

    def alive(self):
        return not self._closed and self.process.poll() is None

    def close(self):
        if self._closed:
            return
        self._closed = True
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=1)
        for stream in (self.process.stdin, self.process.stdout):
            stream.close()
        self._buffer.clear()
        self._outbound.clear()
