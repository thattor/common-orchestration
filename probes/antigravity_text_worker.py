"""One Root-authorized bounded AGY qualification. No default model execution.

The supplied policy is authenticated host code backed by actual current
credits/quota/context evidence, not an arbitrary JSON approval. Fixtures are
not live evidence. Controller AC/Goal uses a separate probe and original turn.
"""
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import stat
import time
from uuid import uuid4

from co_v4 import antigravity_host as host_module
from co_v4.adapters import antigravity
from co_v4 import antigravity_profiles
from co_v4.contracts import AttemptRef, ExecuteRequest, ExecutionConditions, Job, State
from co_v4.delegation import DelegatedScope

EXPECTED = 'CO_AGY_ACCEPTANCE_OK'
MODEL = host_module.MODEL
ADAPTER = antigravity.ADAPTER


def sha(data):
    return hashlib.sha256(data).hexdigest()


def durable_new(path, value):
    data = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(data); f.flush(); os.fsync(f.fileno())
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def durable_bytes(path, data):
    fd=os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(data);stream.flush();os.fsync(stream.fileno())


def source_identity():
    return {'adapter': sha(Path(antigravity.__file__).read_bytes()),
            'host': sha(Path(host_module.__file__).read_bytes()),
            'route_profiles': sha(Path(antigravity_profiles.__file__).read_bytes()),
            'probe': sha(Path(__file__).read_bytes())}


def job_for(run_id):
    return Job(run_id, 'fixed-response',
        'Your final response must be exactly the 20 UTF-8 bytes CO_AGY_ACCEPTANCE_OK. '
        'End immediately after the final K. Do not add LF, CR, spaces, Markdown, quotes or any other bytes. '
        'Use no tools, skills, research or subagents.',
        ('Exact fixed text response.', 'Verified text-only Native completion.',
         'Validated EOF and owned normal exit 0.'))


def make_request(workspace, environment_ref, *, route_profile=antigravity_profiles.LEGACY_ROUTE):
    if type(route_profile) is not antigravity_profiles.AntigravityRouteProfile:
        raise ValueError('exact AGY route profile required')
    ref = AttemptRef('agy-' + uuid4().hex, 'fixed-response', 'one')
    return ExecuteRequest(ref, job_for(ref.run_id),
        ExecutionConditions(route_profile.model, ADAPTER, str(workspace), environment_ref))


def run(output, request, config, *, verify_launch_policy):
    """One live submission only when Root supplies genuine exact launch evidence.

    output is a new private host directory outside the existing approved Native
    cwd; never creates another worker folder or asks for another Trust grant.
    """
    output = Path(output)
    workspace = Path(request.conditions.workspace)
    if (not output.is_absolute() or '..' in output.parts
            or any(p.is_symlink() for p in (output.parent,*output.parent.parents))
            or output == workspace or workspace in output.parents
            or not callable(verify_launch_policy)
            or request.job != job_for(request.ref.run_id)):
        raise ValueError('bound fresh private output and exact Job required')
    output.mkdir(mode=0o700, exist_ok=False)
    source = source_identity()
    host = host_module.AntigravityTextHost(config, request, verify_launch_policy=verify_launch_policy)
    # Preflight does not dispatch. Claim remains even after ambiguous launch.
    host.verify(request, host.profile)
    durable_new(output/'submission-claim.json', {'attempt': asdict(request.ref),
        'payload_sha256': antigravity.payload_digest(request), 'source':source,
        'expected_sha256':sha(EXPECTED.encode()), 'automatic_retry':False})
    adapter = host.make_adapter()
    report = {'schema':'co.agy.text-qualification.v1','source':source,
              'model':request.conditions.model,'requested_effort':config.route_profile.effort,
              'native_version':config.route_profile.native_version,
              'native_executable_sha256':config.route_profile.binary_sha256,
              'provider_turn_effort_verified':False,'fast_qualified':False,
              'effective_effort':'unmeasured',
              'attempt':asdict(request.ref),'controller_exercised':False,
              'catalog_promoted':False,'production_installed':False,
              'ac_passed':False,'automatic_retry':False}
    try:
        reply=adapter.execute(request)
        report['operation']=reply.status.value
        if reply.never_started is not None:
            report['never_started']=True
        else:
            deadline=time.monotonic()+125
            while time.monotonic()<deadline:
                current=adapter.status(request.ref)
                if current.state in (State.COMPLETED,State.ERROR,State.FAILED):
                    break
                time.sleep(.01)
            else:
                adapter.stop(request.ref)
            current=adapter.status(request.ref)
            report['result_state']=current.state.value
            if current.state==State.COMPLETED:
                actual=adapter.text_output(request.ref).encode()
                report.update(actual_sha256=sha(actual),actual_bytes=len(actual),
                              ac_passed=actual==EXPECTED.encode())
            report['stop_status']=adapter.stop(request.ref).status.value
            report['diagnostic']=adapter.diagnostic(request.ref)
    finally:
        adapter.close()
        report['host_observation']=host.observation
        report['process']=host.process_facts()
        report['source_unchanged']=source_identity()==source
        report['structural_observation']=host.structural_observation()
        if report['ac_passed']:
            wire=host.verified_native_stream(EXPECTED)
            durable_bytes(output/'verified-native.ndjson',wire)
            report['verified_native_sha256']=sha(wire)
        report['accepted']=(report['ac_passed'] and report['source_unchanged']
            and report.get('stop_status')=='confirmed'
            and report['process'].get('normal_exit_zero') is True)
        durable_new(output/'report.json',report)
    return report
