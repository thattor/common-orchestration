"""Explicit live, one-Job T3/Codex acceptance probe; never part of offline CI.

Requires an already prepared pinned official source, Node24, and an existing
Codex ChatGPT login. Creates only task-local T3 configuration/session/project.
No installation, provider login, fee change, or global settings mutation.
"""
import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import select
import secrets
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from co_v4.adapters.t3code import ADAPTER, T3CodeAdapter, T3Profile
from co_v4.codex_host import OVERRIDES
from co_v4.contracts import AttemptRef, ExecuteRequest, ExecutionConditions, Job, ResultEvent
from co_v4.t3code_host import SOURCE_REVISION, T3CodeHost, T3CodeHostConfig
from co_v4.t3code_owned import OwnedCodexBroker
from co_v4.t3code_selection import advertised_models, resolve_selection

MAX_BYTES = 2 * 1024 * 1024
CONFIG_SCRIPT = r'''
let raw='';for await(const chunk of process.stdin){raw+=chunk;if(raw.length>16384)throw Error('input bound');}
const {origin,token}=JSON.parse(raw);
const response=await fetch(origin+'/api/auth/websocket-ticket',{method:'POST',headers:{Authorization:'Bearer '+token},signal:AbortSignal.timeout(10000)});
if(!response.ok)throw Error('ticket refused');const {ticket}=await response.json();
const socket=new WebSocket(origin.replace('http:','ws:')+'/ws?orchestrationProtocol=2&wsTicket='+encodeURIComponent(ticket));
const deadline=setTimeout(()=>process.exit(2),45000);
socket.addEventListener('open',()=>socket.send(JSON.stringify({_tag:'Request',id:'1',tag:'server.getConfig',payload:{},headers:[]})));
socket.addEventListener('message',event=>{
 if(event.data.length>2097152)process.exit(3);
 const items=JSON.parse(event.data);
 for(const m of Array.isArray(items)?items:[items]){
  if(m._tag==='Ping'){socket.send(JSON.stringify({_tag:'Pong'}));continue;}
  if(m._tag==='Exit'&&m.requestId==='1'){
   if(m.exit?._tag!=='Success')process.exit(4);
   const c=m.exit.value;for(const p of c.providers)p.auth={status:p.auth.status,type:p.auth.type};
   clearTimeout(deadline);socket.close();process.stdout.write(JSON.stringify(c),()=>process.exit(0));
  }
 }
});
'''


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def source_verified(source):
    return (subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip() == SOURCE_REVISION
            and not subprocess.check_output(['git', '-C', str(source), 'status', '--porcelain'], text=True).strip())


def inherited_control_names(native, argv, env, workspace):
    """Project only control names from config/read; never retain setting values."""
    process = subprocess.Popen([str(native), *argv], cwd=workspace, env=env,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True)
    buffer = b''
    def rpc(identifier, method, params):
        nonlocal buffer
        process.stdin.write((json.dumps({'id': identifier, 'method': method, 'params': params}) + '\n').encode())
        process.stdin.flush()
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if b'\n' in buffer:
                line, buffer = buffer.split(b'\n', 1)
                message = json.loads(line)
                if message.get('id') == identifier:
                    if 'error' in message:
                        raise ValueError('Native metadata refused')
                    return message['result']
            elif select.select([process.stdout], [], [], .1)[0]:
                raw = os.read(process.stdout.fileno(), 65536)
                if not raw:
                    raise ValueError('Native metadata EOF')
                buffer += raw
                if len(buffer) > MAX_BYTES:
                    raise ValueError('Native metadata bound')
        raise ValueError('Native metadata deadline')
    try:
        rpc(1, 'initialize', {'clientInfo': {'name': 'co-t3-readiness', 'version': '0.1'},
                             'capabilities': {'experimentalApi': True}})
        process.stdin.write(b'{"method":"initialized"}\n')
        process.stdin.flush()
        config = rpc(2, 'config/read', {'cwd': str(workspace), 'includeLayers': False})['config']
        entries = config.get('mcp_servers')
        entries = {} if entries is None else entries
        if not isinstance(entries, dict) or len(entries) > 64:
            raise ValueError('Native MCP metadata shape')
        names = sorted(entries)
        if any(not re.fullmatch(r'[A-Za-z0-9_-]+', name) for name in names):
            raise ValueError('Native MCP identifier unsupported')
        return names, cleared_environment_keys(config)
    finally:
        process.stdin.close()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.terminate()
            process.wait(timeout=10)
        process.stdout.close()


def cleared_environment_keys(config):
    policy = config.get('shell_environment_policy')
    if not isinstance(policy, dict):
        raise ValueError('Native shell environment metadata shape')
    values = policy.get('set')
    values = {} if values is None else values
    if not isinstance(values, dict) or len(values) > 64:
        raise ValueError('Native shell environment metadata shape')
    names = tuple(sorted(values))
    if any(not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,127}', name) for name in names):
        raise ValueError('Native environment identifier unsupported')
    return names


def projection_facts(value):
    """Fixed vocabulary and hashes only; never retain message/config/auth values."""
    vocab = {'preparing', 'queued', 'starting', 'running', 'waiting', 'completed',
        'interrupted', 'failed', 'cancelled', 'rolled_back', 'pending', 'ready', 'missing',
        'root_turn', 'assistant_message', 'reasoning', 'plan', 'todo_list', 'user_message',
        'checkpoint', 'command_execution', 'proposed_plan', 'user', 'assistant'}
    def label(value):
        return value if type(value) is str and value in vocab else 'other:' + type(value).__name__
    facts = {}
    if type(value) is not dict:
        return {'value_type': type(value).__name__}
    for key in ('runs', 'nodes', 'attempts', 'providerTurns', 'turnItems', 'checkpoints'):
        rows = value.get(key)
        if type(rows) is list:
            facts[key] = [{name: label(row.get(name)) for name in ('status', 'type', 'kind') if name in row}
                for row in rows[:256] if type(row) is dict]
    rows = value.get('messages')
    if type(rows) is list:
        facts['messages'] = [{'role': label(row.get('role')), 'streaming': row.get('streaming') is True,
            'text_bytes': len(row['text'].encode()) if type(row.get('text')) is str else None,
            'text_sha256': hashlib.sha256(row['text'].encode()).hexdigest() if type(row.get('text')) is str else None}
            for row in rows[:256] if type(row) is dict]
    return facts


def metadata_complete(report):
    """Listing is not qualification; require cleanup and zero admitted turns."""
    children = report.get('owner', {}).get('children', [])
    return (report.get('metadata_only') is True and not report.get('error_type')
        and report.get('server_reaped') is True and report.get('local_service_auth_state_deleted') is True
        and report.get('owner', {}).get('closed') is True and not report['owner'].get('failed')
        and bool(children) and all(c.get('native_turn_id') is None
            and c.get('exit_code') == 0 and c.get('forced') is False
            and c.get('failed') is False and c.get('escaped_group') is False
            and all(c.get(k) is True for k in ('stdout_eof', 'stderr_eof', 'reaped', 'done'))
            for c in children))


def stop_server(server):
    if server.poll() is None:
        os.killpg(server.pid, signal.SIGTERM)
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(server.pid, signal.SIGKILL)
            server.wait(timeout=5)


def run(args):
    with ExitStack() as cleanup:
        return _run(args, cleanup)


def _run(args, cleanup):
    source, root = args.source.resolve(strict=True), args.task_root.resolve()
    native, node, codex_home = (p.resolve(strict=True) for p in (args.native, args.node, args.codex_home))
    if root.exists() or len(os.fsencode(root / 'owner/owner.sock')) > 100:
        raise ValueError('new short task root required')
    if not source_verified(source) or not (source / 'node_modules').is_dir():
        raise ValueError('clean pinned source and prepared dependencies required')
    version = subprocess.check_output([str(node), '--version'], text=True).strip()
    match = re.fullmatch(r'v(\d+)\.(\d+)\.(\d+)', version)
    if not match or int(match[1]) != 24 or tuple(map(int, match.groups())) < (24, 13, 1):
        raise ValueError('Node24 >=24.13.1 required')
    if not (codex_home / 'auth.json').is_file():
        raise ValueError('existing Codex auth required; this probe cannot log in')
    os.umask(0o077)
    root.mkdir(mode=0o700)
    workspace, state, evidence = root / 'worker', root / 'state/userdata', root / 'evidence'
    for path in (workspace, state, evidence):
        path.mkdir(parents=True, mode=0o700)
    env = {'HOME': str(Path.home()), 'CODEX_HOME': str(codex_home), 'PATH': os.pathsep.join(
        (str(node.parent), str(native.parent), '/usr/bin', '/bin')), 'LANG': 'en_US.UTF-8',
        'TMPDIR': str(workspace), 'T3CODE_TELEMETRY_ENABLED': 'false',
        'T3CODE_AUTO_BOOTSTRAP_PROJECT_FROM_CWD': 'false'}
    overrides = (*OVERRIDES, 'features.remote_control=false', 'features.shell_snapshot=false')
    argv = ['app-server', *(part for value in overrides for part in ('-c', value))]
    names, cleared_keys = inherited_control_names(native, argv, env, workspace)
    argv.extend(part for name in names for part in ('-c', f'mcp_servers.{name}.enabled=false'))
    argv.extend(part for name in cleared_keys for part in ('-c', f'shell_environment_policy.set.{name}=""'))
    reservation = socket.socket()
    reservation.bind(('127.0.0.1', 0))
    port = reservation.getsockname()[1]
    reservation.close()  # A bind race fails; never attach to another server.
    cleanup.callback(shutil.rmtree, state, ignore_errors=True)
    owner = OwnedCodexBroker(root / 'owner', executable=native, argv_allowlist=[argv, ['--version']], env=env, cwd=workspace, t3_mcp_url=f'http://127.0.0.1:{port}/mcp', cleared_environment_keys=cleared_keys, disabled_mcp_servers=tuple(names))
    cleanup.callback(owner.close)
    providers = {name: {'enabled': False} for name in ('claudeAgent', 'cursor', 'grok', 'pi', 'opencode', 'antigravity')}
    providers['codex'] = {'enabled': True, 'setupMode': 'existing', 'binaryPath': str(owner.wrapper_path),
        'homePath': str(codex_home), 'shadowHomePath': '', 'launchArgs': shlex.join(argv[1:])}
    settings = state / 'settings.json'
    settings.write_text(json.dumps({'providers': providers, 'enableAgentBrowserAccess': False,
        'enableAgentDeviceAccess': False, 'enableDeviceSupport': False}))
    settings_hash = digest(settings)
    origin, bootstrap, token = f'http://127.0.0.1:{port}', secrets.token_urlsafe(32), ''
    read_fd, write_fd = os.pipe()
    server = subprocess.Popen([str(node), str(source / 'apps/server/src/bin.ts'), 'start',
        '--bootstrap-fd', str(read_fd), '--log-level', 'debug'], cwd=workspace, env=env,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        pass_fds=(read_fd,), start_new_session=True)
    cleanup.callback(stop_server, server)
    os.close(read_fd)
    with os.fdopen(write_fd, 'w') as pipe:
        json.dump({'mode': 'desktop', 'noBrowser': True, 'port': port, 't3Home': str(root / 'state'),
            'host': '127.0.0.1', 'desktopBootstrapToken': bootstrap,
            'tailscaleServeEnabled': False, 'tailscaleServePort': 443}, pipe)
    ready = threading.Event()
    server_output_hash = hashlib.sha256()
    server_output_bytes = 0
    def logs():
        nonlocal server_output_bytes
        for raw in iter(server.stdout.readline, b''):
            server_output_hash.update(raw)
            server_output_bytes += len(raw)
            # Keep no raw server logs: they may contain ephemeral local grants.
            if b'startup phase: complete' in raw:
                ready.set()
    reader = threading.Thread(target=logs, daemon=True)
    reader.start()
    implementation = {name: digest(Path(__file__).resolve().parents[1] / name) for name in
        ('co_v4/adapters/t3code.py', 'co_v4/t3code_host.py', 'co_v4/t3code_owned.py', 'co_v4/t3code_rpc.mjs', 'co_v4/t3code_selection.py')}
    descriptor = {'schema': 'co.t3-owned-text-environment.v1', 'source_revision': SOURCE_REVISION,
        'source_path_sha256': hashlib.sha256(str(source).encode()).hexdigest(),
        'source_lock_sha256': digest(source / 'pnpm-lock.yaml'), 'native_sha256': digest(native),
        'node_version': version, 'implementation': implementation, 'model': args.model,
        'effort': args.effort, 'service_tier': 'default', 'runtime_mode': 'approval-required',
        'native_approval': 'untrusted', 'native_sandbox': 'readOnly', 'native_argv': argv,
        'cleared_environment_keys': list(cleared_keys), 'disabled_mcp_servers': list(names),
        'codex_home_path_sha256': hashlib.sha256(str(codex_home).encode()).hexdigest(),
        'workspace_policy': 'new-owned-private-empty-root-bound-before-turn',
        'endpoint_policy': 'owned-ephemeral-loopback-exact-mcp-url',
        'provider_auth': 'existing-chatgpt', 't3_agent_browser_access': False,
        't3_agent_device_access': False, 't3_device_support': False, 'uid': os.getuid(),
        'system': platform.system(), 'release': platform.release(), 'machine': platform.machine()}
    environment_ref = 't3-owned-environment:sha256:' + hashlib.sha256(
        json.dumps(descriptor, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    report = {'environment_ref': environment_ref, 'environment_descriptor': descriptor,
        'probe_sha256': digest(__file__), 'format': 1, 'source_revision': SOURCE_REVISION, 'node_version': version,
        'source_lock_sha256': digest(source / 'pnpm-lock.yaml'), 'native_sha256': digest(native),
        'settings_sha256': settings_hash, 'inherited_mcp_disabled_count': len(names),
        'cleared_environment_keys': cleared_keys,
        'telemetry_enabled': False, 'api_key_environment_present': False,
        'provider_auth_created': False, 'local_service_auth_created': True}
    def http(path, data=None, method='POST'):
        headers = {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json', 'x-t3-orchestration-protocol': '2'}
        request = urllib.request.Request(origin + path, None if data is None else json.dumps(data).encode(), headers, method=method)
        with urllib.request.urlopen(request, timeout=15) as response:
            raw = response.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError('HTTP metadata bound')
        return json.loads(raw)
    def get_config():
        response = subprocess.run([str(node), '--input-type=module', '-e', CONFIG_SCRIPT],
            input=json.dumps({'origin': origin, 'token': token}), capture_output=True,
            text=True, timeout=50, env=env, check=True)
        if len(response.stdout.encode()) > MAX_BYTES:
            raise ValueError('config bound')
        return json.loads(response.stdout)
    adapter = None
    try:
        if not ready.wait(60) or server.poll() is not None:
            raise ValueError('T3 startup failed')
        form = urllib.parse.urlencode({'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
            'subject_token': bootstrap, 'subject_token_type': 'urn:t3:params:oauth:token-type:environment-bootstrap',
            'requested_token_type': 'urn:ietf:params:oauth:token-type:access_token'}).encode()
        with urllib.request.urlopen(urllib.request.Request(origin + '/oauth/token', form), timeout=10) as response:
            token = json.load(response)['access_token']
        for _ in range(15):
            config = get_config()
            provider = next(p for p in config['providers'] if p['instanceId'] == 'codex')
            if provider['status'] == 'ready' and provider['auth']['status'] == 'authenticated':
                break
            time.sleep(1)
        if provider['status'] != 'ready' or provider['auth'].get('type') != 'chatgpt':
            raise ValueError('existing ChatGPT subscription unverified')
        report['advertised_models'] = advertised_models(config, 'codex')
        if getattr(args, 'list_models', False):
            report.update(metadata_only=True, scope='T3 model advertisement only; no turn or qualification')
            return report
        resolved = resolve_selection(config, mode=getattr(args, 'selection_mode', 'explicit'),
            model=args.model, effort=args.effort)
        descriptor.update(model=resolved.model, effort=resolved.effort, selection=resolved.descriptor())
        environment_ref = 't3-owned-environment:sha256:' + hashlib.sha256(
            json.dumps(descriptor, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        report.update(environment_ref=environment_ref, resolved_selection=resolved.descriptor())
        project = str(uuid4())
        http('/api/projects/mutate', {'type': 'project.create', 'commandId': str(uuid4()),
            'projectId': project, 'title': 'CO owned Native verification', 'workspaceRoot': str(workspace)})
        ref = AttemptRef(str(uuid4()), 'bounded-text', 'one')
        request = ExecuteRequest(ref, Job(ref.run_id, ref.job_id,
            'Return exactly T3_NATIVE_OK. Do not call tools, delegate, access files or network, or change anything.',
            ('exact response T3_NATIVE_OK', 'exact Native model and effective controls', 'original Native EOF/reap and cessation'), '{}'), ExecutionConditions(resolved.model, ADAPTER, str(workspace), environment_ref, ('owned-broker:mandatory-before-first-turn',)))
        profile = resolved.profile(request, project, getattr(args, 'authorization_ref', None)
                or 'explicit-live-acceptance-invocation')
        def admission():
            current = get_config()
            candidates = current['providers']
            codex = next(p for p in candidates if p['instanceId'] == 'codex')
            if (server.poll() is not None
                    or digest(settings) != settings_hash or not source_verified(source)
                    or codex['status'] != 'ready' or not codex['enabled'] or codex['driver'] != 'codex'
                    or codex['auth']['status'] != 'authenticated' or codex['auth'].get('type') != 'chatgpt'
                    or any(p['enabled'] for p in candidates if p['driver'] != 'codex')
                    or any(current['settings'][key] is not False for key in
                        ('enableAgentBrowserAccess', 'enableAgentDeviceAccess', 'enableDeviceSupport'))
                    or any(current['observability'][key] for key in ('otlpTracesEnabled', 'otlpMetricsEnabled', 'otlpLogsEnabled'))
                    or current['settings']['providers']['codex'] != config['settings']['providers']['codex']):
                return False
            try:
                resolved.verify_current(current)
            except ValueError:
                return False
            projects = http('/api/projects', method='GET')
            return any(p['id'] == project and p['workspaceRoot'] == str(workspace) for p in projects['projects'])
        def make_adapter(execution):
            nonlocal request, profile, adapter
            request = execution
            profile = resolved.profile(request, project, getattr(args, 'authorization_ref', None)
                or 'explicit-live-acceptance-invocation')
            def verify(req, selection, endpoint):
                return req == request and selection == profile and endpoint == origin and admission()
            host = T3CodeHost(T3CodeHostConfig(origin, lambda: token, verify,
                node_executable=str(node), timeout_seconds=45, owned_codex=owner))
            class ObservedAdapter(T3CodeAdapter):
                def _projection(self, attempt, value):
                    report['projection_facts'] = projection_facts(value)
                    result = super()._projection(attempt, value)
                    if result is None and any(r.get('status') == 'waiting' for r in value.get('runs', [])):
                        report['checkpoint_pending_polls'] = report.get('checkpoint_pending_polls', 0) + 1
                    return result
            adapter = ObservedAdapter(profile=profile, verify_host=host.verify_host,
                transport_factory=host.open_transport, verify_cessation=host.confirm_cessation,
                timeout=120, poll_interval=.2)
            return adapter
        if getattr(args, 'qualification', None):
            from probes.t3code_controller_acceptance import run as controller_run
            report['scope'] = 'owned Controller one-Job acceptance'
            report.update(controller_run(root=root, request=request, make_adapter=make_adapter,
                admission=admission, owner=owner, qualification_path=args.qualification,
                qualification_sha256=args.qualification_sha256, descriptor=descriptor,
                authorization_ref=args.authorization_ref))
        else:
            report['scope'] = 'owned Adapter direct qualification; Controller not exercised'
            make_adapter(request)
            report['submit_status'] = adapter.execute(request).status.value
            deadline = time.monotonic() + 125
            while time.monotonic() < deadline:
                terminal = next((e.result for e in adapter.events(ref) if isinstance(e, ResultEvent)), None)
                if terminal:
                    report.update(result_state=terminal.status.value, reason=terminal.reason)
                    try:
                        report['text'] = adapter.text_output(ref)
                    except ValueError:
                        pass
                    break
                time.sleep(.05)
            stopped = adapter.stop(ref)
            report.update(stop_status=stopped.status.value, stop_reason=stopped.reason,
                          cessation_evidence_ref=stopped.evidence_ref)
        report['adapter_diagnostic'] = adapter.diagnostic(request.ref) if adapter is not None else None
        report['selection'] = profile.model_selection()
    except Exception as error:
        report.update(error_type=type(error).__name__, status='unverified')
    finally:
        if adapter is not None:
            adapter.close()
        stop_server(server)
        owner.close()
        report['owner'] = owner.observation()
        selected = [child for child in report['owner']['children'] if child['native_turn_id']]
        report['native_completed'] = len(selected) == 1 and selected[0]['native_completed']
        report['normal_completion'] = bool(report['native_completed'] and selected[0]['exit_code'] == 0 and not selected[0]['forced'])
        report['server_reaped'] = server.poll() is not None
        reader.join(timeout=2)
        server.stdout.close()
        report['server_output_sha256'] = server_output_hash.hexdigest()
        report['server_output_bytes'] = server_output_bytes
        shutil.rmtree(state)  # Only this newly created local service/auth state.
        report['local_service_auth_state_deleted'] = True
        report['direct_criteria'] = {
            'exact_text': report.get('result_state') == 'completed' and report.get('text') == 'T3_NATIVE_OK',
            'bound_native_turn': bool(report['native_completed'] and selected[0]['config_verified'] and selected[0]['subscription_verified'] and not selected[0]['failed']),
            'original_cessation': report.get('stop_status') == 'confirmed' and bool(report.get('cessation_evidence_ref'))
                and bool(report['owner']['children']) and all(child['stdout_eof'] and child['stderr_eof']
                    and child['reaped'] and child['done'] and not child['escaped_group']
                    for child in report['owner']['children']),
        }
        report['status'] = ('passed' if all(report['direct_criteria'].values()) and report['server_reaped']
            and (not getattr(args, 'qualification', None) or report.get('accepted') is True) else 'unverified')
        if report.get('metadata_only'):
            report['status'] = 'discovered' if metadata_complete(report) else 'unverified'
        (evidence / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--task-root', type=Path, required=True)
    parser.add_argument('--native', type=Path, required=True)
    parser.add_argument('--node', type=Path, required=True)
    parser.add_argument('--codex-home', type=Path, required=True)
    parser.add_argument('--selection-mode', choices=('default', 'explicit'), default=None,
        help='default resolves T3 advertised recommendations; unrelated to runtime permission auto')
    parser.add_argument('--model')
    parser.add_argument('--effort')
    parser.add_argument('--list-models', action='store_true', help='metadata only; never creates a model turn')
    parser.add_argument('--qualification', type=Path)
    parser.add_argument('--qualification-sha256')
    parser.add_argument('--authorization-ref', help='trusted host operator authorization reference for Controller')
    args = parser.parse_args()
    if args.selection_mode is None:
        args.selection_mode = 'explicit' if args.model or args.effort else 'default'
    if args.list_models and (args.qualification or args.model or args.effort):
        parser.error('metadata listing cannot include qualification or explicit selection')
    if not args.list_models and ((args.selection_mode == 'explicit' and (not args.model or not args.effort))
            or (args.selection_mode == 'default' and (args.model or args.effort))):
        parser.error('explicit requires exact model/effort; default permits neither override')
    if args.qualification and (not args.qualification_sha256 or not args.authorization_ref):
        parser.error('Controller requires reviewed qualification hash and actual authorization reference')
    try:
        report = run(args)
    except Exception as error:
        print(json.dumps({'status': 'unverified', 'error_type': type(error).__name__}))
        return 1
    print(json.dumps({'status': report['status'], 'evidence': str(args.task_root.resolve() / 'evidence/result.json')}))
    return 0 if report['status'] in ('passed', 'discovered') else 1


if __name__ == '__main__':
    raise SystemExit(main())
