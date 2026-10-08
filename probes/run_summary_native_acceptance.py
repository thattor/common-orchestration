"""Issue 166 only: Native-authored regression test, then actual Controller Job.

No CLI, default authority, model fallback, configuration mutation or automatic
retry. Root reviews this composition and supplies actual provenance, policy,
source and generated-code review callbacks. Qualification is not a Controller
run. Only the later Controller artifact is eligible for integration by Root.
"""
from dataclasses import asdict
import ast
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
from uuid import uuid4

from co_v4 import contracts as c
from co_v4.ac import Acceptance, CheckEvidence, Finding
from co_v4.adapters.codex import CodexAdapter
from co_v4.catalog import Catalog, UseCase
from co_v4.codex_host import CodexHostConfig, CodexReadOnlyHost, HostUnverified, OVERRIDES, PROBE
from co_v4.codex_permissions import profile_overrides
from co_v4.codex_profile_transport import CodexProfileTransport
from co_v4.controller import Controller, JobPlan
from co_v4.delegation import DelegatedScope, DelegatedTransport, WorkerWorkspace
from co_v4.judgment import JudgmentRequest, TrustedEvidence
from co_v4.state import ControlStore, Limits, body_digest
from co_v4.usage import UsageStore
from probes.codex_controller_acceptance import DispatchAdmission, ProfileTextSession, _new
from probes.codex_host_preflight import configured_launch_inventory
from probes.codex_profile_acceptance import ObservedTransport, auth_metadata, service_tier_overrides

MODEL, EFFORT, ADAPTER = 'gpt-6-astra', 'medium', 'codex.app-server'
USE = UseCase('other', 'Issue 166 bounded Python regression-test generation')
ARTIFACT = 'test_summary_native_contribution.py'
BASE = Path(__file__).resolve().parents[1]
MUTATION = ' or run.cessation_confirmed is False'
METHOD = 'generate-summary-regression-test'


def sha(value):
    return hashlib.sha256(value).hexdigest()


def source_identity():
    paths = list((BASE / 'co_v4').rglob('*.py')) + [BASE / p for p in (
        'probes/run_summary_native_acceptance.py', 'probes/codex_controller_acceptance.py',
        'probes/codex_profile_acceptance.py', 'probes/codex_profile_metadata_schemas.json',
        'probes/codex_host_preflight.py', 'tests/test_state.py')]
    return {str(p.relative_to(BASE)): sha(p.read_bytes()) for p in sorted(paths)}


def environment_definition(executable, *, service_tier='fast'):
    service_tier_overrides(service_tier)
    executable = Path(executable).resolve(strict=True)
    descriptor = {'schema': 'co.issue166.code-artifact.environment.v1',
        'model': MODEL, 'effort': EFFORT, 'service_tier': service_tier, 'adapter': ADAPTER,
        'native_version': 'codex-cli 0.159.2', 'executable_sha256': sha(executable.read_bytes()),
        'sources': source_identity(), 'use': asdict(USE), 'max_response_bytes': 2048,
        'profile': 'existing exact ephemeral named read-only; network disabled',
        'command_boundary': 'WorkerWorkspace.create_artifact after confirmed Native completion',
        'native_internal_isolation_claimed': False}
    return 'issue166-code-environment:' + body_digest(descriptor), descriptor


def job_for(run_id):
    # Only relevant ordinary source is sent. Host callbacks, account/configuration
    # metadata and ControlStore contents never enter the Job context.
    fixture = (BASE / 'tests/test_state.py').read_text()
    fixture = fixture[fixture.index('class Harness:'):fixture.index('\n\nclass StateTests')]
    context = {'summary_module': (BASE / 'co_v4/summary.py').read_text(),
        'fixture_Harness': fixture,
        'fixture_imports': 'from test_state import Harness; from co_v4 import contracts as c',
        'finalize_api': 'h.ctrl.finalize_run("r", c.State.ERROR, "controller_error", h.rev(), cessation=flag)',
        'test_import': 'from co_v4.summary import render_run_summary'}
    return c.Job(run_id, 'summary-native-contribution',
        'Implement a new useful unittest regression file for Issue 166. Output ONLY Python source, '
        'no markdown, under 2048 UTF-8 bytes. Use no tools, files, network or external context. '
        f'Allowed import modules only: {", ".join(sorted(_ALLOWED_IMPORTS))}. '
        'Use unittest.TestCase and real test_state.Harness in a TemporaryDirectory. '
        'Write at least two discovered tests: an empty Error Run finalized with cessation=False '
        'must include "cessation unconfirmed"; a separate cessation=True control must not. '
        'Both must have exactly five summary lines and leave get_run("r") unchanged. '
        'Close stores and temporary directories via cleanup. Do not inherit existing fixture TestCases. '
        'Do not mock the summary, alter source, or perform subprocess/network/configuration operations. '
        'The file will be integrated only after independent review and real tests. '
        'Do not output a claimed test verdict; author the actual runnable tests.',
        ('Native returned a bound, independently reviewed Python artifact within 2048 bytes.',
         'Exact artifact bytes pass at least two real regression tests and detect removal of the run-level cessation warning.',
         'Bound Native turn completed normally with validated EOF and owned exit zero; no tools or forced cleanup.'),
        json.dumps(context, ensure_ascii=False))


class ObservedReadOnlyHost(CodexReadOnlyHost):
    """Same named-profile construction, with the existing observer as inner wire.

    Deliberately local to this experiment; no global factory patch. Inherited
    launch/session/config/command probes and pre-send binding remain mandatory.
    """
    def __init__(self, config, *, service_tier):
        super().__init__(config)
        self.tier_overrides = service_tier_overrides(service_tier)

    def transport(self, request):
        if request != self._request or self._transport is not None or self._profile_name is None:
            raise HostUnverified('unbound_native_transport')
        self._check_binding(request)
        env = {k: os.environ[k] for k in ('HOME', 'PATH', 'TMPDIR', 'USER', 'LOGNAME', 'LANG') if k in os.environ}
        self.api_environment_absent = not any(k in env for k in
            ('OPENAI_API_KEY', 'OPENAI_ADMIN_KEY', 'CODEX_API_KEY', 'AZURE_OPENAI_API_KEY'))
        overrides = OVERRIDES + tuple('mcp_servers.' + n + '.enabled=false' for n in self.config.disabled_mcp_servers)
        overrides += tuple('shell_environment_policy.set.' + k + '=""' for k in self.config.cleared_environment_keys)
        overrides += profile_overrides(self._profile_name, self._profile_definition)
        overrides += ('features.remote_control=false', 'model_reasoning_effort=' + json.dumps(EFFORT))
        overrides += self.tier_overrides
        self.wire = ObservedTransport(str(self.config.executable), request.conditions.workspace,
            config_overrides=overrides, env=env, required_version='codex-cli 0.159.2')
        self._native_version = self.wire.native_version
        if self._native_version != 'codex-cli 0.159.2':
            self.wire.close()
            raise HostUnverified('profile_native_version_unsupported')
        inner = CodexProfileTransport(self.wire, request, self._profile_name, EFFORT,
            [str(self.config.python), '-I', '-S', '-c', PROBE], self._before_profile_turn)
        self._transport = DelegatedTransport(inner, request, self.config.delegation, admitted=lambda: self._admitted)
        return self._transport


def structural_evidence(wire):
    """Actual owned observer facts; never infer cessation from the generated code.

    The observer validates all original frames, IDs/types/text, terminal inventory
    and drain exactly as before. Its fixed EXPECTED comparison is not invoked.
    """
    text = ''.join(wire.texts.values())
    complete = (wire.turn_submissions == 1 and wire.turn_rpc_confirmed is True
        and wire.terminal == 'completed' and wire.error is None
        and wire.eof_validated is True and wire.wait_exit == 0
        and wire.cleanup_terminated is False and wire.started == wire.finished
        and len(wire.texts) == 1 and 0 < len(text.encode()) <= 2048
        and wire.terminal_inventory is not None and wire._process.poll() == 0)
    return {'scoped_completion_evidence_complete': complete,
        'turn_submissions': wire.turn_submissions, 'native_terminal': wire.terminal,
        'original_turn_rpc_confirmed': wire.turn_rpc_confirmed,
        'observed_sha256': sha(text.encode()), 'observed_utf8_bytes': len(text.encode()),
        'validated_eof': wire.eof_validated, 'owned_wait_exit': wire.wait_exit,
        'cleanup_terminated': wire.cleanup_terminated, 'observation_error': wire.error,
        'unfinished_items': len(wire.started - wire.finished), 'terminal_inventory': wire.terminal_inventory,
        'generic_cessation_capability_granted': False}


class CodeSession(ProfileTextSession):
    def __init__(self, request, config, *, check_source, service_tier):
        self.request, self.config, self.tier = request, config, service_tier
        self.check_source = check_source
        self.host = ObservedReadOnlyHost(config, service_tier=service_tier)
        self.wire = self.result = self.tier_observation = self.subscription = None
        self.claimed = False
        self.adapter = CodexAdapter(verify_host=self._verify, transport_factory=self._transport,
            permission_profile=self.host._profile_name, reasoning_effort=EFFORT, rpc_timeout=30)

    def _transport(self, request):
        if request != self.request or self.wire is not None:
            raise HostUnverified('controller_transport_binding_invalid')
        transport = self.host.transport(request)
        self.wire = self.host.wire
        self.api_environment_absent = self.host.api_environment_absent
        return transport

    def observation(self):
        return {'request_digest': body_digest(self.request), 'ref': asdict(self.request.ref),
            'environment_ref': self.request.conditions.environment_ref,
            'host': self.host.observation,
            'native': structural_evidence(self.wire) if self.wire else None,
            'result': self.result, 'subscription': self.subscription, 'service_tier': self.tier_observation}

    def artifact_bytes(self):
        if self.stop(self.request.ref).status != c.StopStatus.CONFIRMED:
            raise ValueError('artifact unavailable before confirmed completion')
        return next(iter(self.wire.texts.values())).encode()


_ALLOWED_IMPORTS = {'copy', 'unittest', 'tempfile', 'test_state', 'co_v4', 'co_v4.contracts', 'co_v4.summary'}


def failure_code(error):
    """Fixed diagnostics only; never copy arbitrary provider/reviewer exceptions."""
    if isinstance(error, SyntaxError):
        return 'artifact_python_invalid'
    codes = {'unexpected artifact import': 'artifact_import_unsupported',
        'bounded Python artifact required': 'artifact_size_invalid',
        'actual generated-code review evidence required': 'artifact_review_missing',
        'artifact test execution incomplete': 'artifact_execution_incomplete',
        'exact Issue 166 mutation target changed': 'mutation_target_changed',
        'invalid test outcome': 'artifact_test_outcome_invalid',
        'environment or source changed': 'source_changed'}
    return codes.get(str(error), 'unclassified_failure') if type(error) is ValueError else 'unclassified_failure'


def validate_artifact(raw):
    """Bounded syntax check; Root's code review is separately required before exec."""
    if type(raw) is not bytes or not 0 < len(raw) <= 2048:
        raise ValueError('bounded Python artifact required')
    tree = ast.parse(raw.decode('utf-8'), filename=ARTIFACT)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import) and any(a.name not in _ALLOWED_IMPORTS for a in node.names):
            raise ValueError('unexpected artifact import')
        if isinstance(node, ast.ImportFrom) and (node.level or node.module not in _ALLOWED_IMPORTS):
            raise ValueError('unexpected artifact import')
    compile(tree, ARTIFACT, 'exec')
    return sha(raw)


def check_artifact(path, directory, *, review_artifact, request):
    """No test execution until Root reviews these exact source bytes and Attempt.

    The reviewer returns a retained evidence reference after actual code review,
    or raises. It must reject unexpected effects. This syntax check is not an OS
    sandbox or general-purpose Python security validator.
    """
    raw = path.read_bytes()
    digest = validate_artifact(raw)
    review_ref = review_artifact(request, raw)
    if type(review_ref) is not str or not review_ref.strip():
        raise ValueError('actual generated-code review evidence required')
    source = (BASE / 'co_v4/summary.py').read_text()
    if source.count(MUTATION) != 1:
        raise ValueError('exact Issue 166 mutation target changed')
    results = []
    for mutant in (False, True):
        with tempfile.TemporaryDirectory(prefix='summary-check-', dir=directory) as temporary:
            root = Path(temporary)
            shutil.copytree(BASE / 'co_v4', root / 'co_v4', ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
            tests = root / 'tests'; tests.mkdir()
            shutil.copyfile(BASE / 'tests/test_state.py', tests / 'test_state.py')
            (tests / ARTIFACT).write_bytes(raw)
            if mutant:
                (root / 'co_v4/summary.py').write_text(source.replace(MUTATION, ''))
            runner = ('import sys,unittest,json; sys.path[:0]=[sys.argv[1],sys.argv[1]+"/tests"]; '
                's=unittest.defaultTestLoader.discover(sys.argv[1]+"/tests",pattern="' + ARTIFACT + '"); '
                'r=unittest.TextTestRunner().run(s); '
                'print(json.dumps(dict(tests=r.testsRun,failures=len(r.failures),errors=len(r.errors),skipped=len(r.skipped))))')
            process = subprocess.run([sys.executable, '-I', '-B', '-c', runner, str(root)],
                cwd=root, env={'PATH': os.environ.get('PATH', ''), 'PYTHONDONTWRITEBYTECODE': '1'},
                capture_output=True, timeout=20, check=False)
            if process.returncode != 0 or len(process.stdout) > 4096 or len(process.stderr) > 65536:
                raise ValueError('artifact test execution incomplete')
            result = json.loads(process.stdout)
            if (set(result) != {'tests', 'failures', 'errors', 'skipped'}
                    or any(type(v) is not int or v < 0 for v in result.values())):
                raise ValueError('invalid test outcome')
            results.append({**result, 'mutant': mutant, 'stderr_sha256': sha(process.stderr)})
    normal, mutant = results
    passed = (normal['tests'] >= 2 and normal['failures'] == normal['errors'] == normal['skipped'] == 0
        and mutant['tests'] == normal['tests'] and mutant['failures'] >= 1
        and mutant['errors'] == mutant['skipped'] == 0 and path.read_bytes() == raw)
    return {'artifact_sha256': digest, 'artifact_bytes': len(raw), 'review_ref': review_ref,
        'normal': normal, 'mutation': mutant, 'passed': passed}


def run(root, *, run_id, human_intent, human_intent_ref, origin_verifier,
        evidence_resolver, executable, check_source, review_artifact, catalog,
        environment_ref, service_tier='fast', timeout=120, _qualification=False):
    """Root-owned host composition. Live execution is explicit, never an import effect."""
    callbacks = (origin_verifier, evidence_resolver, check_source, review_artifact)
    if (not all(callable(v) for v in callbacks) or type(timeout) not in (int, float)
            or not 1 <= timeout <= 180 or (_qualification and catalog is not None)
            or (not _qualification and type(catalog) is not Catalog)):
        raise ValueError('actual host callbacks, Catalog and bounded timeout required')
    check_source()
    current_ref, descriptor = environment_definition(executable, service_tier=service_tier)
    if environment_ref != current_ref:
        raise ValueError('exact reviewed environment required')
    if not _qualification:
        entry = next((e for e in catalog.entries if e.key == (MODEL, ADAPTER)), None)
        if entry is None or entry.verification(USE, environment_ref) is None:
            raise ValueError('reviewed exact-use qualification required before Controller')
    credential = (Path.home() / '.codex/auth.json').resolve(strict=True)
    auth_before = auth_metadata(credential)
    root = Path(root).resolve(); root.mkdir(mode=0o700, exist_ok=False)
    worker, control = root / 'worker', root / 'control'
    worker.mkdir(mode=0o700); control.mkdir(mode=0o700)
    _new(control / 'environment.json', {'environment_ref': environment_ref, 'descriptor': descriptor})
    conditions = c.ExecutionConditions(MODEL, ADAPTER, str(worker), environment_ref,
        ('codex:checked-launch', 'service-tier:' + service_tier))
    job = job_for(run_id)
    _new(control / 'job.json', asdict(job))
    action = c.Action('native.code.text', c.Scope((('adapter', ADAPTER), ('workspace', str(worker)),
        ('environment', environment_ref), ('job_digest', body_digest(job)), ('artifact', ARTIFACT)), True))
    store = state = bound = session = config = None
    observations, checks = {}, []
    submitted = False
    report = {'schema': 'co.issue166.code-artifact.v1', 'run_id': run_id, 'model': MODEL, 'effort': EFFORT,
        'environment_ref': environment_ref, 'controller_exercised': False,
        'qualification': _qualification, 'accepted': False, 'automatic_retry': False,
        'catalog_promoted': False, 'human_gateway_exercised': False, 'requested_service_tier': service_tier,
        'artifact_integrated': False, 'remaining_usage': 'unknown', 'last_stage': 'setup'}

    def frozen():
        check_source()
        if environment_definition(executable, service_tier=service_tier) != (environment_ref, descriptor):
            raise ValueError('environment or source changed')

    def resolve(snapshot, request):
        nonlocal bound, config
        if (request.conditions != conditions or request.action != action or request.method != METHOD
                or request.proposed_job not in (None, job) or request.confirmation is not None):
            raise ValueError('unbound judgment')
        admission = None
        if request.proposed_job is None:
            if submitted: raise ValueError('dispatch already claimed')
            frozen()
            ref = c.AttemptRef(run_id, job.job_id, request.ref.attempt_id or 'metadata-assessment')
            execution = c.ExecuteRequest(ref, job, conditions)
            mcp, keys = configured_launch_inventory(Path(executable).resolve(), worker)
            candidate = CodexHostConfig(conditions, Path(executable).resolve(), Path(sys.executable).resolve(),
                (control / 'control.db',), (credential,), DelegatedScope(human_intent_ref, ref, str(worker)),
                disabled_mcp_servers=mcp, cleared_environment_keys=keys,
                use_named_permissions=True, reasoning_effort=EFFORT)
            CodexReadOnlyHost(candidate).verify(execution, 'launch', None)
            evidence_id = 'issue166-dispatch:' + body_digest((request, snapshot.revision, environment_ref))
            admission = DispatchAdmission(body_digest(request), snapshot.revision, environment_ref, evidence_id)
            if request.ref.attempt_id:
                if bound is not None and bound != execution: raise ValueError('second Attempt refused')
                bound, config = execution, candidate
            target = control / (evidence_id.split(':')[-1] + '.json')
            if not target.exists(): _new(target, asdict(admission))
        evidence = evidence_resolver(snapshot, request, admission)
        if (type(evidence) is not TrustedEvidence or evidence.request_digest != body_digest(request)
                or (admission is not None and admission.evidence_ref not in evidence.evidence_refs)):
            raise ValueError('host evidence must bind actual admission')
        return evidence

    class Observe:
        def execute(self, request):
            nonlocal session, submitted
            if submitted or request != bound or config is None or len(state.attempts(run_id)) != 1:
                raise ValueError('unbound or repeated dispatch')
            submitted = True
            _new(control / 'submission-claim.json', {'ref': asdict(request.ref), 'request_digest': body_digest(request)})
            session = CodeSession(request, config, check_source=frozen, service_tier=service_tier)
            report['last_stage'] = 'native_execution'
            return session.execute(request)

        def events(self, ref, after=None):
            events = session.events(ref, after)
            if any(isinstance(e, c.ResultEvent) for e in events) and ref not in observations:
                report['last_stage'] = 'native_completion'
                stop = session.stop(ref)
                observed = session.observation()
                if stop.status == c.StopStatus.CONFIRMED:
                    raw = session.artifact_bytes()
                    command = WorkerWorkspace(config.delegation, protected_state=(control / 'control.db',))
                    try: command.create_artifact(ref, ARTIFACT, raw)
                    finally: command.close()
                    report['last_stage'] = 'artifact_validation_review_and_tests'
                    observed['artifact_check'] = check_artifact(worker / ARTIFACT, control,
                        review_artifact=review_artifact, request=bound)
                    frozen()
                observations[ref] = observed
                _new(control / 'observation.json', observed)
            return events

        def stop(self, ref): return session.stop(ref)
        def respond(self, response): return session.respond(response)

    def inspect(request):
        report['last_stage'] = 'independent_ac'
        refs = [request.result.ref] if request.result else [j.result.ref for j in request.jobs]
        criteria = [False] * 3
        if len(refs) == 1 and refs[0] in observations:
            observed = observations[refs[0]]
            if json.loads((control / 'observation.json').read_bytes()) != observed:
                raise ValueError('retained observation changed')
            artifact = observed.get('artifact_check', {})
            path = worker / ARTIFACT
            same = path.is_file() and not path.is_symlink() and sha(path.read_bytes()) == artifact.get('artifact_sha256')
            native = observed.get('native') or {}
            criteria = [same and artifact.get('review_ref') is not None
                        and artifact.get('artifact_sha256') == native.get('observed_sha256'),
                same and artifact.get('passed') is True,
                observed['host'].get('native_handoff_verified') is True
                    and native.get('scoped_completion_evidence_complete') is True
                    and observed['environment_ref'] == environment_ref]
        verdict = 'pass' if all(criteria) else 'fail'
        path = control / ('check-' + str(len(checks)) + '.json')
        _new(path, {'kind': request.kind, 'request_digest': body_digest(request),
            'criteria_passed': criteria, 'verdict': verdict,
            'observation_sha256': sha((control / 'observation.json').read_bytes()) if observations else None,
            'artifact': 'worker/' + ARTIFACT,
            'artifact_sha256': sha((worker / ARTIFACT).read_bytes()) if (worker / ARTIFACT).is_file() else None})
        checks.append(verdict)
        finding = Finding(verdict, (str(path.relative_to(root)),))
        return CheckEvidence(body_digest(request), finding,
            tuple(Finding('pass' if value else 'fail', finding.evidence_refs) for value in criteria)
            if request.kind == 'job' else ())

    try:
        store = ControlStore(control / 'control.db', verifier=origin_verifier, evidence=resolve)
        state = store.controller()
        store.intake().create_run(run_id, human_intent, human_intent_ref)
        state.set_limits(run_id, Limits(jobs=1, attempts_per_job=1, attempts_per_pair=1), state.get_run(run_id).revision)
        observer, acceptance = Observe(), Acceptance(inspect)
        deadline = time.monotonic() + timeout
        if _qualification:
            decision = store.judgment().judge(JudgmentRequest(c.QuestionRef(run_id, job.job_id),
                action, METHOD, conditions, proposed_job=job))
            state.add_job(job, decision.decision_id, decision.state_revision)
            ref = c.AttemptRef(run_id, job.job_id, uuid4().hex)
            execution = c.ExecuteRequest(ref, job, conditions)
            decision = store.judgment().judge(JudgmentRequest(c.QuestionRef(run_id, job.job_id, ref.attempt_id),
                action, METHOD, conditions))
            state.begin_attempt(execution, decision.decision_id, decision.state_revision)
            reply = observer.execute(execution)
            state.record_execute(reply, state.get_attempt(ref).revision)
            cursor = None
            while reply.status == c.OperationStatus.ACCEPTED and time.monotonic() < deadline:
                for event in observer.events(ref, cursor):
                    state.record_event(event, state.get_attempt(ref).revision); cursor = event.event_id
                attempt = state.get_attempt(ref)
                if attempt.result is not None:
                    stop = observer.stop(ref); state.record_stop(stop, attempt.revision)
                    if stop.status == c.StopStatus.CONFIRMED:
                        snapshot = state.get_run(run_id)
                        outcome = acceptance.job(snapshot, job, attempt.result)
                        state.record_job_goal(outcome, snapshot.revision)
                        report.update(accepted=outcome.completed, qualification_ac=outcome.ac.verdict)
                    break
                time.sleep(.01)
            else:
                report['timeout'] = reply.status == c.OperationStatus.ACCEPTED
        else:
            controller = Controller(run_id, state=state, judgment=store.judgment(), catalog=catalog,
                usage=UsageStore(), adapters={ADAPTER: observer}, acceptance=acceptance,
                planner=lambda *_: JobPlan(job, action, METHOD, USE, (conditions,), explicit_model=MODEL, explicit_adapter=ADAPTER))
            report['controller_exercised'] = True
            while time.monotonic() < deadline:
                progress = controller.step()
                if progress.state in c.TERMINAL or progress.state == c.State.WAITING_HUMAN: break
                time.sleep(.01)
            else: report['timeout'] = True
            report['accepted'] = state.get_run(run_id).state == c.State.COMPLETED and not report.get('timeout')
        if report.get('timeout') and session is not None:
            state.record_stop(session.stop(bound.ref), state.get_attempt(bound.ref).revision)
        report.update(controller_state=state.get_run(run_id).state.value,
            attempts=len(state.attempts(run_id)), routing_records=len(state.history(run_id, 'routing_history')),
            job_goal_count=len(state.history(run_id, 'job_goals')), run_goal_count=len(state.history(run_id, 'run_goals')))
    except Exception as error:
        report['accepted'] = False
        report['failure'] = 'issue166_probe_failed_closed'
        report['failure_stage'] = report['last_stage']
        report['failure_code'] = failure_code(error)
    finally:
        try:
            if session is not None: session.close()
            frozen()
            report['source_verified_after_cleanup'] = True
        except Exception:
            report.update(accepted=False, source_verified_after_cleanup=False, failure='cleanup_or_source_unconfirmed')
        report.update(submission_claimed=submitted, check_verdicts=checks,
            observation=session.observation() if session else None,
            authentication_metadata_unchanged=auth_before == auth_metadata(credential),
            artifact_sha256=sha((worker / ARTIFACT).read_bytes()) if (worker / ARTIFACT).is_file() else None)
        if not report['authentication_metadata_unchanged']: report['accepted'] = False
        if store is not None: store.close()
        _new(root / 'report.json', report)
    return report


def qualify(root, **inputs):
    """Measure this exact code-generation use before reviewed Catalog admission."""
    return run(root, **inputs, catalog=None, _qualification=True)
