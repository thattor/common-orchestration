# CO 0.4 runbook

## Native AI coordination

Run these commands from the extracted runtime directory. The supported
host is macOS with Python 3.11–3.13, Git 2.46+, existing first-party Claude
Code/Devin CLI logins for the candidates you use, and a Native workspace
already trusted by the corresponding CLI.
Setup measures the installed CLI versions and exact models. It does not
sign in, approve workspace trust, enable billing, or choose a replacement
model. SWE-2 High must currently be advertised as `Free` by the logged-in
account; subscription limits still apply.
Git is selected from standard system/Homebrew locations after checking its
version; an older installation does not mask a qualifying one.

Choose a fresh private state directory outside both the source repository
and the Native CLI working directory. Keep the Native working directory
small and local; existing Native context can be loaded from it and its
ancestors. Setup discloses the known context locations. Do not put secrets
in the files supplied to a task.

Setup makes real model calls and briefly creates an owned canary directory
inside the Native working directory. It checks a normal response and
read/write/command denial, then removes only its own unchanged canaries.
The configuration requests denial for other tool classes, but those classes
are not qualified by the three probes. A separate development consultation
observed a skill read despite that configuration. Normal task calls continue
to reject every recorded tool request; configuration alone is not proof of
pre-execution denial.
The measured CLI versions are Claude 2.1.291 and Devin 3000.11.3; a CLI or
tool-schema change requires setup again in a fresh state directory.

```sh
python3 -m co_v4.task setup \
  --state-dir /absolute/path/co-state \
  --native-cwd /absolute/path/already-trusted-native-workspace
```

Submit the goal and the scope you authorize. Repeating `--read`/`--write`
lists exact files, not globs. Existing writable files must also be readable;
a writable-only path creates a new file. `--verify` takes an executable and
its arguments directly. Both the host's base Python and the verification
executable must live outside the protected HOME, repository, state,
`/Users`, `/Volumes`, `/Network`, `/private/tmp` and `/private/var/folders`
trees. Homebrew under `/opt/homebrew` or python.org under `/Library/Frameworks`
are suitable; HOME-installed pyenv/uv/conda interpreters are unsupported.
The real sandbox canary and executable location are checked before the
first model call. Verification-command dependencies must also be readable
under the same sandbox policy.

```sh
python3 -m co_v4.task run \
  --state-dir /absolute/path/co-state \
  --repo /absolute/path/my-repository \
  --goal 'Design and implement clamp(x, lo, hi), preserving add. Review the implementation after tests pass.' \
  --read calc.py --read test_calc.py --write calc.py \
  --verify /opt/homebrew/bin/python3.13 -I -S -B -m unittest discover -s . -p test_calc.py
```

Setup creates `routes2.json` with the successfully measured default candidates
and a versioned maintainer prior. It keeps a qualified subset if another
candidate fails, and fails if none qualifies. `setup-report.json` records
failures from that setup attempt; `routes show` displays the current registry.
Use `routes add` for a missing candidate after diagnosing its failed probe.
The prior describes initial fit, separately from the measured
CLI configuration; no benchmark or local quality measurement is implied.
Candidate order and fit determine ties. Existing registries are not silently
rewritten. `setup --legacy` retains the old setup API for task/1 state; it is
not needed for a new task/3 run.

### Reusing CO from another project

Keep the runtime, bundled Skill and state references in the project's existing
entry point, such as `AGENTS.md`, or in an existing local configuration file
that entry point names. A new chat should read those references before asking
where CO is installed. This is an explicit reference convention; CO does not
scan for installations or maintain a separate project registry.

Use absolute paths for the current machine. For example, adapt this block in
the existing project entry; the values below are placeholders, not settings
to copy unchanged:

```text
Common Orchestration for this project:
  Repository: /absolute/path/to/this-project
  Runtime: /absolute/path/to/common-orchestration-runtime
  Skill: /absolute/path/to/common-orchestration-runtime/skills/co-task/SKILL.md
  Python: /opt/homebrew/bin/python3.13
  State: /absolute/path/to/private-co-state/this-project
  Native workspace: /absolute/path/to/already-trusted-native-workspace
  Authorization: <existing project instructions or owner decision reference>
```

Normally use a separate state directory for each project. A suitable macOS
location is `$HOME/Library/Application Support/CommonOrchestration/<project-id>`
with a distinct project ID; expand it to an absolute path in the reference.
This is a recommendation, not a new required location or a migration command.
Keep a working, authorized existing state where it is. State must remain
outside both the target repository and the Native workspace and private to
the user. It contains route measurements, prompts, decisions, work copies and
results; exclude it from Git, release archives and shared configuration.
Do not put credentials in the reference block.

When locating an existing setup:

1. Read the invocation and the existing project entry, following only its
   explicit configuration references. Confirm that the repository and
   authorization apply to the current task; a path reference does not grant
   permission to use every model recorded in that state.
2. If the references identify one authorized setup, use it without asking
   for the same paths again. Confirm the runtime's `VERSION`, Python version
   and CLI help. The recorded Skill must belong to that runtime.
3. To inspect an existing task/2 or task/3 registry, run
   `python -E -s -B -m co_v4.task routes show --state-dir '<absolute state path>'`
   from that runtime with stdin from `/dev/null`. This reads recorded
   candidates; it makes no model calls and does not prove that a route is
   currently usable. Legacy task/1 state uses `routes.json`; a missing
   `routes2.json` is not permission to replace that state.
4. If a required reference is missing, conflicts with another applicable
   reference, points to a missing installation/state, or exceeds the current
   authorization, report the specific unresolved item. Ask only for the
   location or decision that the existing project context cannot resolve.

First-time registration is separate from discovery: record the selected
references only within the authorized project scope. Creating a private
directory is also separate from `setup` or `routes add`, which make real
model calls. Do not silently create, overwrite, move or remeasure state to
make a reference work. No global Skill or Plugin installation is required
by this convention.

Add these options to `run` **before `--verify`**:

- `--mode suitability` (default): select using the step's focus and candidate fit.
- `--mode usage`: use available trusted quota evidence without excluding unknown
  quota. The current Native connections report unknown quota, so their actual
  choice uses fit and candidate order; automatic quota-exhaustion failover is
  not supported in this release.
- `--mode fixed`: provide `--model planner=ROUTE/MODEL` and
  `--model implement=ROUTE/MODEL`, plus targets for any design/review roles the
  plan uses. Missing or unsuitable targets stop before work steps run.
- `--model ROLE=[ROUTE/]MODEL`: pin that role in any mode. A model name alone
  must resolve to exactly one candidate. No alias or silent replacement.
- `--focus CATEGORY`: set the planner's bootstrap focus (default
  `architecture_planning`). Step focuses are proposed in the bounded plan,
  within registered candidate capabilities, and cannot add routes or scope.
- `--quiet`: omit routine progress; retain required decisions, the JSON outcome,
  errors and journal.

New model registration and fit updates are separate operations. Registering a
model never grants a different auth route, paid tier or tool policy. Use the
`routes add`, `routes fit` and `routes show` help for the exact CLI arguments.
A fit declaration names its source and whether it is an initial `prior` or a
reviewed task-competence `measured` observation. CO records the declaration
and source but does not independently validate its evidence. It is not CLI
qualification.

Progress goes to stderr; stdout is one result object. `verified: true`
means the declared command exited successfully, the checked files stayed
unchanged during verification, and every requested review approved the
same file version. Inspect `workspace`, `diff_path` and `result_path` to use
the result. This is evidence for the listed files and command, not a full
repository build or a guarantee of semantic correctness.

```sh
python3 -m co_v4.task status --state-dir /absolute/path/co-state --task TASK_ID
python3 -m co_v4.task resume --state-dir /absolute/path/co-state --task TASK_ID
```

Resume selects the task/1, task/2 or task/3 implementation from the saved schema,
not from current defaults. Mode, targets and announcement preferences remain
those recorded at task creation. Resume reuses saved, digest-checked outputs.
Legacy task/1 and task/2 stop with `call_outcome_unknown` when an interrupted
model call has no recorded outcome. A changed or corrupt workspace/journal,
unmeasured CLI, or unavailable route also stops explicitly.
Status reads the saved journal and checks the workspace without loading
Native routes, so it remains available when the route registry needs repair.

New task/3 recoverable call failures return `awaiting_decision`, without sealing a final
result. On a terminal, `run` and `resume` display the failed call, known process
state, unknown quota and numbered candidates. Choose a number, defer, or cancel;
no JSON editing is needed. Replacing a fixed or individually pinned target
requires explicit confirmation of the named old and new targets. That answer
applies only to the failed call's next attempt. Later steps and repairs keep
their original selection policy. A changed candidate requires a new decision.

Only a failure proven to precede inference, including failure to create its
process, permits another attempt. For a timeout, post-launch error or missing
outcome, CO can show alternatives but leaves retry and switching disabled.
Choosing cancel ends the CO task and does not establish that the old request
stopped. Empty input, EOF and defer leave the task waiting without sending.

Noninteractive `run`/`resume` return the pending JSON with exit code **75**.
The host application presents the `pause` report to the user -- including each
option's route/model and, for `requires_override` choices, the named old/new
pair and its next-one-attempt scope -- and then records the actual user's
selected option with the noninteractive `decide` subcommand (no inline Python
required):

    python -m co_v4.task decide --state-dir DIR --task TID \
        --pause-id PID --report-sha256 'sha256:...' --option-id OID

`--report-sha256` takes the pause report's `report_sha256` verbatim, keeping
the literal `sha256:` prefix; `--option-id` is the chosen option's `option_id`
(`cancel` records cancellation; a defer is simply not invoking `decide`).
`--confirm-override` is required for options marked `requires_override` and is
also accepted, without adding authority, on options that do not require it.
Text produced by an AI or worker is not human permission: only a choice the
real user made may be recorded. On success the command prints one JSON object
`{"status":"decision_recorded","task_id":...}` and exits 0; it records the
decision only -- run `resume` separately to continue the task. A stale or
duplicate answer exits 2 with `route_decision_invalid`; on rejection read
`status`, present the current state, and do not retry with altered values or
blindly resume a rejected answer. Do not edit state files directly. This local
CLI/API does not authenticate a remote user or grant broader model, billing,
tool, merge or deployment permissions.

Use Ctrl-C to interrupt a foreground run. CO cleans up the owned process
group and keeps the journal; interruption alone is not proof that a remote
request never ran. Use status/resume to check the saved outcome. Keep the
private state directory while results are needed: it contains supplied
source, Native transcripts and results. No automatic retention or migration
is performed. To roll back, run the separately retained old archive with its
own compatible state. Keep task/3 state with a compatible runtime: 0.4.2 and
earlier archives reject task/3. Task/2 can still be inspected with 0.4.2.
The new runtime preserves task/1 and task/2 semantics and keeps the legacy
route registry separate; it does not convert old state in place.

Current limits: 1–6 sequential steps, at most one independent review step
(plus re-review after its repair), one repair, 64 KiB per UTF-8 file,
256 KiB source context, 900 seconds per model call and 60 seconds per
verification command. Each state directory permits one model call at a
time; a concurrent call fails with `route_busy`. The verifier allows scratch writes only and
denies network and Mach service access; tests needing installation,
network, Keychain or writes to their sources are unsupported. A detached
descendant remains sandboxed but is outside the process-group cleanup
guarantee. Native inference itself is not OS-contained: tool policy and
transcript checks are measured separately from the verifier sandbox.

The following sections describe the existing OpenAI-compatible service.

All state is task-owned under a fresh `0700` root. Never kill the host,
never force-free a lease, never let a process exit while `close()` is
unconfirmed.

## 1. Verify the published assets

Download the **published** Release assets — never the local build —
into a fresh directory outside the repository: the archive,
`RELEASE-MANIFEST.json`, `SHA256SUMS`. Verify `SHA256SUMS`, then every
per-file sha256 in the manifest. Any mismatch stops here.

## 2. Isolated import check

`-I` ignores `PYTHONPATH` and `cwd`; put the payload on `sys.path`
explicitly:

```sh
python3 -I -c "import os, sys; sys.path.insert(0, '<EXTRACTED>/common-orchestration-v0.4.4'); import co_v4; real = os.path.realpath; assert os.path.commonpath([real(co_v4.__file__), real('<EXTRACTED>')]) == real('<EXTRACTED>')"
```

For repeated use, a task-owned virtualenv may hold one `.pth` with the
payload path (never a global/user site); `-I` honors `.pth`.

## 3. Fresh root, credential and derived template

```sh
mkdir -m 0700 <ROOT>
mkdir -m 0700 <ROOT>/credentials <ROOT>/downloads
```

Provision the provider key with
`co_v4.provider_launcher.provision_credential(path)` — a fresh CSPRNG
`0600` ASCII file, never returned or printed — or equivalently a fresh
`secrets` token written `0600`. Old keys are never read, copied or
migrated.

The chat template is **derived**: the operator explicitly downloads the
pinned upstream JSON (a separate, deliberate step — nothing fetches it
automatically and no product code touches the network), then derives
the template bytes locally. Steps, all fail-closed:

```sh
curl -fsSL -o <ROOT>/downloads/tokenizer_config.json \
  'https://huggingface.co/Qwen/Qwen3-0.6B/resolve/16706fc57485378d4ffaf54139b29ccc66ae08fa/tokenizer_config.json'
```

```python
from pathlib import Path
import hashlib, json

JSON_SHA = 'bbc2c089e3bef8753f63348c10595767be8998bc6ca7c7ebcaada346d401fba8'
UP_SHA   = '87a2728cb8dc9fe424d624542f6060ec05a1d285ebbec578bb078900e33396b5'
DER_SHA  = '57f1fd00f0013a2be96aa79b857391f27e23df5b5f847072b524c897e24d0361'
OLD = ('{%- for message in messages[::-1] %}\n'
       '    {%- set index = (messages|length - 1) - loop.index0 %}\n'
       '    {%- if ns.multi_step_tool and message.role == "user" '
       'and not(message.content.startswith(\'<tool_response>\') and '
       'message.content.endswith(\'</tool_response>\')) %}')
NEW = ('{%- for index in range(ns.last_query_index, -1, -1) %}\n'
       '    {%- set message = messages[index] %}\n'
       '    {%- if ns.multi_step_tool and message.role == "user" '
       'and not(\'<tool_response>\' in message.content and '
       '\'</tool_response>\' in message.content) %}')

def _reject(x): raise ValueError('non-finite')
def _obj(pairs):
    seen, out = set(), {}
    for k, v in pairs:
        if k in seen: raise ValueError('duplicate key')
        seen.add(k); out[k] = v
    return out

with open('<ROOT>/downloads/tokenizer_config.json', 'rb') as handle:
    blob = handle.read((1 << 20) + 1)                # bounded read
assert 0 < len(blob) <= 1 << 20
assert hashlib.sha256(blob).hexdigest() == JSON_SHA  # pinned download
doc = json.loads(blob.decode('utf-8', 'strict'),
                 parse_constant=_reject, object_pairs_hook=_obj)
tpl = doc['chat_template']
assert type(tpl) is str
up = tpl.encode('utf-8')                             # no added newline
assert len(up) == 4116 and hashlib.sha256(up).hexdigest() == UP_SHA
assert tpl.count(OLD) == 1                           # exactly-once, no fuzz
der = tpl.replace(OLD, NEW, 1).encode('utf-8')
assert len(der) == 4100 and hashlib.sha256(der).hexdigest() == DER_SHA
```

Then write `der` to `<ROOT>/template.txt` as a fresh `0600` file under
the owned root (`os.open` with `O_WRONLY | O_CREAT | O_EXCL`). This is
plain owned-file creation — not the launcher's atomic publish seam, and
no atomicity is claimed. Provenance and the Apache-2.0 license text are
in `examples/templates/`; no `.jinja`/template bytes are shipped. The
original modification's author and time are unknown — that is recorded,
not hidden.

## 3.5 Principals and registry — minimal provision

`principals_file` is a closed JSON list of `{"principal",
"token_sha256"}` rows — the sha256 of the operator's fresh Bearer
token, never the token itself; write it `0600`, same uid, nlink 1:

```python
import hashlib, json, secrets
token = secrets.token_hex(32)          # the Bearer secret, minted once
rows = [{'principal': 'ops',
         'token_sha256': hashlib.sha256(
             token.encode('ascii')).hexdigest()}]
# json.dumps(rows) -> <ROOT>/principals.json as a fresh 0600 file;
# `token` belongs only in the client's own secret channel.
```

`registry_file` is a `co.task-profile-registry/1` document whose
entries pin the issued `(model, adapter, environment_ref)` route
triples — so it is built AFTER §4 issues the profiles. The declared
digest comes from the real API, never guessed:

```python
from co_v4.profile_registry import revision_digest

entry = {'profile_id': 'co-text', 'effect_class': 'pure',
         'requires_output': True,
         'routes': [[model, 'openai.chat', env_chat],
                    [model, 'openai.responses', env_resp]],   # sorted
         'route_bounds': [
             {'route': [model, 'openai.chat', env_chat],
              'total_s': 120, 'max_drain_s': 30},
             {'route': [model, 'openai.responses', env_resp],
              'total_s': 120, 'max_drain_s': 30}],
         'unconfirmed_after_seconds': 180,   # >= max(total+drain)+30
         'use_case': 'general',
         'job_instructions': 'Produce the requested text only.',
         'job_criteria': ['ac:media_types', 'ac:max_bytes',
                          'ac:non_whitespace', 'ac:no_forbidden_literals'],
         'ac': {'media_types': ['text/plain'], 'max_bytes': 65536,
                'non_whitespace': True,
                'forbidden_literals': ['</think>', '<think>']}}
# Per-protocol qualification aliases: each pins exactly ONE route, so a
# pass through it provably exercises that adapter. The instruction text
# is the known-answer contract verbatim from the qualification driver;
# 'ac:exact' is appended after the four base criteria because
# exact_any is declared (registry-enforced order).
QUAL_INSTRUCTIONS = (
    'Answer the arithmetic question in context.input. Reply with the '
    'resulting digit only: exactly one ASCII character, no words, no '
    'punctuation, no whitespace, no explanation. The correct digit is 4.')

def _qual_entry(profile_id, route):
    return {'profile_id': profile_id, 'effect_class': 'pure',
            'requires_output': True,
            'routes': [route],
            'route_bounds': [{'route': route,
                              'total_s': 120, 'max_drain_s': 30}],
            'unconfirmed_after_seconds': 180,
            'use_case': 'general',
            'job_instructions': QUAL_INSTRUCTIONS,
            'job_criteria': ['ac:media_types', 'ac:max_bytes',
                             'ac:non_whitespace',
                             'ac:no_forbidden_literals',
                             'ac:exact'],
            'ac': {'media_types': ['text/plain'], 'max_bytes': 65536,
                   'non_whitespace': True,
                   'forbidden_literals': ['</think>', '<think>'],
                   'exact_any': ['4']}}

qual_resp = _qual_entry('co-text-resp',
                        [model, 'openai.responses', env_resp])
qual_chat = _qual_entry('co-text-chat',
                        [model, 'openai.chat', env_chat])
digest = revision_digest(entry)
digest_resp = revision_digest(qual_resp)
digest_chat = revision_digest(qual_chat)
doc = {'schema': 'co.task-profile-registry/1',
       'entries': [{'revision_digest': digest, 'entry': entry},
                   {'revision_digest': digest_resp, 'entry': qual_resp},
                   {'revision_digest': digest_chat, 'entry': qual_chat}],
       'aliases': [{'alias': 'co-text', 'profile_id': 'co-text',
                    'revision_digest': digest},
                   {'alias': 'co-text-resp',
                    'profile_id': 'co-text-resp',
                    'revision_digest': digest_resp},
                   {'alias': 'co-text-chat',
                    'profile_id': 'co-text-chat',
                    'revision_digest': digest_chat}]}
```

The general `co-text` entry is retained unchanged — both routes, no
fixed answer, no correctness claim. Which adapter `co-text` reaches is
decided by route order and exclusions, not by the client, so a pass
through it is not protocol evidence; the two single-route aliases are
what make each protocol independently provable.

`routes`/`route_bounds` are aligned and sorted; `forbidden_literals`
must include both think markers and be sorted; the closed `ac` key set
is enforced by `load_registry`. Each route's Catalog Verification —
the `use_case` + `output_mode: 'collect'` evidence the config's
`verification` block also carries — comes from the measured
qualification, not from this skeleton.

## 4. Fresh qualification — existing product APIs only

No qualification executable ships. Order matters: captures must exist
before a manifest can verify, so `launch_provider` — which requires an
already-verified `manifest_sha256` — does NOT apply to a fresh
qualification; use the external two-phase path:

1. **Validate argv and take descriptors.**
   `launch_attestation.validate_launch_argv(argv, executable_path=...,
   model_path=..., template_path=..., credential_file=..., model_id=...,
   threads=..., slots=..., host=..., port=...)` — argv positional, the
   rest keyword-only — then `before = {'executable':
   file_descriptor(executable_path), 'model': file_descriptor(
   model_path), 'template': file_descriptor(template_path)}`, the exact
   keys `build_launch_record` consumes.
2. **Spawn.** `provider_launcher.spawn_owned(argv, stdin=DEVNULL,
   stdout=DEVNULL, stderr=DEVNULL)` — `env={}` is a constant. Keep the
   returned `Popen` handle.
3. **Bounded readiness + captures.** `launch_attestation.
   make_models_probe(endpoint, supplier, expected_model)` builds a
   conforming bounded `/models` probe over the credential supplier;
   then take bounded raw SSE captures per protocol and hash the exact
   bytes `co_v4.host_routes.read_evidence` returns — the plain
   evidence-file reader; `read_protected` is the separate protected-fd
   config reader. Hash those bytes yourself.
4. **Manifest.** Assemble the closed `co.provider-manifest/1` document:
   `protocol_profile.parse_manifest(text)` accepts JSON text;
   `load_manifest(doc)` accepts a dict; `verify_manifest(doc,
   read_evidence)` takes the dict and rehashes every capture, yielding
   the sealed object and `manifest_sha256`.
5. **Record the launch.** `provider_launcher.record_owned_launch(
   proc=<original Popen>, before=<descriptors>, argv=argv,
   manifest_sha256=<verified>, endpoint, credential_ref,
   credential_file, model_id, threads, slots, record_path)` re-runs
   kernel PID/argv/birth, descriptor identity and the argv allowlist,
   then publishes the `0600` `co.provider-launch/1` record atomically.
   An unconfirmed child stop raises `cleanup_failed` with the handle
   retained on `.child`.
6. **Profiles and reference.** Issue the actual measured modes:
   `issue_profile(verified, 'responses',
   index_mode='absent_single_part', sequence_mode='absent',
   inert_fields={'response.completed': ('timings',)})` — the measured
   single-part Responses stream carries no `sequence_number`, and the
   measured `response.completed` carries the inert `timings` key — and
   `issue_profile(verified, 'chat')`: generic `present`/`present`
   defaults (the Chat stream has no `sequence_number`, so these fields
   are never consumed by the parser — they are profile identity).
   One manifest, both profiles. `environment_ref(endpoint, auth_ref,
   profile.profile_digest)` derives each Catalog-bound reference.

   A fresh qualification issues new honest values with the same semantic
   fields: each `profile_digest` binds the fresh `manifest_sha256` and
   must differ from the release-time value, and each `environment_ref` is
   re-derived from that new digest and recorded as new. Release-time
   digests are never reused.

   Fixed measured profile fields (README carries the same table):

   | Adapter | protocol | index_mode | sequence_mode | inert_fields |
   |---|---|---|---|---|
   | `openai.responses` | `responses` | `absent_single_part` | `absent` | `{'response.completed': ('timings',)}` |
   | `openai.chat` | `chat` | `present` | `present` | `{}` |
7. **Gates.** `launch_attestation.LaunchAttestor(record_path,
   credential_file)` is the `launch_attested` callback wired by
   `co_v4.host_routes.build_routes` / `co_v4.qualified_route`; it
   re-checks kernel identity, descriptors and argv. Manifest fields —
   `provider_build`, `provider_commit`, `model_sha256`, `model_id`,
   `chat_template_sha256`, `slots`, `threads`, `sdk_version`,
   `auth_results`, every assertion `passed`, `multipart` — must equal
   the measured values.
8. **argv rule.** On reinstall only `--chat-template-file`,
   `--api-key-file` and `--port` may differ; normalized argv must be
   byte-equal to the release-time normalized argv.

**Failure anywhere in steps 2–5.** No qualification driver ships, so
the operator's own driver must meet these normative requirements. The
original `Popen` handle and its recorded birth are never dropped.
Cleanup may signal only that owned, unreaped handle — a PID cannot be
reused while its own child stays unreaped. Each bounded round is
`terminate()` (SIGTERM), a wait bounded at 5s, `kill()` (SIGKILL)
**only if that same owned handle is still live**, then a final wait
bounded at 5s; no other PID is ever signalled. A round is confirmed only when `wait()` has reaped the
child AND the kernel re-read of `(pid, uid, recorded birth)` reports
`dead` or `mismatch`; `poll()` alone is never proof, and identity is
compared before argv, so a dead or PID-reused child is refused without
any argv read. The driver runs up to three bounded rounds,
then retains the handle and repeats the bounded round in an unbounded
parent loop, 10s between rounds, until confirmed — it never exits
unsure. Without a recorded birth the outcome can never be confirmed,
even after the child is reaped: a bare reaped PID is never classified
`dead`. This is an intentional permanent hold that cannot converge —
the retained parent keeps retrying and the operator must never kill
it; it is the task-local qualification driver, not production. Once
the child is reaped, the driver may write a `0600`
`cleanup-checkpoint.json` recording only actual checkpoint facts —
root, pid, uid, recorded birth, stage; it may include the wait status
— a facts record, never stop proof.
This provider-owned terminate/kill is the qualification helper only;
the Host CLI stop path stays SIGTERM-only and is unaffected. A failed
qualification never records a stop it could not confirm and never
reads raw process environment or credential bytes.

## 5. Configure and start

Apply the documented substitutions to `examples/host.example.json`
(real `0700` root; `0600` protected files; both routes reference the
**same** manifest and launch record — one launch, two issued profiles).
Start:

```sh
python3 -I -c "import sys; sys.path.insert(0, '<PAYLOAD>'); from co_v4.cli import main; raise SystemExit(main(['--config', '<ABS-CONFIG>']))"
```

(or `python -I -m co_v4 --config <ABS-CONFIG>` inside the task venv.)

`POST /v1/responses` waits up to `sync_wait_s`; `GET`/`cancel` poll.

## 5.5 Protocol proof — SDK pass through each qualification alias

With the host running (§5), drive the measurement SDK (openai 3.24.0,
the task venv) once through EACH qualification alias:

- `model='co-text-resp'` and `model='co-text-chat'` in separate runs.
  `input` is the qualification driver's exact string `2+2` — copied
  verbatim from the driver, never reconstructed. The known answer `4`
  is declared only by the two qualification aliases; the general
  `co-text` alias declares no fixed answer.
- One POST per alias, then bounded `GET /v1/responses/{id}` polls of
  the SAME returned id until a terminal status — never resubmit and
  never mint a second response when a poll times out.
- Expected: `status='completed'` with the single-character output `4`.
  The host-side `ac:exact`/`exact_any` check already ran; this pass is
  protocol evidence, not a second AC.

`co-text-resp` proves `openai.responses`; `co-text-chat` proves
`openai.chat`. A pass through the general `co-text` alias alone is not
protocol evidence, since stable route order and exclusions decide
which adapter it reaches.

### Recording what actually dispatched

The wire Response deliberately carries no route fields. Inspection of
the task-owned `control.sqlite` and the configured capacity ledger —
the config's `ledger_path`, not a fixed filename — is permitted only
after the host is confirmed `stopped` (§6) AND the owner probe
reports `free` — that pair is necessary but not sufficient. The
ledger is host-wide, may be shared across roots and has no owner
flock, so this root's `free` alone does not prove no other host is
writing it: the inspected evidence run must use a task-owned ledger
that no other live root shares — the existing trial's isolated
task-owned ledger qualifies; never inspect a production-ledger copy —
otherwise a hash mismatch is refusal of the evidence, not an expected
race. An existing `-wal`/`-shm` leaves writer/checkpoint state
unproved, and is never ignored, deleted, checkpointed or recovered to
force the probe to pass. The read-only inspection probe first requires
that no `-wal`/`-shm` sidecar exists for EITHER DB, and records sha256
of every file plus the exact file set; if any sidecar exists the probe
refuses and leaves all files untouched. Only then does it open via
`sqlite3.connect(Path(p).as_uri() + '?mode=ro&immutable=1', uri=True)`
— `as_uri()` handles path encoding; `immutable=1` is valid only
because the probe already proved `stopped` + `free` + a task-owned
exclusive ledger + zero sidecars on BOTH DBs,
and it prevents the read-only open from creating or modifying
sidecars. Read each Run's committed Attempt `conditions` (`model`,
`adapter`, `environment_ref`) plus the output/store digest. After
closing, re-hash both DBs and compare the file set: all hashes and the
exact key set must be unchanged, satisfying §7's hash-identical
requirement and leaving startup sidecar checks unaffected. Evidence
names the adapter and `environment_ref` actually dispatched — not
merely the alias requested — and shows only non-secret conditions and
hashes: never prompts, request bodies or credential material. No new
wire field, log line or product API is added for this.

## 6. Stop, retry, restart — local vs remote

Graceful operator stop is **SIGINT/SIGTERM only**: `close()` returns
`stopped` or `host_stop_unconfirmed`; the CLI retries unconfirmed
closes with bounded backoff and never exits while a writer is
unconfirmed. `stopped` means the **local** host teardown finished —
socket released, handlers drained, stores closed, owner released. It is
not a remote-provider `CONFIRMED` cessation, and no such claim is made.
A forced kill is a crash-test scenario, never an operator stop: after a
crash the next process reconciles through recovery, and an unresolved
admitted Attempt keeps its lease as unknown — never auto-resent.

Restart is a new process on the same root: completed Runs are
retrievable and byte-identical; pending Runs recover through the
checkpoint/journal path, which records only real committed facts and audit entries — no
fabricated Result or cessation, and no fabricated provider state.

## 7. Rollback and roll-forward

Only after `stopped` is confirmed and the second-process owner probe
reports `free`. Rollback switches the task-owned selection to the
preserved previous compatible archive, or to absence. State DB and
credentials must be hash-identical before/after — no deletion,
downgrade or migration. Installed 0.3.5 / 0.2.13 copies are verified
unchanged read-only. Roll-forward is a normal restart on the same root.

## 8. Failure handling

A close that never confirms = an unconfirmed writer: hold the owner, do
not kill, do not remove state, do not declare the Run stopped. The
retry loop and the owner probe (`owned_elsewhere`/`free`) are the only
proofs.
