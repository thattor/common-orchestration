# CO 0.4 runtime

## AI coordination — one goal, automatic assignment

The `python -m co_v4.task` entry point turns one scoped goal into working
files and a verified result. It plans only the steps the goal needs, selects
setup-measured routes by their declared fit, passes recorded outputs
between steps, applies permitted file replacements and runs the owner's
verification command. At most one repair is allowed; a repair requested by
review must be reviewed again.

Choose a selection mode independently of progress announcements:

| Mode | Behaviour |
|---|---|
| `suitability` (default) | Prefer the candidate's declared fit for this step's focus. |
| `usage` | Within suitable candidates, use quota when all snapshots are fresh and comparable; otherwise demote evidenced low remaining and use fit/order. Unknown quota remains selectable. |
| `fixed` | Use the exact role assignments you provide; stop if a target cannot be used. |

`--model ROLE=[ROUTE/]MODEL` pins an individual role in any mode. Pins must
still meet the step's fit requirement and are never silently replaced. `--quiet`
suppresses routine stderr progress while keeping the final JSON result and
all execution records. Roles do not define model identities. The shipped
candidate profile is an explicitly labelled maintainer prior, adjustable
through the route commands; its ordinal preferences are not measured model
performance.

**Native quota limitation:** the current Claude/Devin task connections have
no remaining-quota collector. With those connections, `usage` records unknown
quota and chooses by fit and stored order. The shared policy supports trusted
comparable snapshots, but this is not proof of Native quota-based allocation.
Automatic model switching after Native quota exhaustion is not implemented.
New tasks pause on recoverable failures of a selected route and show what is
known, what remains unknown and the eligible alternatives. If inference has provably not started,
you can choose a candidate for one next attempt. Changing an exact role target
requires a separate confirmation naming both targets. A timeout or missing
response does not prove quota exhaustion or permit another send.

In a terminal, `run` and `resume` show a numbered choice, including defer and
cancel. `--quiet` still shows required decisions. Without interactive input,
the command returns `awaiting_decision` and exit code 75; the hosting application
can use `decide` and then `resume`. A pending task releases its lock.
Cancelling ends the CO task; it does not confirm that an old remote call stopped.

Tasks use a fixed Git commit and a separate workspace containing the listed
files. The original checkout, index and uncommitted work are preserved. The
result includes changes, model assignments, selection reasons, review verdicts
and verification evidence; it is not merged into the original branch.

Independent `run` commands can execute concurrently, including with the same
state directory. Each task retains its own workspace, journal and results;
dependent steps within one task remain sequential. All task state directories
and models on this user account share **12 slots per Native adapter**. Full
capacity returns `capacity_full` before sending, with no queue or automatic
model switch. `python -m co_v4.task capacity status` shows reserved and
unconfirmed execution counts; these are not provider quota or proof of live
processes. See [parallel tasks](RUNBOOK.md#parallel-tasks) for setup exclusion,
interruption and upgrade limits.

Use [RUNBOOK: Native AI coordination](RUNBOOK.md#native-ai-coordination)
for setup and the single-goal command. New candidates live in `routes2.json`;
legacy `routes.json` and saved task/1 and task/2 semantics are retained for resume.
New task/3 state keeps each attempt and decision; older releases reject it.
This task runner's measured Native routes do not qualify Native adapters in
the existing Controller Catalog or change the OpenAI-compatible API below.

The bundled `skills/co-task/SKILL.md` is an optional entry point: in an AI
window, give it the exact file path — the explicit-path workflow is the only
documented use; auto-discovery, global installs and Plugin registration are
unverified. It calls the runtime's `run`, `status`, `decide`, `resume` and `capacity status`
commands, so it needs this extracted runtime directory and the task state
location. The CLI equivalent is `python -m co_v4.task` run directly.

Version: `VERSION` (`0.4.5`). Python **3.11, 3.12 or 3.13** — exactly
the versions measured by CI; no other version is claimed. Product code
is standard library only. CO release version and Controller/Adapter
versions are independent.

This standalone tree does not require the former private monorepo or
its history. There is no installed entry point, installer, daemon or
service-manager registration.

## Platform

Measured platform: **macOS 27 on arm64, local APFS volume**.
`ServiceOwner` itself verifies Darwin/arm64, `apfs` + `MNT_LOCAL`, the
`0700` same-uid canonical state root and a single-link `0600` lock file,
and refuses everything else with a fixed `OwnerUnavailable` code. No
other OS, filesystem or architecture is supported.

## Qualified provider — the measured combination only

- llama.cpp build **b11429**, commit
  `d81235049384534c167caea52b85a694f6103d14`.
- Model artifact `Qwen3-0.6B-Q8_0` (the GGUF file), sha256
  `9465e63a22add5354d9bb4b99e90117043c7124007664907259bd16d043bb031`;
  served under `model_id`/`--alias` `co04-qwen3-06b` — the artifact and
  the served alias are different identifiers, both bound by the launch
  record and manifest.
- Chat template: a **derived** Jinja template — the upstream
  `chat_template` string extracted from `tokenizer_config.json`
  (Qwen/Qwen3-0.6B @ `16706fc57485378d4ffaf54139b29ccc66ae08fa`,
  4116 bytes, sha256 `87a2728c…96b5`) plus one exact substring
  replacement, giving 4100 bytes sha256
  `57f1fd00f0013a2be96aa79b857391f27e23df5b5f847072b524c897e24d0361`,
  byte-identical to the release-measured template. No template bytes
  ship in this tree; the deterministic derivation, provenance and
  license are in `examples/templates/` and the operator procedure in
  `RUNBOOK` §3. The manifest schema records only the sha256.
- Measurement SDK set inside the task-owned virtualenv: openai
  `3.24.0`, httpx2 `2.13.1`, httpcore2 `2.13.1`. The product itself
  stays standard-library only.
- Launch argv: the normalized argv recorded in the release manifest
  pins `--temp 0`, `--reasoning off`, `--reasoning-budget 0` plus the
  measured threads, slots and context-size values. On reinstall only
  `--chat-template-file`, `--api-key-file` and `--port` may differ
  (RUNBOOK §4, argv rule).
- Both shipped adapters, `openai.responses` and `openai.chat`
  (`0.1.0`, `controller_compat` 4.0.0), are qualified for exactly this
  combination. One launch produces one manifest; both route profiles
  are issued from that same manifest, and the release records one
  `native_tested` entry per protocol with its own measured
  `profile_digest`/`environment_ref`.

Issued route profiles — fixed measured fields:

| Adapter | protocol | index_mode | sequence_mode | inert_fields |
|---|---|---|---|---|
| `openai.responses` | `responses` | `absent_single_part` | `absent` | `{'response.completed': ('timings',)}` |
| `openai.chat` | `chat` | `present` | `present` | `{}` |

The Chat modes are the generic parser-deviation defaults — the Chat
stream carries no `sequence_number`, so the parser never consumes them;
they exist for profile identity only. Any profile change issues a new
`profile_digest` and a new `environment_ref`.

## What `completed` means — and does not

Through the general `co-text` alias, a Response with `status` =
`completed` guarantees exactly: the request ran to completion on a
qualified route; the returned text is policy-clean (no forbidden
literals), untruncated and well-formed within the declared AC bounds;
and the serialized text bytes are identical to the bytes AC evaluated.
It is **not** a claim of semantic correctness — CO proves the route,
the process and the declared acceptance predicates, never that the
answer is right. The general alias pins no fixed answer.

## Northbound surface — strict subset only

Loopback `127.0.0.1` `ThreadingHTTPServer`. `POST /v1/responses`
accepts a strict subset of the SDK 3.24.0 request shape:

| Field | Accepted |
|---|---|
| `model` | required; alias ≤ 128 printable chars |
| `input` | required; string, or ordered `message` items (roles `system`/`developer`/`user`/`assistant`, ≤ 64 items); content a string or typed parts (`input_text`, or `output_text` on `assistant` only, ≤ 64 parts) |
| `instructions` | optional string |
| `background` | optional bool |
| `stream` | absent or `false` only |
| `metadata` | ≤ 16 pairs; key ≤ 64, value ≤ 512 chars |
| `store` | `null` counts as absent; otherwise `true` only — CO persists |
| `tools` | `null` counts as absent; otherwise `[]` only |
| `tool_choice` | `null` counts as absent; any other value is `unsupported_field` |
| `text` | `null` counts as absent; otherwise only `{"format":{"type":"text"}}` |
| `include` | `null`/`[]` count as absent; otherwise `unsupported_field` |

Every other SDK 3.24.0 request field — `temperature`, `top_p`,
`reasoning`, `max_output_tokens`, `previous_response_id`,
`conversation`, `prompt`, `stream_options`, `service_tier`,
`moderation`, `truncation`, `user`, etc. — is refused as
`unsupported_field`; truly unknown keys as `unknown_field`.
An explicit `null` on any known field — accepted or unsupported —
counts as absent; the inert-null rule never rescues an unknown key.
`Idempotency-Key` is a single optional header. `GET /v1/responses/{id}`
reads the committed projection; `POST /v1/responses/{id}/cancel` takes
an empty or `{}` body; `GET /v1/models` lists aliases. Fixed error
envelopes only; a latched global failure answers 503.

A failed Response carries `error.code = "server_error"` and
`error.message = "<co_code>: <fixed text>"`. Clients discriminate on
the `co_code` token before the first `": "`; the text after it is
fixed, not machine-readable. The nine closed `co_code` values and
their fixed texts:

| `co_code` | fixed message tail |
|---|---|
| `provider_refusal` | `the model provider refused the request` |
| `content_filter` | `the response was blocked by a content filter` |
| `protocol_violation` | `the provider reply violated the protocol` |
| `output_unavailable` | `the run completed without a usable output` |
| `approval_required` | `the request requires approval` |
| `integrity_violation` | `stored state failed an integrity check` |
| `cessation_unconfirmed` | `execution cessation was not confirmed` |
| `cancellation_unconfirmed` | `the cancellation was not confirmed` |
| `run_failed` | `the run failed` |

## Lifecycle and state

- `co_v4/cli.py`: `python -m co_v4 --config <abs>`; SIGINT/SIGTERM stop;
  `close()` returns `stopped` or `host_stop_unconfirmed` — **local host
  teardown only**, never a remote-provider cessation claim.
- One flock owner per state root; `ServiceHost` is single-shot per
  process and releases the owner last. A confirmed `stopped` means the
  local drain/release finished; the provider process is a separately
  owned lifecycle.
- Capacity leases release only on genuine evidence: an exact
  request-bound `NeverStarted` receipt, or `CONFIRMED` cessation (with
  or without a real `Result`). Without a Result the Run's settlement
  stays held pending its own evidence. Nothing fabricates results or
  force-frees leases.
- Control store contract marker `co.controller/4` (`CONTROLLER_VERSION`
  4.0.0); content-addressed `OutputStore` digests.

## Limits and closed config

`co.service-host/1` read through a protected fd (`0600`/same-uid/
nlink-1/`O_NOFOLLOW`); every level is a closed key set — unknown fields
refuse, never ignore. Bounds: `bind.port` 1024–65535,
`max_body_bytes` ≤ 262144, `sync_wait_s` ≤ 60, ≤ 64 routes, deadlines
and `max_drain_s` 1–600, literal loopback endpoints only, 32 handler
slots, per-Job Attempt limits from the authenticated grant.

## Unsupported in the OpenAI-compatible service

Everything not listed: non-loopback endpoints, tools/function-calling
and non-text roles, client streaming, credential migration (fresh
`0600` keys only), non-APFS state roots, OS service integration. Copied
Native adapters ship with existing gates/scopes intact as new
V4 identities carrying the `0.2.0-dev` version marker (e.g. T3 Code);
the baseline they were copied from is recorded in source comments, not
in the version field. Readiness is `unqualified` with `native_tested: []` — no live Native proof exists
for any copied adapter in the Controller Catalog. These are distinct from
the task runner's Native CLI routes. Paths already declared held or deferred
keep that existing status verbatim.

## Tests

```sh
cd '<standalone-checkout>'
PYTHONPATH=. python3 -m unittest discover -s tests -v
```

## Source distribution and verification

This standalone 0.4.5 source distribution contains the measured engine,
CLI and common Skill. The maintainer retains the original release and
test evidence separately. Engine and Skill bytes are unchanged; build
paths, test fixtures and this README are adapted for the standalone tree.

The [GitHub workflow](https://github.com/thattor/common-orchestration/actions)
runs offline tests and checks a deterministic build on macOS. These checks
do not qualify cloud providers, Native adapters or new platforms.
Some maintainer-prior and development-probe references still point to
private historical issues. Those references are provenance, not accessible
setup instructions. Legacy development probes are not standalone user
entry points; their opt-in Native invocation is unverified here.

## License

Common Orchestration is provided by thattor under Sustainable Use License
1.0 in [LICENSE.md](LICENSE.md). Keep the license and applicable notices
when redistributing. This is source-available software with use and
distribution conditions. No usage registration, reporting or
modified-source disclosure requirement is added.

See [NOTICE](NOTICE) for the licensor identity and the retained third-party
template provenance and Apache-2.0 terms.
