# CO 0.4 runtime

[English](#english) | [日本語](#日本語)

## English

[English](#english) | [日本語](#日本語)

### Overview and development status

Common Orchestration is a standalone runtime for scoped AI tasks and a local
OpenAI-compatible text service. Version `0.4.5` includes the task runner,
CLI and optional common Skill. Qualification applies only to the measured
combinations below; a successful task verification does not qualify a new
provider, platform or Native adapter in the Controller Catalog.

### Setup and usage

Use Python 3.11, 3.12 or 3.13 from the source directory. Product code uses
the standard library and has no package installation step.

```sh
git clone https://github.com/thattor/common-orchestration.git
cd common-orchestration
python3 -m co_v4.task --help
```

Native tasks also require Git 2.46+, existing first-party Claude Code/Devin
CLI logins for the selected routes, and an already trusted Native workspace.
Use an already measured state directory or follow the
[Native setup procedure](RUNBOOK.md#native-ai-coordination). Setup makes
real model calls; it does not establish new authentication, workspace trust
or billing authority. Runtime/state/repository paths and the verifier
executable must meet the RUNBOOK's location and sandbox requirements.

Example for an authorized repository that contains `calc.py` and
`test_calc.py`; replace the absolute paths with your actual locations.
Put all `run` options before `--verify`, which consumes the remaining argv.

```sh
python3 -m co_v4.task run \
  --state-dir /absolute/path/co-state \
  --repo /absolute/path/my-repository \
  --base HEAD \
  --goal 'Design and implement clamp(x, lo, hi), preserving add. Review the implementation after tests pass.' \
  --read calc.py --read test_calc.py --write calc.py \
  --verify /opt/homebrew/bin/python3.13 -I -S -B -m unittest discover -s . -p test_calc.py
```

The run uses a fixed commit; uncommitted work is excluded. Inspect the
returned `workspace`, `diff_path` and `result_path`. `verified: true`
means the declared verifier passed, checked files stayed unchanged during
verification and requested reviews approved that version; it does not
establish unrestricted semantic correctness. Existing tasks can be inspected
without inference:

```sh
python3 -m co_v4.task status --state-dir /absolute/path/co-state --task TASK_ID
```

For the OpenAI-compatible service, follow [RUNBOOK.md](RUNBOOK.md) for
fresh qualification and protected configuration before using
`python3 -m co_v4 --config /absolute/path/host.json`.

### AI coordination — one goal, automatic assignment

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

### Platform

Measured platform: **macOS 27 on arm64, local APFS volume**.
`ServiceOwner` itself verifies Darwin/arm64, `apfs` + `MNT_LOCAL`, the
`0700` same-uid canonical state root and a single-link `0600` lock file,
and refuses everything else with a fixed `OwnerUnavailable` code. No
other OS, filesystem or architecture is supported.

### Qualified provider — the measured combination only

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

### What `completed` means — and does not

Through the general `co-text` alias, a Response with `status` =
`completed` guarantees exactly: the request ran to completion on a
qualified route; the returned text is policy-clean (no forbidden
literals), untruncated and well-formed within the declared AC bounds;
and the serialized text bytes are identical to the bytes AC evaluated.
It is **not** a claim of semantic correctness — CO proves the route,
the process and the declared acceptance predicates, never that the
answer is right. The general alias pins no fixed answer.

### Northbound surface — strict subset only

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

### Lifecycle and state

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

### Limits and closed config

`co.service-host/1` read through a protected fd (`0600`/same-uid/
nlink-1/`O_NOFOLLOW`); every level is a closed key set — unknown fields
refuse, never ignore. Bounds: `bind.port` 1024–65535,
`max_body_bytes` ≤ 262144, `sync_wait_s` ≤ 60, ≤ 64 routes, deadlines
and `max_drain_s` 1–600, literal loopback endpoints only, 32 handler
slots, per-Job Attempt limits from the authenticated grant.

### Unsupported in the OpenAI-compatible service

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

### Tests

Product code is standard-library only, but SDK integration tests require
the pinned test dependency in [requirements-sdk-test.txt](requirements-sdk-test.txt)
in a separate test environment. Run from the repository root. The
[CI workflow](.github/workflows/ci.yml) records the isolated environment and
its opt-in local host fixture; these tests do not make real provider calls.

```sh
cd '<standalone-checkout>'
PYTHONPATH=. python3 -m unittest discover -s tests -v
```

### Source distribution and verification

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

### License

Common Orchestration is provided by thattor under Sustainable Use License
1.0 in [LICENSE.md](LICENSE.md). Keep the license and applicable notices
when redistributing. This is source-available software with use and
distribution conditions. No usage registration, reporting or
modified-source disclosure requirement is added.

See [NOTICE](NOTICE) for the licensor identity and the retained third-party
template provenance and Apache-2.0 terms.

## 日本語

[English](#english) | [日本語](#日本語)

### 概要と開発段階

Common Orchestrationは、範囲を限定したAIタスクとローカルのOpenAI互換テキストサービスを提供する独立したruntimeです。版 `0.4.5` にはタスク実行器、CLI、任意の共通Skillを含みます。適格性を確認した範囲は後述の検証済みの組合せに限ります。タスクの検証成功だけで、新しいprovider、プラットフォーム、Controller CatalogのNative adapterを適格と認めるものではありません。

### 導入と使い方

ソースのフォルダでPython 3.11、3.12、3.13のいずれかを使います。製品コードは標準ライブラリだけを使い、パッケージのインストール手順はありません。

```sh
git clone https://github.com/thattor/common-orchestration.git
cd common-orchestration
python3 -m co_v4.task --help
```

NativeタスクにはGit 2.46以降、選択した経路の既存の公式Claude Code/Devin CLIログイン、各CLIですでに信頼を許可したNative workspaceも必要です。検証済みのstateフォルダを再利用するか、[Native導入手順](RUNBOOK.md#native-ai-coordination) に従います。setupは実モデルを呼び出します。新しい認証、workspaceの信頼許可、課金の権限を与えるものではありません。runtime・state・repositoryのパスと検証用実行ファイルには、RUNBOOKの配置・sandbox条件が適用されます。

以下は `calc.py` と `test_calc.py` を含む、作業を許可されたrepositoryでの例です。絶対パスは実際の配置に置き換えます。`--verify` は残りのargvを受け取るため、他の `run` オプションをすべてその前に置いてください。

```sh
python3 -m co_v4.task run \
  --state-dir /absolute/path/co-state \
  --repo /absolute/path/my-repository \
  --base HEAD \
  --goal 'Design and implement clamp(x, lo, hi), preserving add. Review the implementation after tests pass.' \
  --read calc.py --read test_calc.py --write calc.py \
  --verify /opt/homebrew/bin/python3.13 -I -S -B -m unittest discover -s . -p test_calc.py
```

固定commitから実行し、未コミットの変更は含めません。結果の `workspace`、`diff_path`、`result_path` を確認してください。`verified: true` は、指定検証コマンドの成功、検証中に対象ファイルが変更されなかったこと、依頼したレビューが同じ版を承認したことを意味します。内容が無条件に正しいという保証ではありません。既存タスクはモデルを呼ばずに確認できます。

```sh
python3 -m co_v4.task status --state-dir /absolute/path/co-state --task TASK_ID
```

OpenAI互換サービスには、[RUNBOOK.md](RUNBOOK.md) の新しい適格性検証と保護された設定を使い、その後に `python3 -m co_v4 --config /absolute/path/host.json` で起動します。

### AIの協調 — 1つのゴールと自動割当

`python -m co_v4.task` は、範囲を限定した1つのゴールから作業ファイルと検証結果を生成します。必要な工程だけを計画し、setupで確認した経路を申告済みの適性に従って選び、記録した出力を工程間で渡します。許可されたファイルを置き換え、所有者の検証コマンドを実行します。修復は最大1回で、レビューによる修復要求は修復後に再レビューします。

選択モードと進捗表示は独立に指定できます。

| モード | 動作 |
|---|---|
| `suitability`（既定） | 工程のfocusに対する候補の申告済み適性を優先します。 |
| `usage` | 適性のある候補内で、すべてのquota観測が新鮮かつ比較可能なら利用枠を使います。それ以外は証拠のある残量不足を下位にし、適性と保存済み順序で選びます。quota不明の候補も選択できます。 |
| `fixed` | 指定した役割の割当をそのまま使い、対象を利用できなければ停止します。 |

`--model ROLE=[ROUTE/]MODEL` は、どのモードでも個別役割を固定します。固定候補も工程の適性条件を満たす必要があり、無通知で置き換えません。`--quiet` は通常のstderr進捗表示を抑えますが、最終JSON結果と実行記録は残します。役割名はモデルの識別名を定義しません。同梱の候補profileは、管理者による初期判断（maintainer prior）と明記され、routeコマンドで調整できます。順位はモデル性能の実測ではありません。

**Native quotaの制約:** 現在のClaude/Devin接続には残りquotaの取得機構がありません。これらの接続で `usage` を使うとquotaは不明と記録され、適性と保存済み順序で選びます。共通方針は信頼できる比較可能な観測を扱えますが、Nativeのquotaに基づく割当が実証されたわけではありません。Nativeのquota枯渇後の自動モデル切替は未実装です。新しいタスクは、選択経路の回復可能な失敗で一時停止し、既知・不明・選択可能な代替を示します。推論未開始が証明された場合だけ、次の1回の試行候補を選べます。役割の固定対象を変えるには、新旧両対象を明示した別の確認が必要です。timeoutや応答欠落だけでquota枯渇や再送の許可を推定しません。

端末の `run` と `resume` は、保留・中止を含む番号付き選択を表示します。`--quiet` でも必要な判断は表示します。対話入力がなければ `awaiting_decision` とexit code 75を返し、呼出し側アプリケーションで `decide` の後に `resume` を使えます。保留中のタスクはlockを解放します。中止はCOタスクを終了しますが、以前のリモート呼出しの停止確認にはなりません。

タスクは固定Git commitと、指定したファイルを含む分離workspaceを使います。元checkout、index、未コミット変更は保持します。結果には変更、モデル割当、選択理由、レビュー判定、検証証拠を含み、元ブランチへマージしません。

独立した `run` は、同じstateフォルダを使う場合も並行実行できます。各タスクは専用workspace、journal、結果を持ち、1つのタスク内の依存工程は順次実行します。このユーザーアカウントの全task state・全モデルは **Native adapterごとに12枠**を共有します。満杯なら送信前に `capacity_full` を返し、待ち行列や自動モデル切替はありません。`python -m co_v4.task capacity status` は予約済みと実行未確認の数を表示します。これはproviderのquotaや実プロセスの生存証明ではありません。setupとの排他、中断、更新時の制約は [並行タスク](RUNBOOK.md#parallel-tasks) を参照してください。

導入と単一ゴールのコマンドは [RUNBOOK: Native AI coordination](RUNBOOK.md#native-ai-coordination) にあります。新候補は `routes2.json` に保存し、旧 `routes.json` とtask/1・task/2の意味は再開用に保持します。新しいtask/3は各試行と判断を保存し、古いreleaseは受け付けません。タスク実行器で確認したNative経路は、既存Controller CatalogのNative adapterを適格化せず、後述のOpenAI互換APIを変更しません。

同梱の `skills/co-task/SKILL.md` は任意の入口です。AI画面でこのファイルの正確なパスを指定します。文書化した利用方法は明示パス方式だけで、自動検出、グローバル導入、Plugin登録は未検証です。runtimeの `run`、`status`、`decide`、`resume`、`capacity status` を呼ぶため、展開済みruntimeフォルダとtask stateの場所が必要です。CLIから直接 `python -m co_v4.task` を使う方法と対応します。

版は `VERSION`（`0.4.5`）。Python **3.11、3.12、3.13**だけをCIで確認しており、他の版の動作は主張しません。製品コードは標準ライブラリだけを使います。COのrelease版とController/Adapterの版は独立です。

この独立したソース一式は、以前のprivate monorepoやその履歴を必要としません。インストール済みentry point、installer、daemon、service managerへの登録はありません。

### プラットフォーム

確認済み環境は **macOS 27、arm64、ローカルAPFS volume**です。`ServiceOwner` 自体がDarwin/arm64、`apfs` と `MNT_LOCAL`、同じuidで正規化された `0700` のstate root、単一linkの `0600` lockファイルを検査し、それ以外を固定コード `OwnerUnavailable` で拒否します。他のOS、filesystem、architectureは対応対象としていません。

### 適格性を確認したprovider — 実測した組合せのみ

- llama.cpp build **b11429**、commit `d81235049384534c167caea52b85a694f6103d14`。
- モデルartifactはGGUFファイル `Qwen3-0.6B-Q8_0`、sha256 `9465e63a22add5354d9bb4b99e90117043c7124007664907259bd16d043bb031`。提供時の `model_id` / `--alias` は `co04-qwen3-06b`。artifactと提供aliasは別識別子で、起動記録とmanifestで両者を結びます。
- Chat templateは**派生した**Jinja templateです。Qwen/Qwen3-0.6B @ `16706fc57485378d4ffaf54139b29ccc66ae08fa` の `tokenizer_config.json` から抽出した上流 `chat_template`（4116 bytes、sha256 `87a2728c…96b5`）へ、指定した1箇所の部分文字列置換を行います。結果は4100 bytes、sha256 `57f1fd00f0013a2be96aa79b857391f27e23df5b5f847072b524c897e24d0361` で、release検証時のtemplateとbyte同一です。template本体は同梱しません。再現可能な派生手順、由来、ライセンスは `examples/templates/`、運用手順はRUNBOOK §3にあります。manifest schemaにはsha256だけを記録します。
- 測定用SDKはtask専用virtualenv内のopenai `3.24.0`、httpx2 `2.13.1`、httpcore2 `2.13.1`。製品自体は標準ライブラリだけを使います。
- 起動argvはrelease manifestに正規化して記録し、`--temp 0`、`--reasoning off`、`--reasoning-budget 0` と、測定したthreads・slots・context-sizeを固定します。再導入で変更できるのは `--chat-template-file`、`--api-key-file`、`--port` だけです（RUNBOOK §4のargv規則）。
- 同梱の `openai.responses` と `openai.chat`（`0.1.0`、`controller_compat` 4.0.0）は、この組合せだけで適格性を確認しています。1回の起動から1つのmanifestを作り、両route profileを同じmanifestから発行します。releaseはprotocolごとに、それぞれの実測 `profile_digest` / `environment_ref` を持つ `native_tested` を1件記録します。

発行済みroute profileの固定実測値:

| Adapter | protocol | index_mode | sequence_mode | inert_fields |
|---|---|---|---|---|
| `openai.responses` | `responses` | `absent_single_part` | `absent` | `{'response.completed': ('timings',)}` |
| `openai.chat` | `chat` | `present` | `present` | `{}` |

Chatのmodeは、共通parserの逸脱対応の既定値です。Chat streamに `sequence_number` はなく、parserはこれらを消費しません。profile識別のために存在します。profileを変更すると、新しい `profile_digest` と `environment_ref` を発行します。

### `completed` の意味と保証範囲

一般alias `co-text` のResponseが `status = completed` なら、適格な経路で要求が完走し、返却textが禁止literalを含まず、切り詰められず、宣言したACの範囲内で形式を満たし、serializeされたtext bytesがACの評価したbytesと一致することを保証します。意味内容の正しさを保証するものではありません。COが確認するのは経路、処理、宣言した受入述語です。一般aliasは固定の答えを指定しません。

### クライアント向けAPI — 限定した部分集合

ループバック `127.0.0.1` の `ThreadingHTTPServer` を使います。`POST /v1/responses` が受け付けるSDK 3.24.0の要求は、次の部分集合だけです。

| Field | 受理する値 |
|---|---|
| `model` | 必須。aliasは表示可能文字128字以内 |
| `input` | 必須。文字列、または順序付きの `message` 項目（roleは `system` / `developer` / `user` / `assistant`、64項目以内）。contentは文字列または型付きpart（`input_text`、`assistant` のみ `output_text`、64 part以内） |
| `instructions` | 任意の文字列 |
| `background` | 任意のbool |
| `stream` | 省略または `false` だけ |
| `metadata` | 16組以内。keyは64字、valueは512字以内 |
| `store` | `null` は省略扱い。それ以外は `true` だけ。CO側で永続化 |
| `tools` | `null` は省略扱い。それ以外は `[]` だけ |
| `tool_choice` | `null` は省略扱い。それ以外は `unsupported_field` |
| `text` | `null` は省略扱い。それ以外は `{"format":{"type":"text"}}` だけ |
| `include` | `null` / `[]` は省略扱い。それ以外は `unsupported_field` |

SDK 3.24.0の他の要求field（`temperature`、`top_p`、`reasoning`、`max_output_tokens`、`previous_response_id`、`conversation`、`prompt`、`stream_options`、`service_tier`、`moderation`、`truncation`、`user` 等）は `unsupported_field` で拒否し、未知のkeyは `unknown_field` で拒否します。既知のfieldでは、対応・非対応を問わず明示的な `null` を省略扱いにします。この規則で未知のkeyは受理しません。`Idempotency-Key` は任意の単一headerです。`GET /v1/responses/{id}` はcommit済み投影を読み、`POST /v1/responses/{id}/cancel` は空bodyまたは `{}` を受け付け、`GET /v1/models` はaliasを一覧にします。error envelopeは固定で、全体失敗が保持された場合は503を返します。

失敗Responseは `error.code = "server_error"` と `error.message = "<co_code>: <fixed text>"` を持ちます。クライアントは最初の `": "` より前の `co_code` tokenで判別します。その後の固定textは機械判定用ではありません。9種類の `co_code` と固定メッセージ末尾:

| `co_code` | 固定メッセージ末尾 |
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

### ライフサイクルと状態

- `co_v4/cli.py`: `python -m co_v4 --config <abs>`。SIGINT/SIGTERMで停止し、`close()` は `stopped` または `host_stop_unconfirmed` を返します。**ローカルhostの終了処理だけ**を表し、リモートproviderの停止を主張しません。
- state rootごとにflockの所有者は1つです。`ServiceHost` は1プロセス1回だけ使い、最後に所有権を解放します。確認済み `stopped` はローカルのdrain・解放の完了を表し、providerプロセスのライフサイクルは別の所有者が管理します。
- capacity leaseは、要求に正確に結び付いた `NeverStarted` receipt、または本物の `Result` の有無を問わない `CONFIRMED` 停止証拠によってだけ解放します。ResultがなければRunの精算は自身の証拠待ちとして保持します。結果の捏造やleaseの強制解放はしません。
- 制御ストアの契約マーカーは `co.controller/4`（`CONTROLLER_VERSION` 4.0.0）。`OutputStore` は内容digestで識別します。

### 上限と閉じた設定schema

`co.service-host/1` は保護したfd（`0600` / same-uid / nlink-1 / `O_NOFOLLOW`）から読みます。すべての階層でkey集合を固定し、未知fieldは無視せず拒否します。上限は `bind.port` 1024〜65535、`max_body_bytes` 262144以下、`sync_wait_s` 60以下、route64以下、deadlineと `max_drain_s` 1〜600、literalのループバックendpointだけ、handler32枠です。JobごとのAttempt上限は認証済みgrantに従います。

### OpenAI互換サービスの非対応範囲

列挙した範囲以外は対応しません。非ループバックendpoint、tools/function-calling、非text role、クライアントstreaming、資格情報の移行（新しい `0600` keyだけ）、非APFS state root、OS service統合が対象外です。コピーしたNative adapterは既存gate・scopeを保った新しいV4識別子として同梱し、版マーカーは `0.2.0-dev` です（T3 Codeなど）。コピー元baselineはsource commentに記録し、version fieldには使いません。readinessは `unqualified`、`native_tested: []` で、Controller Catalogのコピー済みadapterに実Native証拠はありません。これらはタスク実行器のNative CLI経路とは別です。すでに保留・延期とされた経路は元の状態を維持します。

### テスト

製品コードは標準ライブラリだけですが、SDK統合テストには [requirements-sdk-test.txt](requirements-sdk-test.txt) の固定したテスト依存を別の検証環境に用意する必要があります。repository rootから実行します。[CI workflow](.github/workflows/ci.yml) に分離環境と任意のローカルhost fixtureを記録しています。これらのテストは実providerを呼び出しません。

```sh
cd '<standalone-checkout>'
PYTHONPATH=. python3 -m unittest discover -s tests -v
```

### ソース配布と検証

独立した0.4.5のソース配布に、確認済みengine、CLI、共通Skillを含みます。管理者は元のreleaseと検証証拠を別に保持しています。engineとSkillのbytesは元配布から変えず、build path、test fixture、このREADMEを独立したソース一式に合わせています。

[GitHub workflow](https://github.com/thattor/common-orchestration/actions) はmacOSでofflineテストと決定的buildを検査します。cloud provider、Native adapter、新しいプラットフォームの適格性を証明するものではありません。管理者の初期判断や開発probeの一部は、過去のprivate Issueを参照します。これらは由来であり、公開された導入手順ではありません。旧開発probeは独立した利用者向け入口ではなく、明示起動時のNative呼出しもここでは未検証です。

### ライセンス

Common Orchestrationはthattorが [LICENSE.md](LICENSE.md) のSustainable Use License 1.0に基づいて提供します。再配布時はライセンスと適用されるnoticeを保持してください。利用・配布条件のあるsource-available softwareです。利用登録、報告、変更ソースの開示義務を追加していません。

[NOTICE](NOTICE) に提供者の識別と、保持した第三者templateの由来・Apache-2.0条件があります。
