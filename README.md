# Coldline Task 4.2 — OIDC and RBAC

This repository starts from the Task 1 checkpoint, with the settled threat model under
`docs/student/threat-model.md`, and adds what the API needs to identify its caller: a
development token issuer in `compose.yaml`, supplied token-checking middleware under
`src/api/security/`, eight token fixtures under `tests/fixtures/tokens/`, and the access
policy in `docs/security/access-policy.md`. At this checkpoint
`GET /api/v1/exceptions/{exception_id}` still answers any caller that can reach the API. You
configure the verifier, protect that one endpoint with one least-privilege role and scope
rule, and prove every rejection with tests.

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/tripleten-com/ai-system-engineering-curriculum-sprint-4-task-4-2/tree/main)

## Start the system

Prerequisites are Python 3.12 and Docker with Compose v2. The supplied bootstrap supports macOS
arm64/x86-64, Windows x86-64, and Linux x86-64/aarch64, and installs pinned uv 0.11.8 under
`.tools/bin`. If your computer cannot run the stack locally, use the Codespaces button above.

On macOS and most Linux distributions the interpreter is `python3`; substitute it wherever these
commands say `python`.

```shell
python infra/scripts/bootstrap.py
./.tools/bin/uv sync --frozen
./.tools/bin/uv run --frozen poe preflight
./.tools/bin/uv run --frozen poe start
./.tools/bin/uv run --frozen poe ready
./.tools/bin/uv run --frozen poe ingest
```

PowerShell and POSIX wrappers are available under `infra/scripts/`. After uv is on `PATH`, the
shorter `uv run --frozen poe <task>` form works; in PowerShell on Windows the pinned binary is
`.tools/bin/uv.exe`.

| Service | Local URL | Purpose |
|---|---|---|
| API | `http://localhost:8000` | Submit readings, poll exception summaries, search procedures |
| Token issuer: discovery document | `http://localhost:8180/.well-known/openid-configuration` | The development issuer's OIDC discovery document: its `issuer` and `jwks_uri` |
| Token issuer: key set | `http://localhost:8180/.well-known/jwks.json` | The published key set (JWKS); note the `alg` its one key declares |
| Jaeger | `http://localhost:16686` | Open traces |
| Grafana | `http://localhost:3000` | Use the focused diagnostics dashboard |
| Prometheus | `http://localhost:9090` | Query bounded metrics and inspect the deployed alert rule |
| Alertmanager | `http://localhost:9093` | Inspect firing and resolved alerts |
| LocalStack S3/SQS | `http://localhost:4566` | Inspect the emulated object-storage and queue endpoint |

Each of these ports can be overridden by setting the matching `COLDLINE_API_HOST_PORT`,
`COLDLINE_ISSUER_HOST_PORT`, `COLDLINE_JAEGER_HOST_PORT`, `COLDLINE_GRAFANA_HOST_PORT`,
`COLDLINE_PROMETHEUS_HOST_PORT`, `COLDLINE_ALERTMANAGER_HOST_PORT`, or
`COLDLINE_LOCALSTACK_HOST_PORT` environment variable in your shell environment or a local
`.env` file (copy `.env.example`) if a default collides with something already running on your
machine. Keep the override in place for every `poe` command. The issuer's discovery document is
rendered when its container starts, from the issuer port actually in use, so its `jwks_uri` is
always the URL to copy into `config/auth.yaml`; the `issuer` value never changes with the port.

This Task runs as its own Compose project, `coldline-task-4-2`. If an earlier Task's stack is
still running, run `poe stop` in that Task's repository first; otherwise `poe start` here fails
because the published ports are already taken.

PostgreSQL, Redis, worker metrics, and OTLP remain inside the Compose network. Codespaces uses the
same `compose.yaml` and keeps every forwarded port private. Redis keeps running only for an
earlier checkpoint's own contract test; no composition root reads it anymore.

### How the API reaches the key set

`config/auth.yaml` names the key set by the host URL the discovery document prints
(`http://localhost:8180/...`), which is what your browser, `poe token-check`, and your tests
open. Inside the Compose network that host port does not exist, so `compose.yaml` gives the API
`COLDLINE_ISSUER_JWKS_ORIGIN=http://issuer:8180`, and the supplied `TokenVerifier` swaps the
origin of your `jwks_url` for it while keeping the path. A wrong path in `jwks_url` therefore
fails inside the container exactly as it does on the host; nothing about the mapping relaxes
the check. [TokenIssuer fidelity](docs/fidelity/TokenIssuer.md) records the rest of what this
development issuer does and does not prove.

### After you edit a file

The API image carries `config/auth.yaml` and `src/api/routes.py` as they were when it was
built. After editing either, run `poe start` again: it rebuilds the image and recreates the
API container. `poe restart` restarts containers without rebuilding and is not enough.
`poe token-check` and `poe student-tests` read `config/auth.yaml` from your checkout directly
and need no rebuild, only the running issuer.

## Command path

For this Task, run the supplied commands in this order:

```text
poe start
poe ingest
poe token-check <fixture>
poe auth-checks
poe student-tests
poe verify
```

The exact public command is `./.tools/bin/uv run --frozen poe verify`, run from the repository
root. Where a Task page shortens a command to `poe <task>`, that is the form it means.

| Command | Use |
|---|---|
| `poe route-guard` | Compare `src/api/routes.py` with the supplied file without importing it (the file must be UTF-8): only the access rule on `get_exception` and the imports it needs may differ. Runs inside `poe verify` before anything imports the module |
| `poe student-guard` | Read `tests/student/test_exception_access.py` without running it and apply five flat rules: only `import pytest`, the `annotations` future, `typing` names, and `AccessHarness` may be imported; none of the listed environment names (`__file__`, `sys`, `importlib`, `getattr`, `open`, `Path`, any dunder, ...) appears anywhere, not even as a variable of the file's own; `pytest` is used only for fixtures, marks, `param` and `raises`; no function has a parameter named after a pytest built-in fixture (`request`, `monkeypatch`, `tmp_path`, ...: rename it, for example to `resp`; a local `request = f"/api/v1/exceptions/{exception_id}"` is fine); and every test asserts the `.status_code` of a response from the harness client (and its body or `.text` when it expects 401 or 403, itself or in a helper it hands the response). Runs inside `poe verify` before anything executes the file and as the first step of `poe student-tests`; the assessed checks refuse to run a file it rejects |
| `poe integrity-record`, `poe integrity-check` | The first and last steps of `poe verify`: hash your three files and the checks' own files into a snapshot outside the repository, then compare the tree with it, so a file that changed while the run was in progress is named |
| `poe token-check <fixture>` | Run one fixture from `tests/fixtures/tokens/` through the supplied verifier as `config/auth.yaml` configures it; prints `accepted` or `rejected: <reason>`. The reason names the failed claim or the signature |
| `poe auth-checks` | Create one exception with a stored summary through the running stack, request it once per fixture with that fixture's bearer token, and print a Markdown table of fixture, status, and reason. Paste the table into your pull request. Its wait reads the status URL as the dispatcher, so a refused read shows up in the table; the assessed checks wait through the database instead |
| `poe auth-config` | Check `config/auth.yaml` against `docs/security/access-policy.md` and the issuer's live discovery document: one algorithm, leeway in range, the policy's audience, the discovery document's issuer and `jwks_uri` |
| `poe student-tests` | Run the student-test guard, then the supplied tests under `tests/student/`, including your `test_exception_access.py`; a file the guard rejects is named and never collected. `poe student-tests-run` is the bare pytest run behind it and forwards arguments (`poe student-tests-run -k <name>`), as `poe e2e-tests` does for `poe e2e` |
| `poe access-mutation` | Run your access tests once, recording which fixture each test sent and which exception it requested, then rerun them against copies of the route and the rule with one thing changed each (the rule removed, 401 and 403 swapped, the summary leaked into refusals, the summary withheld, the exception id swapped) and report which of your tests still pass |
| `poe access-contract` | The assessed checks, one per Check-list row: the route guard, the settings, one request per fixture and one without a token, and your tests as written and under the mutations above |
| `poe answers` | The answer sheet's format only: `submission.yaml` records `answers: {}` |
| `poe submission` | The same check plus the permitted-files boundary: the diff from your merge base touches only the three permitted files |
| `poe verify` | The public student verification path: it starts the stack, exercises the inherited platform, and runs this Task's own checks |
| `poe scenario` | Task 1's walkthrough, kept: send the supplied reading and print the exception and trace ids. It reads the status URL with `dispatcher-valid` |
| `poe queue-contract`, `poe slo-contract`, `poe gate-contract`, `poe runbook-contract` | Project 3's own checks, inherited and passing as shipped; `poe verify` runs them |
| `poe contract` | Check interfaces, boundaries, submissions, and repository structure |
| `poe smoke` | Check the initialized running platform, including the issuer's documents |
| `poe e2e` | Run the external API-to-worker workflow, including the joined trace |
| `poe migrate`, `poe migrate-down`, `poe migrate-current` | Step the schema by hand; the initializer brings it to head on every start |
| `poe restart` | Restart the existing API and worker containers **without rebuilding** |
| `poe stop` | Remove containers and the network, keeping named volumes |
| `poe reset` | Remove containers, the network, and local named volumes |

`poe verify` records an integrity snapshot of your three files and the checks' own files,
runs the route guard before anything imports `src/api/routes.py`, runs the student-test
guard before anything executes `tests/student/test_exception_access.py`, then the unit
tests; it starts the stack, ingests the supplied corpus, runs the smoke tests, then this
Task's assessed checks (`config/auth.yaml` against the policy and the live discovery
document; the rule as a parameter handing `get_exception` the verified `Principal`; the
student file's imports, names, and assertions; `200`, `401`, and `403` per fixture and `401`
with no token against the running API, for an exception confirmed through the database to
hold a stored summary; your tests as written, with their requests recorded, and under the
supplied mutations), then the end-to-end exception workflow, the inherited queue, SLO, gate,
and runbook checks, the answer-sheet format check, your student tests (behind the
student-test guard again, as `poe student-tests` always runs them), the permitted-files
boundary, and finally the integrity check against the snapshot. The Project 3
exercise commands
(`poe inject-failure`, `poe redrive`, `poe trigger-alert-load`, `poe verify-alert-recovery`,
`poe dev-failure-lab`) still run but are not part of this Task; they read summaries as the
dispatcher too.

## Folder map

```text
repository root/
├── config/              Retrieval configuration, settled since Sprint 2, and auth.yaml, which you complete
├── docs/                Student guidance, public contracts, fidelity notes, and the security material
│   ├── contracts/       Machine-readable public contracts, including this Task's (empty) answer schema
│   ├── fidelity/        Local-runtime boundary notes for each active adapter, including the token issuer
│   ├── security/        The supplied workflow, threat catalog, scoring rule, control matrix, and access policy
│   ├── architecture/    Supplied vector engine technical profiles, in prose
│   ├── retrieval/       Supplied retrieval pipeline reference
│   └── student/         This Task's contract, the settled threat model, and the supplied Project 3 runbook
├── infra/               Local setup and runtime configuration
│   ├── containers/      The API and worker Dockerfiles, with the build identity arguments
│   ├── issuer/          The development token issuer: its server script and the published key set
│   ├── observability/   Prometheus, Alertmanager, and Grafana configuration
│   ├── release/         The supplied release manifest, unchanged
│   ├── corpus/          Supplied synthetic corpus, query set, and designated investigation
│   ├── judge/           Supplied cached judge evidence and its provenance record
│   ├── profiles/        Supplied engine and emulator profiles, and their provenance record
│   └── postgres/        Database initialization and the migration baseline stamp
├── loadtest/            Supplied traffic profile and provider-latency harness
├── migrations/          Alembic environment, revision template, and revisions
├── src/
│   ├── api/             HTTP application code, the retrieval and document paths, composition
│   │   └── security/    The supplied TokenVerifier and require_access rule; not student-editable
│   ├── worker/          Background application code, the procedure lookup, the dead-letter depth poller
│   ├── domain/          Shared domain code, contracts, the failure taxonomy, service and repository contracts
│   ├── ports/           Application interfaces
│   └── adapters/        Technology-specific implementations, including the model emulator and the SQS adapter
└── tests/
    ├── unit/            Isolated behavior checks, including the verifier's and the mutation tooling's
    ├── benchmark/       Supplied evaluation harness, metrics, and adoption policy
    ├── contract/        Interface, retrieval, and repository checks, and this Task's assessed access checks
    ├── diagnostics/     Supplied stage inspector
    ├── doubles/         Supplied deterministic test doubles
    ├── failure/         Supplied Project 3 failure-lab and exercise scripts; not this Task's work
    ├── fixtures/        Supplied fixtures, including tokens/fixtures.yaml, the eight token fixtures
    ├── security/        Supplied tooling: the fixture loader, the in-process harness, the two static guards, token-check, auth-checks, mutations
    ├── student/         Your test_exception_access.py beside the supplied boundary tests
    ├── smoke/           Running-platform checks
    └── e2e/             Supplied workflow tools and checks, including `poe scenario`
```

## Overview

Use the Task 2 lesson (Task 4.2 in this repository) to decide what to do. This README covers
local setup and repository orientation.

1. `README.md` — local setup, commands, and permitted changes.
2. [`docs/student/task-4-2-contract.md`](docs/student/task-4-2-contract.md) — what this Task
   assesses and who assesses it, the Check-list rows and the checks that read them, and the
   three permitted paths.
3. [`docs/security/access-policy.md`](docs/security/access-policy.md) — the roles, scopes, API
   audience, leeway range, and the grants, including the one row for reading a summary.
4. [`src/api/security/access.py`](src/api/security/access.py) and
   [`src/api/security/tokens.py`](src/api/security/tokens.py) — the supplied rule and verifier,
   with the call form in the first file's docstring.
5. [`tests/student/test_exception_access.py`](tests/student/test_exception_access.py) — the
   template you complete, with the harness documented in its docstring.
6. [`docs/student/threat-model.md`](docs/student/threat-model.md) — the settled Task 1 threat
   model this Project's controls answer; TH-01 is the threat this Task closes with C-01.

The application source lives in five flat packages:

| Package | Responsibility |
|---|---|
| `api` | HTTP delivery, API use cases, the retrieval workflow, versioned routes, token verification and the access rule, configuration, and composition |
| `worker` | Background processing, retries, procedure lookup, the dead-letter depth poller, configuration, and composition |
| `domain` | Provider-neutral contracts, state rules, identity, redaction, embedding, chunking, fusion, access constraints, failure classification, service and repository contracts |
| `ports` | Exactly five visible application interfaces |
| `adapters` | PostgreSQL, pgvector retrieval, LocalStack SQS/DLQ, S3-compatible object storage, the deterministic model emulator, the resilient model-provider wrapper, logs, traces |

`src/api/bootstrap.py` and `src/worker/bootstrap.py` compose each process from its settings and
adapters. Process settings live in `src/api/config.py` and `src/worker/config.py`; the token
verification settings live in `config/auth.yaml`.

## The five ports

Find the available interfaces in `src/ports/`. A port describes an application capability; an
adapter provides it using a concrete technology.

| Port | General responsibility |
|---|---|
| `ModelProvider` | Call an AI model service; from the Project 4 opening checkpoint it returns the provider's raw answer text |
| `Retriever` | Look up relevant context or documents; the worker calls it too |
| `ObjectStore` | Store large binary objects or files |
| `JobQueue` | Publish and consume background work |
| `SecretProvider` | Read API keys and credentials; no adapter is composed yet |

## Test levels

| Level | Requires Compose | Main question |
|---|---:|---|
| Unit | No | Does one responsibility behave correctly, including failures? |
| Contract | Some | Do interfaces, schemas, paths, and dependency rules stay compatible? |
| Smoke | Yes | Did the complete local platform initialize and become observable? |
| E2E | Yes | Can an external client complete the supplied workflow, in one trace? |
| Student | Issuer | Does the protected endpoint admit the dispatcher and refuse the seven other fixtures? |

Contract checks marked `runtime` need the running stack. `poe contract` skips them; `poe verify`,
`poe runtime-contract`, `poe queue-contract`, `poe slo-contract`, and `poe gate-contract` run them.
Contract checks marked `assessed` read your three files and the running API and are expected to
fail on a fresh checkout; `poe contract` skips them too, and `poe access-contract` and
`poe verify` run them. Your student tests build the API in-process from `src/` and verify tokens
against the key set at the `jwks_url` you configured, so they need the issuer running.

## Submission checks

Run `poe verify` locally before opening your student pull request. Public GitHub CI repeats
the student checks, running `poe answers` first so a malformed sheet fails fast. This Task
records `answers: {}` and has no protected answer check: your configuration, your access rule,
and your tests are the evidence, and `poe verify` is the whole automated assessment. Follow the
Task lesson's instructor-review and progression policy.

## Task boundary

Task 4.2 asks you to complete `config/auth.yaml`, apply the supplied access rule to
`GET /api/v1/exceptions/{exception_id}` in `src/api/routes.py`, write the eight tests in
`tests/student/test_exception_access.py`, run `poe verify`, open a pull request that changes
only those three files, and add the `poe auth-checks` table to the pull request description
with the command and when you ran it.

The only student-editable paths are:

- `config/auth.yaml`
- `src/api/routes.py`
- `tests/student/test_exception_access.py`

Keep the issuer (`compose.yaml`, `infra/issuer/`), its key set, the token fixtures under
`tests/fixtures/tokens/`, the access policy, the supplied middleware under `src/api/security/`,
the supplied tests, and `.github/workflows/task.yml` exactly as supplied; the public check
compares the diff from your merge base against the three permitted files and reports any other
change as a boundary violation. In `src/api/routes.py`, change the `get_exception` route only:
`poe route-guard` compares the file with the supplied one and names any other difference.

### Student walkthrough

See **Task 2: OIDC and RBAC** in your course platform for the full walkthrough. In outline:
start the stack, open the discovery document and the key set, read the access policy, fill in
`config/auth.yaml`, run `poe token-check` for each fixture, apply `require_access` to
`get_exception` with the role and scope the policy grants, run `poe start` again and then
`poe auth-checks`, write the eight tests, run `poe student-tests`, prove the rejection tests
can fail, run `poe verify`, open and merge your pull request, and submit on the platform.

## Operational limits

This local system does not authenticate users against a managed identity provider, terminate
TLS, or manage production secrets. The token issuer is a development service: it publishes one
fixed key set over plain HTTP and issues no tokens; the eight fixtures were signed once and
committed, and they grant nothing outside this repository. The Compose PostgreSQL password and
the LocalStack access keys are local-only non-secret credentials. The worker's model-provider
key is a development literal for the emulator; it grants nothing anywhere. Never place real
credentials, personal data, or production records in this repository. The handling note in the
supplied scenario is synthetic; test with the supplied readings only.

Alertmanager here is configured with a "default" receiver that has no notification integration:
alerts are queryable through its own API but never sent anywhere real. Never add a webhook, email,
Slack, or paid integration; Sprints 1-4 are emulator-only and never call a hosted endpoint.

LocalStack's SQS emulation is a local reliability primitive, not a managed-service durability,
IAM, availability, or cost claim. Stopping and starting one Compose container is a local fault
control, not an ECS service event. See [JobQueue fidelity](docs/fidelity/JobQueue.md) for the
exact boundary.

Named volumes preserve local PostgreSQL, Redis, Prometheus, Alertmanager, Grafana, and Jaeger state
across `poe stop`. LocalStack object and queue contents are deliberately not persisted; the
initializer re-uploads the supplied corpus artifacts and re-provisions the queue on every start.
The `poe reset` command deletes the named volumes. This topology makes no backup, replication,
high-availability, disaster-recovery, capacity, latency-SLO, or availability claim beyond what
Project 3 settled.

See [TokenIssuer fidelity](docs/fidelity/TokenIssuer.md),
[JobQueue fidelity](docs/fidelity/JobQueue.md),
[ModelProvider fidelity](docs/fidelity/ModelProvider.md),
[ObjectStore fidelity](docs/fidelity/ObjectStore.md), and
[Retriever fidelity](docs/fidelity/Retriever.md) for the active adapter boundaries. The
[local runtime evidence](docs/fidelity/local-runtime.md) records the current measurement and its
qualification limits.
