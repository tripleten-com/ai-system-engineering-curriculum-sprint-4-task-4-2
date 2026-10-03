# Task 4.2 — OIDC and RBAC contract

Protect the exception summary endpoint with verified tokens and one least-privilege role and
scope rule. You configure the supplied verifier in `config/auth.yaml`, apply the supplied
`require_access` rule to `GET /api/v1/exceptions/{exception_id}` in `src/api/routes.py`, and
write eight tests in `tests/student/test_exception_access.py`. You write no verifier, decode
no token yourself, and change no other route.

## What is assessed, and by whom

| Assessed | By |
|---|---|
| The pull request changes only `config/auth.yaml`, `src/api/routes.py`, and `tests/student/test_exception_access.py` | Automated, in this repository |
| `src/api/routes.py` differs from the supplied file only by the access rule on `get_exception` and the imports it needs | Automated, by a static comparison with the supplied file that never imports yours (the file is read as bytes and must be UTF-8); it runs inside `poe verify` before anything imports the module |
| `get_exception` receives the verified `Principal` through the parameter that applies the rule: `principal: Annotated[Principal, Depends(require_access(...))]` or `principal: Principal = Depends(require_access(...))` | Automated, static, over the same bytes (`poe verify`); `dependencies=[...]` on the decorator protects the route but does not complete this row |
| Nothing under the three permitted files or the checks' own files changed while `poe verify` ran | Automated: `poe verify` records a hash snapshot as its first step and checks it as its last |
| `tests/student/test_exception_access.py` imports only `pytest`, the `annotations` future, `typing` names, and `AccessHarness`; uses none of the listed environment names anywhere (`__file__`, `sys`, `importlib`, `getattr`, `open`, `Path`, any dunder, ...); uses `pytest` only for fixtures, marks, `param` and `raises`; gives no function a parameter named after a pytest built-in fixture (`request`, `monkeypatch`, `tmp_path`, ...); and asserts the `.status_code` of a response from the harness client in every test, plus something about its body or `.text` in every test that expects `401` or `403`, itself or in a helper it hands the response | Automated, static, over the file's bytes, never an import (`poe student-guard`, inside `poe verify` before anything executes the file, and the first step of `poe student-tests`); the checks refuse to run a file that fails it |
| `config/auth.yaml` names one algorithm, a leeway inside the policy's range, the policy's audience, and the discovery document's issuer and `jwks_uri` | Automated, against the file, the policy, and the live issuer (`poe verify`) |
| The protected endpoint answers `200` to `dispatcher-valid`, `401` to the four invalid-token fixtures and to a request with no token, and `403` to `gateway-valid`, `wrong-role`, and `missing-scope` | Automated, against the running API (`poe verify`), for an exception the checks create and confirm through the database to have a stored summary |
| No other endpoint's access behavior changed | Automated, against the running API (`poe verify`) |
| Your eight tests pass as written and each really requests a stored exception with its fixture; each rejection test fails when the rule is removed, when 401 and 403 trade places, and when a refusal leaks the summary; the allowed test fails when the summary or the exception id is withheld | Automated, by running your tests with their requests recorded and again against mutated copies of `src/` (`poe verify`) |
| `submission.yaml` still records `answers: {}` | Automated, in this repository (`poe answers`, repeated by `poe verify`) |
| What your `poe auth-checks` table in the pull request shows | Your instructor, at the Task 4 Instructor Review; you use it again at the Project Defense |

There is no protected answer check for this Task: `answers: {}` is the whole answer sheet, and
`poe verify` is the whole automated assessment. The inherited Project 3 checks (smoke,
end-to-end workflow, queue, SLO, gate, and runbook contracts) also run inside `poe verify`, over
the supplied checkpoint, and pass as shipped; from this Task they read summaries with
`dispatcher-valid`.

## The supplied material

| Supplied | Where | Note |
|---|---|---|
| The development token issuer | `compose.yaml` (`issuer`), `infra/issuer/` | Serves the discovery document and the key set on `http://localhost:8180`; signs nothing at runtime. Not student-editable |
| The token verifier | `src/api/security/tokens.py` | `TokenVerifier`, configured from `config/auth.yaml` only: signature against the pinned algorithm and the published key, then issuer, audience, and expiry with leeway. Not student-editable |
| The access rule | `src/api/security/access.py` | `require_access(role=..., scope=...)`, a FastAPI dependency; the call form is in its docstring. It runs the verifier itself, so removing it removes both checks. Not student-editable |
| The eight token fixtures | `tests/fixtures/tokens/fixtures.yaml` | One compact token per fixture name; `tests/security/fixtures.py` loads them. Not student-editable |
| The access policy | `docs/security/access-policy.md` | Roles, scopes, the API audience, the `leeway_seconds` range, and the grants, including exactly one row for reading an exception summary |
| The settled threat model | `docs/student/threat-model.md` | Task 1's completed model; TH-01 is the threat this Task's control (C-01) answers. Not student-editable here |
| The student-test harness | `tests/security/harness.py` | Builds the API from `src/` in-process with a memory store and the real verifier; `tests/student/test_exception_access.py` documents how to use it. When the assessed checks run your file, it records which fixture each test sent and which exception it requested |
| The route guard | `tests/security/route_guard.py` | Compares `src/api/routes.py` with the supplied file as syntax trees, without importing it, after validating that the file is UTF-8; `poe route-guard`, run inside `poe verify` before anything imports the module. The same module checks that the rule is a parameter handing the route the `Principal` |
| The student-test guard | `tests/security/student_guard.py` | Reads `tests/student/test_exception_access.py` as bytes, without running it, and applies five flat rules: its imports, the names it uses anywhere, how it uses `pytest`, its parameter names, and that every test asserts the `.status_code` of a response from the harness client (and the body or `.text` when it expects a refusal); `poe student-guard`, run inside `poe verify` before anything executes the file, as the first step of `poe student-tests`, and repeated by the checks before they run it |
| The integrity snapshot | `tests/security/integrity.py` | Hashes your three files and the checks' own files when `poe verify` starts and compares them when it ends, so a test that rewrites a file behind the checks is named; `poe integrity-record` and `poe integrity-check` |

## The three steps

### Step 1 — Configure token verification

Open the discovery document and the key set at the URLs `README.md` lists, read the audience
and the leeway range in `docs/security/access-policy.md`, and fill in the five values of
`config/auth.yaml`. Run `poe token-check <fixture>` for each of the eight fixtures: it prints
`accepted` or `rejected: <reason>`, and the reason names the failed claim or the signature. At
this point the three valid-but-ungranted fixtures are accepted; Step 2 is what refuses them.

### Step 2 — Protect the summary endpoint

Find the one row of the access policy that grants reading an exception summary. In
`src/api/routes.py`, add `require_access` with that role and that scope as a parameter of
`get_exception`, exactly as the docstring of `src/api/security/access.py` shows, and add the
imports that call form needs (`Annotated`, `Depends`, `require_access`, `Principal`). The rule
must be a parameter, so the route receives the verified `Principal`: the `Annotated[Principal,
Depends(require_access(...))]` form shown, or `principal: Principal =
Depends(require_access(...))`. Putting it in `dependencies=[...]` on the decorator protects
the route but hands it no principal, and the assessed check names that. Change nothing else
in the file: `poe route-guard` compares it with the supplied file and names any other
difference. Run `poe start` again (the API image carries your two files), then
`poe auth-checks`, and read the table: `200` for `dispatcher-valid` only, `401` for the four
invalid tokens, `403` for the three valid tokens the policy does not grant.

### Step 3 — Prove every rejection with tests

Complete the eight marked places in `tests/student/test_exception_access.py`: one allowed test
and one rejection test per refused fixture. Every test creates its own exception with a stored
summary through the harness, requests it through `harness.bearer_client(...)` with its
fixture, and asserts the exact status; the rejection tests also assert that the summary text
is not returned, and the allowed test asserts the exception id and the stored summary. The
checks identify each test by the request it makes, not by what it names: a test counts as the
rejection test for a fixture only when it requests a stored exception as that fixture and no
other. The file describes responses and nothing else, under five flat rules: it imports only
`import pytest`, `from __future__ import annotations`, `from typing import ...`, and
`from tests.security.harness import AccessHarness`; it uses none of `__file__`, `sys`, `os`,
`importlib`, `inspect`, `getattr`, `eval`, `open`, `Path` (the full list is in the table
below) or any `x.__anything__` anywhere, not even as a variable of its own; it uses `pytest`
only as `@pytest.fixture`, `pytest.mark.<name>`, `pytest.param`, and `pytest.raises`; no
function in it, test, fixture, helper, or nested function, has a parameter named `request`,
`monkeypatch`, `tmp_path`, or another pytest built-in fixture, so rename such a parameter,
for example to `resp` (a variable you bind yourself, such as
`request = f"/api/v1/exceptions/{exception_id}"`, is fine); and every test asserts the
`.status_code` of a response it got through `harness.bearer_client(...)`, itself or in a
helper defined in the file that it hands the response (a helper you hand `response.text` or
`response.json()` may hold the body assertion too). `poe student-guard` reads the file and
names anything else, by line, before any check runs it, and `poe student-tests` runs that
guard before it collects your tests. Run `poe student-tests`, then prove the tests can fail
with `poe access-mutation`.

## Commands

```shell
poe route-guard             # src/api/routes.py against the supplied file, without importing it
poe student-guard           # tests/student/test_exception_access.py: imports, names, and asserts, without running it
poe integrity-record        # hash your files and the checks' files; the first step of `poe verify`
poe integrity-check         # compare the tree with that snapshot; the last step of `poe verify`
poe token-check <fixture>   # one fixture through the verifier: accepted / rejected: <reason>
poe auth-config             # config/auth.yaml against the policy and the live discovery document
poe auth-checks             # one request per fixture against the running API, as a Markdown table
poe student-tests           # the student-test guard, then your tests as written
poe student-tests-run       # the bare pytest run behind it; forwards arguments (-k <name>)
poe access-mutation         # what your tests request, then your tests against the five mutated copies of src/
poe access-contract         # the assessed Check-list rows
poe answers                 # the answer sheet's format only
poe verify                  # the full public path
```

Start the stack per `README.md` first; `poe verify` starts it again itself and ingests the
supplied corpus. `poe route-guard`, `poe student-guard`, and `poe answers` are static; every
other command above needs the running issuer, and `poe auth-checks` and `poe access-contract`
need the running API and worker. `poe verify` begins by recording a hash snapshot of your
three files and the checks' own files (`poe integrity-record`), runs the route guard next,
before anything imports `src/api/routes.py`, then the student-test guard, before anything
executes `tests/student/test_exception_access.py`, runs `poe access-contract` right after the
smoke checks, before the inherited end-to-end checks and `poe student-tests`, and ends by
comparing the tree with the snapshot (`poe integrity-check`): a file that changed while the
run was in progress fails that last step by name.

## Check-list rows and the checks that read them

| Check-list row | Check |
|---|---|
| `config/auth.yaml` names the issuer, the audience, the key set URL, one algorithm, and a leeway inside the policy range | `test_auth_config_pins_exactly_one_algorithm`, `test_auth_config_leeway_is_inside_the_policy_range`, `test_auth_config_audience_is_the_access_policy_audience`, `test_auth_config_matches_the_live_discovery_document` |
| `GET /api/v1/exceptions/{exception_id}` requires the role and scope the access policy grants for reading a summary | `test_dispatcher_valid_receives_200_with_the_stored_summary` together with `test_unauthorized_fixtures_receive_403`; `test_routes_module_changed_only_the_access_rule_on_get_exception` checks that the rule is the only change to `src/api/routes.py`, and `test_get_exception_receives_the_principal_through_the_rule_parameter` that the rule is a parameter handing the route the verified `Principal` |
| `dispatcher-valid` receives `200` from the protected endpoint | `test_dispatcher_valid_receives_200_with_the_stored_summary` |
| `bad-signature`, `wrong-issuer`, `wrong-audience`, and `expired` each receive `401` | `test_invalid_token_fixtures_receive_401[<fixture>]`, four cases; `test_a_request_without_a_token_receives_401` adds the request with no token |
| `gateway-valid`, `wrong-role`, and `missing-scope` each receive `403` | `test_unauthorized_fixtures_receive_403[<fixture>]`, three cases |
| No other endpoint's access behavior changed | `test_no_other_endpoint_changed_its_access_behavior`, and `test_routes_module_changed_only_the_access_rule_on_get_exception` for the file itself |
| `tests/student/test_exception_access.py` has one allowed test and one rejection test per refused fixture | `test_student_file_uses_only_the_harness_and_asserts_each_response` first (static: the imports, the names, and a `.status_code` assert in every test, read without running the file; the rows below refuse to run a file that fails it), then `test_student_file_has_one_allowed_test_and_one_rejection_test_per_refused_fixture` (your file is run once with its requests recorded: one case that requested a stored exception as `dispatcher-valid` alone, and one per refused fixture that requested one as that fixture alone) |
| The allowed test asserts the exception id and the stored summary in the response | `test_the_allowed_test_asserts_the_exception_id_and_the_stored_summary` (the `identity-swapped` and `summary-withheld` mutations) |
| Every rejection test requests an exception with a stored summary, asserts the exact status, and asserts that the summary text isn't returned | `test_each_rejection_test_asserts_the_exact_status_without_the_summary` (the `status-swapped` and `rejection-summary-leaked` mutations; the recorded requests show the stored exception), with the row below |
| Each rejection test fails when the access rule is removed | `test_each_rejection_test_fails_when_the_access_rule_is_removed` (the `rule-removed` mutation) |
| `submission.yaml` still records `answers: {}` | `test_submission_records_no_answers`, and `poe answers` |
| The pull request modifies only `config/auth.yaml`, `src/api/routes.py`, and `tests/student/test_exception_access.py` | `test_submission_change_stays_within_the_permitted_diff` in `tests/contract/test_authoring_contract.py`, and `poe submission` (the `tests/contract/submission_validation.py` module, which applies the same boundary) inside `poe verify` |

All of these live in `tests/contract/test_exception_access.py` except the last, which is the
test `test_submission_change_stays_within_the_permitted_diff` in
`tests/contract/test_authoring_contract.py`; the module behind `poe answers` and
`poe submission`, `tests/contract/submission_validation.py`, applies the same permitted-files
boundary as a command. They are marked `assessed`: `poe contract` leaves them out, and
`poe access-contract` and `poe verify` run them. The rows that request the API or run your
tests are also marked `runtime`. A fresh checkout fails most of them, which is the exercise;
`test_routes_module_changed_only_the_access_rule_on_get_exception`,
`test_student_file_uses_only_the_harness_and_asserts_each_response`,
`test_dispatcher_valid_receives_200_with_the_stored_summary`, and
`test_no_other_endpoint_changed_its_access_behavior` pass on it, because the two files are as
supplied (the template has no tests to check yet) and the route is still open.

## What the checks verify

| Check | What it looks at |
|---|---|
| `tests/security/route_guard.py` | `src/api/routes.py` read as bytes (its source encoding must be UTF-8, with or without a BOM or a `coding` line saying so; any other declaration is rejected before anything is compared), parsed, never imported, and compared with the supplied file statement by statement as syntax trees (formatting and comments are invisible). Permitted differences: the four imports the rule needs, one `Depends(require_access(role=..., scope=...))` on `get_exception` in any of its three forms, and docstrings. Every other route, `get_exception`'s body and `exception_id: str` parameter, and every module-level statement must be the supplied ones; anything else is named, by statement. The completion row then requires that one application to be a parameter annotated `Principal` (directly or through `Annotated`), so the route receives the verified principal |
| `tests/security/student_guard.py` | `tests/student/test_exception_access.py` read as bytes (UTF-8 only, as for the route module), parsed, never imported. Five flat rules, each by presence and with no exemption for a binding the file makes itself. **Imports:** exactly `import pytest`, `from __future__ import annotations`, `from typing import ...`, and `from tests.security.harness import AccessHarness`; everything else is rejected wherever it appears, `from pytest import ...` and `import typing` included, and `as` is rejected except on a typing name. **Names:** `__file__`, `__import__`, `__builtins__`, `importlib`, `inspect`, `sys`, `os`, `subprocess`, `builtins`, `globals`, `locals`, `vars`, `getattr`, `setattr`, `delattr`, `eval`, `exec`, `compile`, `open`, `Path`, every dunder (`x.__class__`, `__spec__`), the frame, code and traceback attributes, and the harness's path handles (`root`, ...) are rejected in every position: a read, an assignment or loop target, a comprehension target, a parameter, an import alias, a function or class name, and the attribute of any `x.<name>`; so `eval = eval` is two findings, not a variable. **Pytest:** `pytest` is used only as `@pytest.fixture` (bare or called, directly in a decorator list), `pytest.mark.<name>`, `pytest.param`, and `pytest.raises`; any other `pytest.<attribute>`, `pytest.fixture` assigned or passed, and `pytest` on its own are rejected. **Parameters:** no function, whether a test, a fixture, a helper, a nested function, or a lambda, has a parameter named `request`, `monkeypatch`, `pytestconfig`, `capsys`, `capfd`, `caplog`, `tmp_path`, `tmp_path_factory`, `recwarn`, or another pytest built-in fixture; the finding says to rename it, for example to `resp`. A local variable of that name is fine. **Assertions:** every collected test (`test*` functions and `test*` methods of `Test*` classes) has an `assert` comparing the `.status_code` of a response obtained from the harness client (`harness.bearer_client(...)`, a name bound from it, or the result of a helper that returns one), in the test, in a function nested in it, or in a module-level helper it calls; a test that compares against `401` or `403` must also have an `assert` about that response's `.text`, `.content`, `.json()`, or a name bound from one of them. Provenance into a helper is per parameter and per call: `assert_no_summary(response.text, summary)` makes that helper's first parameter the body and nothing else, so an assert in another helper over a parameter that merely shares the name counts for nothing. Only presence is checked here; the mutations check that the assertions can fail. A file with findings is never executed by any check, and `poe student-tests` runs this guard before pytest collects the file |
| `tests/security/integrity.py` | SHA-256 digests of `config/auth.yaml`, `src/api/routes.py`, `tests/student/test_exception_access.py`, and every file under `tests/contract/`, `tests/security/`, `src/api/security/`, `tests/fixtures/tokens/`, plus `pyproject.toml`, recorded to a file outside the repository when `poe verify` starts and compared when it ends. Any file changed, added, or removed in between is named and fails the last step |
| `tests/security/auth_config.py` | `config/auth.yaml` parsed as the five published keys: `algorithms` is a list of exactly one name; `leeway_seconds` is a whole number inside the policy's range; `audience` equals the policy's API audience; `issuer` and `jwks_url` equal the live discovery document's `issuer` and `jwks_uri`, and the one algorithm is one the issuer declares |
| The live rows | One exception created through the running stack's open intake and waited for through the database (`tests/security/live_record.py` polls the `exceptions` table inside the `postgres` container until the record is `COMPLETED` with a non-empty summary; `FAILED` or a timeout is an error on every live row, not a row's failure), then requested once per fixture with that fixture's bearer token and once with no token; the status, and that no record came back on a refusal. Plus an in-range reading reaching the intake's own validation, a document listing, and the health and version probes, all without a token |
| `tests/security/mutation.py` | First the student-test guard above must pass, or nothing below runs. Then your file is run once as written with the harness recording every request each test makes: the fixture it sent and whether the exception it requested has a stored summary. That record decides which test is the allowed test (requested a stored exception as `dispatcher-valid` alone) and which is each fixture's rejection test (requested one as that fixture alone); eight such cases are required, and a parametrized test counts once per parameter. Each case is identified by its full pytest node id (class and parameter included), so two tests with one method name in two classes are two cases. Then five reruns of your file against a copy of `src/` with one change: `rule-removed` strips `require_access` from `get_exception` (every rejection test must fail); `status-swapped` makes the rule answer 403 for 401 and 401 for 403 (every rejection test must fail, so each asserts its exact status); `rejection-summary-leaked` keeps every refusal's status but puts the requested record's stored summary in the response (every rejection test must fail, so each asserts the summary is not returned); `summary-withheld` returns the record with `summary: null` and `identity-swapped` returns it under another id (the allowed test must fail under each). Only a test outcome of `failed` counts: a test that still passes, is skipped, or errors is reported by name, and an error makes that rerun invalid. A test that asserts `status_code != 200`, or forgets the summary, still passes a mutation and is reported by name. The copied files are read as UTF-8 with or without a BOM, as the route guard accepts them |
| `tests/contract/submission_validation.py` (`poe answers`, `poe submission`) and `test_submission_change_stays_within_the_permitted_diff` in `tests/contract/test_authoring_contract.py` | `submission.yaml` is one plain YAML mapping whose `answers` is present and empty; the diff from the merge base with `main` touches only the three permitted files, with no directory prefix exempted. The command and the test apply the same boundary |

The runs of your file leave your files untouched: each mutation copies `src/` to a temporary
directory, changes the copy, runs your test file against it, and deletes the copy; the
recording of your requests goes to a temporary file the checks read and delete.

## Student-editable paths

- `config/auth.yaml`
- `src/api/routes.py` (the `get_exception` route only)
- `tests/student/test_exception_access.py`

That is the whole list. The issuer, its key set, the token fixtures, the access policy, the
supplied middleware under `src/api/security/`, the supplied tests, `compose.yaml`, and the
workflows stay as supplied. Before you push, run `git status` and `git diff --stat`: if anything
else changed, the public check reports the boundary violation rather than your work. Inside
`src/api/routes.py` the same holds for every statement but the one route: `poe route-guard`
reports any other difference from the supplied file before `poe verify` runs anything else.
