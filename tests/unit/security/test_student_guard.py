"""Coldline.

===================

File:              tests/unit/security/test_student_guard.py
Component:         Unit tests — Static student-test guard
Purpose:           Prove the guard accepts tests that describe responses and rejects every
                    way a test could inspect its environment instead, before any execution.
Interacts With:    tests/security/student_guard.py, pyproject.toml
Sprint/Task:       Sprint 4 — Project 4 / Task 4.2
Concepts:          Trusted static analysis, closed import set, flat name rules, assertions
                    over responses
Tools:             Python 3.12, pytest, tomllib

Every test here feeds a synthetic source to the guard; none reads the shipped student
file, whose state is the student's (the assessed row and `poe student-guard` read it). The
authoring suite checks the shipped template and the private completions separately. One
test runs the real `poe student-tests` sequence in a scratch project, to prove a rejected
file's module-level code never executes through that command. The snippets that spell
`eval`, `__file__` or `pytest.fixture` are source text handed to the parser; nothing here
executes them.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import sysconfig
import tomllib
from pathlib import Path

import pytest

from tests.security import student_guard
from tests.security.fixtures import EXPECTED_STATUS, REFUSED

TASK_ROOT = Path(__file__).resolve().parents[3]

HEADER = '''"""Student tests."""

import pytest

from tests.security.harness import AccessHarness


@pytest.fixture
def harness() -> AccessHarness:
    """Return a fresh in-process API."""
    return AccessHarness()
'''

ALLOWED_TEST = '''

async def test_dispatcher_valid_reads_the_stored_summary(harness: AccessHarness) -> None:
    """200 with the id and the summary."""
    exception_id, summary = harness.stored_exception()
    async with harness.bearer_client("dispatcher-valid") as client:
        response = await client.get(f"/api/v1/exceptions/{exception_id}")

    assert response.status_code == 200
    body = response.json()
    assert body["exception_id"] == exception_id
    assert body["summary"] == summary
'''

REJECTION_TEST = '''

async def test_expired_is_refused_with_401(harness: AccessHarness) -> None:
    """401, and no summary comes back."""
    exception_id, summary = harness.stored_exception()
    async with harness.bearer_client("expired") as client:
        response = await client.get(f"/api/v1/exceptions/{exception_id}")

    assert response.status_code == 401
    assert summary not in response.text
'''

ACCEPTED = HEADER + ALLOWED_TEST + REJECTION_TEST
STATUS_AND_BODY = (
    "    assert response.status_code == 401\n    assert summary not in response.text\n"
)
RENAME = "rename it, for example to `resp`"


def _guard(source: str | bytes) -> list[str]:
    return student_guard.findings_for_source(source)


def _line_of(source: str, needle: str) -> int:
    """Return the 1-based line of the first line containing ``needle``."""
    return next(number for number, line in enumerate(source.splitlines(), 1) if needle in line)


def _named(found: list[str], name: str) -> list[int]:
    """Return the lines on which ``name`` is reported as a forbidden name."""
    prefix = "line "
    return [
        int(finding[len(prefix) :].split(":", 1)[0])
        for finding in found
        if finding.startswith(prefix)
        and f"`{name}` is not permitted in the student file" in finding
    ]


def _file_counterexample() -> str:
    """Return Astra's round-3 counterexample: eight tests that assert where routes.py lives.

    Each test makes the request the inventory requires, as its fixture, and then asserts
    only that the imported route module belongs to the original checkout. As written it
    passes; under every mutation the copy lives elsewhere, so it fails; and it says
    nothing about any response.
    """
    tests = ["import api.routes\n\nORIGINAL = api.routes.__file__\n"]
    for fixture in ("dispatcher-valid", *REFUSED):
        name = fixture.replace("-", "_")
        tests.append(
            f"\n\nasync def test_{name}(harness: AccessHarness) -> None:\n"
            f'    """Request as {fixture}, then look at the environment."""\n'
            "    exception_id, _ = harness.stored_exception()\n"
            f'    async with harness.bearer_client("{fixture}") as client:\n'
            '        await client.get(f"/api/v1/exceptions/{exception_id}")\n'
            "    assert api.routes.__file__ == ORIGINAL\n"
        )
    return HEADER + "\n" + "".join(tests)


def test_the_template_shape_with_no_tests_passes_vacuously() -> None:
    """The shipped template's shape (imports, the fixture, no tests) has nothing to report.

    The executed-case inventory is what requires the eight tests; the guard only refuses
    files that must not be executed, and an empty one is harmless to run.
    """
    assert _guard(HEADER) == []
    assert _guard("") == []


def test_tests_that_describe_responses_are_accepted() -> None:
    """One allowed test and one rejection test in the reference's shape pass."""
    assert _guard(ACCEPTED) == []
    assert _guard(ACCEPTED.encode("utf-8")) == []


def test_astras_eight_case_file_counterexample_is_rejected_before_any_execution() -> None:
    """Eight tests asserting `api.routes.__file__` are named three ways and never run.

    The import of `api.routes` is outside the permitted set, `__file__` is a forbidden
    attribute, and no test compares a `.status_code`.
    """
    found = _guard(_file_counterexample())

    assert any("`import api.routes` is not permitted" in finding for finding in found)
    assert sum("`__file__` is not permitted" in finding for finding in found) == 9
    missing_status = [finding for finding in found if "has no `assert` comparing" in finding]
    assert len(missing_status) == 8
    assert "`test_dispatcher_valid` has no `assert` comparing a response's `.status_code`" in found
    assert "`test_expired` has no `assert` comparing a response's `.status_code`" in found


# Each snippet is source text handed to the guard as a string; nothing here is executed.
@pytest.mark.parametrize(
    "snippet, name",
    [
        ("    import sys\n    assert 'pytest' in sys.modules\n", "sys"),
        ("    assert getattr(response, 'status_code') == 401\n", "getattr"),
        ("    assert open('config/auth.yaml').read()\n", "open"),
        ("    assert eval('1') == 1\n", "eval"),
        ("    assert __import__('os')\n", "__import__"),
        ("    assert response.__class__.__module__\n", "__class__"),
        ("    assert harness.root\n", "root"),
        ("    assert client.get.__code__.co_filename\n", "__code__"),
        ("    import importlib\n    assert importlib\n", "importlib"),
        ("    from pathlib import Path\n    assert Path('x')\n", "Path"),
        ("    assert __spec__.origin\n", "__spec__"),
        ("    assert delattr(harness, 'root') is None\n", "delattr"),
    ],
)
def test_each_forbidden_name_or_attribute_is_named_by_line(snippet: str, name: str) -> None:
    """A forbidden name as a Name, an Attribute, or an import binding is one finding by line."""
    source = ACCEPTED.replace("    assert response.status_code == 401\n", snippet, 1)
    found = _guard(source)

    assert any(f"`{name}` is not permitted in the student file" in finding for finding in found), (
        found
    )
    assert all(finding.startswith("line ") for finding in found if "not permitted" in finding)


def test_forbidden_names_are_rejected_wherever_they_appear_with_no_binding_exemption() -> None:
    """Astra's round-3b finding 1: a binding does not make a forbidden name ordinary.

    `eval = eval` resolves the right-hand side to the real builtin, and a comprehension
    target binds nothing in the enclosing function; the earlier binding exemption accepted
    both. Now every position is a finding: a read, an assignment target, a `for`, `with` or
    comprehension target, a parameter of any function, a lambda parameter, an import alias,
    a function or class name, a `global` statement, and an exception-handler name.
    """
    module_level = HEADER + "\neval = eval\nenvironment = eval('globals()')\n" + REJECTION_TEST
    found = _guard(module_level)
    assert _named(found, "eval") == [
        _line_of(module_level, "eval = eval"),
        _line_of(module_level, "environment = eval"),
    ]
    assert [finding for finding in found if "not permitted" not in finding] == []

    comprehension = ACCEPTED.replace(
        "    assert response.status_code == 401\n",
        "    unused = [eval for eval in ()]\n"
        "    environment = eval('globals()')\n"
        "    assert response.status_code == 401\n",
    )
    found = _guard(comprehension)
    assert _named(found, "eval") == [
        _line_of(comprehension, "unused = [eval"),
        _line_of(comprehension, "environment = eval"),
    ]

    every_position = ACCEPTED.replace(
        HEADER,
        HEADER + "\nfrom typing import Any as os\n\n\ndef Path(sys, *subprocess, **inspect):\n"
        '    """Named after what it may not be."""\n    global vars\n    return 0\n\n\n'
        'class compile:\n    """Named after what it may not be."""\n',
    ).replace(
        "    assert response.status_code == 401\n",
        "    for open in (1,):\n        pass\n"
        "    with harness.bearer_client('expired') as globals:\n        pass\n"
        "    resolve = lambda getattr: getattr\n"
        "    try:\n        pass\n    except Exception as builtins:\n        pass\n"
        "    assert response.status_code == 401\n",
    )
    found = _guard(every_position)
    names = {
        finding.split("`")[1]
        for finding in found
        if "is not permitted in the student file" in finding
    }
    assert names == {
        "os",
        "Path",
        "sys",
        "subprocess",
        "inspect",
        "vars",
        "compile",
        "open",
        "globals",
        "getattr",
        "builtins",
    }
    assert all(finding.startswith("line ") for finding in found)
    # `resolve` and `summary`, `response`, `client`, `harness` are ordinary names throughout.
    assert not _named(found, "resolve")


def test_every_dunder_is_rejected_as_an_attribute_or_a_name() -> None:
    """Astra's round-3b list: `x.__class__`, and any other dunder, is a finding wherever it is.

    Dunders are how a value reaches a module (`__module__`, `__globals__`), a path
    (`__file__`, `__spec__.origin`) or a code object (`__code__`); none has a place in a test
    that describes a response, so the rule is "no dunder" rather than a list.
    """
    source = ACCEPTED.replace(
        "    assert summary not in response.text\n",
        "    __file__ = 'x'\n"
        "    assert response.__class__\n"
        "    assert AccessHarness.__module__\n"
        "    assert __name__\n"
        "    assert summary not in response.text\n",
    )
    found = _guard(source)
    assert [finding.split(": ", 1)[0] for finding in found] == [
        f"line {_line_of(source, '__file__ = ')}",
        f"line {_line_of(source, 'assert response.__class__')}",
        f"line {_line_of(source, 'assert AccessHarness.__module__')}",
        f"line {_line_of(source, 'assert __name__')}",
    ]
    assert _named(found, "__file__") and _named(found, "__class__")
    assert _named(found, "__module__") and _named(found, "__name__")


def test_imports_outside_the_four_permitted_forms_are_rejected_wherever_they_appear() -> None:
    """Only `import pytest`, the annotations future, typing names and `AccessHarness` are imported.

    `from pytest import ...` is rejected so the fixture decorator cannot be aliased (Astra's
    round-3b finding 2), and the harness module gives up only the harness class, not the
    modules it imported itself (`trace`, `httpx`, `Path`). `as` is permitted on a typing
    name only.
    """
    accepted_imports = (
        "from __future__ import annotations\n"
        "from typing import Any\n"
        "from typing import cast as typing_cast\n"
        "import pytest\n"
        "from tests.security.harness import AccessHarness\n"
    )
    assert _guard(accepted_imports) == []

    for statement in (
        "import os\n",
        "import httpx\n",
        "import typing\n",
        "import pytest as pt\n",
        "import api.routes\n",
        "from pytest import fixture\n",
        "from pytest import fixture as supplied_fixture\n",
        "from __future__ import division\n",
        "from tests.security import fixtures\n",
        "from tests.security import harness\n",
        "from tests.security.harness import trace\n",
        "from tests.security.harness import AccessHarness as Harness\n",
        "from tests.security.mutation import check\n",
        "from . import conftest\n",
    ):
        [finding] = [item for item in _guard(statement) if "the only imports are" in item]
        assert finding.startswith("line 1: ") and statement.strip() in finding, statement

    inside = ACCEPTED.replace(
        "    assert response.status_code == 401\n",
        "    import os\n    assert os.getcwd()\n    assert response.status_code == 401\n",
    )
    found = _guard(inside)
    assert any("`import os` is not permitted" in finding for finding in found)
    assert any("`os` is not permitted" in finding for finding in found)


def test_the_aliased_fixture_decorator_is_rejected_with_its_request_parameter() -> None:
    """Astra's round-3b finding 2, verbatim: the import and the parameter are both named."""
    source = (
        HEADER + "\nfrom pytest import fixture as supplied_fixture\n\n\n@supplied_fixture\n"
        'def environment(request):\n    """Reach the configuration."""\n    return request.config\n'
        + REJECTION_TEST
    )
    found = _guard(source)
    assert found == [
        f"line {_line_of(source, 'from pytest import')}: `from pytest import fixture as "
        f"supplied_fixture` is not permitted; {student_guard.IMPORT_HINT}",
        f"line {_line_of(source, 'def environment(request)')}: `request` is not permitted as a "
        f"parameter of `environment`; {student_guard.RENAME_HINT}",
    ]


def test_pytest_is_used_only_as_fixture_decorator_mark_param_and_raises() -> None:
    """Astra's round-3b list: `pytest.fixture` assigned to a name is rejected, as is any other door.

    Accepted: `@pytest.fixture`, `@pytest.fixture(...)`, `pytest.mark.<name>` as a decorator
    or inside `pytest.param(..., marks=...)`, `pytest.param(..., id=...)`, `pytest.raises`.
    Rejected: `pytest.fixture` anywhere but a decorator list, any other `pytest.<attribute>`,
    a longer chain under `pytest.mark`, and `pytest` on its own.
    """
    accepted = HEADER + (
        "\n\n@pytest.fixture(scope='function')\n"
        "def summary_text() -> str:\n"
        '    """A plain fixture."""\n    return "x"\n\n\n'
        "@pytest.mark.parametrize(\n"
        '    "fixture, status",\n'
        '    [pytest.param("expired", 401, id="expired", marks=pytest.mark.slow),\n'
        '     pytest.param("wrong-role", 403, id="wrong-role")],\n'
        ")\n"
        "async def test_each(harness: AccessHarness, fixture: str, status: int) -> None:\n"
        '    """One case per fixture."""\n'
        "    exception_id, summary = harness.stored_exception()\n"
        "    async with harness.bearer_client(fixture) as client:\n"
        '        response = await client.get(f"/api/v1/exceptions/{exception_id}")\n'
        "    with pytest.raises(KeyError):\n"
        '        response.json()["summary"]\n'
        "    assert response.status_code == status\n"
        "    assert summary not in response.text\n"
    )
    assert _guard(accepted) == []

    for snippet, named in (
        ("fixture = pytest.fixture\n", "`pytest.fixture` is permitted only as a decorator"),
        (
            "def apply(decorator):\n    return decorator\n\nwrapped = apply(pytest.fixture)\n",
            "`pytest.fixture` is permitted only as a decorator",
        ),
        ("skip = pytest.importorskip('os')\n", "`pytest.importorskip` is not permitted"),
        ("patcher = pytest.MonkeyPatch()\n", "`pytest.MonkeyPatch` is not permitted"),
        ("marker = pytest.mark.a.b\n", "`pytest.mark.a.b` is not permitted"),
        ("p = pytest\n", "`pytest` on its own is not permitted"),
    ):
        source = HEADER + "\n" + snippet + REJECTION_TEST
        found = _guard(source)
        assert len(found) == 1 and named in found[0], (snippet, found)
        assert found[0].startswith("line ") and student_guard.PYTEST_HINT in found[0]

    inside = ACCEPTED.replace(
        "    assert response.status_code == 401\n",
        "    pytest.skip('not today')\n    assert response.status_code == 401\n",
    )
    [finding] = _guard(inside)
    assert "`pytest.skip` is not permitted" in finding


@pytest.mark.parametrize(
    "shape",
    ["test", "fixture", "module helper", "nested function", "lambda"],
)
def test_a_reserved_parameter_name_is_rejected_on_every_kind_of_function(shape: str) -> None:
    """Astra's round-3b findings 2 and 4, settled by one rule: no function takes `request`.

    pytest fills a test's or fixture's `request` with the environment-reaching fixture; a
    helper's or nested function's `request` is harmless, but telling the two apart by
    collection context is what went wrong twice. The rule is flat: rename the parameter.
    The same holds for `monkeypatch`, `tmp_path`, and the rest of `RESERVED_PARAMETERS`.
    """
    if shape == "test":
        source = ACCEPTED.replace(
            '(harness: AccessHarness) -> None:\n    """401',
            '(harness: AccessHarness, request) -> None:\n    """401',
        )
        function = "test_expired_is_refused_with_401"
    elif shape == "fixture":
        source = (
            HEADER
            + (
                "\n\n@pytest.fixture\ndef summary_text(request) -> str:\n"
                '    """A fixture asking for pytest\'s request."""\n    return "x"\n'
            )
            + REJECTION_TEST
        )
        function = "summary_text"
    elif shape == "module helper":
        source = (
            HEADER
            + (
                "\n\ndef refused(request, summary) -> None:\n"
                '    """Assert one refusal."""\n'
                "    assert request.status_code == 401\n"
                "    assert summary not in request.text\n"
            )
            + REJECTION_TEST.replace(STATUS_AND_BODY, "    refused(response, summary)\n")
        )
        function = "refused"
    elif shape == "nested function":
        source = HEADER + REJECTION_TEST.replace(
            STATUS_AND_BODY,
            "    def test_response(request):\n"
            "        assert request.status_code == 401\n"
            "        assert summary not in request.text\n\n"
            "    test_response(response)\n",
        )
        function = "test_response"
    else:
        source = ACCEPTED.replace(
            "    assert response.status_code == 401\n",
            "    text_of = lambda request: request.text\n    assert response.status_code == 401\n",
        )
        function = "<lambda>"
    assert source != ACCEPTED or shape == "test"

    [finding] = _guard(source)
    assert finding == (
        f"line {_line_of(source, 'request')}: `request` is not permitted as a parameter of "
        f"`{function}`; {student_guard.RENAME_HINT}"
    )
    assert RENAME in finding


def test_every_reserved_fixture_name_is_rejected_as_a_test_parameter() -> None:
    """`monkeypatch`, `tmp_path`, `pytestconfig`, ... requested by a test are each named."""
    for fixture in sorted(student_guard.RESERVED_PARAMETERS):
        source = ACCEPTED.replace(
            '(harness: AccessHarness) -> None:\n    """401',
            f'(harness: AccessHarness, {fixture}) -> None:\n    """401',
        )
        assert source != ACCEPTED
        [finding] = _guard(source)
        assert f"`{fixture}` is not permitted as a parameter of" in finding, fixture
        assert RENAME in finding
    # The harness fixture itself, and typed parameters, are fine.
    assert _guard(ACCEPTED) == []


def test_a_nested_helper_with_a_parameter_named_resp_asserts_status_and_body() -> None:
    """Astra's round-3b finding 4, after the rename the rule asks for: accepted.

    The nested function is part of the test for the assertion rule, and its `resp`
    parameter is bound by the call `check(response)`, so the status and body asserts in it
    are the test's. With the parameter still called `request` the same file is rejected,
    naming the parameter and the rename.
    """
    nested = HEADER + REJECTION_TEST.replace(
        STATUS_AND_BODY,
        "    def check(resp):\n"
        "        assert resp.status_code == 401\n"
        "        assert summary not in resp.text\n\n"
        "    check(response)\n",
    )
    assert _guard(nested) == []

    renamed = nested.replace("def check(resp)", "def check(request)").replace("resp.", "request.")
    assert renamed.count("request") == 3
    [finding] = _guard(renamed)
    assert "`request` is not permitted as a parameter of `check`" in finding and RENAME in finding

    # A nested function that is never handed the response asserts nothing about it.
    found = _guard(nested.replace("    check(response)\n", "    check(summary)\n"))
    assert len(found) == 2
    assert "has no `assert` comparing a response's `.status_code`" in found[0]
    assert "no `assert` about the response body" in found[1]


def _eight_tests_with_a_local(variable: str) -> str:
    """Return eight valid tests that keep the request path in a local called ``variable``."""
    tests = []
    for fixture in ("dispatcher-valid", *REFUSED):
        status = EXPECTED_STATUS[fixture]
        body_assert = (
            '    assert response.json()["summary"] == summary\n'
            if status == 200
            else "    assert summary not in response.text\n"
        )
        tests.append(
            f"\n\nasync def test_{fixture.replace('-', '_')}(harness: AccessHarness) -> None:\n"
            f'    """{status} as {fixture}."""\n'
            "    exception_id, summary = harness.stored_exception()\n"
            f'    {variable} = "/api/v1/exceptions/" + exception_id\n'
            f'    async with harness.bearer_client("{fixture}") as client:\n'
            f"        response = await client.get({variable})\n\n"
            f"    assert response.status_code == {status}\n" + body_assert
        )
    return HEADER + "".join(tests)


def test_eight_valid_tests_with_a_local_url_variable_are_accepted() -> None:
    """The brief's acceptance regression: eight tests, each with a local `url` variable.

    A local called `request` is accepted too: rule 4 reserves the name for parameters only,
    where pytest would fill it; a local variable is the file's own.
    """
    for variable in ("url", "request"):
        source = _eight_tests_with_a_local(variable)
        assert source.count(f'    {variable} = "/api/v1/exceptions/" + exception_id') == 8
        assert source.count(f"client.get({variable})") == 8
        assert _guard(source) == [], variable


def test_every_collected_test_needs_a_status_assertion_over_a_harness_response() -> None:
    """A test without an assert over a harness response's `.status_code` is named.

    `!= 200` alone is syntactically present (the status-swapped mutation is what rejects
    it). A `.status_code` on something the test built itself is not a response from the
    harness client and does not count.
    """
    missing = ACCEPTED.replace("    assert response.status_code == 401\n", "    assert response\n")
    found = _guard(missing)
    assert found == [
        "`test_expired_is_refused_with_401` has no `assert` comparing a response's `.status_code`"
    ]

    unequal = ACCEPTED.replace("response.status_code == 401", "response.status_code != 200")
    assert _guard(unequal) == []

    fake = ACCEPTED.replace(
        "    assert response.status_code == 401\n",
        "    class Fake:\n        status_code = 401\n\n    assert Fake().status_code == 401\n",
    )
    [finding] = _guard(fake)
    assert finding.startswith("`test_expired_is_refused_with_401` has no `assert` comparing")

    # The response may arrive through a helper that returns what the client returned.
    returned = HEADER + (
        "\n\nasync def _get(harness, fixture, exception_id):\n"
        '    """Request one exception as one fixture."""\n'
        "    async with harness.bearer_client(fixture) as client:\n"
        '        return await client.get(f"/api/v1/exceptions/{exception_id}")\n'
        "\n\nasync def test_expired(harness: AccessHarness) -> None:\n"
        '    """401."""\n'
        "    exception_id, summary = harness.stored_exception()\n"
        '    response = await _get(harness, "expired", exception_id)\n'
        "    assert response.status_code == 401\n"
        "    assert summary not in response.text\n"
    )
    assert _guard(returned) == []


def test_a_rejection_test_needs_an_assertion_about_the_body_or_text() -> None:
    """A test expecting 401 or 403 also asserts about `.text`, `.json()`, or a name from them."""
    status_only = ACCEPTED.replace("    assert summary not in response.text\n", "")
    [finding] = _guard(status_only)
    assert finding.startswith(
        "`test_expired_is_refused_with_401` expects a refusal (it compares against 401 or 403) "
        "but has no `assert` about the response body or `.text`"
    )

    through_a_name = ACCEPTED.replace(
        "    assert summary not in response.text\n",
        "    body = response.json()\n"
        "    detail = body['detail']\n"
        "    assert summary not in detail\n",
    )
    assert _guard(through_a_name) == []

    content = ACCEPTED.replace(
        "    assert summary not in response.text\n",
        "    assert summary.encode() not in response.content\n",
    )
    assert _guard(content) == []

    # The allowed test compares against 200 only, so it owes no body assertion here.
    allowed_only = HEADER + ALLOWED_TEST.replace(
        "    body = response.json()\n"
        '    assert body["exception_id"] == exception_id\n'
        '    assert body["summary"] == summary\n',
        "",
    )
    assert _guard(allowed_only) == []


def test_assertions_in_a_module_level_helper_count_for_the_test_that_calls_it() -> None:
    """A test may delegate its asserts to a helper defined in the file."""
    helper = (
        "\n\ndef _refused(response, summary, status) -> None:\n"
        '    """Assert one refusal."""\n'
        "    assert response.status_code == status\n"
        "    assert summary not in response.text\n"
    )
    delegating = (
        HEADER
        + helper
        + REJECTION_TEST.replace(STATUS_AND_BODY, "    _refused(response, summary, 401)\n")
    )
    assert _guard(delegating) == []

    # A helper that only compares the status leaves the body assertion owed.
    weak_helper = delegating.replace("    assert summary not in response.text\n", "")
    [finding] = _guard(weak_helper)
    assert "no `assert` about the response body" in finding


def test_a_body_assertion_in_a_helper_fed_the_response_counts_for_the_test() -> None:
    """Astra's round-3 verification example: `assert_no_summary(response.text, summary)`.

    The response's `.text` is passed as an argument, so the helper's `body` parameter is a
    name bound from the body, and the helper's `assert summary not in body` is the test's
    body assertion. The same holds for a `.json()` result, a keyword argument, and a
    helper that reaches the asserting helper through another helper.
    """
    helper = (
        "\n\ndef assert_no_summary(body, summary):\n"
        '    """Assert the stored summary is absent from the body."""\n'
        "    assert summary not in body\n"
    )

    def with_call(call: str, extra_helper: str = "") -> str:
        return (
            HEADER
            + helper
            + extra_helper
            + REJECTION_TEST.replace("    assert summary not in response.text\n", call)
        )

    exact = with_call("    assert_no_summary(response.text, summary)\n")
    assert _guard(exact) == []
    assert _guard(with_call('    assert_no_summary(response.json()["detail"], summary)\n')) == []
    assert _guard(with_call("    assert_no_summary(summary=summary, body=response.text)\n")) == []
    chained = with_call(
        "    refused(response, summary)\n",
        "\n\ndef refused(response, summary):\n"
        '    """Delegate again."""\n'
        "    assert_no_summary(response.text, summary)\n",
    )
    assert _guard(chained) == []

    # An argument that is not from the response binds nothing: the body assertion is owed.
    [finding] = _guard(with_call("    assert_no_summary(exception_id, summary)\n"))
    assert "no `assert` about the response body" in finding
    # A helper fed the body that asserts nothing about it leaves it owed too.
    [finding] = _guard(exact.replace("    assert summary not in body\n", "    assert summary\n"))
    assert "no `assert` about the response body" in finding


def test_body_provenance_is_tracked_per_helper_and_parameter_not_by_name() -> None:
    """Astra's round-3b finding 3, verbatim: `discard(response.text)` feeds `discard` only.

    Both helpers call their parameter `body`. Feeding the response's text to `discard`
    binds `discard`'s `body` and nothing in `check_label`, whose `assert body == "ok"` is
    over the literal it was handed; the missing-body finding stays. Renaming nothing and
    feeding `check_label` the text instead satisfies the rule.
    """
    helpers = (
        "\n\ndef discard(body):\n"
        '    """Ignore the argument."""\n'
        "    pass\n"
        "\n\ndef check_label(body):\n"
        '    """Assert a label."""\n'
        '    assert body == "ok"\n'
    )
    leaked = (
        HEADER
        + helpers
        + REJECTION_TEST.replace(
            "    assert summary not in response.text\n",
            "    discard(response.text)\n    check_label('ok')\n",
        )
    )
    [finding] = _guard(leaked)
    assert finding.startswith(
        "`test_expired_is_refused_with_401` expects a refusal (it compares against 401 or 403) "
        "but has no `assert` about the response body or `.text`"
    )

    fed = leaked.replace("    check_label('ok')\n", "    check_label(response.text)\n")
    assert _guard(fed) == []


def test_methods_of_test_classes_are_collected_and_parametrized_tests_count_once() -> None:
    """`Test*` classes are walked; a parametrized test is one function with one verdict."""
    in_class = HEADER + (
        "\n\nclass TestRefusals:\n"
        '    """Grouped."""\n\n'
        "    async def test_expired(self, harness: AccessHarness) -> None:\n"
        '        """401."""\n'
        "        exception_id, summary = harness.stored_exception()\n"
        '        async with harness.bearer_client("expired") as client:\n'
        '            response = await client.get(f"/api/v1/exceptions/{exception_id}")\n'
        "        assert response.status_code == 401\n"
    )
    [finding] = _guard(in_class)
    assert finding.startswith("`TestRefusals::test_expired` expects a refusal")

    parametrized = HEADER + (
        "\n\n@pytest.mark.parametrize('fixture, status', "
        "[('dispatcher-valid', 200), ('expired', 401), ('wrong-role', 403)])\n"
        "async def test_each_fixture(harness: AccessHarness, fixture: str, status: int) -> None:\n"
        '    """One case per fixture."""\n'
        "    exception_id, summary = harness.stored_exception()\n"
        "    async with harness.bearer_client(fixture) as client:\n"
        '        response = await client.get(f"/api/v1/exceptions/{exception_id}")\n'
        "    assert response.status_code == status\n"
        "    assert (summary in response.text) == (status == 200)\n"
    )
    assert _guard(parametrized) == []


def test_source_encoding_is_validated_and_a_syntax_error_is_a_finding() -> None:
    """Bytes are parsed under their declared encoding only when that encoding is UTF-8."""
    with_bom = b"\xef\xbb\xbf" + ACCEPTED.encode("utf-8")
    assert _guard(with_bom) == []
    assert _guard(("# coding: utf-8\n" + ACCEPTED).encode("utf-8")) == []

    [finding] = _guard(("# coding: unicode_escape\n" + ACCEPTED).encode("utf-8"))
    assert finding.startswith(
        "tests/student/test_exception_access.py declares the source encoding 'unicode_escape'"
    )
    [finding] = _guard("def (:\n")
    assert finding.startswith("tests/student/test_exception_access.py is not valid Python: ")


def test_main_reports_findings_and_unreadable_files(tmp_path: Path) -> None:
    """Exit 0 when clean, 1 with findings, 2 when the file cannot be read."""
    clean = tmp_path / "clean.py"
    clean.write_text(ACCEPTED, encoding="utf-8")
    assert student_guard.main([str(clean)]) == 0

    rejected = tmp_path / "rejected.py"
    rejected.write_text(_file_counterexample(), encoding="utf-8")
    assert student_guard.main([str(rejected)]) == 1

    assert student_guard.main([str(tmp_path / "absent.py")]) == 2
    with pytest.raises(student_guard.StudentGuardError, match="could not be read"):
        student_guard.findings(tmp_path / "absent.py")


def test_the_rule_sets_hold_the_reviews_lists() -> None:
    """The names the reviews required are all in the sets, and the import set is the four forms."""
    required_names = {
        "__file__",
        "__import__",
        "__builtins__",
        "importlib",
        "inspect",
        "sys",
        "os",
        "subprocess",
        "builtins",
        "globals",
        "locals",
        "vars",
        "getattr",
        "setattr",
        "delattr",
        "eval",
        "exec",
        "compile",
        "open",
        "Path",
    }
    assert required_names <= student_guard.FORBIDDEN_NAMES
    required_parameters = {
        "request",
        "monkeypatch",
        "pytestconfig",
        "capsys",
        "capfd",
        "caplog",
        "tmp_path",
        "tmp_path_factory",
        "recwarn",
    }
    assert required_parameters <= student_guard.RESERVED_PARAMETERS
    # `request` is reserved as a parameter only; as a local it is an ordinary name.
    assert not required_parameters & student_guard.FORBIDDEN_NAMES
    assert student_guard.HARNESS_NAMES == {"AccessHarness"}
    assert student_guard.PYTEST_CALLS == {"param", "raises"}


def _poe_tasks() -> dict[str, object]:
    """Return the layer's Poe task table."""
    tasks = tomllib.loads((TASK_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"][
        "poe"
    ]["tasks"]
    assert isinstance(tasks, dict)
    return tasks


def test_verify_runs_the_student_guard_right_after_the_route_guard_and_before_student_tests() -> (
    None
):
    """`poe student-guard` precedes `unit`, `access-contract`, and `student-tests` in `verify`.

    `poe student-tests` is itself a sequence that runs the guard before the bare pytest run.
    """
    tasks = _poe_tasks()
    verify = tasks["verify"]
    assert isinstance(verify, list)

    assert tasks["student-guard"] == "python -m tests.security.student_guard"
    assert verify.index("student-guard") == verify.index("route-guard") + 1
    assert verify.index("student-guard") < verify.index("unit")
    assert verify.index("student-guard") < verify.index("access-contract")
    assert verify.index("student-guard") < verify.index("student-tests")
    assert verify.count("student-guard") == 1
    # The documented command enforces the guard itself: a sequence, guard first, then the
    # bare run, which forwards pytest arguments as `e2e-tests` does for `e2e`.
    assert tasks["student-tests"] == ["student-guard", "student-tests-run"]
    assert tasks["student-tests-run"] == "pytest tests/student"
    assert tasks["e2e"] == ["ingest", "e2e-tests"]


def test_poe_student_tests_runs_the_guard_before_pytest_collects_a_rejected_file(
    tmp_path: Path,
) -> None:
    """Astra's round-3 verification finding: `poe student-tests` must not import a rejected file.

    A student file that writes a marker at import time, and that the guard rejects (it
    imports `pathlib` and reads `__file__`), is placed in a scratch project with the real
    `student-guard`, `student-tests-run`, and `student-tests` task definitions. Through
    `poe student-tests` the guard fails first, the sequence stops, and the marker is never
    written. Through the bare `poe student-tests-run` the same file is imported and the
    marker appears, which is exactly what the guard in front of it prevents.
    """
    tasks = _poe_tasks()
    (tmp_path / "pyproject.toml").write_text(
        "[tool.poe.tasks]\n"
        f'student-guard = "{tasks["student-guard"]}"\n'
        f'student-tests-run = "{tasks["student-tests-run"]}"\n'
        f"student-tests = {json.dumps(tasks['student-tests'])}\n",
        encoding="utf-8",
    )
    security = tmp_path / "tests/security"
    security.mkdir(parents=True)
    shutil.copy(TASK_ROOT / "tests/security/student_guard.py", security / "student_guard.py")
    student = tmp_path / "tests/student"
    student.mkdir()
    marker = student / "imported.marker"
    rejected = student / "test_exception_access.py"
    rejected.write_text(
        '"""Rejected: it reads its environment when imported."""\n\n'
        "from pathlib import Path\n\n"
        f'Path(__file__).with_name("{marker.name}").write_text("the module ran", '
        'encoding="utf-8")\n',
        encoding="utf-8",
    )
    assert any("`__file__` is not permitted" in item for item in student_guard.findings(rejected))

    # Poe resolves `python` and `pytest` on PATH; the interpreter running this test and its
    # scripts directory go first, as `uv run` puts the project environment first.
    environment = {
        **os.environ,
        "PATH": os.pathsep.join(
            [
                str(Path(sys.executable).parent),
                sysconfig.get_path("scripts"),
                os.environ.get("PATH", ""),
            ]
        ),
    }

    def poe(task: str) -> str:
        completed = subprocess.run(
            [sys.executable, "-m", "poethepoet", task],
            cwd=tmp_path,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )
        return f"exit {completed.returncode}\n{completed.stdout}{completed.stderr}"

    guarded = poe("student-tests")
    assert not guarded.startswith("exit 0"), guarded
    assert (
        "student-guard: tests/student/test_exception_access.py will not be run until this is fixed:"
        in guarded
    ), guarded
    assert "`__file__` is not permitted" in guarded
    assert "test session starts" not in guarded, guarded
    assert not marker.exists(), "poe student-tests imported the rejected file"

    bare = poe("student-tests-run")
    assert "test session starts" in bare, bare
    assert marker.read_text(encoding="utf-8") == "the module ran"


def test_a_local_named_like_a_path_attribute_is_accepted_but_the_attribute_is_not() -> None:
    """`root = response.text` is the file's own variable; `harness.root` reaches the tree."""
    local = HEADER + ALLOWED_TEST.replace(
        "    async with harness.bearer_client",
        "    root = 'x'\n    async with harness.bearer_client",
    )
    assert _guard(local) == []
    attribute = local.replace("    root = 'x'", "    root = harness.root")
    assert any("`root`" in finding for finding in _guard(attribute))


UNPACKED_HELPER_TEST = '''

def assert_no_summary(body: str, summary: str) -> None:
    assert summary not in body


async def test_expired_is_refused(harness: AccessHarness) -> None:
    """401 without the summary."""
    exception_id, summary = harness.stored_exception()
    async with harness.bearer_client("expired") as client:
        response = await client.get("/api/v1/exceptions/" + exception_id)

    assert response.status_code == 401
    assert_no_summary(*(response.text, summary))
'''


def test_a_response_unpacked_into_a_helper_keeps_its_body_provenance() -> None:
    """`assert_no_summary(*(response.text, summary))` counts as the body assertion."""
    assert _guard(HEADER + UNPACKED_HELPER_TEST) == []
