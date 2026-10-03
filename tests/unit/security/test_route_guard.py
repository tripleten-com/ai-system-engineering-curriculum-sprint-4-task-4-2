"""Coldline.

===================

File:              tests/unit/security/test_route_guard.py
Component:         Unit tests — Static route guard
Purpose:           Prove the guard accepts every permitted edit of the route module and rejects
                    everything else, without importing any route module.
Interacts With:    tests/security/route_guard.py, src/api/routes.py, pyproject.toml
Sprint/Task:       Sprint 4 — Project 4 / Task 4.2
Concepts:          Trusted static analysis, syntax-tree comparison, verify order
Tools:             Python 3.12, pytest, tomllib

Most tests here work on a small module shaped like the starter, with its own baseline, so
they say exactly which edit is accepted or rejected and why. Two read the real files: the
shipped route module must pass the guard (it does in every legitimate state, starter or
completed, so this pins no starter state), and `poe verify` must run the guard before any
import. The completion check is tested beside the guard: it accepts the two parameter
forms and names the decorator-only form, the untouched starter, and an unannotated default.
"""

from __future__ import annotations

import ast
import tomllib
from pathlib import Path

import pytest

from tests.security import route_guard

TASK_ROOT = Path(__file__).resolve().parents[3]
ENCODING_REGRESSION = (
    "# coding: unicode_escape\n"
    "# harmless comment \\x0aimport os, sys\\x0aif 'pytest' in sys.modules: os._exit(0)\n"
)

STARTER = '''"""Routes."""

from collections.abc import Callable

from fastapi import FastAPI, HTTPException
from api.security.tokens import TokenVerifier
from domain.contracts import ExceptionRecord

_KNOWN_ROUTES = frozenset({"/health/live", "/version"})


class Accepted:
    """Return the identity of accepted work."""

    exception_id: str


def create_app(repository, token_verifier: TokenVerifier | None = None) -> FastAPI:
    """Create the HTTP layer."""
    app = FastAPI()
    app.state.token_verifier = token_verifier

    @app.get("/health/live", include_in_schema=False)
    async def liveness() -> dict[str, str]:
        """Report that the API process can serve requests."""
        return {"status": "alive"}

    @app.get("/api/v1/exceptions/{exception_id}", response_model=ExceptionRecord)
    async def get_exception(exception_id: str) -> ExceptionRecord:
        """Return the durable state of one exception workflow."""
        record = await repository.get(exception_id)
        if record is None:
            raise HTTPException(status_code=404, detail="exception not found")
        return record

    @app.get("/version", include_in_schema=False)
    async def version() -> dict[str, str]:
        """Report which build is answering."""
        return {"service": "coldline-api"}

    return app


def _route_label(path: str) -> str:
    """Normalize request paths."""
    return path if path in _KNOWN_ROUTES else "unmatched"
'''

RULE_IMPORTS = (
    "from typing import Annotated\n"
    "from fastapi import Depends\n"
    "from api.security.access import require_access\n"
    "from api.security.tokens import Principal\n"
)
OPEN_SIGNATURE = "    async def get_exception(exception_id: str) -> ExceptionRecord:\n"
ANNOTATED_SIGNATURE = (
    "    async def get_exception(\n"
    "        exception_id: str,\n"
    "        principal: Annotated[\n"
    "            Principal, Depends(require_access(role='dispatcher', scope='exceptions:read'))\n"
    "        ],\n"
    "    ) -> ExceptionRecord:\n"
)
DEFAULT_SIGNATURE = (
    "    async def get_exception(\n"
    "        exception_id: str,\n"
    "        principal: Principal = Depends(require_access(role='dispatcher', "
    "scope='exceptions:read')),\n"
    "    ) -> ExceptionRecord:\n"
)
KEYWORD_ONLY_SIGNATURE = (
    "    async def get_exception(\n"
    "        exception_id: str,\n"
    "        *,\n"
    "        who=Depends(require_access(role='dispatcher', scope='exceptions:read')),\n"
    "    ) -> ExceptionRecord:\n"
)
OPEN_DECORATOR = (
    '    @app.get("/api/v1/exceptions/{exception_id}", response_model=ExceptionRecord)\n'
)
RULE_DECORATOR = (
    "    @app.get(\n"
    '        "/api/v1/exceptions/{exception_id}",\n'
    "        response_model=ExceptionRecord,\n"
    "        dependencies=[Depends(require_access(role='dispatcher', scope='exceptions:read'))],\n"
    "    )\n"
)
BASELINE = route_guard.baseline_of(STARTER)


def _with_rule(signature: str = OPEN_SIGNATURE, decorator: str = OPEN_DECORATOR) -> str:
    """Return the synthetic starter with the rule imports and the given route head."""
    source = STARTER.replace(
        "from domain.contracts import ExceptionRecord\n",
        RULE_IMPORTS + "from domain.contracts import ExceptionRecord\n",
    )
    source = source.replace(OPEN_SIGNATURE, signature)
    source = source.replace(OPEN_DECORATOR, decorator)
    assert source != STARTER
    return source


def _findings(source: str) -> list[str]:
    """Run the guard over one synthetic module against the synthetic baseline."""
    return route_guard.findings_for_source(source, BASELINE)


def test_the_starter_passes_against_its_own_baseline() -> None:
    """A module that was not edited has no findings: the guard passes on a fresh starter."""
    assert _findings(STARTER) == []


def test_the_reference_form_is_accepted() -> None:
    """The Annotated parameter the access module's docstring shows, with its four imports."""
    assert _findings(_with_rule(ANNOTATED_SIGNATURE)) == []


@pytest.mark.parametrize(
    "signature, decorator",
    [
        (ANNOTATED_SIGNATURE, OPEN_DECORATOR),
        (DEFAULT_SIGNATURE, OPEN_DECORATOR),
        (KEYWORD_ONLY_SIGNATURE, OPEN_DECORATOR),
        (OPEN_SIGNATURE, RULE_DECORATOR),
    ],
    ids=["annotated", "default", "keyword-only-default", "decorator-dependencies"],
)
def test_each_form_strip_access_rule_handles_is_accepted(signature: str, decorator: str) -> None:
    """Every call form the mutation strips is a permitted way to apply the rule."""
    assert _findings(_with_rule(signature, decorator)) == []


def test_import_grouping_order_and_formatting_are_invisible() -> None:
    """A formatter's reflow, merged import lines, and a new docstring change nothing."""
    source = _with_rule(ANNOTATED_SIGNATURE)
    source = source.replace(
        "from fastapi import FastAPI, HTTPException\n",
        "from fastapi import (\n    FastAPI,\n    HTTPException,\n)\n",
    )
    source = source.replace(
        '_KNOWN_ROUTES = frozenset({"/health/live", "/version"})',
        '_KNOWN_ROUTES = frozenset(\n    {\n        "/health/live",\n        "/version",\n    }\n)',
    )
    source = source.replace(
        '"""Return the durable state of one exception workflow."""',
        '"""Return the durable state of one exception workflow to a dispatcher."""',
    )
    source = source.replace('"""Routes."""', '"""Routes, with the summary route protected."""')
    assert _findings(source) == []


def test_an_import_time_exit_is_rejected_by_import_and_by_statement() -> None:
    """The `os._exit` injection is named twice: the import and the module-level conditional."""
    injected = STARTER.replace(
        "_KNOWN_ROUTES = frozenset(",
        "import os\nimport sys\n\n"
        'if "pytest" in sys.modules:\n    os._exit(0)\n\n'
        "_KNOWN_ROUTES = frozenset(",
    )
    found = _findings(injected)

    assert "`import os` is not a permitted import" in found
    assert "`import sys` is not a permitted import" in found
    assert "statement 1: a module-level If was added" in found
    assert len(found) == 3, found


def test_a_second_route_changed_is_rejected() -> None:
    """A change to any other route inside create_app is one finding naming create_app."""
    changed = _with_rule(ANNOTATED_SIGNATURE).replace(
        'return {"status": "alive"}', 'return {"status": "alive", "auth": "off"}'
    )
    assert _findings(changed) == ["statement 3: `create_app` changed outside `get_exception`"]


def test_the_route_body_and_first_parameter_must_stay_the_starters() -> None:
    """get_exception's body, return annotation, and `exception_id: str` are not editable."""
    body = _with_rule(ANNOTATED_SIGNATURE).replace(
        "        return record\n", '        return record.model_copy(update={"summary": None})\n'
    )
    assert _findings(body) == ["`get_exception`'s body changed; only its docstring may differ"]

    parameter = _with_rule(ANNOTATED_SIGNATURE).replace("exception_id: str,", "exception_id: int,")
    assert _findings(parameter) == [
        "`get_exception`'s first parameter must stay the starter's `exception_id: str`"
    ]

    returns = _with_rule(ANNOTATED_SIGNATURE).replace(") -> ExceptionRecord:\n", ") -> dict:\n", 1)
    assert "`get_exception`'s return annotation changed" in _findings(returns)


def test_module_level_additions_and_removals_are_rejected() -> None:
    """A new call, a new assignment, or a removed statement is reported by position."""
    call = STARTER + '\nprint("loaded")\n'
    assert _findings(call) == ["statement 5: a module-level Expr was added"]

    assignment = STARTER.replace("class Accepted:", "OPEN = True\n\n\nclass Accepted:")
    assert _findings(assignment) == ["statement 2: a module-level Assign `OPEN` was added"]

    removed = STARTER.replace(
        'def _route_label(path: str) -> str:\n    """Normalize request paths."""\n'
        '    return path if path in _KNOWN_ROUTES else "unmatched"\n',
        "",
    )
    assert _findings(removed) == ["the starter's FunctionDef `_route_label` was removed"]


def test_unpermitted_imports_and_aliases_are_rejected() -> None:
    """Only the four names the rule needs may be added, and only under their own names."""
    extra = STARTER.replace(
        "from collections.abc import Callable\n",
        "from collections.abc import Callable\nfrom os import environ\n",
    )
    assert _findings(extra) == ["`from os import environ` is not a permitted import"]

    aliased = (
        _with_rule(ANNOTATED_SIGNATURE)
        .replace("from fastapi import Depends\n", "from fastapi import Depends as Dep\n")
        .replace("Depends(require_access", "Dep(require_access")
    )
    found = _findings(aliased)
    assert "`from fastapi import Depends as Dep` is aliased" in found

    dropped = STARTER.replace("from collections.abc import Callable\n", "")
    assert _findings(dropped) == [
        "the starter's `from collections.abc import Callable` was removed"
    ]


def test_the_rule_must_be_applied_once_with_role_and_scope_keywords() -> None:
    """Two applications, positional arguments, or a non-rule parameter are each named."""
    twice = _with_rule(ANNOTATED_SIGNATURE, RULE_DECORATOR)
    assert any("applies the rule 2 times" in finding for finding in _findings(twice))

    positional = _with_rule(
        ANNOTATED_SIGNATURE.replace(
            "require_access(role='dispatcher', scope='exceptions:read')",
            "require_access('dispatcher', 'exceptions:read')",
        )
    )
    found = _findings(positional)
    assert "parameter `principal`: `require_access` takes `role=` and `scope=` as keywords" in found

    blank = _with_rule(ANNOTATED_SIGNATURE.replace("scope='exceptions:read'", "scope=''"))
    assert "parameter `principal`: `scope=` must be a non-empty string literal" in _findings(blank)

    stranger = _with_rule(
        "    async def get_exception(exception_id: str, request: Request) -> ExceptionRecord:\n"
    )
    assert _findings(stranger) == [
        "parameter `request` is not a rule parameter; only `Depends(require_access(...))` may be "
        "added to `get_exception`"
    ]


def test_a_missing_or_duplicated_route_and_a_syntax_error_are_findings() -> None:
    """The guard reports, rather than raises, when the module has no checkable route."""
    assert _findings("def create_app():\n    pass\n")[-1] == (
        "`create_app` must define `get_exception` exactly once; found 0"
    )
    [finding] = _findings("def create_app(:\n")
    assert finding.startswith("src/api/routes.py is not valid Python: ")


def test_a_non_utf8_source_encoding_is_rejected_before_anything_is_compared(
    tmp_path: Path,
) -> None:
    """A `coding: unicode_escape` file whose comment hides escaped statements is one finding.

    Decoded under its declaration, as an import does, the comment line becomes three
    statements (an import, and a conditional `os._exit`); decoded as UTF-8 text it is one
    comment and the tree is the starter's. The guard reads the bytes, detects the
    declaration the way the interpreter does, and rejects every encoding but UTF-8, so the
    file is never parsed under the declaration and never imported.
    """
    injected = (ENCODING_REGRESSION + STARTER).encode("utf-8")
    assert route_guard.findings_for_source(injected, BASELINE) == [
        "src/api/routes.py declares the source encoding 'unicode_escape'; only UTF-8 is "
        "permitted (remove the `coding` declaration)"
    ]
    assert route_guard.completion_findings(injected, BASELINE) == [
        "src/api/routes.py declares the source encoding 'unicode_escape'; only UTF-8 is "
        "permitted (remove the `coding` declaration)"
    ]
    # The same bytes decoded as text would have looked untouched: that is the bypass.
    assert route_guard.findings_for_source(injected.decode("utf-8"), BASELINE) == []

    path = tmp_path / "routes.py"
    path.write_bytes(injected)
    assert route_guard.main([str(path)]) == 1
    with pytest.raises(route_guard.RouteGuardError, match="declares the source encoding"):
        route_guard.baseline_of(injected)

    latin = ("# -*- coding: latin-1 -*-\n" + STARTER).encode("utf-8")
    [finding] = route_guard.findings_for_source(latin, BASELINE)
    assert finding.startswith("src/api/routes.py declares the source encoding 'iso-8859-1'")
    unknown = ("# coding: no-such-codec\n" + STARTER).encode("utf-8")
    [finding] = route_guard.findings_for_source(unknown, BASELINE)
    assert finding.startswith("src/api/routes.py declares an unusable source encoding")


def test_a_utf8_bom_and_a_utf8_coding_line_are_accepted() -> None:
    """UTF-8 is UTF-8 however it is declared: a BOM, `utf-8`, or `UTF8` change nothing."""
    with_bom = b"\xef\xbb\xbf" + STARTER.encode("utf-8")
    assert route_guard.findings_for_source(with_bom, BASELINE) == []
    for declaration in ("# coding: utf-8\n", "# -*- coding: UTF8 -*-\n"):
        source = (declaration + _with_rule(ANNOTATED_SIGNATURE)).encode("utf-8")
        assert route_guard.findings_for_source(source, BASELINE) == [], declaration
        assert route_guard.completion_findings(source, BASELINE) == [], declaration
    assert route_guard.encoding_findings(b"\xef\xbb\xbf# coding: utf-8\nx = 1\n") == []


# --- The completion check ----------------------------------------------------------------


def _completion(source: str) -> list[str]:
    """Run the completion check over one synthetic module against the synthetic baseline."""
    return route_guard.completion_findings(source, BASELINE)


@pytest.mark.parametrize(
    "signature", [ANNOTATED_SIGNATURE, DEFAULT_SIGNATURE], ids=["annotated", "default"]
)
def test_the_completion_check_accepts_the_two_principal_parameter_forms(signature: str) -> None:
    """`Annotated[Principal, Depends(...)]` and `principal: Principal = Depends(...)` both do."""
    assert _completion(_with_rule(signature)) == []


def test_the_completion_check_names_the_untouched_starter() -> None:
    """The starter passes the structural guard and fails the completion check, by name."""
    assert _findings(STARTER) == []
    [finding] = _completion(STARTER)
    assert finding.startswith("`get_exception` applies no `Depends(require_access(...))` yet; ")
    assert "`principal: Annotated[Principal, Depends(require_access(...))]`" in finding
    assert "`principal: Principal = Depends(require_access(...))`" in finding


def test_decorator_only_completion_protects_the_route_but_is_not_the_completion() -> None:
    """`dependencies=[Depends(...)]` passes the guard; T23's binding is on the completion row."""
    decorated = _with_rule(OPEN_SIGNATURE, RULE_DECORATOR)
    assert _findings(decorated) == []
    [finding] = _completion(decorated)
    assert finding.startswith(
        "decorator keyword `dependencies`: the rule protects the route but hands it no principal; "
    )
    assert "`get_exception` must receive the verified `Principal` through a parameter" in finding


def test_an_unannotated_default_parameter_is_not_the_completion() -> None:
    """`who=Depends(require_access(...))` carries the principal untyped: guard yes, completion no.

    The structural guard permits it (it is one of the forms `strip_access_rule` handles);
    the completion check asks for the `Principal` annotation.
    """
    keyword_only = _with_rule(KEYWORD_ONLY_SIGNATURE)
    assert _findings(keyword_only) == []
    [finding] = _completion(keyword_only)
    assert finding.startswith("parameter `who`: the rule parameter is not annotated `Principal`; ")


def test_the_completion_check_repeats_the_guards_findings_about_the_rule() -> None:
    """A malformed or doubled application is named here too, never accepted as complete."""
    twice = _with_rule(ANNOTATED_SIGNATURE, RULE_DECORATOR)
    assert any("applies the rule 2 times" in finding for finding in _completion(twice))
    blank = _with_rule(ANNOTATED_SIGNATURE.replace("scope='exceptions:read'", "scope=''"))
    found = _completion(blank)
    assert "parameter `principal`: `scope=` must be a non-empty string literal" in found
    assert _completion("def create_app():\n    pass\n") == [
        "`create_app` must define `get_exception` exactly once; found 0"
    ]


def test_the_shipped_route_module_relates_the_guard_and_the_completion_check(
    tmp_path: Path,
) -> None:
    """`completion()` reads the real file as bytes; the row it backs fails on the starter only.

    Either the file is the starter (one finding: no rule yet) or it is completed (none).
    This pins neither state; it pins the relation between the two checks on the real file.
    """
    shipped = route_guard.read_source()
    assert route_guard.findings_for_source(shipped) == []
    completed = route_guard.completion_findings(shipped)
    assert completed == [] or (
        len(completed) == 1 and completed[0].startswith("`get_exception` applies no ")
    )
    copy = tmp_path / "routes.py"
    copy.write_bytes(shipped)
    assert route_guard.completion(copy) == completed


def test_the_baseline_renders_as_a_literal_that_round_trips() -> None:
    """`--print-baseline` output is the literal the module embeds."""
    rendered = route_guard.render_baseline(BASELINE)
    literal = rendered.split("= ", 1)[1]

    assert ast.literal_eval(literal) == BASELINE
    assert [row[1] for row in BASELINE["statements"]] == [
        "_KNOWN_ROUTES",
        "Accepted",
        "create_app",
        "_route_label",
    ]


def test_the_shipped_route_module_passes_the_guard() -> None:
    """The real module passes in every legitimate state: as shipped, and correctly completed."""
    assert route_guard.findings() == []
    assert [row[1] for row in route_guard.STARTER_BASELINE["statements"]][-2:] == [
        "create_app",
        "_route_label",
    ]


def test_verify_order_guard_first_and_contract_after_smoke() -> None:
    """The order the reviews required: integrity bookends, the guard first inside them."""
    tasks = tomllib.loads((TASK_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"][
        "poe"
    ]["tasks"]
    verify = tasks["verify"]

    assert tasks["integrity-record"] == "python -m tests.security.integrity record"
    assert tasks["integrity-check"] == "python -m tests.security.integrity check"
    assert tasks["route-guard"] == "python -m tests.security.route_guard"
    assert tasks["student-guard"] == "python -m tests.security.student_guard"
    assert verify[:4] == ["integrity-record", "route-guard", "student-guard", "unit"]
    assert verify.index("access-contract") == verify.index("smoke") + 1
    assert verify.index("access-contract") < verify.index("e2e")
    assert verify.index("access-contract") < verify.index("student-tests")
    assert verify[-2:] == ["submission", "integrity-check"]
    assert verify.count("integrity-record") == verify.count("integrity-check") == 1
