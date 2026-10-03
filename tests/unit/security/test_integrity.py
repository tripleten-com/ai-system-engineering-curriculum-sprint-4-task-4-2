"""Coldline.

===================

File:              tests/unit/security/test_integrity.py
Component:         Unit tests — Verification integrity snapshot
Purpose:           Prove the snapshot names every file changed, added, or removed while `poe
                    verify` ran, including by a student test's teardown.
Interacts With:    tests/security/integrity.py, pyproject.toml
Sprint/Task:       Sprint 4 — Project 4 / Task 4.2
Concepts:          Trusted bookends, content hashes, tamper evidence
Tools:             Python 3.12, pytest

The tests build a small tree shaped like the Task's trusted paths under ``tmp_path`` and
point the snapshot at a file beside it, so nothing here touches the real checkout or the
system temporary directory. One test runs a real pytest subprocess over a student file
whose session teardown rewrites the route module, the scenario the check exists for.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from tests.security import integrity

TRUSTED_TREE = {
    "pyproject.toml": "[tool.poe.tasks]\nverify = []\n",
    "config/auth.yaml": "issuer: https://issuer.coldline.test\n",
    "src/api/routes.py": "def create_app():\n    return Depends(require_access(role='r'))\n",
    "src/api/security/access.py": "STATUS_BY_KIND = {}\n",
    "tests/contract/test_exception_access.py": "def test_row():\n    pass\n",
    "tests/security/mutation.py": "MUTATIONS = ()\n",
    "tests/fixtures/tokens/fixtures.yaml": "fixtures: {}\n",
    "tests/student/test_exception_access.py": "def test_student():\n    pass\n",
}

TAMPERING_STUDENT_FILE = '''"""A student file whose session teardown rewrites the route module."""

from pathlib import Path

import pytest

ROUTES = Path(__file__).resolve().parents[2] / "src/api/routes.py"


@pytest.fixture(scope="session")
def harness():
    yield "harness"
    # Teardown: by now every assertion has run; rewrite the route module behind the checks.
    ROUTES.write_text("def create_app():\\n    return None\\n", encoding="utf-8")


def test_dispatcher_reads(harness):
    assert harness == "harness"
'''


def _tree(root: Path) -> None:
    """Write the small trusted tree, plus noise the snapshot must ignore."""
    for relative, text in TRUSTED_TREE.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    cache = root / "tests/security/__pycache__"
    cache.mkdir()
    (cache / "mutation.cpython-312.pyc").write_bytes(b"\x00")
    (root / "README.md").write_text("not covered\n", encoding="utf-8")


def test_the_snapshot_covers_the_trusted_paths_and_skips_caches(tmp_path: Path) -> None:
    """Every file under the trusted paths is hashed; `__pycache__` and other files are not."""
    _tree(tmp_path)

    files = [path.as_posix() for path in integrity.trusted_files(tmp_path)]

    assert files == [
        "config/auth.yaml",
        "src/api/routes.py",
        "tests/student/test_exception_access.py",
        "tests/contract/test_exception_access.py",
        "tests/security/mutation.py",
        "src/api/security/access.py",
        "tests/fixtures/tokens/fixtures.yaml",
        "pyproject.toml",
    ]
    digests = integrity.snapshot(tmp_path)
    assert set(digests) == set(files)
    assert all(len(digest) == 64 for digest in digests.values())


def test_compare_names_changed_added_and_removed_files() -> None:
    """One finding per file, in path order, saying which of the three happened."""
    before = {"a.py": "1", "b.py": "2", "c.py": "3"}
    after = {"a.py": "1", "b.py": "9", "d.py": "4"}

    assert integrity.compare(before, after) == [
        "b.py changed during verification",
        "c.py was removed during verification",
        "d.py was added during verification",
    ]
    assert integrity.compare(before, dict(before)) == []


def test_a_student_teardown_that_rewrites_the_route_module_is_named(tmp_path: Path) -> None:
    """Record, run a student file whose session teardown edits routes.py, check: routes.py is named.

    This is Astra's round-2 scenario: the student tests pass as written, and only after
    the last assertion does the teardown strip the rule. The snapshot recorded before the
    run disagrees with the tree after it, and the check says which file.
    """
    _tree(tmp_path)
    student = tmp_path / "tests/student/test_exception_access.py"
    student.write_text(TAMPERING_STUDENT_FILE, encoding="utf-8")
    snapshot = tmp_path.parent / f"{tmp_path.name}-snapshot.json"

    recorded = integrity.record(tmp_path, snapshot)
    assert recorded == snapshot and snapshot.is_file()
    before = (tmp_path / "src/api/routes.py").read_text(encoding="utf-8")

    completed = subprocess.run(
        [sys.executable, "-m", "pytest", str(student), "-q", "-p", "no:cacheprovider"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert (tmp_path / "src/api/routes.py").read_text(encoding="utf-8") != before

    assert integrity.check(tmp_path, snapshot) == [
        "src/api/routes.py changed during verification",
    ]
    assert not snapshot.exists(), "the snapshot is consumed by the check"


def test_an_unchanged_tree_passes_and_the_snapshot_is_consumed(tmp_path: Path) -> None:
    """Record then check with nothing in between: no findings, and the snapshot is gone."""
    _tree(tmp_path)
    snapshot = tmp_path.parent / f"{tmp_path.name}-clean.json"

    integrity.record(tmp_path, snapshot)
    assert integrity.check(tmp_path, snapshot) == []
    assert not snapshot.exists()


def test_a_missing_foreign_or_malformed_snapshot_is_a_tooling_error(tmp_path: Path) -> None:
    """No snapshot, another checkout's snapshot, or an unreadable one: an error, not a pass."""
    _tree(tmp_path)
    snapshot = tmp_path.parent / f"{tmp_path.name}-errors.json"

    with pytest.raises(integrity.IntegrityError, match="no integrity snapshot"):
        integrity.check(tmp_path, snapshot)

    other = tmp_path / "other"
    other.mkdir()
    _tree(other)
    integrity.record(other, snapshot)
    with pytest.raises(integrity.IntegrityError, match="was recorded for"):
        integrity.check(tmp_path, snapshot)

    snapshot.write_text("{not json", encoding="utf-8")
    with pytest.raises(integrity.IntegrityError, match="could not be read"):
        integrity.check(tmp_path, snapshot)
    snapshot.write_text('{"root": "x", "files": "nope"}', encoding="utf-8")
    with pytest.raises(integrity.IntegrityError, match="no file digests"):
        integrity.check(tmp_path, snapshot)


def test_the_snapshot_lives_outside_the_repository_per_checkout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The default path is in the system temporary directory and differs per checkout root."""
    monkeypatch.delenv(integrity.SNAPSHOT_VARIABLE, raising=False)
    first = integrity.snapshot_path(tmp_path / "one")
    second = integrity.snapshot_path(tmp_path / "two")

    assert first != second
    assert first.parent == second.parent
    assert not first.is_relative_to(tmp_path)
    assert first.name.startswith("coldline-verify-") and first.suffix == ".json"

    monkeypatch.setenv(integrity.SNAPSHOT_VARIABLE, str(tmp_path / "override.json"))
    assert integrity.snapshot_path(tmp_path / "one") == tmp_path / "override.json"


def test_the_command_line_records_then_checks(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`record` exits 0 with the count; `check` exits 1 naming a change, 2 without a snapshot."""
    _tree(tmp_path)
    monkeypatch.setenv(integrity.SNAPSHOT_VARIABLE, str(tmp_path.parent / f"{tmp_path.name}.json"))

    assert integrity.main(["check", "--root", str(tmp_path)]) == 2
    assert "no integrity snapshot" in capsys.readouterr().err

    assert integrity.main(["record", "--root", str(tmp_path)]) == 0
    assert "recorded 8 trusted files" in capsys.readouterr().out
    (tmp_path / "tests/security/mutation.py").write_text("MUTATIONS = ('x',)\n", encoding="utf-8")
    assert integrity.main(["check", "--root", str(tmp_path)]) == 1
    assert "- tests/security/mutation.py changed during verification" in capsys.readouterr().err

    assert integrity.main(["record", "--root", str(tmp_path)]) == 0
    assert integrity.main(["check", "--root", str(tmp_path)]) == 0
    assert "every trusted file is as it was" in capsys.readouterr().out
