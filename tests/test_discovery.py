import shutil
import subprocess
from datetime import date, datetime, time
from pathlib import Path

import pytest

from sqlsniff.discovery import (
    discover_sql_files,
    load_ignore_patterns,
    matches_ignore_patterns,
    parse_since_date,
)
from sqlsniff.linter import lint_migrations, stamp_ignore_lint


def _write_sql(path: Path, contents: str, modified: datetime | None = None) -> Path:
    path.write_text(contents, encoding="utf-8")
    if modified is not None:
        stamp = modified.timestamp()
        path.touch()
        import os

        os.utime(path, (stamp, stamp))
    return path


def test_parse_since_date():
    assert parse_since_date("01-15-2024") == date(2024, 1, 15)


def test_skips_files_older_than_since(tmp_path: Path):
    old = _write_sql(
        tmp_path / "old.sql",
        "SELECT 1;",
        modified=datetime.combine(date(2020, 1, 1), time.min),
    )
    new = _write_sql(
        tmp_path / "new.sql",
        "SELECT 1;",
        modified=datetime.combine(date(2024, 6, 1), time.min),
    )

    discovered = {item.path.name: item for item in discover_sql_files(tmp_path, since=date(2024, 1, 1))}
    assert discovered[old.name].skipped
    assert discovered[old.name].skip_reason == "older than 01-01-2024"
    assert not discovered[new.name].skipped


def test_skips_files_with_ignore_lint_comment(tmp_path: Path):
    ignored = _write_sql(tmp_path / "done.sql", "-- ignore-lint\nSELECT 1;\n")
    pending = _write_sql(tmp_path / "todo.sql", "SELECT 1;\n")
    discovered = {item.path.name: item for item in discover_sql_files(tmp_path)}
    assert discovered[ignored.name].skipped
    assert not discovered[pending.name].skipped


def test_ignore_patterns(tmp_path: Path):
    _write_sql(tmp_path / "keep.sql", "SELECT 1;")
    _write_sql(tmp_path / "skip_legacy.sql", "SELECT 1;")
    discovered = {
        item.path.name: item
        for item in discover_sql_files(tmp_path, ignore_patterns=["*legacy*"])
    }
    assert discovered["skip_legacy.sql"].skipped
    assert not discovered["keep.sql"].skipped


def test_stamp_ignore_lint_is_idempotent(tmp_path: Path):
    path = _write_sql(tmp_path / "ok.sql", "SELECT 1;\n")
    assert stamp_ignore_lint(path) is True
    assert path.read_text(encoding="utf-8").startswith("-- ignore-lint sha256:")
    assert stamp_ignore_lint(path) is False
    assert path.read_text(encoding="utf-8").count("-- ignore-lint") == 1


CLEAN_SQL = (
    "CREATE TABLE t (\n"
    "  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,\n"
    "  PRIMARY KEY (id)\n"
    ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;\n"
)


def test_stamp_preserves_bom_and_is_not_repeated(tmp_path: Path):
    path = tmp_path / "bom.sql"
    path.write_bytes(b"\xef\xbb\xbf" + CLEAN_SQL.encode())
    for _ in range(3):
        lint_migrations(tmp_path, stamp_passing=True)
    data = path.read_bytes()
    assert data.startswith(b"\xef\xbb\xbf-- ignore-lint sha256:")
    assert data.count(b"-- ignore-lint") == 1
    assert data.endswith(CLEAN_SQL.encode())


def test_stamp_does_not_corrupt_non_utf8_files(tmp_path: Path):
    path = tmp_path / "latin1.sql"
    original = CLEAN_SQL.replace("PRIMARY KEY (id)", "PRIMARY KEY (id) COMMENT 'caf\xe9'").encode("latin-1")
    path.write_bytes(original)
    result = lint_migrations(tmp_path, stamp_passing=True)
    assert result.files[0].stamped
    assert path.read_bytes().endswith(original)


def test_stamp_preserves_crlf_line_endings(tmp_path: Path):
    path = tmp_path / "crlf.sql"
    original = CLEAN_SQL.replace("\n", "\r\n").encode()
    path.write_bytes(original)
    lint_migrations(tmp_path, stamp_passing=True)
    data = path.read_bytes()
    assert data.endswith(original)
    assert b"\n" not in data.replace(b"\r\n", b"")


def test_stamped_file_is_linted_again_after_it_is_edited(tmp_path: Path):
    path = tmp_path / "001.sql"
    path.write_text(CLEAN_SQL, encoding="utf-8")
    lint_migrations(tmp_path, stamp_passing=True)
    assert lint_migrations(tmp_path).files[0].skipped

    with path.open("a", encoding="utf-8") as handle:
        handle.write("CREATE TABLE bad (x ENUM('a','b')) ENGINE=MyISAM;\n")
    result = lint_migrations(tmp_path, stamp_passing=True)
    assert not result.files[0].skipped
    assert not result.ok

    fixed = path.read_text(encoding="utf-8").replace("ENUM('a','b')) ENGINE=MyISAM", "BIGINT PRIMARY KEY) ENGINE=InnoDB")
    path.write_text(fixed, encoding="utf-8")
    result = lint_migrations(tmp_path, stamp_passing=True)
    assert result.ok and result.files[0].stamped
    assert lint_migrations(tmp_path).files[0].skipped
    assert path.read_text(encoding="utf-8").count("-- ignore-lint") == 1


def test_manual_ignore_lint_always_skips(tmp_path: Path):
    path = _write_sql(tmp_path / "exception.sql", "-- ignore-lint\nCREATE TABLE t (x ENUM('a'));\n")
    assert lint_migrations(tmp_path).files[0].skipped
    assert stamp_ignore_lint(path) is False


def test_ignore_patterns_do_not_match_parent_directories(tmp_path: Path):
    root = tmp_path / "legacy-app" / "migrations"
    (root / "vendor").mkdir(parents=True)
    _write_sql(root / "keep.sql", "SELECT 1;")
    _write_sql(root / "old_legacy.sql", "SELECT 1;")
    _write_sql(root / "vendor" / "lib.sql", "SELECT 1;")
    discovered = {
        item.path.name: item
        for item in discover_sql_files(root, ignore_patterns=["*legacy*", "vendor/"])
    }
    assert not discovered["keep.sql"].skipped
    assert discovered["old_legacy.sql"].skipped
    assert discovered["lib.sql"].skipped


def test_ignore_pattern_with_regex_characters_does_not_crash():
    assert matches_ignore_patterns(Path("/m/001.sql"), ["[abc", "(x", "a+b"]) is False


def test_ignore_file_adds_to_sqlsniffignore_and_must_exist(tmp_path: Path):
    (tmp_path / ".sqlsniffignore").write_text("# comment\n*legacy*\n", encoding="utf-8")
    extra = tmp_path / "extra.txt"
    extra.write_text("vendor/\n", encoding="utf-8")
    assert load_ignore_patterns(tmp_path, ignore_file=extra) == ["*legacy*", "vendor/"]
    with pytest.raises(FileNotFoundError):
        load_ignore_patterns(tmp_path, ignore_file=tmp_path / "missing.txt")


@pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
def test_since_uses_git_commit_dates_not_checkout_time(tmp_path: Path):
    def git(*args: str, when: str | None = None) -> None:
        env = {"GIT_AUTHOR_DATE": when, "GIT_COMMITTER_DATE": when} if when else {}
        subprocess.run(
            ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", *args],
            cwd=tmp_path,
            check=True,
            capture_output=True,
            env={**__import__("os").environ, **env},
        )

    git("init", "-q")
    _write_sql(tmp_path / "old.sql", "SELECT 1;\n")
    git("add", "old.sql")
    git("commit", "-q", "-m", "old", when="2020-01-01T12:00:00")
    _write_sql(tmp_path / "new.sql", "SELECT 1;\n")
    git("add", "new.sql")
    git("commit", "-q", "-m", "new", when="2024-06-01T12:00:00")
    _write_sql(tmp_path / "untracked.sql", "SELECT 1;\n")

    # Every file has a fresh modified time, exactly as after a CI checkout.
    discovered = {item.path.name: item for item in discover_sql_files(tmp_path, since=date(2024, 1, 1))}
    assert discovered["old.sql"].skipped
    assert not discovered["new.sql"].skipped
    assert not discovered["untracked.sql"].skipped

    # An uncommitted edit to an old file falls back to its modified time.
    _write_sql(tmp_path / "old.sql", "SELECT 2;\n")
    discovered = {item.path.name: item for item in discover_sql_files(tmp_path, since=date(2024, 1, 1))}
    assert not discovered["old.sql"].skipped
