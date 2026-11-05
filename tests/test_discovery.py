from datetime import date, datetime, time
from pathlib import Path

from sqlsniff.discovery import discover_sql_files, parse_since_date
from sqlsniff.linter import stamp_ignore_lint


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
    assert path.read_text(encoding="utf-8").startswith("-- ignore-lint\n")
    assert stamp_ignore_lint(path) is False
    assert path.read_text(encoding="utf-8").count("-- ignore-lint") == 1
