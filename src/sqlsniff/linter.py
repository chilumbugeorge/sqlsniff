from __future__ import annotations

from datetime import date
from pathlib import Path

from sqlsniff.discovery import (
    IGNORE_COMMENT,
    DiscoveredFile,
    discover_sql_files,
    has_ignore_lint_comment,
    load_ignore_patterns,
)
from sqlsniff.models import FileResult, LintResult
from sqlsniff.rules import lint_sql


def default_migrations_dir() -> Path:
    return (Path.cwd() / ".." / "migrations").resolve()


def stamp_ignore_lint(path: Path) -> bool:
    """Prepend `-- ignore-lint` so later runs skip this file. Returns True if written."""
    if has_ignore_lint_comment(path):
        return False
    original = path.read_text(encoding="utf-8", errors="replace")
    prefix = f"{IGNORE_COMMENT}\n"
    if original.startswith("\ufeff"):
        original = original.lstrip("\ufeff")
        path.write_text("\ufeff" + prefix + original, encoding="utf-8")
    else:
        path.write_text(prefix + original, encoding="utf-8")
    return True


def lint_file(path: Path) -> FileResult:
    sql = path.read_text(encoding="utf-8", errors="replace")
    return FileResult(path=path, violations=lint_sql(sql))


def lint_migrations(
    migrations_dir: Path | None = None,
    since: date | None = None,
    ignore_file: Path | None = None,
    stamp_passing: bool = True,
) -> LintResult:
    target = (migrations_dir or default_migrations_dir()).resolve()
    if not target.exists():
        raise FileNotFoundError(
            f"Migrations folder not found: {target}. "
            "Pass a path or run sqlsniff from a checkout next to a ../migrations folder."
        )
    if not target.is_dir():
        raise NotADirectoryError(f"Not a directory: {target}")

    patterns = load_ignore_patterns(target, ignore_file=ignore_file)
    result = LintResult()
    for discovered in discover_sql_files(target, since=since, ignore_patterns=patterns):
        result.files.append(_lint_discovered(discovered, stamp_passing=stamp_passing))
    return result


def _lint_discovered(discovered: DiscoveredFile, stamp_passing: bool) -> FileResult:
    if discovered.skipped:
        return FileResult(
            path=discovered.path,
            skipped=True,
            skip_reason=discovered.skip_reason,
        )
    file_result = lint_file(discovered.path)
    if stamp_passing and file_result.ok:
        file_result.stamped = stamp_ignore_lint(discovered.path)
    return file_result
