from __future__ import annotations

from datetime import date
from pathlib import Path

from sqlsniff.discovery import (
    IGNORE_COMMENT,
    DiscoveredFile,
    content_checksum,
    discover_sql_files,
    load_ignore_patterns,
    read_stamp,
)
from sqlsniff.models import FileResult, LintResult
from sqlsniff.rules import lint_sql


def default_migrations_dir() -> Path:
    return (Path.cwd() / ".." / "migrations").resolve()


def stamp_ignore_lint(path: Path) -> bool:
    """Prepend `-- ignore-lint sha256:<digest>` so later runs skip this file.

    Works on raw bytes, so the file's encoding, BOM and line endings are untouched.
    The digest covers the rest of the file: if the file is edited later the stamp
    no longer matches and the file is linted again. Returns True if written.
    """
    stamp = read_stamp(path.read_bytes())
    if stamp.state in ("manual", "valid"):
        return False
    newline = b"\r\n" if b"\r\n" in stamp.body else b"\n"
    line = f"{IGNORE_COMMENT} sha256:{content_checksum(stamp.body)}".encode("ascii")
    path.write_bytes(stamp.bom + line + newline + stamp.body)
    return True


def read_sql(path: Path) -> str:
    """Decode a migration file without ever failing: UTF-8 first, then Latin-1."""
    data = path.read_bytes()
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def lint_file(path: Path) -> FileResult:
    return FileResult(path=path, violations=lint_sql(read_sql(path)))


def lint_migrations(
    migrations_dir: Path | None = None,
    since: date | None = None,
    ignore_file: Path | None = None,
    stamp_passing: bool = False,
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
