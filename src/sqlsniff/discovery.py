from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path

IGNORE_COMMENT = "-- ignore-lint"
DATE_FORMAT = "%m-%d-%Y"


class DateArgumentError(ValueError):
    """Raised when a since-date argument is not MM-DD-YYYY."""


@dataclass(frozen=True)
class DiscoveredFile:
    path: Path
    skipped: bool = False
    skip_reason: str | None = None


def parse_since_date(value: str) -> date:
    try:
        return datetime.strptime(value, DATE_FORMAT).date()
    except ValueError as exc:
        raise DateArgumentError(
            f"Invalid date {value!r}. Use MM-DD-YYYY, for example 01-15-2024."
        ) from exc


def file_modified_date(path: Path) -> date:
    return datetime.fromtimestamp(path.stat().st_mtime).date()


def has_ignore_lint_comment(path: Path) -> bool:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line:
                    continue
                return line.lower().startswith(IGNORE_COMMENT)
    except OSError:
        return False
    return False


def load_ignore_patterns(migrations_dir: Path, ignore_file: Path | None = None) -> list[str]:
    candidates = []
    if ignore_file is not None:
        candidates.append(ignore_file)
    else:
        candidates.extend(
            [
                migrations_dir / ".sqlsniffignore",
                Path.cwd() / ".sqlsniffignore",
            ]
        )

    for candidate in candidates:
        if candidate.is_file():
            return [
                line.strip()
                for line in candidate.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]
    return []


def matches_ignore_patterns(path: Path, patterns: list[str]) -> bool:
    haystacks = {path.as_posix(), path.name}
    for pattern in patterns:
        regex_ready = any(token in pattern for token in r"[](){}^$+?")
        for haystack in haystacks:
            if fnmatch.fnmatch(haystack, pattern) or fnmatch.fnmatch(haystack, f"*{pattern}*"):
                return True
            if regex_ready and re.search(pattern, haystack):
                return True
    return False


def discover_sql_files(
    migrations_dir: Path,
    since: date | None = None,
    ignore_patterns: list[str] | None = None,
) -> list[DiscoveredFile]:
    patterns = ignore_patterns or []
    discovered: list[DiscoveredFile] = []
    for path in sorted(migrations_dir.rglob("*.sql")):
        if not path.is_file():
            continue
        if matches_ignore_patterns(path, patterns):
            discovered.append(
                DiscoveredFile(path=path, skipped=True, skip_reason="matches ignore pattern")
            )
            continue
        if has_ignore_lint_comment(path):
            discovered.append(
                DiscoveredFile(path=path, skipped=True, skip_reason="has -- ignore-lint")
            )
            continue
        if since is not None and file_modified_date(path) < since:
            discovered.append(
                DiscoveredFile(
                    path=path,
                    skipped=True,
                    skip_reason=f"older than {since.strftime(DATE_FORMAT)}",
                )
            )
            continue
        discovered.append(DiscoveredFile(path=path))
    return discovered
