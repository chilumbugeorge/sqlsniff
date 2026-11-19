from __future__ import annotations

import fnmatch
import hashlib
import re
import subprocess
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path

IGNORE_COMMENT = "-- ignore-lint"
DATE_FORMAT = "%m-%d-%Y"
BOM = b"\xef\xbb\xbf"

# First non-blank line is `-- ignore-lint`, optionally followed by `sha256:<digest>`.
STAMP_RE = re.compile(
    rb"\A(?P<lead>(?:[ \t]*\r?\n)*)[ \t]*--[ \t]+ignore-lint\b(?P<rest>[^\r\n]*)(?:\r?\n|\Z)",
    re.IGNORECASE,
)
CHECKSUM_RE = re.compile(rb"sha256:([0-9a-f]{16})\b", re.IGNORECASE)


class DateArgumentError(ValueError):
    """Raised when a since-date argument is not MM-DD-YYYY."""


@dataclass(frozen=True)
class DiscoveredFile:
    path: Path
    skipped: bool = False
    skip_reason: str | None = None


@dataclass(frozen=True)
class Stamp:
    """State of the `-- ignore-lint` line at the top of a file.

    state is one of:
      "none"   - no stamp
      "manual" - bare `-- ignore-lint`, a hand-written exception that always skips
      "valid"  - written by `--stamp`, and the file is unchanged since it passed
      "stale"  - written by `--stamp`, but the file has been edited since
    """

    state: str
    bom: bytes
    body: bytes


def content_checksum(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()[:16]


def read_stamp(data: bytes) -> Stamp:
    bom = BOM if data.startswith(BOM) else b""
    content = data[len(bom) :]
    match = STAMP_RE.match(content)
    if not match:
        return Stamp("none", bom, content)
    body = match.group("lead") + content[match.end() :]
    checksum = CHECKSUM_RE.search(match.group("rest"))
    if not checksum:
        return Stamp("manual", bom, body)
    valid = checksum.group(1).decode().lower() == content_checksum(body)
    return Stamp("valid" if valid else "stale", bom, body)


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
    """True when the file should be skipped because of its `-- ignore-lint` line."""
    try:
        return read_stamp(path.read_bytes()).state in ("manual", "valid")
    except OSError:
        return False


def _read_patterns(path: Path) -> list[str]:
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def load_ignore_patterns(migrations_dir: Path, ignore_file: Path | None = None) -> list[str]:
    """Patterns from `.sqlsniffignore` plus any extra patterns from `ignore_file`."""
    patterns: list[str] = []
    for candidate in (migrations_dir / ".sqlsniffignore", Path.cwd() / ".sqlsniffignore"):
        if candidate.is_file():
            patterns.extend(_read_patterns(candidate))
            break
    if ignore_file is not None:
        if not ignore_file.is_file():
            raise FileNotFoundError(f"Ignore file not found: {ignore_file}")
        patterns.extend(_read_patterns(ignore_file))
    return patterns


def matches_ignore_patterns(path: Path, patterns: list[str], root: Path | None = None) -> bool:
    """Glob/substring match against the path relative to the migrations folder."""
    relative = path
    if root is not None:
        try:
            relative = path.relative_to(root)
        except ValueError:
            relative = path
    haystacks = {relative.as_posix(), path.name}
    for pattern in patterns:
        for haystack in haystacks:
            if fnmatch.fnmatch(haystack, pattern) or fnmatch.fnmatch(haystack, f"*{pattern}*"):
                return True
    return False


def _git(directory: Path, *args: str) -> str | None:
    try:
        completed = subprocess.run(
            ["git", "-C", str(directory), *args],
            capture_output=True,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.decode("utf-8", errors="surrogateescape")


@dataclass(frozen=True)
class GitHistory:
    """Which tracked files changed since a date, according to git commit history."""

    tracked: frozenset[Path]
    dirty: frozenset[Path]
    committed_since: frozenset[Path]

    def changed_since(self, path: Path) -> bool | None:
        """None means git cannot answer for this file (untracked or uncommitted edits)."""
        resolved = path.resolve()
        if resolved not in self.tracked or resolved in self.dirty:
            return None
        return resolved in self.committed_since


def load_git_history(directory: Path, since: date) -> GitHistory | None:
    """Read commit history for `directory`. Returns None outside a git work tree."""
    top = _git(directory, "rev-parse", "--show-toplevel")
    if top is None:
        return None
    root = Path(top.strip())
    tracked = _git(directory, "ls-files", "-z", "--full-name", "--", ".")
    status = _git(directory, "status", "--porcelain", "-z", "--untracked-files=all", "--", ".")
    log = _git(
        directory,
        "log",
        f"--since={since.isoformat()}T00:00:00",
        "--name-only",
        "--pretty=format:",
        "-z",
        "--",
        ".",
    )
    if tracked is None or status is None or log is None:
        return None

    def paths(names: list[str]) -> frozenset[Path]:
        return frozenset((root / name).resolve() for name in names if name)

    dirty: list[str] = []
    entries = status.split("\0")
    index = 0
    while index < len(entries):
        entry = entries[index]
        if len(entry) > 3:
            dirty.append(entry[3:])
            if entry[0] in "RC":
                index += 1  # skip the rename/copy source path
        index += 1

    return GitHistory(
        tracked=paths(tracked.split("\0")),
        dirty=paths(dirty),
        committed_since=paths([name.strip() for name in re.split(r"[\0\n]", log)]),
    )


def discover_sql_files(
    migrations_dir: Path,
    since: date | None = None,
    ignore_patterns: list[str] | None = None,
) -> list[DiscoveredFile]:
    patterns = ignore_patterns or []
    history = load_git_history(migrations_dir, since) if since is not None else None
    discovered: list[DiscoveredFile] = []
    for path in sorted(migrations_dir.rglob("*.sql")):
        if not path.is_file():
            continue
        if matches_ignore_patterns(path, patterns, root=migrations_dir):
            discovered.append(
                DiscoveredFile(path=path, skipped=True, skip_reason="matches ignore pattern")
            )
            continue
        if has_ignore_lint_comment(path):
            discovered.append(
                DiscoveredFile(path=path, skipped=True, skip_reason="has -- ignore-lint")
            )
            continue
        if since is not None:
            recent = history.changed_since(path) if history is not None else None
            if recent is None:
                recent = file_modified_date(path) >= since
            if not recent:
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
