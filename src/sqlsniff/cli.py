from __future__ import annotations

import argparse
import sys
from pathlib import Path

from sqlsniff.discovery import DateArgumentError, parse_since_date
from sqlsniff.linter import default_migrations_dir, lint_migrations
from sqlsniff.models import LintResult


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sqlsniff",
        description=(
            "Lint MySQL schema migration files against database standards. "
            "By default this looks at ../migrations relative to the current working directory."
        ),
    )
    parser.add_argument(
        "migrations_dir",
        nargs="?",
        default=None,
        help="Folder that contains .sql migration files (default: ../migrations).",
    )
    parser.add_argument(
        "--since",
        metavar="MM-DD-YYYY",
        help=(
            "Skip migration files not changed since this date. Uses git commit history when "
            "the folder is in a git repository, otherwise the file's last modified date."
        ),
    )
    parser.add_argument(
        "--ignore-file",
        type=Path,
        help="Extra file of path patterns to skip, in addition to .sqlsniffignore.",
    )
    parser.add_argument(
        "--stamp",
        action="store_true",
        help=(
            "Write '-- ignore-lint sha256:...' at the top of files that pass, so later runs "
            "skip them until they are edited. Off by default: this modifies migration files."
        ),
    )
    # Accepted for backwards compatibility; not stamping is now the default.
    parser.add_argument("--no-stamp", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument(
        "--list-skipped",
        action="store_true",
        help="Print skipped files and the reason they were skipped.",
    )
    return parser


def format_result(result: LintResult, list_skipped: bool = False, stamping: bool = False) -> str:
    lines: list[str] = []
    linted = [item for item in result.files if not item.skipped]
    skipped = [item for item in result.files if item.skipped]
    stamped = [item for item in linted if item.stamped]

    for file_result in linted:
        for violation in file_result.violations:
            lines.append(violation.format(file_result.path))

    if list_skipped:
        for file_result in skipped:
            lines.append(f"{file_result.path}: skipped ({file_result.skip_reason})")

    blocking = [violation for _path, violation in result.violations if violation.blocking]
    advisories = len(result.violations) - len(blocking)
    summary = (
        f"Linted {len(linted)} file(s), skipped {len(skipped)}, "
        f"found {len(blocking)} issue(s)"
    )
    if advisories:
        summary += f" and {advisories} advisory note(s)"
    summary += f", stamped {len(stamped)} passing file(s)." if stamping else "."
    lines.append(summary)
    if not result.ok:
        lines.append(
            "Fix the errors and warnings above (advisory notes do not fail the run), or add "
            "'-- ignore-lint' on its own first line only after a DBA-approved exception."
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    since = None
    if args.since:
        try:
            since = parse_since_date(args.since)
        except DateArgumentError as exc:
            print(str(exc), file=sys.stderr)
            return 2

    stamping = args.stamp and not args.no_stamp
    migrations_dir = Path(args.migrations_dir) if args.migrations_dir else default_migrations_dir()
    try:
        result = lint_migrations(
            migrations_dir=migrations_dir,
            since=since,
            ignore_file=args.ignore_file,
            stamp_passing=stamping,
        )
    except (FileNotFoundError, NotADirectoryError) as exc:
        print(str(exc), file=sys.stderr)
        return 2

    print(format_result(result, list_skipped=args.list_skipped, stamping=stamping))
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
