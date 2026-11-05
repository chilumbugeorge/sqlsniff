from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class Severity(str, Enum):
    ERROR = "error"
    WARNING = "warning"


@dataclass(frozen=True)
class Violation:
    rule_id: str
    message: str
    severity: Severity
    line: int | None = None

    def format(self, path: Path) -> str:
        location = f"{path}:{self.line}" if self.line is not None else str(path)
        return f"{location}: {self.severity.value}: [{self.rule_id}] {self.message}"


@dataclass
class FileResult:
    path: Path
    skipped: bool = False
    skip_reason: str | None = None
    violations: list[Violation] = field(default_factory=list)
    stamped: bool = False

    @property
    def ok(self) -> bool:
        return self.skipped or not self.violations


@dataclass
class LintResult:
    files: list[FileResult] = field(default_factory=list)

    @property
    def violations(self) -> list[tuple[Path, Violation]]:
        return [
            (result.path, violation)
            for result in self.files
            if not result.skipped
            for violation in result.violations
        ]

    @property
    def ok(self) -> bool:
        return not self.violations
