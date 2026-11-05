"""sqlSniff: lint MySQL schema migration files against database standards."""

from sqlsniff.linter import lint_migrations
from sqlsniff.models import LintResult, Violation

__all__ = ["lint_migrations", "LintResult", "Violation"]
__version__ = "1.0.0"
