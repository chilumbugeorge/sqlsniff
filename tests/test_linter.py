from pathlib import Path

from sqlsniff.linter import lint_migrations

CLEAN_SQL = """
CREATE TABLE users (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  email VARCHAR(128) NOT NULL,
  PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""

DIRTY_SQL = """
CREATE TABLE users (
  id INT NOT NULL AUTO_INCREMENT,
  profile JSON,
  PRIMARY KEY (id)
) ENGINE=MyISAM;
"""


def test_passing_files_are_stamped(tmp_path: Path):
    path = tmp_path / "001_init.sql"
    path.write_text(CLEAN_SQL, encoding="utf-8")

    result = lint_migrations(tmp_path)
    assert result.ok
    assert result.files[0].stamped
    assert path.read_text(encoding="utf-8").startswith("-- ignore-lint\n")


def test_failing_files_are_not_stamped(tmp_path: Path):
    path = tmp_path / "001_bad.sql"
    path.write_text(DIRTY_SQL, encoding="utf-8")

    result = lint_migrations(tmp_path)
    assert not result.ok
    assert not result.files[0].stamped
    assert not path.read_text(encoding="utf-8").startswith("-- ignore-lint")
    rule_ids = {violation.rule_id for _, violation in result.violations}
    assert "BIGINT_PRIMARY_KEY" in rule_ids
    assert "ALLOWED_ENGINE" in rule_ids
    assert "NO_JSON" in rule_ids


def test_already_stamped_files_are_skipped(tmp_path: Path):
    path = tmp_path / "001_old.sql"
    path.write_text("-- ignore-lint\n" + DIRTY_SQL, encoding="utf-8")

    result = lint_migrations(tmp_path)
    assert result.ok
    assert result.files[0].skipped


def test_no_stamp_flag(tmp_path: Path):
    path = tmp_path / "001_init.sql"
    path.write_text(CLEAN_SQL, encoding="utf-8")

    result = lint_migrations(tmp_path, stamp_passing=False)
    assert result.ok
    assert not result.files[0].stamped
    assert "ignore-lint" not in path.read_text(encoding="utf-8")
