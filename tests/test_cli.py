from pathlib import Path

from sqlsniff.cli import main

CLEAN_SQL = """
CREATE TABLE users (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  email VARCHAR(128) NOT NULL,
  PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
"""


def test_cli_success(tmp_path: Path, capsys):
    (tmp_path / "001.sql").write_text(CLEAN_SQL, encoding="utf-8")
    assert main([str(tmp_path), "--stamp"]) == 0
    output = capsys.readouterr().out
    assert "found 0 issue(s)" in output
    assert "stamped 1 passing file(s)" in output
    assert (tmp_path / "001.sql").read_text(encoding="utf-8").startswith("-- ignore-lint sha256:")


def test_cli_failure(tmp_path: Path):
    (tmp_path / "001.sql").write_text(
        "CREATE TABLE t (id INT PRIMARY KEY) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;",
        encoding="utf-8",
    )
    assert main([str(tmp_path), "--no-stamp"]) == 1


def test_cli_missing_dir(tmp_path: Path):
    assert main([str(tmp_path / "missing")]) == 2


def test_cli_invalid_date(tmp_path: Path):
    assert main([str(tmp_path), "--since", "2024-01-15"]) == 2


def test_cli_does_not_modify_files_by_default(tmp_path: Path, capsys):
    path = tmp_path / "001.sql"
    path.write_text(CLEAN_SQL, encoding="utf-8")
    assert main([str(tmp_path)]) == 0
    assert path.read_text(encoding="utf-8") == CLEAN_SQL
    assert "stamped" not in capsys.readouterr().out


def test_cli_missing_ignore_file_is_a_usage_error(tmp_path: Path):
    (tmp_path / "001.sql").write_text(CLEAN_SQL, encoding="utf-8")
    assert main([str(tmp_path), "--ignore-file", str(tmp_path / "nope.txt")]) == 2


def test_cli_syntax_error_fails_the_run(tmp_path: Path, capsys):
    (tmp_path / "001.sql").write_text("CREAT TABLE t (id BIGINT);", encoding="utf-8")
    assert main([str(tmp_path)]) == 1
    assert "[SYNTAX_ERROR]" in capsys.readouterr().out


def test_cli_advisory_is_reported_but_does_not_fail(tmp_path: Path, capsys):
    (tmp_path / "001.sql").write_text(
        "CREATE TABLE users (\n  id CHAR(36) PRIMARY KEY DEFAULT (UUID()),\n  username VARCHAR(50) NOT NULL\n);\n",
        encoding="utf-8",
    )
    assert main([str(tmp_path)]) == 0
    output = capsys.readouterr().out
    assert "001.sql:2: advisory: [UUID_PRIMARY_KEY]" in output
    assert "found 0 issue(s) and 1 advisory note(s)." in output
    assert "Fix the errors" not in output
