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
    assert main([str(tmp_path)]) == 0
    output = capsys.readouterr().out
    assert "found 0 issue(s)" in output
    assert (tmp_path / "001.sql").read_text(encoding="utf-8").startswith("-- ignore-lint")


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
