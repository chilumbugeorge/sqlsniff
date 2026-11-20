from pathlib import Path

import pytest

from sqlsniff.rules import lint_sql

CLEAN = """
CREATE TABLE users (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  email VARCHAR(128) NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  balance DECIMAL(12,2) NOT NULL DEFAULT 0.00,
  full_name VARCHAR(64) GENERATED ALWAYS AS (CONCAT(email, 'x')) STORED,
  PRIMARY KEY (id),
  UNIQUE KEY uq_email (email),
  KEY idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

ALTER TABLE users
  ADD COLUMN nickname VARCHAR(32) NULL AFTER email,
  ADD INDEX idx_nickname (nickname),
  DROP INDEX idx_created,
  DROP COLUMN balance,
  RENAME COLUMN full_name TO display_name;

CREATE UNIQUE INDEX idx_x ON users (email);
DROP TABLE IF EXISTS old_users;
RENAME TABLE a TO b;
INSERT INTO users (email) VALUES ('a@example.com'), ('b;c@example.com')
  ON DUPLICATE KEY UPDATE email = VALUES(email);
INSERT INTO archive SELECT * FROM users WHERE id < 10;
UPDATE users SET email = 'x' WHERE id = 1;
SET NAMES utf8mb4;
START TRANSACTION;
COMMIT;
"""


def syntax_errors(sql: str) -> list[tuple[int | None, str]]:
    return [(v.line, v.message) for v in lint_sql(sql) if v.rule_id == "SYNTAX_ERROR"]


def test_valid_sql_has_no_syntax_errors():
    assert lint_sql(CLEAN) == []


def test_wide_range_of_valid_mysql_is_accepted():
    sql = (Path(__file__).parent / "fixtures" / "valid.sql").read_text(encoding="utf-8")
    assert lint_sql(sql) == []


@pytest.mark.parametrize(
    ("sql", "line", "fragment"),
    [
        ("SELECT 'abc;\nSELECT 2;", 1, "Unterminated string literal"),
        ("SELECT 1;\n/* never closed\nSELECT 2;", 2, "Unterminated /* block comment"),
        ("SELECT `abc FROM t;", 1, "Unterminated ` quoted identifier"),
        ("CREATE TABLE t (\n  id BIGINT UNSIGNED PRIMARY KEY\n ENGINE=InnoDB;", 1, "Unclosed '('"),
        ("CREATE TABLE t (id BIGINT UNSIGNED PRIMARY KEY)) ENGINE=InnoDB;", 1, "Unexpected ')'"),
        ("SELECT 1;\nSELECT 2", 2, "not terminated with ';'"),
        ("CREAT TABLE t (id BIGINT);", 1, "Unrecognised statement starting with `CREAT`"),
        ("CREATE TABEL t (id BIGINT);", 1, "Unrecognised CREATE statement"),
        ("ALTER TABEL t ADD COLUMN a BIGINT;", 1, "Unrecognised ALTER statement"),
        ("DROP TABEL t;", 1, "Unrecognised DROP statement"),
        ("CREATE TABLE (id BIGINT);", 1, "missing a table name"),
        ("CREATE TABLE t id BIGINT;", 1, "has no '(' column list"),
        ("CREATE TABLE t () ENGINE=InnoDB;", 1, "has no columns"),
    ],
)
def test_statement_level_syntax_errors(sql: str, line: int, fragment: str):
    errors = syntax_errors(sql)
    assert any(found_line == line and fragment in message for found_line, message in errors), errors


def body(*lines: str) -> str:
    return "CREATE TABLE t (\n" + "\n".join(lines) + "\n) ENGINE=InnoDB;\n"


@pytest.mark.parametrize(
    ("sql", "line", "fragment"),
    [
        (body("  id BIGINT UNSIGNED PRIMARY KEY,", "  a BIGINT,"), 4, "stray or trailing comma"),
        (body("  id BIGINT UNSIGNED PRIMARY KEY,,", "  a BIGINT"), 2, "stray or trailing comma"),
        (body("  id BIGINT UNSIGNED PRIMARY KEY,", "  a BIGINT", "  b BIGINT"), 4, "comma is probably missing"),
        (body("  id BIGINT UNSIGNED PRIMARY KEY,", "  a VARCHRA(32)"), 3, "Unknown data type `VARCHRA`"),
        (body("  id BIGINT UNSIGNED PRIMARY KEY,", "  a"), 3, "Column `a` has no data type"),
        (body("  id BIGINT UNSIGNED PRIMARY KEY,", "  a BIGINT,", "  A BIGINT"), 4, "Duplicate column name `a`"),
        (body("  id BIGINT UNSIGNED PRIMARY KEY,", "  PRIMARY KEY (id)"), 1, "more than one PRIMARY KEY"),
        (body("  id BIGINT UNSIGNED,", "  PRIMARY KEY (idd)"), 3, "unknown column `idd`"),
        ("ALTER TABLE t ADD COLUMN a BIGNIT;", 1, "Unknown data type `BIGNIT`"),
        ("ALTER TABLE t\n  ADD COLUMN a BIGINT\n  ADD COLUMN b BIGINT;", 3, "comma is probably missing"),
    ],
)
def test_table_definition_syntax_errors(sql: str, line: int, fragment: str):
    errors = syntax_errors(sql)
    assert any(found_line == line and fragment in message for found_line, message in errors), errors


def test_misspelt_column_attribute_is_reported():
    sql = (
        "create table tb1(\n"
        "    id bigint unsigned not null auto_increment,\n"
        "    first varchar(128) not nul,\n"
        "    primary key(id)\n"
        ");\n"
    )
    violations = lint_sql(sql)
    assert [(v.line, v.rule_id) for v in violations] == [(3, "SYNTAX_ERROR")]
    assert violations[0].message == (
        "Unexpected `NUL` in the definition of column `first`. Did you mean `NULL`?"
    )


@pytest.mark.parametrize(
    ("column", "fragment"),
    [
        ("a BIGINT NOT NULL AUTO_INCREMNT", "Unexpected `AUTO_INCREMNT`"),
        ("a BIGINT UNSIGND NOT NULL", "Unexpected `UNSIGND`"),
        ("a VARCHAR(32) NOT NULL DEFALT 'x'", "Unexpected `DEFALT`"),
        ("a VARCHAR(32) NULL COMENT 'note'", "Unexpected `COMENT`"),
        ("a DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ONUPDATE CURRENT_TIMESTAMP", "Unexpected `ONUPDATE`"),
        ("a BIGINT NOT NULL PRIMRY KEY", "Unexpected `PRIMRY`"),
    ],
)
def test_misspelt_column_attributes(column: str, fragment: str):
    errors = syntax_errors(body("  id BIGINT UNSIGNED PRIMARY KEY,", f"  {column}"))
    assert len(errors) == 1 and errors[0][0] == 3 and fragment in errors[0][1], errors
    errors = syntax_errors(f"ALTER TABLE t ADD COLUMN {column};")
    assert len(errors) == 1 and fragment in errors[0][1], errors


@pytest.mark.parametrize(
    "column",
    [
        "a VARCHAR(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL DEFAULT 'not nul'",
        "a BIGINT UNSIGNED NOT NULL DEFAULT 0 COMMENT 'nul defalt'",
        "a DECIMAL(10,2) NOT NULL DEFAULT -1.5",
        "a BIT(1) NOT NULL DEFAULT b'0'",
        "a DATETIME(6) NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP(6)",
        "a DATETIME NOT NULL DEFAULT NOW()",
        "a BIGINT GENERATED ALWAYS AS (id + 1) STORED NOT NULL",
        "a BIGINT AS (id * 2) VIRTUAL INVISIBLE",
        "a VARCHAR(16) NOT NULL DEFAULT (UUID()) CHECK (a <> 'nul') NOT ENFORCED",
        "a BIGINT CONSTRAINT chk_a CHECK (a > 0)",
        "a BIGINT UNSIGNED NOT NULL UNIQUE KEY COLUMN_FORMAT FIXED STORAGE DISK",
        "a VARCHAR(8) COLLATE utf8mb4_bin DEFAULT _utf8mb4'x'",
    ],
)
def test_valid_column_attributes_are_accepted(column: str):
    assert syntax_errors(body("  id BIGINT UNSIGNED PRIMARY KEY,", f"  {column}")) == []


def test_alter_column_position_keywords_are_accepted():
    assert lint_sql("ALTER TABLE t ADD COLUMN a BIGINT NOT NULL FIRST, MODIFY b BIGINT NULL AFTER a;") == []


@pytest.mark.parametrize(
    ("options", "fragment"),
    [
        ("ENGIN=InnoDB", "Unknown table option `ENGIN` for table `t`. Did you mean `ENGINE`?"),
        ("ENGINE=InnoDB DEFAULT CHARST=utf8mb4", "Unknown table option `CHARST`"),
        ("ENGINE=InnoDB ROW_FORMT=DYNAMIC", "Unknown table option `ROW_FORMT`"),
    ],
)
def test_misspelt_table_options(options: str, fragment: str):
    errors = syntax_errors(f"CREATE TABLE t (\n  id BIGINT UNSIGNED PRIMARY KEY\n) {options};")
    assert len(errors) == 1 and errors[0][0] == 3 and fragment in errors[0][1], errors


@pytest.mark.parametrize(
    "options",
    [
        "",
        "ENGINE = InnoDB, DEFAULT CHARACTER SET = utf8mb4 COLLATE = utf8mb4_bin",
        "ENGINE=InnoDB AUTO_INCREMENT=5 ROW_FORMAT=COMPRESSED KEY_BLOCK_SIZE=8 COMMENT='engin charst'",
        "ENGINE=InnoDB STATS_PERSISTENT=1 DATA DIRECTORY='/x' TABLESPACE ts1 PARTITION BY KEY (id) PARTITIONS 2",
    ],
)
def test_valid_table_options_are_accepted(options: str):
    assert lint_sql(f"CREATE TABLE t (\n  id BIGINT UNSIGNED PRIMARY KEY\n) {options};") == []


def test_missing_semicolon_between_statements():
    sql = "CREATE TABLE a (id BIGINT UNSIGNED PRIMARY KEY) ENGINE=InnoDB\nCREATE TABLE b (id BIGINT UNSIGNED PRIMARY KEY) ENGINE=InnoDB;\n"
    assert (2, "`CREATE TABLE` begins inside another statement - a ';' is probably missing before it.") in syntax_errors(sql)

    sql = "DROP TABLE a\nALTER TABLE b ADD COLUMN c BIGINT;"
    assert any(line == 2 and "ALTER TABLE" in message for line, message in syntax_errors(sql))


def test_composite_primary_key_with_prefix_and_order_is_accepted():
    sql = body(
        "  tenant BIGINT UNSIGNED NOT NULL,",
        "  code VARCHAR(64) NOT NULL,",
        "  PRIMARY KEY (tenant, code(16) DESC)",
    )
    assert syntax_errors(sql) == []


def test_syntax_error_in_string_stops_other_rules():
    violations = lint_sql("CREATE TABLE t (a ENUM('x)) ENGINE=MyISAM;")
    assert [v.rule_id for v in violations] == ["SYNTAX_ERROR"]
