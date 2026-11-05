from sqlsniff.rules import lint_sql


def rule_ids(sql: str) -> set[str]:
    return {violation.rule_id for violation in lint_sql(sql)}


CLEAN_TABLE = """
CREATE TABLE users (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  email VARCHAR(128) NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
"""


def test_clean_table_passes():
    assert lint_sql(CLEAN_TABLE) == []


def test_enum_is_flagged():
    sql = "ALTER TABLE users ADD COLUMN status ENUM('active','disabled');"
    assert "NO_ENUM" in rule_ids(sql)


def test_set_type_is_flagged():
    sql = """
    CREATE TABLE flags (
      id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
      flags SET('a','b')
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """
    assert "NO_SET" in rule_ids(sql)


def test_disallowed_engine():
    sql = """
    CREATE TABLE t (
      id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY
    ) ENGINE=MyISAM;
    """
    assert "ALLOWED_ENGINE" in rule_ids(sql)


def test_innodb_engine_allowed():
    assert "ALLOWED_ENGINE" not in rule_ids(CLEAN_TABLE)


def test_blob_and_tinyblob():
    blob_sql = "ALTER TABLE t ADD COLUMN payload BLOB;"
    tiny_sql = "ALTER TABLE t ADD COLUMN payload TINYBLOB;"
    assert "NO_BLOB" in rule_ids(blob_sql)
    assert "NO_BLOB" not in rule_ids(tiny_sql)


def test_json_and_text():
    assert "NO_JSON" in rule_ids("ALTER TABLE t ADD COLUMN meta JSON;")
    assert "NO_TEXT" in rule_ids("ALTER TABLE t ADD COLUMN body TEXT;")
    assert "NO_TEXT" not in rule_ids("ALTER TABLE t ADD COLUMN body TINYTEXT;")


def test_varchar_width():
    assert "VARCHAR_WIDTH" in rule_ids("ALTER TABLE t ADD COLUMN name VARCHAR(255);")
    assert "VARCHAR_WIDTH" not in rule_ids("ALTER TABLE t ADD COLUMN name VARCHAR(128);")


def test_foreign_keys_and_routines():
    assert "NO_FOREIGN_KEY" in rule_ids(
        "ALTER TABLE orders ADD CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users(id);"
    )
    assert "CREATE_VIEW" in rule_ids("CREATE VIEW active_users AS SELECT id FROM users;")
    assert "CREATE_TRIGGER" in rule_ids("CREATE TRIGGER trg BEFORE INSERT ON t FOR EACH ROW SET NEW.id = NEW.id;")
    assert "CREATE_FUNCTION" in rule_ids("CREATE FUNCTION foo() RETURNS INT BEGIN RETURN 1; END;")
    assert "CREATE_PROCEDURE" in rule_ids("CREATE PROCEDURE foo() BEGIN SELECT 1; END;")
    assert "CREATE_EVENT" in rule_ids("CREATE EVENT ev ON SCHEDULE AT CURRENT_TIMESTAMP DO SELECT 1;")


def test_missing_primary_key():
    sql = """
    CREATE TABLE t (
      email VARCHAR(128) NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """
    assert "REQUIRE_PRIMARY_KEY" in rule_ids(sql)


def test_int_primary_key_must_be_bigint():
    sql = """
    CREATE TABLE t (
      id INT UNSIGNED NOT NULL AUTO_INCREMENT,
      PRIMARY KEY (id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """
    ids = rule_ids(sql)
    assert "BIGINT_PRIMARY_KEY" in ids
    assert "AUTO_INCREMENT_BIGINT" in ids


def test_inline_int_primary_key_must_be_bigint():
    sql = """
    CREATE TABLE t (
      id INT PRIMARY KEY,
      name VARCHAR(32)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """
    assert "BIGINT_PRIMARY_KEY" in rule_ids(sql)


def test_bigint_primary_key_passes():
    assert "BIGINT_PRIMARY_KEY" not in rule_ids(CLEAN_TABLE)


def test_auto_increment_must_be_unsigned():
    sql = """
    CREATE TABLE t (
      id BIGINT NOT NULL AUTO_INCREMENT,
      PRIMARY KEY (id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """
    assert "AUTO_INCREMENT_UNSIGNED" in rule_ids(sql)


def test_charset_utf8_is_rejected():
    sql = """
    CREATE TABLE t (
      id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
    """
    assert "CHARSET_UTF8MB4" in rule_ids(sql)


def test_zerofill_and_display_width():
    sql = "ALTER TABLE t ADD COLUMN n INT(11) ZEROFILL;"
    ids = rule_ids(sql)
    assert "NO_ZEROFILL" in ids
    assert "NO_INT_DISPLAY_WIDTH" in ids


def test_float_and_timestamp():
    sql = """
    ALTER TABLE t
      ADD COLUMN amount FLOAT,
      ADD COLUMN seen_at TIMESTAMP NULL;
    """
    ids = rule_ids(sql)
    assert "PREFER_DECIMAL" in ids
    assert "NO_TIMESTAMP" in ids
    assert "NO_TIMESTAMP" not in rule_ids(CLEAN_TABLE)


def test_comments_are_not_linted():
    sql = """
    CREATE TABLE t (
      id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY
      -- this mentions enum and json only in a comment
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """
    assert lint_sql(sql) == []
