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


def table(column: str, options: str = "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4") -> str:
    return (
        "CREATE TABLE t (\n"
        "  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,\n"
        f"  {column},\n"
        "  PRIMARY KEY (id)\n"
        f") {options};\n"
    )


def test_words_inside_strings_are_not_linted():
    assert lint_sql(table("note VARCHAR(64) COMMENT 'free text, json, float; enum('")) == []
    assert lint_sql(table("kind VARCHAR(16) NOT NULL DEFAULT 'timestamp'")) == []


def test_data_statements_are_not_linted_for_types():
    sql = """
    INSERT INTO t (a, b) VALUES ('plain text, json, float, real', "it''s a blob");
    UPDATE items SET type = 3, engine = 'MyISAM' WHERE id = 1;
    DELETE FROM t WHERE kind = 'enum';
    """
    assert lint_sql(sql) == []


def test_column_names_that_look_like_types_are_not_flagged():
    assert lint_sql(table("created_timestamp DATETIME NOT NULL")) == []
    assert lint_sql(table("`text` VARCHAR(32)")) == []
    assert lint_sql(table("`timestamp` DATETIME, json_payload VARCHAR(64), `charset` VARCHAR(16)")) == []


def test_auto_increment_table_option_is_not_flagged():
    assert lint_sql("ALTER TABLE t AUTO_INCREMENT = 1000;") == []
    assert lint_sql(table("a BIGINT", "ENGINE=InnoDB AUTO_INCREMENT=100 DEFAULT CHARSET=utf8mb4")) == []


def test_alter_auto_increment_column_is_checked():
    ids = rule_ids("ALTER TABLE t MODIFY COLUMN id INT NOT NULL AUTO_INCREMENT;")
    assert {"AUTO_INCREMENT_UNSIGNED", "AUTO_INCREMENT_BIGINT"} <= ids
    assert lint_sql("ALTER TABLE t MODIFY id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT;") == []


def test_rocksdb_engine_allowed_and_engine_is_required():
    assert lint_sql(table("a BIGINT", "ENGINE=ROCKSDB DEFAULT CHARSET=utf8mb4")) == []
    assert "ALLOWED_ENGINE" in rule_ids(table("a BIGINT", "ENGINE = 'MyISAM'"))
    assert "ALLOWED_ENGINE" in rule_ids("ALTER TABLE t ENGINE=MyISAM;")
    assert "REQUIRE_ENGINE" in rule_ids(table("a BIGINT", "DEFAULT CHARSET=utf8mb4"))
    assert lint_sql("CREATE TABLE copy LIKE original;") == []


def test_tinyint_1_is_allowed_but_other_display_widths_are_not():
    assert lint_sql(table("is_active TINYINT(1) NOT NULL DEFAULT 0")) == []
    assert "NO_INT_DISPLAY_WIDTH" in rule_ids(table("n TINYINT(4)"))
    assert "NO_INT_DISPLAY_WIDTH" in rule_ids(table("n BIGINT(20)"))
    assert lint_sql(table("price DECIMAL(10,2) NOT NULL")) == []


def test_temporary_tables_are_checked():
    ids = rule_ids("CREATE TEMPORARY TABLE x (a INT AUTO_INCREMENT) ENGINE=InnoDB;")
    assert {"REQUIRE_PRIMARY_KEY", "AUTO_INCREMENT_UNSIGNED", "AUTO_INCREMENT_BIGINT"} <= ids


def test_parenthesis_inside_a_comment_string_does_not_hide_columns():
    sql = table("a BIGINT COMMENT 'weird ) paren', b JSON")
    assert rule_ids(sql) == {"NO_JSON"}


def test_schema_qualified_and_quoted_table_names():
    sql = "CREATE TABLE IF NOT EXISTS `app`.`users` (id INT PRIMARY KEY) ENGINE=InnoDB;"
    violations = lint_sql(sql)
    assert {v.rule_id for v in violations} == {"BIGINT_PRIMARY_KEY"}
    assert "`users.id`" in violations[0].message


def test_charset_rules_cover_columns_alter_and_database():
    assert "CHARSET_UTF8MB4" in rule_ids(table("name VARCHAR(32) CHARACTER SET latin1"))
    assert "CHARSET_UTF8MB4" in rule_ids(table("name VARCHAR(32) COLLATE utf8_general_ci"))
    assert "CHARSET_UTF8MB4" in rule_ids("ALTER TABLE t CONVERT TO CHARACTER SET utf8;")
    assert "CHARSET_UTF8MB4" in rule_ids("CREATE DATABASE app DEFAULT CHARACTER SET = 'latin1';")
    assert lint_sql("CREATE DATABASE app CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;") == []


def test_foreign_key_forms():
    assert "NO_FOREIGN_KEY" in rule_ids(table("user_id BIGINT REFERENCES users (id)"))
    assert "NO_FOREIGN_KEY" in rule_ids(table("user_id BIGINT, FOREIGN KEY (user_id) REFERENCES users (id)"))
    assert lint_sql("ALTER TABLE orders DROP FOREIGN KEY fk_user;") == []


def test_multi_column_alter_and_line_numbers():
    sql = "ALTER TABLE t\n  ADD COLUMN (a TEXT,\n    b VARCHAR(300)),\n  CHANGE old_name new_name DOUBLE;\n"
    found = {(v.line, v.rule_id) for v in lint_sql(sql)}
    assert found == {(2, "NO_TEXT"), (3, "VARCHAR_WIDTH"), (4, "PREFER_DECIMAL")}


def test_definer_views_and_delimiter_blocks():
    assert "CREATE_VIEW" in rule_ids("CREATE DEFINER='root'@'localhost' SQL SECURITY DEFINER VIEW v AS SELECT 1;")
    sql = "DELIMITER //\nCREATE PROCEDURE p()\nBEGIN\n  INSERT INTO t VALUES (1);\n  SELECT 1;\nEND//\nDELIMITER ;\n"
    assert rule_ids(sql) == {"CREATE_PROCEDURE"}
