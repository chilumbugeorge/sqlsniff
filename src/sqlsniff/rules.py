from __future__ import annotations

import re
from collections.abc import Callable

from sqlsniff.models import Severity, Violation
from sqlsniff.parser import (
    INTEGER_TYPES,
    NON_BIGINT_INTEGER_TYPES,
    CreateTable,
    iter_statements,
    parse_create_tables,
    strip_sql_comments,
)

RuleFn = Callable[[str], list[Violation]]

ENUM_MSG = (
    "ENUM is not advised: it has limited flexibility, portability, and maintainability. "
    "Use a lookup table or VARCHAR with a constrained set of values instead."
)
ENGINE_MSG = "Only InnoDB, and in some cases MyRocks, table engines are allowed."
FK_MSG = (
    "FOREIGN KEY constraints are not advised because they add overhead when constraints "
    "are evaluated. Enforce relationships in application code where possible."
)
ROUTINES_MSG = (
    "are not advised due to the overhead, especially on busy tables. "
    "Prefer implementing the same behavior in application code."
)
PK_MSG = "Every table must declare a PRIMARY KEY."
VARCHAR_MSG = (
    "VARCHAR(255) or wider is not advised; large VARCHAR widths can bloat temporary tables. "
    "Prefer VARCHAR(128) or less when possible."
)
JSON_MSG = (
    "JSON columns add storage overhead and can slow queries that filter on JSON data. "
    "Prefer typed columns for values you query frequently."
)
TEXT_MSG = (
    "TEXT types add storage and retrieval overhead on large datasets. "
    "If the value will stay within a manageable limit, prefer VARCHAR."
)
BLOB_MSG = (
    "BLOB types add storage overhead and often require extra application encoding logic. "
    "Prefer storing large binaries outside the database when possible."
)
BIGINT_PK_MSG = (
    "Integer primary keys must be BIGINT (preferably BIGINT UNSIGNED). "
    "INT and smaller integer types can exhaust the key space as tables grow."
)
AUTO_INCREMENT_UNSIGNED_MSG = "AUTO_INCREMENT integer columns must be UNSIGNED."
AUTO_INCREMENT_BIGINT_MSG = "AUTO_INCREMENT integer columns must be BIGINT UNSIGNED."
SET_MSG = (
    "SET column types have the same flexibility and portability problems as ENUM. "
    "Use a lookup table or a separate mapping table instead."
)
CHARSET_MSG = (
    "Use utf8mb4 (and a utf8mb4 collation) so the schema can store the full Unicode range, "
    "including emoji. utf8 in MySQL is a 3-byte charset and is not equivalent."
)
ZEROFILL_MSG = "ZEROFILL is deprecated in MySQL 8.0.17+ and should not be used in new schemas."
DISPLAY_WIDTH_MSG = (
    "Integer display widths such as INT(11) are deprecated in MySQL 8.0.17+ and have no "
    "effect on storage. Declare the integer type without a display width."
)
FLOAT_MSG = (
    "FLOAT and DOUBLE are approximate types and are not suitable for exact values such as "
    "money. Use DECIMAL with an explicit precision and scale."
)
TIMESTAMP_MSG = (
    "TIMESTAMP is limited to 1970-2038 (the Y2038 problem). Prefer DATETIME for values that "
    "must remain valid beyond 2038."
)

CREATE_ROUTINE_PATTERNS = (
    ("CREATE_VIEW", r"\bcreate\s+(or\s+replace\s+)?view\b", f"VIEWS {ROUTINES_MSG}"),
    ("CREATE_TRIGGER", r"\bcreate\s+trigger\b", f"TRIGGERS {ROUTINES_MSG}"),
    ("CREATE_FUNCTION", r"\bcreate\s+(definer\s*=\s*\S+\s+)?function\b", f"FUNCTIONS {ROUTINES_MSG}"),
    ("CREATE_PROCEDURE", r"\bcreate\s+(definer\s*=\s*\S+\s+)?procedure\b", f"PROCEDURES {ROUTINES_MSG}"),
    ("CREATE_EVENT", r"\bcreate\s+event\b", f"EVENTs {ROUTINES_MSG}"),
)

ALLOWED_ENGINES = {"innodb", "myrocks"}
ALLOWED_CHARSETS = {"utf8mb4"}
DISALLOWED_CHARSETS = {"utf8", "utf8mb3", "latin1", "ascii", "ucs2", "utf16", "utf16le", "utf32"}


def _line_violations(sql: str, pattern: str, rule_id: str, message: str, severity: Severity) -> list[Violation]:
    violations: list[Violation] = []
    regex = re.compile(pattern, re.IGNORECASE)
    for line_no, line in enumerate(sql.splitlines(), start=1):
        if regex.search(line):
            violations.append(
                Violation(rule_id=rule_id, message=message, severity=severity, line=line_no)
            )
    return violations


def rule_enum(sql: str) -> list[Violation]:
    return _line_violations(sql, r"\benum\s*\(", "NO_ENUM", ENUM_MSG, Severity.WARNING)


def rule_set_type(sql: str) -> list[Violation]:
    return _line_violations(
        sql,
        r"(?:^|,)\s*(?:`[^`]+`|\w+)\s+set\s*\(",
        "NO_SET",
        SET_MSG,
        Severity.WARNING,
    )


def rule_engine(sql: str) -> list[Violation]:
    violations: list[Violation] = []
    regex = re.compile(r"\b(?:engine|type)\s*=\s*(\w+)", re.IGNORECASE)
    for line_no, line in enumerate(sql.splitlines(), start=1):
        match = regex.search(line)
        if match and match.group(1).lower() not in ALLOWED_ENGINES:
            violations.append(
                Violation(rule_id="ALLOWED_ENGINE", message=ENGINE_MSG, severity=Severity.ERROR, line=line_no)
            )
    return violations


def rule_blob(sql: str) -> list[Violation]:
    return _line_violations(
        sql,
        r"\b(?:mediumblob|longblob|(?<!tiny)blob)\b",
        "NO_BLOB",
        BLOB_MSG,
        Severity.WARNING,
    )


def rule_json(sql: str) -> list[Violation]:
    return _line_violations(sql, r"\bjson\b", "NO_JSON", JSON_MSG, Severity.WARNING)


def rule_text(sql: str) -> list[Violation]:
    return _line_violations(
        sql,
        r"\b(?:mediumtext|longtext|(?<!tiny)text)\b",
        "NO_TEXT",
        TEXT_MSG,
        Severity.WARNING,
    )


def rule_varchar_width(sql: str) -> list[Violation]:
    violations: list[Violation] = []
    regex = re.compile(r"\b(?:var)?(?:national\s+)?(?:char|character|varchar)\s*\(\s*(\d+)\s*\)", re.IGNORECASE)
    for line_no, line in enumerate(sql.splitlines(), start=1):
        for match in regex.finditer(line):
            if int(match.group(1)) >= 255:
                violations.append(
                    Violation(
                        rule_id="VARCHAR_WIDTH",
                        message=VARCHAR_MSG,
                        severity=Severity.WARNING,
                        line=line_no,
                    )
                )
    return violations


def rule_foreign_keys(sql: str) -> list[Violation]:
    violations: list[Violation] = []
    for line_no, line in enumerate(sql.splitlines(), start=1):
        if re.search(r"\bforeign\s+key\b", line, re.IGNORECASE) or re.search(
            r"\breferences\b", line, re.IGNORECASE
        ):
            violations.append(
                Violation(rule_id="NO_FOREIGN_KEY", message=FK_MSG, severity=Severity.WARNING, line=line_no)
            )
    return violations


def rule_routines(sql: str) -> list[Violation]:
    violations: list[Violation] = []
    for rule_id, pattern, message in CREATE_ROUTINE_PATTERNS:
        violations.extend(_line_violations(sql, pattern, rule_id, message, Severity.WARNING))
    return violations


def rule_charset(sql: str) -> list[Violation]:
    violations: list[Violation] = []
    charset_re = re.compile(
        r"(?:character\s+set|charset)\s*=?\s*([a-z0-9_]+)",
        re.IGNORECASE,
    )
    collate_re = re.compile(r"\bcollate\s*=?\s*([a-z0-9_]+)", re.IGNORECASE)
    for line_no, line in enumerate(sql.splitlines(), start=1):
        for match in charset_re.finditer(line):
            charset = match.group(1).lower()
            if charset not in ALLOWED_CHARSETS:
                violations.append(
                    Violation(rule_id="CHARSET_UTF8MB4", message=CHARSET_MSG, severity=Severity.ERROR, line=line_no)
                )
        for match in collate_re.finditer(line):
            collation = match.group(1).lower()
            if not collation.startswith("utf8mb4"):
                violations.append(
                    Violation(rule_id="CHARSET_UTF8MB4", message=CHARSET_MSG, severity=Severity.ERROR, line=line_no)
                )
    return violations


def rule_zerofill(sql: str) -> list[Violation]:
    return _line_violations(sql, r"\bzerofill\b", "NO_ZEROFILL", ZEROFILL_MSG, Severity.ERROR)


def rule_integer_display_width(sql: str) -> list[Violation]:
    return _line_violations(
        sql,
        r"\b(?:tinyint|smallint|mediumint|int|integer|bigint)\s*\(\s*\d+\s*\)",
        "NO_INT_DISPLAY_WIDTH",
        DISPLAY_WIDTH_MSG,
        Severity.WARNING,
    )


def rule_float(sql: str) -> list[Violation]:
    return _line_violations(
        sql,
        r"\b(?:float|double|real|double\s+precision)\b",
        "PREFER_DECIMAL",
        FLOAT_MSG,
        Severity.WARNING,
    )


def rule_timestamp(sql: str) -> list[Violation]:
    return _line_violations(
        sql,
        r"(?<!current_)timestamp\b",
        "NO_TIMESTAMP",
        TIMESTAMP_MSG,
        Severity.WARNING,
    )


def _primary_key_columns(table: CreateTable) -> set[str]:
    names = {column.name for column in table.columns if column.is_primary_key}
    names.update(table.table_primary_key)
    return names


def rule_primary_keys(sql: str) -> list[Violation]:
    violations: list[Violation] = []
    for table in parse_create_tables(sql):
        if not _primary_key_columns(table):
            violations.append(
                Violation(
                    rule_id="REQUIRE_PRIMARY_KEY",
                    message=f"Table `{table.name}` is missing a PRIMARY KEY. {PK_MSG}",
                    severity=Severity.ERROR,
                    line=table.line,
                )
            )
    return violations


def rule_bigint_primary_keys(sql: str) -> list[Violation]:
    violations: list[Violation] = []
    for table in parse_create_tables(sql):
        pk_names = _primary_key_columns(table)
        for column in table.columns:
            if column.name not in pk_names:
                continue
            if column.type_name in NON_BIGINT_INTEGER_TYPES:
                violations.append(
                    Violation(
                        rule_id="BIGINT_PRIMARY_KEY",
                        message=(
                            f"Primary key column `{table.name}.{column.name}` uses "
                            f"{column.type_name.upper()}; {BIGINT_PK_MSG}"
                        ),
                        severity=Severity.ERROR,
                        line=column.line,
                    )
                )
    violations.extend(_alter_integer_primary_keys(sql))
    return violations


def _alter_integer_primary_keys(sql: str) -> list[Violation]:
    violations: list[Violation] = []
    pattern = re.compile(
        r"alter\s+table\s+\S+\s+(?:add|modify|change)\s+(?:column\s+)?(?:\S+\s+)?(\S+)\s+"
        r"(tinyint|smallint|mediumint|int|integer|bool|boolean)"
        r"[^;]*\bprimary\s+key\b",
        re.IGNORECASE | re.DOTALL,
    )
    for match in pattern.finditer(sql):
        from sqlsniff.parser import line_number_for_offset

        violations.append(
            Violation(
                rule_id="BIGINT_PRIMARY_KEY",
                message=BIGINT_PK_MSG,
                severity=Severity.ERROR,
                line=line_number_for_offset(sql, match.start()),
            )
        )
    return violations


def rule_auto_increment(sql: str) -> list[Violation]:
    violations: list[Violation] = []
    for table in parse_create_tables(sql):
        for column in table.columns:
            if not column.auto_increment:
                continue
            if (column.type_name in INTEGER_TYPES or not column.type_name) and not column.unsigned:
                violations.append(
                    Violation(
                        rule_id="AUTO_INCREMENT_UNSIGNED",
                        message=AUTO_INCREMENT_UNSIGNED_MSG,
                        severity=Severity.ERROR,
                        line=column.line,
                    )
                )
            if column.type_name in NON_BIGINT_INTEGER_TYPES:
                violations.append(
                    Violation(
                        rule_id="AUTO_INCREMENT_BIGINT",
                        message=AUTO_INCREMENT_BIGINT_MSG,
                        severity=Severity.ERROR,
                        line=column.line,
                    )
                )
    for line_no, statement in iter_statements(sql):
        if "auto_increment" not in statement.lower():
            continue
        if re.search(r"\bauto_increment\b", statement, re.IGNORECASE) and not re.search(
            r"\bunsigned\b", statement, re.IGNORECASE
        ):
            # CREATE TABLE is already covered; catch ALTER TABLE and one-liners.
            if re.search(r"\balter\s+table\b", statement, re.IGNORECASE):
                violations.append(
                    Violation(
                        rule_id="AUTO_INCREMENT_UNSIGNED",
                        message=AUTO_INCREMENT_UNSIGNED_MSG,
                        severity=Severity.ERROR,
                        line=line_no,
                    )
                )
    return violations


RULES: list[tuple[str, RuleFn]] = [
    ("NO_ENUM", rule_enum),
    ("NO_SET", rule_set_type),
    ("ALLOWED_ENGINE", rule_engine),
    ("NO_BLOB", rule_blob),
    ("NO_JSON", rule_json),
    ("NO_TEXT", rule_text),
    ("VARCHAR_WIDTH", rule_varchar_width),
    ("NO_FOREIGN_KEY", rule_foreign_keys),
    ("ROUTINES", rule_routines),
    ("CHARSET_UTF8MB4", rule_charset),
    ("NO_ZEROFILL", rule_zerofill),
    ("NO_INT_DISPLAY_WIDTH", rule_integer_display_width),
    ("PREFER_DECIMAL", rule_float),
    ("NO_TIMESTAMP", rule_timestamp),
    ("REQUIRE_PRIMARY_KEY", rule_primary_keys),
    ("BIGINT_PRIMARY_KEY", rule_bigint_primary_keys),
    ("AUTO_INCREMENT", rule_auto_increment),
]


def lint_sql(sql: str) -> list[Violation]:
    sql = strip_sql_comments(sql)
    violations: list[Violation] = []
    for _rule_id, rule in RULES:
        violations.extend(rule(sql))
    violations.sort(key=lambda item: (item.line or 0, item.rule_id))
    return violations
