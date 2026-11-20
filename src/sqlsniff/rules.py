"""Lint rules. Each rule receives a parsed :class:`Context` and returns violations."""

from __future__ import annotations

import difflib
import re
from collections.abc import Callable
from dataclasses import dataclass, field

from sqlsniff.models import Severity, Violation
from sqlsniff.parser import (
    COLUMN_TYPE_RE,
    INTEGER_TYPES,
    NON_BIGINT_INTEGER_TYPES,
    AlterTable,
    ColumnDef,
    CreateTable,
    Statement,
    flatten,
    line_number_for_offset,
    mask_sql,
    paren_errors,
    parse_alter_table,
    parse_create_table,
    split_statements,
)

ENUM_MSG = (
    "ENUM is not advised: it has limited flexibility, portability, and maintainability. "
    "Use a lookup table or VARCHAR with a constrained set of values instead."
)
ENGINE_MSG = "Only the InnoDB and RocksDB (MyRocks) table engines are allowed."
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
UUID_PK_MSG = (
    "is a UUID stored as text. Random UUIDs scatter inserts across the clustered index "
    "(page splits, fragmentation), and a 36-character key is copied into every secondary "
    "index. Alternatives: (1) BIGINT UNSIGNED AUTO_INCREMENT, giving each node its own "
    "auto_increment_offset with a shared auto_increment_increment so ids never collide when "
    "data from several nodes is merged; (2) if a UUID is required, store it time-ordered in "
    "16 bytes: BINARY(16) DEFAULT (UUID_TO_BIN(UUID(), 1)) on MySQL 8, or the UUID column "
    "type on MariaDB 10.7+."
)
TIMESTAMP_MSG = (
    "TIMESTAMP is limited to 1970-2038 (the Y2038 problem). Prefer DATETIME for values that "
    "must remain valid beyond 2038."
)

ROUTINE_MESSAGES = {
    "view": ("CREATE_VIEW", f"VIEWS {ROUTINES_MSG}"),
    "trigger": ("CREATE_TRIGGER", f"TRIGGERS {ROUTINES_MSG}"),
    "function": ("CREATE_FUNCTION", f"FUNCTIONS {ROUTINES_MSG}"),
    "procedure": ("CREATE_PROCEDURE", f"PROCEDURES {ROUTINES_MSG}"),
    "event": ("CREATE_EVENT", f"EVENTS {ROUTINES_MSG}"),
}
ROUTINE_RE = re.compile(
    r"create\s+(?:or\s+replace\s+)?(?:algorithm\s*=\s*\w+\s+)?(?:definer\s*=\s*\S+\s+)?"
    r"(?:sql\s+security\s+\w+\s+)?(?:aggregate\s+)?"
    r"(view|trigger|function|procedure|event)\b",
    re.IGNORECASE,
)

ALLOWED_ENGINES = {"innodb", "rocksdb"}
ALLOWED_CHARSETS = {"utf8mb4"}

ENGINE_RE = re.compile(r"\bengine\s*=?\s*['\"`]?", re.IGNORECASE)
CHARSET_RE = re.compile(r"\b(?:character\s+set|charset)\s*=?\s*['\"`]?", re.IGNORECASE)
COLLATE_RE = re.compile(r"\bcollate\s*=?\s*['\"`]?", re.IGNORECASE)
NAME_RE = re.compile(r"[A-Za-z0-9_]+")
DATABASE_RE = re.compile(r"(?:create|alter)\s+(?:database|schema)\b", re.IGNORECASE)

TEXT_TYPES = {"text", "mediumtext", "longtext"}
BLOB_TYPES = {"blob", "mediumblob", "longblob"}
CHAR_TYPES = {"char", "varchar", "character", "nchar", "nvarchar"}
FLOAT_TYPES = {"float", "double", "real", "float4", "float8"}
DISPLAY_WIDTH_TYPES = {"tinyint", "smallint", "mediumint", "int", "integer", "bigint"}

KNOWN_TYPES = (
    INTEGER_TYPES
    | TEXT_TYPES
    | BLOB_TYPES
    | CHAR_TYPES
    | FLOAT_TYPES
    | {
        "bit", "int1", "int2", "int3", "int4", "int8", "middleint",
        "decimal", "dec", "numeric", "fixed",
        "date", "datetime", "timestamp", "time", "year",
        "binary", "varbinary", "tinyblob", "tinytext", "long",
        "enum", "set", "json", "vector", "uuid", "inet4", "inet6",
        "geometry", "point", "linestring", "polygon", "multipoint",
        "multilinestring", "multipolygon", "geometrycollection", "geomcollection",
    }
)  # fmt: skip

# A second data type inside one column definition almost always means a missing comma.
SECOND_TYPE_RE = re.compile(
    r"\b(tinyint|smallint|mediumint|int|integer|bigint|varchar|varbinary|decimal|numeric|"
    r"datetime|timestamp|date|tinytext|text|mediumtext|longtext|tinyblob|blob|mediumblob|"
    r"longblob|json|float|double|boolean|bool|enum)\b",
    re.IGNORECASE,
)

# Words that may follow the data type in a column definition.
COLUMN_ATTRIBUTE_WORDS = {
    "not", "null", "default", "auto_increment", "unique", "primary", "key", "comment",
    "collate", "character", "charset", "set", "unsigned", "signed", "zerofill", "binary",
    "ascii", "unicode", "byte", "generated", "always", "as", "virtual", "stored", "persistent",
    "on", "update", "visible", "invisible", "column_format", "fixed", "dynamic", "storage",
    "disk", "memory", "references", "check", "constraint", "enforced", "srid", "first", "after",
    "serial", "value", "for", "engine_attribute", "secondary_engine_attribute", "secondary",
    "compressed", "with", "without", "system", "versioning",
}  # fmt: skip
# After these words comes a free-form value (a name, literal or function), not a keyword.
VALUE_FOLLOWS = {
    "default", "collate", "set", "charset", "after", "update", "srid", "column_format",
    "storage", "for", "constraint",
}  # fmt: skip
TABLE_OPTION_WORDS = {
    "engine", "auto_increment", "autoextend_size", "avg_row_length", "charset", "checksum",
    "collate", "comment", "compression", "connection", "delay_key_write", "encryption",
    "engine_attribute", "insert_method", "key_block_size", "max_rows", "min_rows", "pack_keys",
    "password", "row_format", "secondary_engine_attribute", "stats_auto_recalc",
    "stats_persistent", "stats_sample_pages", "tablespace", "storage", "union",
    # MariaDB
    "encrypted", "encryption_key_id", "ietf_quotes", "page_checksum", "page_compressed",
    "page_compression_level", "sequence", "transactional",
}  # fmt: skip
TABLE_OPTION_PAIRS = {"character": "set", "data": "directory", "index": "directory", "start": "transaction"}
TABLE_OPTION_STOP = {"partition", "as", "select", "ignore", "replace", "with"}
WORD_RE = re.compile(r"\b[A-Za-z_][\w$]*\b")
QUOTED_RE = re.compile(r"'[^']*'|\"[^\"]*\"")
OPTION_VALUE_RE = re.compile(r"\s*=?\s*(?:'[^']*'|\"[^\"]*\"|\([^)]*\)|[\w$.\-]+)?")

STATEMENT_KEYWORDS = {
    "alter", "analyze", "begin", "call", "check", "commit", "create", "deallocate", "delete",
    "desc", "describe", "do", "drop", "execute", "explain", "flush", "grant", "handler",
    "insert", "install", "load", "lock", "optimize", "prepare", "release", "rename", "repair",
    "replace", "revoke", "rollback", "savepoint", "select", "set", "show", "start", "table",
    "truncate", "uninstall", "unlock", "update", "use", "values", "with",
    # Compound-statement keywords, seen when a routine body is split on ';'.
    "case", "close", "declare", "else", "elseif", "end", "fetch", "get", "if", "iterate",
    "leave", "loop", "open", "repeat", "resignal", "return", "signal", "until", "while",
}  # fmt: skip
OBJECT_KEYWORDS = {
    "create": (
        "table|index|view|trigger|function|procedure|event|database|schema|user|role|server|"
        "tablespace|logfile|resource|spatial|undo"
    ),
    "alter": (
        "table|view|event|function|procedure|database|schema|user|server|tablespace|instance|"
        "logfile|resource|undo"
    ),
    "drop": (
        "table|tables|index|view|trigger|function|procedure|event|database|schema|user|role|"
        "server|tablespace|prepare|logfile|resource|spatial|undo"
    ),
}
EMBEDDED_STATEMENT_HEADS = {
    "alter", "create", "delete", "drop", "insert", "rename", "replace", "set", "truncate",
    "update", "use",
}  # fmt: skip
EMBEDDED_STATEMENT_RE = re.compile(
    r"\b(create\s+(?:temporary\s+)?table|create\s+(?:unique\s+)?index|alter\s+table|"
    r"drop\s+table|rename\s+table|truncate\s+table|insert\s+into|delete\s+from)\b",
    re.IGNORECASE,
)


@dataclass
class Context:
    """Everything the rules need, parsed once per file."""

    sql: str
    masked: str
    statements: list[Statement] = field(default_factory=list)
    broken: set[int] = field(default_factory=set)
    creates: list[CreateTable] = field(default_factory=list)
    alters: list[AlterTable] = field(default_factory=list)

    def line(self, offset: int) -> int:
        return line_number_for_offset(self.masked, offset)

    @property
    def columns(self) -> list[ColumnDef]:
        columns = [column for table in self.creates for column in table.columns]
        columns.extend(column for alter in self.alters for column in alter.columns)
        return columns

    def attribute_segments(self) -> list[tuple[int, str]]:
        """Masked text where table/column attributes (charset, zerofill...) may appear."""
        segments = [(column.tail_offset, column.tail) for column in self.columns]
        segments.extend((table.options_offset, table.options) for table in self.creates)
        for alter in self.alters:
            segments.extend(alter.other_specs)
        for index, statement in enumerate(self.statements):
            if index not in self.broken and DATABASE_RE.match(statement.text):
                segments.append((statement.offset, statement.text))
        return segments


RuleFn = Callable[[Context], list[Violation]]


def build_context(sql: str, masked: str) -> Context:
    context = Context(sql=sql, masked=masked, statements=split_statements(masked))
    for index, statement in enumerate(context.statements):
        if paren_errors(statement.text):
            context.broken.add(index)
            continue
        create = parse_create_table(statement)
        if create is not None:
            context.creates.append(create)
            continue
        alter = parse_alter_table(statement)
        if alter is not None:
            context.alters.append(alter)
    return context


def _violation(context: Context, rule_id: str, message: str, severity: Severity, offset: int) -> Violation:
    return Violation(rule_id=rule_id, message=message, severity=severity, line=context.line(offset))


def _column_type_rule(
    types: set[str], rule_id: str, message: str, severity: Severity = Severity.WARNING
) -> RuleFn:
    def rule(context: Context) -> list[Violation]:
        return [
            _violation(context, rule_id, message, severity, column.offset)
            for column in context.columns
            if column.type_name in types
        ]

    return rule


rule_enum = _column_type_rule({"enum"}, "NO_ENUM", ENUM_MSG)
rule_set_type = _column_type_rule({"set"}, "NO_SET", SET_MSG)
rule_json = _column_type_rule({"json"}, "NO_JSON", JSON_MSG)
rule_text = _column_type_rule(TEXT_TYPES, "NO_TEXT", TEXT_MSG)
rule_blob = _column_type_rule(BLOB_TYPES, "NO_BLOB", BLOB_MSG)
rule_float = _column_type_rule(FLOAT_TYPES, "PREFER_DECIMAL", FLOAT_MSG)
rule_timestamp = _column_type_rule({"timestamp"}, "NO_TIMESTAMP", TIMESTAMP_MSG)


def rule_varchar_width(context: Context) -> list[Violation]:
    return [
        _violation(context, "VARCHAR_WIDTH", VARCHAR_MSG, Severity.WARNING, column.offset)
        for column in context.columns
        if column.type_name in CHAR_TYPES and column.type_args.isdigit() and int(column.type_args) >= 255
    ]


def rule_integer_display_width(context: Context) -> list[Violation]:
    violations: list[Violation] = []
    for column in context.columns:
        if column.type_name not in DISPLAY_WIDTH_TYPES or not column.type_args.isdigit():
            continue
        if column.type_name == "tinyint" and column.type_args == "1":
            continue  # TINYINT(1) is the MySQL boolean idiom and is not deprecated.
        violations.append(
            _violation(context, "NO_INT_DISPLAY_WIDTH", DISPLAY_WIDTH_MSG, Severity.WARNING, column.offset)
        )
    return violations


def _named_values(context: Context, regex: re.Pattern[str], offset: int, text: str) -> list[tuple[int, str]]:
    """Find `KEYWORD [=] name` and read the name from the original (unmasked) SQL."""
    values: list[tuple[int, str]] = []
    for match in regex.finditer(text):
        name = NAME_RE.match(context.sql, offset + match.end())
        if name:
            values.append((offset + match.start(), name.group(0).lower()))
    return values


def rule_engine(context: Context) -> list[Violation]:
    violations: list[Violation] = []
    segments: list[tuple[int, str]] = []
    # A table with no ENGINE clause uses the server default, which is InnoDB on
    # MySQL and MariaDB, so it is treated as InnoDB and passes.
    for table in context.creates:
        if table.has_body:
            segments.append((table.options_offset, table.options))
    for alter in context.alters:
        segments.extend(spec for spec in alter.other_specs if ENGINE_RE.match(spec[1]))
    for offset, text in segments:
        for position, engine in _named_values(context, ENGINE_RE, offset, text):
            if engine not in ALLOWED_ENGINES:
                violations.append(
                    _violation(context, "ALLOWED_ENGINE", ENGINE_MSG, Severity.ERROR, position)
                )
    return violations


def rule_charset(context: Context) -> list[Violation]:
    violations: list[Violation] = []
    for offset, text in context.attribute_segments():
        bad = [
            position
            for position, charset in _named_values(context, CHARSET_RE, offset, text)
            if charset not in ALLOWED_CHARSETS
        ]
        bad.extend(
            position
            for position, collation in _named_values(context, COLLATE_RE, offset, text)
            if not collation.startswith("utf8mb4")
        )
        violations.extend(
            _violation(context, "CHARSET_UTF8MB4", CHARSET_MSG, Severity.ERROR, position)
            for position in bad
        )
    return violations


def rule_zerofill(context: Context) -> list[Violation]:
    return [
        _violation(context, "NO_ZEROFILL", ZEROFILL_MSG, Severity.ERROR, column.offset)
        for column in context.columns
        if re.search(r"\bzerofill\b", column.tail, re.IGNORECASE)
    ]


def rule_foreign_keys(context: Context) -> list[Violation]:
    offsets = [
        column.offset
        for column in context.columns
        if re.search(r"\breferences\b", column.tail, re.IGNORECASE)
    ]
    for table in context.creates:
        offsets.extend(
            offset
            for offset, text in table.constraints
            if re.search(r"\bforeign\s+key\b", text, re.IGNORECASE)
        )
    for alter in context.alters:
        offsets.extend(
            offset
            for offset, text in alter.other_specs
            if re.match(r"add\b", text, re.IGNORECASE)
            and re.search(r"\bforeign\s+key\b", text, re.IGNORECASE)
        )
    return [_violation(context, "NO_FOREIGN_KEY", FK_MSG, Severity.WARNING, offset) for offset in offsets]


def rule_routines(context: Context) -> list[Violation]:
    violations: list[Violation] = []
    for statement in context.statements:
        match = ROUTINE_RE.match(statement.text)
        if match:
            rule_id, message = ROUTINE_MESSAGES[match.group(1).lower()]
            violations.append(_violation(context, rule_id, message, Severity.WARNING, statement.offset))
    return violations


def _primary_key_columns(table: CreateTable) -> set[str]:
    names = {column.name for column in table.columns if column.is_primary_key}
    names.update(table.table_primary_key)
    return names


def rule_primary_keys(context: Context) -> list[Violation]:
    return [
        _violation(
            context,
            "REQUIRE_PRIMARY_KEY",
            f"Table `{table.name}` is missing a PRIMARY KEY. {PK_MSG}",
            Severity.ERROR,
            table.offset,
        )
        for table in context.creates
        if table.has_body and not table.primary_keys and not _primary_key_columns(table)
    ]


def rule_bigint_primary_keys(context: Context) -> list[Violation]:
    violations: list[Violation] = []
    for table in context.creates:
        pk_names = _primary_key_columns(table)
        for column in table.columns:
            if column.name in pk_names and column.type_name in NON_BIGINT_INTEGER_TYPES:
                violations.append(
                    _violation(
                        context,
                        "BIGINT_PRIMARY_KEY",
                        f"Primary key column `{table.name}.{column.name}` uses "
                        f"{column.type_name.upper()}; {BIGINT_PK_MSG}",
                        Severity.ERROR,
                        column.offset,
                    )
                )
    for alter in context.alters:
        for column in alter.columns:
            if column.is_primary_key and column.type_name in NON_BIGINT_INTEGER_TYPES:
                violations.append(
                    _violation(context, "BIGINT_PRIMARY_KEY", BIGINT_PK_MSG, Severity.ERROR, column.offset)
                )
    return violations


def rule_uuid_primary_key(context: Context) -> list[Violation]:
    """Advisory: a primary key that holds a UUID as CHAR/VARCHAR text."""
    violations: list[Violation] = []
    for table in context.creates:
        pk_names = _primary_key_columns(table)
        for column in table.columns:
            if column.name not in pk_names or column.type_name not in CHAR_TYPES:
                continue
            uuid_width = column.type_args in ("32", "36")
            uuid_default = re.search(r"\buuid(?:_v[47])?\s*\(", column.tail, re.IGNORECASE)
            if uuid_width or uuid_default:
                violations.append(
                    _violation(
                        context,
                        "UUID_PRIMARY_KEY",
                        f"Primary key `{table.name}.{column.name}` {UUID_PK_MSG}",
                        Severity.ADVISORY,
                        column.offset,
                    )
                )
    return violations


def rule_auto_increment(context: Context) -> list[Violation]:
    violations: list[Violation] = []
    for column in context.columns:
        if not column.auto_increment:
            continue
        if column.type_name in INTEGER_TYPES and column.type_name != "serial" and not column.unsigned:
            violations.append(
                _violation(
                    context, "AUTO_INCREMENT_UNSIGNED", AUTO_INCREMENT_UNSIGNED_MSG, Severity.ERROR, column.offset
                )
            )
        if column.type_name in NON_BIGINT_INTEGER_TYPES:
            violations.append(
                _violation(
                    context, "AUTO_INCREMENT_BIGINT", AUTO_INCREMENT_BIGINT_MSG, Severity.ERROR, column.offset
                )
            )
    return violations


def _syntax(context: Context, offset: int, message: str) -> Violation:
    return _violation(context, "SYNTAX_ERROR", message, Severity.ERROR, offset)


def _suggestion(word: str, candidates: set[str]) -> str:
    close = difflib.get_close_matches(word.lower(), sorted(candidates), n=1, cutoff=0.6)
    return f" Did you mean `{close[0].upper()}`?" if close else ""


def _blank_strings(text: str) -> str:
    return QUOTED_RE.sub(lambda match: " " * len(match.group(0)), text)


def _attribute_syntax(context: Context, column: ColumnDef, type_end: int) -> list[Violation]:
    """Every bare word after the data type must be a known column attribute keyword."""
    flat = flatten(column.tail)
    bare = _blank_strings(flat)
    previous = ""
    previous_end = type_end
    for match in WORD_RE.finditer(bare, type_end):
        word = match.group(0).lower()
        if flat[match.end() : match.end() + 1] in ("'", '"'):
            previous, previous_end = "", match.end()  # literal prefix: b'0', x'1F', _utf8mb4'..'
            continue
        gap = column.tail[previous_end : match.start()].strip()
        is_value = previous in VALUE_FOLLOWS and gap in ("", "=", "+", "-")
        if is_value and not (previous == "constraint" and word == "check"):
            previous, previous_end = "", match.end()
            continue
        if word == "references":
            break  # table name and referential actions follow
        if word not in COLUMN_ATTRIBUTE_WORDS:
            return [
                _syntax(
                    context,
                    column.tail_offset + match.start(),
                    f"Unexpected `{match.group(0).upper()}` in the definition of column "
                    f"`{column.name}`.{_suggestion(word, COLUMN_ATTRIBUTE_WORDS)}",
                )
            ]
        previous, previous_end = word, match.end()
    return []


def _table_option_syntax(context: Context, table: CreateTable) -> list[Violation]:
    """Table options are `NAME [=] value` pairs; flag an unknown option name."""
    text = _blank_strings(table.options)
    position = 0
    while True:
        match = WORD_RE.search(text, position)
        if not match or text[position : match.start()].strip(" \t\r\n,"):
            return []  # nothing left, or something this check does not model
        word = match.group(0).lower()
        position = match.end()
        if word in TABLE_OPTION_STOP:
            return []
        if word == "default":
            continue
        if word in TABLE_OPTION_PAIRS:
            follower = re.compile(r"\s*([A-Za-z_]+)").match(text, position)
            if not follower or follower.group(1).lower() != TABLE_OPTION_PAIRS[word]:
                return []
            position = follower.end()
            if word == "start":
                continue
        elif word not in TABLE_OPTION_WORDS:
            candidates = TABLE_OPTION_WORDS | set(TABLE_OPTION_PAIRS) | {"default"}
            return [
                _syntax(
                    context,
                    table.options_offset + match.start(),
                    f"Unknown table option `{match.group(0).upper()}` for table "
                    f"`{table.name}`.{_suggestion(word, candidates)}",
                )
            ]
        position = OPTION_VALUE_RE.match(table.options, position).end()


def _column_syntax(context: Context, column: ColumnDef) -> list[Violation]:
    if not column.type_name:
        return [_syntax(context, column.offset, f"Column `{column.name}` has no data type.")]
    if column.type_name not in KNOWN_TYPES:
        return [
            _syntax(
                context,
                column.offset,
                f"Unknown data type `{column.type_name.upper()}` for column `{column.name}`.",
            )
        ]
    type_match = COLUMN_TYPE_RE.match(column.tail)
    type_end = type_match.end() if type_match else 0
    extra = SECOND_TYPE_RE.search(flatten(column.tail), type_end)
    if extra and column.type_name != "long":  # LONG VARCHAR / LONG VARBINARY are valid
        return [
            _syntax(
                context,
                column.tail_offset + extra.start(),
                f"Unexpected `{extra.group(1).upper()}` in the definition of column "
                f"`{column.name}` - a comma is probably missing.",
            )
        ]
    return _attribute_syntax(context, column, type_end)


def _create_table_syntax(context: Context, table: CreateTable) -> list[Violation]:
    violations: list[Violation] = []
    if not table.has_body:
        # CREATE TABLE ... LIKE other / ... [options] [AS] SELECT ... need no column list.
        if not table.remainder.startswith("(") and not re.search(
            r"\b(?:like|select)\b", flatten(table.remainder), re.IGNORECASE
        ):
            violations.append(
                _syntax(context, table.offset, f"CREATE TABLE `{table.name}` has no '(' column list.")
            )
        return violations

    if not table.columns and not table.constraints:
        return [_syntax(context, table.offset, f"CREATE TABLE `{table.name}` has no columns.")]
    violations.extend(
        _syntax(context, offset, "Empty definition - stray or trailing comma in the column list.")
        for offset in table.empty_pieces
    )

    seen: set[str] = set()
    for column in table.columns:
        violations.extend(_column_syntax(context, column))
        if column.name in seen:
            violations.append(
                _syntax(context, column.offset, f"Duplicate column name `{column.name}` in table `{table.name}`.")
            )
        seen.add(column.name)

    inline = [column for column in table.columns if column.is_primary_key]
    if len(inline) + len(table.primary_keys) > 1:
        violations.append(
            _syntax(context, table.offset, f"Table `{table.name}` defines more than one PRIMARY KEY.")
        )
    for offset, names in table.primary_keys:
        violations.extend(
            _syntax(context, offset, f"PRIMARY KEY refers to unknown column `{name}`.")
            for name in names
            if name not in seen
        )
    violations.extend(_table_option_syntax(context, table))
    return violations


def _statement_syntax(context: Context, statement: Statement) -> list[Violation]:
    violations: list[Violation] = []
    text = statement.text
    word = re.match(r"[A-Za-z_]+", text)
    keyword = word.group(0).lower() if word else ""

    if text.startswith("("):
        keyword = "select"  # parenthesised query
    if keyword not in STATEMENT_KEYWORDS:
        shown = text.split(None, 1)[0][:30]
        return [_syntax(context, statement.offset, f"Unrecognised statement starting with `{shown}`.")]

    is_routine = bool(ROUTINE_RE.match(text))
    objects = OBJECT_KEYWORDS.get(keyword)
    if objects and not is_routine:
        if not re.match(rf"{keyword}\b[^(]*?\b(?:{objects})\b", text, re.IGNORECASE):
            return [
                _syntax(
                    context,
                    statement.offset,
                    f"Unrecognised {keyword.upper()} statement - check the object keyword "
                    "(TABLE, INDEX, DATABASE...).",
                )
            ]

    if keyword in EMBEDDED_STATEMENT_HEADS and not is_routine:
        embedded = EMBEDDED_STATEMENT_RE.search(flatten(text), 1)
        if embedded:
            start = " ".join(embedded.group(1).upper().split())
            violations.append(
                _syntax(
                    context,
                    statement.offset + embedded.start(),
                    f"`{start}` begins inside another statement - a ';' is probably missing before it.",
                )
            )
    return violations


def rule_syntax(context: Context) -> list[Violation]:
    violations: list[Violation] = []
    for index, statement in enumerate(context.statements):
        if index in context.broken:
            violations.extend(
                _syntax(context, statement.offset + offset, message)
                for offset, message in paren_errors(statement.text)
            )
            continue
        violations.extend(_statement_syntax(context, statement))
        if not statement.terminated:
            violations.append(
                _syntax(context, statement.end - 1, "Statement is not terminated with ';'.")
            )

    for table in context.creates:
        violations.extend(_create_table_syntax(context, table))
    for alter in context.alters:
        for column in alter.columns:
            violations.extend(_column_syntax(context, column))

    # CREATE TABLE with no table name never reaches the parser above.
    for index, statement in enumerate(context.statements):
        if index in context.broken:
            continue
        if re.match(r"create\s+(?:temporary\s+)?table\b", statement.text, re.IGNORECASE) and not any(
            table.offset == statement.offset for table in context.creates
        ):
            violations.append(_syntax(context, statement.offset, "CREATE TABLE is missing a table name."))
    return violations


RULES: list[RuleFn] = [
    rule_syntax,
    rule_enum,
    rule_set_type,
    rule_engine,
    rule_blob,
    rule_json,
    rule_text,
    rule_varchar_width,
    rule_foreign_keys,
    rule_routines,
    rule_charset,
    rule_zerofill,
    rule_integer_display_width,
    rule_float,
    rule_timestamp,
    rule_primary_keys,
    rule_bigint_primary_keys,
    rule_uuid_primary_key,
    rule_auto_increment,
]


def lint_sql(sql: str) -> list[Violation]:
    masked, lex_errors = mask_sql(sql)
    if lex_errors:
        # An unterminated string or comment swallows the rest of the file, so nothing
        # after it can be analysed reliably. Report it and stop.
        return [
            Violation(
                rule_id="SYNTAX_ERROR",
                message=error.message,
                severity=Severity.ERROR,
                line=line_number_for_offset(sql, error.offset),
            )
            for error in lex_errors
        ]

    context = build_context(sql, masked)
    seen: set[Violation] = set()
    violations: list[Violation] = []
    for rule in RULES:
        for violation in rule(context):
            if violation not in seen:
                seen.add(violation)
                violations.append(violation)
    violations.sort(key=lambda item: (item.line or 0, item.rule_id))
    return violations
