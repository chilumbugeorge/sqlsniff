"""Dependency-free parsing helpers for MySQL migration files.

The linter never executes SQL. It first *masks* the source (comments become
spaces and string contents become a filler character) so that rules can use
simple pattern matching without being fooled by words inside comments, string
literals or data. Masking preserves length and newlines, so every offset in the
masked text maps to the same line in the original file.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

FILLER = "x"

INTEGER_TYPES = {
    "tinyint",
    "smallint",
    "mediumint",
    "int",
    "integer",
    "bigint",
    "serial",
    "bool",
    "boolean",
}
NON_BIGINT_INTEGER_TYPES = INTEGER_TYPES - {"bigint", "serial"}

IDENT = r"(?:`(?:[^`]|``)+`|[\w$]+)"
QUALIFIED_IDENT = rf"{IDENT}(?:\s*\.\s*{IDENT})?"

CREATE_TABLE_HEAD_RE = re.compile(
    r"create\s+(?P<temporary>temporary\s+)?table\b", re.IGNORECASE
)
CREATE_TABLE_NAME_RE = re.compile(
    rf"create\s+(?:temporary\s+)?table\s+(?:if\s+not\s+exists\s+)?(?P<name>{QUALIFIED_IDENT})\s*",
    re.IGNORECASE,
)
ALTER_TABLE_RE = re.compile(
    rf"alter\s+(?:(?:online|offline|ignore)\s+)*table\s+(?:if\s+exists\s+)?(?P<name>{QUALIFIED_IDENT})\s*",
    re.IGNORECASE,
)
TABLE_CONSTRAINT_RE = re.compile(
    r"(?:constraint\b|primary\s+key\b|unique\b|key\b|index\b|foreign\s+key\b|fulltext\b|spatial\b|check\s*\()",
    re.IGNORECASE,
)
TABLE_PRIMARY_KEY_RE = re.compile(
    rf"(?:constraint\s+(?:{IDENT}\s+)?)?primary\s+key\s*(?:using\s+\w+\s*)?\(",
    re.IGNORECASE,
)
COLUMN_NAME_RE = re.compile(rf"(?P<name>{IDENT})\s*")
COLUMN_TYPE_RE = re.compile(
    r"(?:national\s+)?(?P<type>[a-z_][a-z0-9_]*)(?:\s+(?:varying|precision)\b)?\s*(?:\((?P<args>[^()]*)\))?",
    re.IGNORECASE,
)
DELIMITER_RE = re.compile(r"[ \t]*delimiter[ \t]+(\S+)[ \t]*(?:\r?\n|\Z)", re.IGNORECASE)

ADD_COLUMN_LIST_RE = re.compile(
    r"add\s+(?:column\s+)?(?:if\s+not\s+exists\s+)?\(", re.IGNORECASE
)
ADD_COLUMN_RE = re.compile(
    r"add\s+(?!(?:constraint|primary|unique|index|key|foreign|fulltext|spatial|check|partition)\b)"
    r"(?:column\s+)?(?:if\s+not\s+exists\s+)?",
    re.IGNORECASE,
)
MODIFY_COLUMN_RE = re.compile(r"modify\s+(?:column\s+)?(?:if\s+exists\s+)?", re.IGNORECASE)
CHANGE_COLUMN_RE = re.compile(
    rf"change\s+(?:column\s+)?(?:if\s+exists\s+)?{IDENT}\s+", re.IGNORECASE
)


@dataclass(frozen=True)
class LexError:
    offset: int
    message: str


@dataclass(frozen=True)
class Statement:
    offset: int
    text: str
    terminated: bool

    @property
    def end(self) -> int:
        return self.offset + len(self.text)


@dataclass
class ColumnDef:
    name: str
    type_name: str
    type_args: str
    tail: str
    offset: int
    tail_offset: int
    is_primary_key: bool
    auto_increment: bool
    unsigned: bool


@dataclass
class CreateTable:
    name: str
    offset: int
    temporary: bool
    has_body: bool
    columns: list[ColumnDef] = field(default_factory=list)
    constraints: list[tuple[int, str]] = field(default_factory=list)
    primary_keys: list[tuple[int, list[str]]] = field(default_factory=list)
    empty_pieces: list[int] = field(default_factory=list)
    options: str = ""
    options_offset: int = 0
    remainder: str = ""

    @property
    def table_primary_key(self) -> list[str]:
        return [name for _offset, names in self.primary_keys for name in names]


@dataclass
class AlterTable:
    name: str
    offset: int
    columns: list[ColumnDef] = field(default_factory=list)
    other_specs: list[tuple[int, str]] = field(default_factory=list)


def mask_sql(sql: str) -> tuple[str, list[LexError]]:
    """Blank out comments and string contents. Length and newlines are preserved."""
    out: list[str] = []
    errors: list[LexError] = []
    i = 0
    n = len(sql)

    while i < n:
        ch = sql[i]
        nxt = sql[i + 1] if i + 1 < n else ""

        if ch == "/" and nxt == "*":
            end = sql.find("*/", i + 2)
            if end == -1:
                errors.append(LexError(i, "Unterminated /* block comment."))
                end = n - 2
            stop = end + 2
            out.append("".join("\n" if c == "\n" else " " for c in sql[i:stop]))
            i = stop
            continue

        is_dash_comment = (
            ch == "-" and nxt == "-" and (i + 2 >= n or sql[i + 2] in " \t\r\n\f\v")
        )
        if ch == "#" or is_dash_comment:
            while i < n and sql[i] != "\n":
                out.append(" ")
                i += 1
            continue

        if ch in ("'", '"'):
            start = i
            out.append(ch)
            i += 1
            closed = False
            while i < n:
                c = sql[i]
                if c == "\\" and i + 1 < n:
                    out.append(FILLER)
                    out.append("\n" if sql[i + 1] == "\n" else FILLER)
                    i += 2
                    continue
                if c == ch:
                    if i + 1 < n and sql[i + 1] == ch:
                        out.append(FILLER * 2)
                        i += 2
                        continue
                    out.append(ch)
                    i += 1
                    closed = True
                    break
                out.append("\n" if c == "\n" else FILLER)
                i += 1
            if not closed:
                errors.append(LexError(start, f"Unterminated string literal (opening {ch})."))
            continue

        if ch == "`":
            start = i
            out.append(ch)
            i += 1
            closed = False
            while i < n:
                c = sql[i]
                out.append(c)
                i += 1
                if c == "`":
                    if i < n and sql[i] == "`":
                        out.append("`")
                        i += 1
                        continue
                    closed = True
                    break
            if not closed:
                errors.append(LexError(start, "Unterminated ` quoted identifier."))
            continue

        out.append(ch)
        i += 1

    return "".join(out), errors


def line_number_for_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, max(offset, 0)) + 1


def normalize_identifier(name: str) -> str:
    """Lower-case an identifier, dropping quotes and any schema qualifier."""
    parts = re.findall(r"`((?:[^`]|``)+)`|([\w$]+)", name)
    if not parts:
        return name.strip().lower()
    quoted, bare = parts[-1]
    return (quoted.replace("``", "`") if quoted else bare).lower()


def split_statements(masked: str) -> list[Statement]:
    """Split masked SQL into statements, honouring the mysql client DELIMITER command."""
    statements: list[Statement] = []
    delimiter = ";"
    start = 0
    i = 0
    n = len(masked)
    in_backtick = False
    blank = True

    def emit(end: int, terminated: bool) -> None:
        chunk = masked[start:end]
        stripped = chunk.strip()
        if stripped:
            lead = len(chunk) - len(chunk.lstrip())
            statements.append(Statement(start + lead, stripped, terminated))

    while i < n:
        if blank and not in_backtick and (i == 0 or masked[i - 1] == "\n"):
            match = DELIMITER_RE.match(masked, i)
            if match:
                delimiter = match.group(1)
                i = match.end()
                start = i
                continue
        ch = masked[i]
        if ch == "`":
            in_backtick = not in_backtick
            blank = False
            i += 1
            continue
        if not in_backtick and masked.startswith(delimiter, i):
            emit(i, True)
            i += len(delimiter)
            start = i
            blank = True
            continue
        if not ch.isspace():
            blank = False
        i += 1

    emit(n, False)
    return statements


def split_top_level(text: str, delimiter: str = ",") -> list[tuple[int, str]]:
    """Split on a delimiter outside parentheses/backticks. Returns (offset, raw piece)."""
    pieces: list[tuple[int, str]] = []
    depth = 0
    in_backtick = False
    start = 0
    for i, ch in enumerate(text):
        if ch == "`":
            in_backtick = not in_backtick
        elif in_backtick:
            continue
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        elif ch == delimiter and depth == 0:
            pieces.append((start, text[start:i]))
            start = i + 1
    pieces.append((start, text[start:]))
    return pieces


def find_matching_paren(text: str, open_index: int) -> int:
    depth = 0
    in_backtick = False
    for i in range(open_index, len(text)):
        ch = text[i]
        if ch == "`":
            in_backtick = not in_backtick
        elif in_backtick:
            continue
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i
    return -1


def paren_errors(text: str) -> list[tuple[int, str]]:
    """Return (offset, message) for unbalanced parentheses in a masked statement."""
    stack: list[int] = []
    in_backtick = False
    for i, ch in enumerate(text):
        if ch == "`":
            in_backtick = not in_backtick
        elif in_backtick:
            continue
        elif ch == "(":
            stack.append(i)
        elif ch == ")":
            if not stack:
                return [(i, "Unexpected ')' with no matching '('.")]
            stack.pop()
    if stack:
        return [(stack[0], "Unclosed '(' - missing ')'.")]
    return []


def flatten(text: str) -> str:
    """Blank out parenthesised groups and backtick identifiers (length preserved)."""
    out: list[str] = []
    depth = 0
    in_backtick = False
    for ch in text:
        if ch == "`":
            in_backtick = not in_backtick
            out.append(" ")
        elif in_backtick:
            out.append(" ")
        elif ch == "(":
            depth += 1
            out.append(" ")
        elif ch == ")":
            depth = max(0, depth - 1)
            out.append(" ")
        elif depth:
            out.append("\n" if ch == "\n" else " ")
        else:
            out.append(ch)
    return "".join(out)


def _stripped(offset: int, raw: str) -> tuple[int, str]:
    lead = len(raw) - len(raw.lstrip())
    return offset + lead, raw.strip()


def parse_column_def(text: str, offset: int) -> ColumnDef | None:
    """Parse `name TYPE[(args)] attributes...` from a masked, stripped definition."""
    name_match = COLUMN_NAME_RE.match(text)
    if not name_match:
        return None
    tail = text[name_match.end() :]
    type_match = COLUMN_TYPE_RE.match(tail)
    type_name = type_match.group("type").lower() if type_match else ""
    type_args = (type_match.group("args") or "").strip() if type_match else ""
    lowered = tail.lower()
    return ColumnDef(
        name=normalize_identifier(name_match.group("name")),
        type_name=type_name,
        type_args=type_args,
        tail=tail,
        offset=offset,
        tail_offset=offset + name_match.end(),
        is_primary_key=bool(re.search(r"\bprimary\s+key\b", lowered)),
        auto_increment=bool(re.search(r"\bauto_increment\b", lowered)),
        unsigned=bool(re.search(r"\bunsigned\b", lowered)),
    )


def _primary_key_columns(inner: str) -> list[str]:
    names: list[str] = []
    for _offset, raw in split_top_level(inner):
        part = raw.strip()
        if not part:
            continue
        match = re.match(IDENT, part)
        if match:
            names.append(normalize_identifier(match.group(0)))
    return names


def parse_create_table(statement: Statement) -> CreateTable | None:
    """Parse a CREATE TABLE statement. Returns None when the table name is missing."""
    text = statement.text
    head = CREATE_TABLE_HEAD_RE.match(text)
    name_match = CREATE_TABLE_NAME_RE.match(text)
    if not head or not name_match:
        return None

    table = CreateTable(
        name=normalize_identifier(name_match.group("name")),
        offset=statement.offset,
        temporary=bool(head.group("temporary")),
        has_body=False,
        remainder=text[name_match.end() :],
    )
    if not table.remainder.startswith("("):
        return table

    open_index = name_match.end()
    close_index = find_matching_paren(text, open_index)
    if close_index == -1:
        return table
    body = text[open_index + 1 : close_index]
    if re.match(r"\s*(?:like|select|with)\b", body, re.IGNORECASE):
        return table

    table.has_body = True
    table.options = text[close_index + 1 :]
    table.options_offset = statement.offset + close_index + 1
    body_offset = statement.offset + open_index + 1

    for raw_offset, raw in split_top_level(body):
        offset, piece = _stripped(body_offset + raw_offset, raw)
        if not piece:
            table.empty_pieces.append(offset)
            continue
        if TABLE_CONSTRAINT_RE.match(piece):
            table.constraints.append((offset, piece))
            pk_match = TABLE_PRIMARY_KEY_RE.match(piece)
            if pk_match:
                close = find_matching_paren(piece, pk_match.end() - 1)
                inner = piece[pk_match.end() : close] if close != -1 else ""
                table.primary_keys.append((offset, _primary_key_columns(inner)))
            continue
        column = parse_column_def(piece, offset)
        if column:
            table.columns.append(column)
    return table


def parse_alter_table(statement: Statement) -> AlterTable | None:
    text = statement.text
    match = ALTER_TABLE_RE.match(text)
    if not match:
        return None
    alter = AlterTable(name=normalize_identifier(match.group("name")), offset=statement.offset)
    specs_offset = statement.offset + match.end()

    for raw_offset, raw in split_top_level(text[match.end() :]):
        offset, spec = _stripped(specs_offset + raw_offset, raw)
        if not spec:
            continue

        list_match = ADD_COLUMN_LIST_RE.match(spec)
        if list_match:
            open_index = list_match.end() - 1
            close_index = find_matching_paren(spec, open_index)
            inner = spec[open_index + 1 : close_index] if close_index != -1 else ""
            for inner_offset, inner_raw in split_top_level(inner):
                col_offset, piece = _stripped(offset + open_index + 1 + inner_offset, inner_raw)
                column = parse_column_def(piece, col_offset) if piece else None
                if column:
                    alter.columns.append(column)
            continue

        column_match = (
            ADD_COLUMN_RE.match(spec) or MODIFY_COLUMN_RE.match(spec) or CHANGE_COLUMN_RE.match(spec)
        )
        if column_match:
            column = parse_column_def(spec[column_match.end() :], offset + column_match.end())
            if column:
                alter.columns.append(column)
                continue
        alter.other_specs.append((offset, spec))
    return alter
