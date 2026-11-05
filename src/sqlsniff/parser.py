from __future__ import annotations

import re
from dataclasses import dataclass

CREATE_TABLE_RE = re.compile(
    r"create\s+table\s+(?:if\s+not\s+exists\s+)?(?P<name>(?:`[^`]+`|\"[^\"]+\"|\[[^\]]+\]|\S+))\s*\(",
    re.IGNORECASE,
)
IDENTIFIER_RE = re.compile(r"^`([^`]+)`$|^\"([^\"]+)\"$|^\[([^\]]+)\]$|^(.+)$")
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


@dataclass
class ColumnDef:
    name: str
    type_name: str
    raw: str
    is_primary_key: bool
    auto_increment: bool
    unsigned: bool
    line: int


@dataclass
class CreateTable:
    name: str
    columns: list[ColumnDef]
    table_primary_key: list[str]
    options: str
    line: int


def strip_sql_comments(sql: str) -> str:
    """Remove comments while preserving newlines so line numbers stay aligned."""
    result: list[str] = []
    i = 0
    n = len(sql)
    in_single = False
    in_double = False
    in_backtick = False
    in_block = False

    while i < n:
        ch = sql[i]
        nxt = sql[i + 1] if i + 1 < n else ""

        if in_block:
            if ch == "*" and nxt == "/":
                in_block = False
                result.append("  ")
                i += 2
                continue
            result.append("\n" if ch == "\n" else " ")
            i += 1
            continue

        if in_single:
            result.append(ch)
            if ch == "\\" and nxt:
                result.append(nxt)
                i += 2
                continue
            if ch == "'":
                in_single = False
            i += 1
            continue

        if in_double:
            result.append(ch)
            if ch == "\\" and nxt:
                result.append(nxt)
                i += 2
                continue
            if ch == '"':
                in_double = False
            i += 1
            continue

        if in_backtick:
            result.append(ch)
            if ch == "`":
                in_backtick = False
            i += 1
            continue

        if ch == "-" and nxt == "-":
            while i < n and sql[i] != "\n":
                result.append(" ")
                i += 1
            continue
        if ch == "#":
            while i < n and sql[i] != "\n":
                result.append(" ")
                i += 1
            continue
        if ch == "/" and nxt == "*":
            in_block = True
            result.append("  ")
            i += 2
            continue
        if ch == "'":
            in_single = True
            result.append(ch)
            i += 1
            continue
        if ch == '"':
            in_double = True
            result.append(ch)
            i += 1
            continue
        if ch == "`":
            in_backtick = True
            result.append(ch)
            i += 1
            continue

        result.append(ch)
        i += 1

    return "".join(result)


def line_number_for_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def normalize_identifier(name: str) -> str:
    name = name.strip().rstrip(",")
    match = IDENTIFIER_RE.match(name)
    if not match:
        return name.lower()
    return next(group for group in match.groups() if group is not None).lower()


def split_top_level(text: str, delimiter: str = ",") -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    depth = 0
    in_single = False
    in_double = False
    in_backtick = False
    i = 0

    while i < len(text):
        ch = text[i]
        if in_single:
            current.append(ch)
            if ch == "'" and (i + 1 >= len(text) or text[i + 1] != "'"):
                in_single = False
            elif ch == "'" and text[i + 1] == "'":
                current.append(text[i + 1])
                i += 2
                continue
            i += 1
            continue
        if in_double:
            current.append(ch)
            if ch == '"':
                in_double = False
            i += 1
            continue
        if in_backtick:
            current.append(ch)
            if ch == "`":
                in_backtick = False
            i += 1
            continue
        if ch == "'":
            in_single = True
            current.append(ch)
        elif ch == '"':
            in_double = True
            current.append(ch)
        elif ch == "`":
            in_backtick = True
            current.append(ch)
        elif ch == "(":
            depth += 1
            current.append(ch)
        elif ch == ")":
            depth = max(0, depth - 1)
            current.append(ch)
        elif ch == delimiter and depth == 0:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
        i += 1

    leftover = "".join(current).strip()
    if leftover:
        parts.append(leftover)
    return parts


def extract_paren_block(text: str, open_paren_index: int) -> tuple[str, int]:
    depth = 0
    for i in range(open_paren_index, len(text)):
        ch = text[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[open_paren_index + 1 : i], i
    return text[open_paren_index + 1 :], len(text) - 1


def _parse_column(raw: str, statement: str, statement_offset: int) -> ColumnDef | None:
    stripped = raw.strip()
    if not stripped:
        return None
    if re.match(
        r"^(primary\s+key|unique(\s+key|\s+index)?|key|index|constraint|foreign\s+key|fulltext|spatial|check)\b",
        stripped,
        re.IGNORECASE,
    ):
        return None

    tokens = _tokenize_definition(stripped)
    if not tokens:
        return None

    name = normalize_identifier(tokens[0])
    type_name = tokens[1].lower() if len(tokens) > 1 else ""
    type_name = re.sub(r"\(.*\)$", "", type_name)
    lowered = stripped.lower()
    line = line_number_for_offset(statement, statement_offset + statement[statement_offset:].find(raw.strip()[:20]))
    return ColumnDef(
        name=name,
        type_name=type_name,
        raw=stripped,
        is_primary_key=bool(re.search(r"\bprimary\s+key\b", lowered)),
        auto_increment="auto_increment" in lowered,
        unsigned=bool(re.search(r"\bunsigned\b", lowered)),
        line=line,
    )


def _tokenize_definition(raw: str) -> list[str]:
    tokens: list[str] = []
    current: list[str] = []
    depth = 0
    in_backtick = False
    for ch in raw:
        if ch == "`":
            in_backtick = not in_backtick
            current.append(ch)
            continue
        if in_backtick:
            current.append(ch)
            continue
        if ch == "(":
            depth += 1
            current.append(ch)
            continue
        if ch == ")":
            depth = max(0, depth - 1)
            current.append(ch)
            continue
        if ch.isspace() and depth == 0:
            if current:
                tokens.append("".join(current))
                current = []
            continue
        current.append(ch)
    if current:
        tokens.append("".join(current))
    return tokens


def parse_create_tables(sql: str) -> list[CreateTable]:
    tables: list[CreateTable] = []
    for match in CREATE_TABLE_RE.finditer(sql):
        open_paren = match.end() - 1
        body, close_index = extract_paren_block(sql, open_paren)
        options = sql[close_index + 1 :]
        next_create = CREATE_TABLE_RE.search(sql, close_index + 1)
        if next_create:
            options = sql[close_index + 1 : next_create.start()]
        semicolon = options.find(";")
        if semicolon != -1:
            options = options[:semicolon]

        pieces = split_top_level(body)
        columns: list[ColumnDef] = []
        table_pk: list[str] = []
        body_offset = match.end()
        for piece in pieces:
            pk_match = re.match(
                r"^(?:constraint\s+\S+\s+)?primary\s+key\s*(?:using\s+\w+\s*)?\((.+)\)",
                piece,
                re.IGNORECASE | re.DOTALL,
            )
            if pk_match:
                table_pk = [
                    normalize_identifier(part)
                    for part in split_top_level(pk_match.group(1))
                    if part.strip()
                ]
                continue
            column = _parse_column(piece, sql, match.start())
            if column:
                # Prefer a line number from the body snippet when possible.
                rel = body.find(piece.strip()[: min(24, len(piece.strip()))])
                if rel != -1:
                    column.line = line_number_for_offset(sql, body_offset + rel)
                columns.append(column)

        tables.append(
            CreateTable(
                name=normalize_identifier(match.group("name")),
                columns=columns,
                table_primary_key=table_pk,
                options=options,
                line=line_number_for_offset(sql, match.start()),
            )
        )
    return tables


def iter_statements(sql: str) -> list[tuple[int, str]]:
    statements: list[tuple[int, str]] = []
    for part in split_top_level(sql, ";"):
        stripped = part.strip()
        if stripped:
            offset = sql.find(stripped[: min(40, len(stripped))])
            statements.append((line_number_for_offset(sql, max(offset, 0)), stripped))
    return statements
