# sqlsniff

sqlSniff lints MySQL schema migration files for SQL syntax mistakes and against database standards that keep schemas portable and performant. It only reads your files: nothing is executed and no database connection is needed.

Clone this repository next to your service's `migrations` folder and run it locally (or in CI) against those SQL files.

```text
parent/
  sqlsniff/
  migrations/
    20241105_create_users.sql
```

## Requirements

- Python 3.10 or newer

## Setup

```bash
cd sqlsniff
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Usage

From the `sqlsniff` directory, the default target is `../migrations`:

```bash
sqlsniff
```

Or run the module without installing the console script:

```bash
python -m sqlsniff
```

Point at any migrations folder:

```bash
sqlsniff /path/to/migrations
```

### Skip old files

Pass `--since MM-DD-YYYY` to skip `.sql` files that have not changed since that day. This is the intended way to avoid relinting a large historical backlog:

```bash
sqlsniff --since 01-15-2024
```

When the migrations folder is inside a git repository, "changed" means the file was touched by a commit on or after that date. This works in CI, where a fresh checkout gives every file today's modified time. Files with uncommitted edits, untracked files, and folders outside git fall back to the file's last modified date.

CI must fetch full history for this to work (for GitHub Actions, `fetch-depth: 0`). With a shallow clone git cannot see older commits, so every file is treated as recent and linted.

### Optional `-- ignore-lint` stamp

sqlSniff does not modify your files unless you ask it to. With `--stamp`, each file that passes gets a first line such as:

```sql
-- ignore-lint sha256:9d74ae7986ddd0d9
```

Later runs skip that file for as long as its contents are unchanged. If the file is edited, the checksum no longer matches and it is linted again. Stamping works on raw bytes, so encoding, BOM and line endings are preserved. Files that fail are never stamped.

Do not use `--stamp` if your migration tool checksums migration files (Flyway, for example), and note that a stamp only helps in CI if the stamped file is committed.

A bare `-- ignore-lint` first line, with no checksum, is a manual exception: the file is always skipped. Use it only for a DBA-approved exception. Stamps written by sqlSniff 1.x are bare and are therefore treated this way.

### Optional path ignore file

Exclude path patterns with a `.sqlsniffignore` file in the migrations folder. `--ignore-file PATH` adds the patterns from another file on top. Each non-comment line is a glob or substring matched against the file name and the path relative to the migrations folder:

```text
# .sqlsniffignore
*legacy*
vendor/
```

### Useful flags

```text
sqlsniff [migrations_dir] [--since MM-DD-YYYY] [--ignore-file PATH] [--stamp] [--list-skipped]
```

| Flag | Meaning |
| --- | --- |
| `--since MM-DD-YYYY` | Skip files not changed since this date |
| `--ignore-file PATH` | Extra ignore patterns, in addition to `.sqlsniffignore` |
| `--stamp` | Write `-- ignore-lint sha256:...` on passing files |
| `--list-skipped` | Print skipped files and why they were skipped |

Exit codes: `0` all linted files passed, `1` one or more violations, `2` usage or path error (including a missing `--ignore-file`).

## Rules

All of the following fail the run, whether reported as `error` or `warning`; the label only indicates how serious the finding is.

Comments, string literals and data are ignored, so a word such as `text` inside a `COMMENT`, a default value or an `INSERT` is never flagged. Type rules apply to column definitions in `CREATE TABLE` and `ALTER TABLE ... ADD / MODIFY / CHANGE`.

| Rule | What it enforces |
| --- | --- |
| `SYNTAX_ERROR` | SQL syntax mistakes (see below) |
| `NO_ENUM` | Do not use `ENUM` |
| `NO_SET` | Do not use `SET` column types |
| `ALLOWED_ENGINE` | Table engine must be `InnoDB` or `ROCKSDB` (MyRocks). A table with no `ENGINE` clause is assumed to be InnoDB, the MySQL/MariaDB default |
| `REQUIRE_PRIMARY_KEY` | Every `CREATE TABLE`, including temporary tables, must declare a primary key |
| `BIGINT_PRIMARY_KEY` | Integer primary keys must be `BIGINT` |
| `AUTO_INCREMENT_UNSIGNED` | `AUTO_INCREMENT` integers must be `UNSIGNED` |
| `AUTO_INCREMENT_BIGINT` | `AUTO_INCREMENT` integers must be `BIGINT UNSIGNED` |
| `VARCHAR_WIDTH` | Avoid `VARCHAR` / `CHAR` widths of 255 or more |
| `NO_JSON` | Avoid `JSON` columns |
| `NO_TEXT` | Avoid `TEXT` / `MEDIUMTEXT` / `LONGTEXT` (`TINYTEXT` allowed) |
| `NO_BLOB` | Avoid `BLOB` / `MEDIUMBLOB` / `LONGBLOB` (`TINYBLOB` allowed) |
| `NO_FOREIGN_KEY` | Avoid `FOREIGN KEY` / `REFERENCES` |
| `CREATE_VIEW` / `CREATE_TRIGGER` / `CREATE_FUNCTION` / `CREATE_PROCEDURE` / `CREATE_EVENT` | Avoid database routines; keep this logic in the application |
| `CHARSET_UTF8MB4` | When a charset or collation is declared, use `utf8mb4` |
| `NO_ZEROFILL` | `ZEROFILL` is deprecated in MySQL 8 |
| `NO_INT_DISPLAY_WIDTH` | Integer display widths such as `INT(11)` are deprecated (`TINYINT(1)` allowed) |
| `PREFER_DECIMAL` | Do not use `FLOAT` / `DOUBLE` / `REAL` for exact values |
| `NO_TIMESTAMP` | Prefer `DATETIME` over `TIMESTAMP` (Y2038) |

A typical passing table looks like:

```sql
CREATE TABLE users (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  email VARCHAR(128) NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
```

### Syntax checks

`SYNTAX_ERROR` catches the mistakes that most often break a migration:

- unterminated string, quoted identifier or `/* */` comment
- unbalanced parentheses
- a statement with no terminating `;`, or a `;` missing between two statements
- misspelt statements and object keywords (`CREAT TABLE`, `CREATE TABEL`)
- `CREATE TABLE` with no name, no column list or no columns
- a stray or trailing comma, or a missing comma between column definitions
- a column with no data type or an unknown data type (`VARCHRA`)
- duplicate column names, more than one primary key, or a primary key on a column that does not exist

These are structural checks, not a full MySQL grammar. A file that passes can still be rejected by MySQL for reasons sqlSniff does not model, such as an unknown table or a misspelt keyword inside an expression. Run migrations against a real MySQL instance before release.

When a string or comment is left unterminated, only that error is reported for the file, because nothing after it can be read reliably.

## Tests

```bash
python -m pytest
```

## CI

Run the same command developers run locally. Example:

```bash
pip install -e ".[dev]"
sqlsniff ../migrations --since 01-15-2024
```

Check out full git history in CI so `--since` can see commit dates (see "Skip old files").

There is no private container registry image to pull; this repo is meant to be cloned and executed as a Python tool.
