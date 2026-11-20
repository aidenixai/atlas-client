"""Read records and count rows in tabular responses using the same header and format rules."""
from __future__ import annotations

import bz2
import codecs
import csv
import datetime as _dt
import io
import json
import numbers
import re
import zipfile
import zlib
from collections import Counter
from itertools import chain, islice

from ._recipe_runtime import ResourceLimitError, _ArchiveZip, _archive_cap

# Identifies the parser revision used to derive columns and row counts.
READER_VERSION = "2026-11-17.1"

# Metadata documents, resource listings and unsupported bodies contain no tabular rows.
NOT_DATA = frozenset({"pdf", "html", "parquet", "turtle", "ntriples",
                      "xml-meta", "binary", "archive", "json-resources"})

# Wrappers that `records`/`count_rows` strip before re-sniffing the content.
WRAPPERS = frozenset({"gzip", "bz2"})

# Local ATLAS_UNPACK_CAP_MB may raise/lower this default. Bound output before allocation.
UNPACK_CAP = 256 * 1024**2


def _unpack_cap() -> int:
    return _archive_cap(UNPACK_CAP)

# A response may contain both column metadata and data arrays. Only descend through record keys.
LIST_KEYS = ("features", "records", "data", "results", "items", "value", "rows",
             "observations", "elements", "entries")

# How many rows beyond the requested n to read from a file or sheet: enough for
# a sheet title, a multi-row header, footnotes and the first records.
WINDOW = 60

# Window used to decide the header for the READER by default (n=5) and always for the COUNTER:
# both decide on the same first 65 rows, then the counter streams.
# Limiting header detection to this window keeps the count consistent with the sample.
HEAD_ROWS = 5 + WINDOW

# Cap the number of rows scanned in a CSV.
CSV_ROW_LIMIT = 2_000_000

# How many leading XML records the "records made of links" rule inspects — independent of n in
# records, so the body kind does not depend on how many records the caller asked for.
URL_SAMPLE = 5

# XML roots that hold a description rather than a table: RDF/DCAT catalog, ISO metadata
# (gmd:MD_Metadata), feeds (Atom feed / rss), sitemaps, OGC GetCapabilities responses
# (WMS/WFS/WMTS "Capabilities"), error reports (OWS ExceptionReport, WMS ServiceException,
# S3/Azure `<Error>`). These are exactly the bodies where the client stopped instead of
# trying the next endpoint.
META_ROOTS = frozenset({"RDF", "MD_Metadata", "feed", "rss", "urlset", "sitemapindex",
                        "WMS_Capabilities", "WFS_Capabilities", "WMT_MS_Capabilities",
                        "Capabilities", "ServiceExceptionReport", "ExceptionReport",
                        "ServiceException", "Error"})
_META_ROOTS_LOW = frozenset(r.lower() for r in META_ROOTS)
# Same OGC family by suffix: WCS_Capabilities (WCS 1.0), CSW/SOS variants — a root with
# such a tail is always a service description or its error.
_META_SUFFIXES = ("capabilities", "exceptionreport")
# Descriptive ROOT namespaces (prefix or URI): OGC OWS, Atom, RDF, ISO gmd.
# Only the root is checked, not all declared xmlns: WFS FeatureCollection declares ows
# next to wfs and is still data.
META_NS = frozenset({"ows", "atom", "rdf", "gmd"})
_META_NS_URI = ("opengis.net/ows", "w3.org/2005/atom", "22-rdf-syntax-ns", "isotc211.org/2005/gmd")

_OLE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
# Binary files with known magic and no reader: sqlite, HDF5, 7z, rar, PNG,
# TIFF (both byte orders). Checked BEFORE the UTF-16 rule (`_utf16_guess`): GeoTIFF has
# zeros after its 49 49 2a 00 magic and passed the "NUL every other byte" test as UTF-16.
_BINARY_MAGIC = (b"SQLite format 3\x00", b"\x89HDF\r\n\x1a\n", b"7z\xbc\xaf\x27\x1c",
                 b"Rar!\x1a\x07", b"\x89PNG\r\n\x1a\n", b"II*\x00", b"MM\x00*")
# Sentence terminators — a sign of prose in single-column mode (`_prose`).
_SENTENCE_END = ".!?…"
_BOM = "﻿"
_SEPS = (",", ";", "\t", "|")
_SSML = "{urn:schemas-microsoft-com:office:spreadsheet}"
# .dbf comes BEFORE .txt: a shapefile zip has licence.txt / readme.txt next to the
# attribute table, and alphabetically it would come first.
_ZIP_ORDER = (".csv", ".tsv", ".xlsx", ".xlsm", ".xls", ".dbf", ".px", ".txt")

# Empty cell: None, whitespace and Excel errors. `#N/A` came from a real case (a first sheet
# with one such cell was considered "denser" than an empty one); the other errors are of the same
# nature: `data_only` returns them as strings instead of values.
_EMPTY_MARKS = frozenset({"#n/a", "#null!", "#ref!", "#div/0!", "#value!", "#name?", "#num!"})

# "No value" markers in statistical tables. Treated as number-like because they stand
# IN PLACE of a number: the row ["Hokkaido", 5381733, "-", 2708452] is data, not a header,
# and without this rule half its non-empty cells would be "not numbers" and it would go into the header.
_MISSING = frozenset({"-", "–", "—", "−", "…", "...", ":", ".", "n/a", "na", "n.a.",
                      "nan", "null", "none", "nd", "n.d."})

_NUM_RE = re.compile(r"(?:\d[\d\s  ,.'’]*|[.,]\d+)(?:[eE][-+]?\d+)?")
_DATE_RES = (
    re.compile(r"\d{4}-\d{1,2}-\d{1,2}"
               r"(?:[T ]\d{1,2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)?"),
    re.compile(r"\d{4}-\d{2}"),                       # 2021-05
    re.compile(r"\d{1,2}[./-]\d{1,2}[./-]\d{2,4}"),   # 01/05/2021, 1.5.21
    re.compile(r"\d{4}[./]\d{1,2}[./]\d{1,2}"),       # 2021/05/01
    re.compile(r"\d{1,2}:\d{2}(?::\d{2})?"),          # 12:30
)
_YEAR_RE = re.compile(r"\d{4}")
# N-Triples triple: <subject> <predicate> and an object that is an IRI, literal or blank node.
# The trailing dot is not required: the body head is cut at 400 bytes and a long literal may not reach it.
# Subject and predicate are ABSOLUTE IRIs, i.e. with a scheme (`http:`, `urn:`): without this
# requirement single-line XML `<r> <rec> <n>A</n> …` (space-separated tags, no declaration)
# passed as a triple and was discarded as a graph, while xml_records produced two
# records from it. A closing tag `</` never appears in a triple line — the second check is in
# sniff_kind.
_NT_IRI = r"<[A-Za-z][A-Za-z0-9+.\-]*:[^>\s]*>"
_NT_RE = re.compile(rf'^{_NT_IRI}\s+{_NT_IRI}\s+(?:<[^>\s]*>|"|_:)')
# Page detection by TAG `<html`/`<head` (word boundary), not by substring: `"<head" in …`
# flagged as a page any XML starting with a <header>/<heading> element, and the recipe was
# marked "did not reach data" where a table had actually arrived.
_HTML_TAG_RE = re.compile(r"<(?:html|head)\b")
_CYR = re.compile(r"[Ѐ-ӿ]{3,}")
# XML root tag in the body head: first tag that is not `<?…?>`, `<!…>` or a closing tag;
# prefix, local name and the attribute tail (where xmlns declarations live).
_ROOT_TAG_RE = re.compile(r"<(?![!?/])\s*(?:([A-Za-z_][\w.\-]*):)?([A-Za-z_][\w.\-]*)([^>]*)")
_XMLNS_RE = re.compile(r"""xmlns(?::([\w.\-]+))?\s*=\s*["']([^"']*)["']""")
_COMMENT_RE = re.compile(r"<!--.*?-->", re.S)
_XML_DECL_RE = re.compile(r"^\s*<\?xml[^>]*\?>")
_URL_PREFIXES = ("http://", "https://")


# ── cells ────────────────────────────────────────────────────────────────────
def _is_empty(cell) -> bool:
    if cell is None:
        return True
    if isinstance(cell, str):
        s = cell.replace(_BOM, "").strip()
        return not s or s.lower() in _EMPTY_MARKS
    if isinstance(cell, float) and cell != cell:      # NaN
        return True
    return False


def _text(cell) -> str:
    """Cell as a name: no line breaks or control chars, numbers without ".0", dates as ISO.

    xlrd returns all numbers as floats, so a year in the header came out as "2019.0"; openpyxl returns
    a line break inside a cell as is, and the column name ended up in jsonb with "\\n"."""
    if _is_empty(cell):
        return ""
    if isinstance(cell, bool):
        return str(cell)
    if isinstance(cell, float):
        return str(int(cell)) if cell.is_integer() and abs(cell) < 1e15 else repr(cell)
    if isinstance(cell, _dt.datetime):
        if cell.hour or cell.minute or cell.second or cell.microsecond:
            return cell.isoformat(sep=" ")
        return cell.date().isoformat()
    if isinstance(cell, _dt.date):
        return cell.isoformat()
    if isinstance(cell, bytes):
        cell = cell.decode("utf-8", "replace")
    s = re.sub(r"\s+", " ", str(cell)).replace(_BOM, "")
    return "".join(ch for ch in s if ch.isprintable()).strip()


def _value(v):
    """Record value: primitives as is, dates as text, everything else as str."""
    if isinstance(v, (str, bool, int, float)):
        return v
    if isinstance(v, (_dt.datetime, _dt.date)):
        return _text(v)
    if isinstance(v, numbers.Number):
        try:
            return float(v)
        except (TypeError, ValueError):
            return str(v)
    return str(v)


def is_numberish(cell) -> bool:
    """Number, numeric string (1 234,5 / 12.5% / -3 / 1e5), date (2021-05-01, 01/05/2021,
    2021), time, datetime/date, and "no value" markers. None and empty — False."""
    if cell is None or isinstance(cell, bool):
        return cell is not None
    if isinstance(cell, numbers.Number):
        return True
    if isinstance(cell, (_dt.datetime, _dt.date, _dt.time)):
        return True
    s = str(cell).replace(_BOM, "").strip()
    if not s:
        return False
    if s.lower() in _MISSING:
        return True
    if len(s) > 2 and s[0] == "(" and s[-1] == ")":      # accounting negative: (1 234)
        s = s[1:-1].strip()
    s = s.rstrip("%").strip().lstrip("+-−").strip()
    if not s:
        return False
    if _NUM_RE.fullmatch(s):
        return True
    return any(rx.fullmatch(s) for rx in _DATE_RES)


def _is_year(cell) -> bool:
    if isinstance(cell, bool) or _is_empty(cell):
        return False
    if isinstance(cell, numbers.Number):
        try:
            v = float(cell)
        except (TypeError, ValueError):
            return False
        return v.is_integer() and 1900 <= v <= 2100
    s = str(cell).strip()
    return bool(_YEAR_RE.fullmatch(s)) and 1900 <= int(s) <= 2100


# ── rows ─────────────────────────────────────────────────────────────────────
def _cells(row) -> list:
    return [c for c in row if not _is_empty(c)]


def _textual(row) -> bool:
    """At least half of the non-empty cells are NOT numberish — a row of names, not values."""
    ne = _cells(row)
    if not ne:
        return False
    return sum(1 for c in ne if not is_numberish(c)) * 2 >= len(ne)


def _years_row(row) -> bool:
    """Year columns of statistical tables: [2019, 2020, 2021] or ["Region", 2019, 2020].

    A row with a label on the left and years on the right is the most common statistics header;
    under the "mostly numberish = data" rule it would go to data, so the exception is broader
    than literally "all are years": at least two years, and everything number-like in the row is a year."""
    ne = _cells(row)
    if len(ne) < 2:
        return False
    years = sum(1 for c in ne if _is_year(c))
    return years >= 2 and all(_is_year(c) for c in ne if is_numberish(c))


def _data_like(row) -> bool:
    """Row of values: two or more non-empty cells, mostly numberish."""
    return len(_cells(row)) >= 2 and not _textual(row)


def _years_header(rows: list[list], j: int) -> bool:
    """Year row rows[j] is a header, not a record with years among its values.

    The `_years_row` rule alone cannot tell `[None, 2019, 2020]` from `["North", 1990, 2005]`
    — both have "at least two years, everything number-like is a year". The NEXT row with
    two or more non-empty cells tells them apart: under a year header lie values (["Tokyo", 1, 2, 3]), while under
    a record with years lies a similar record (["South", 1995, 2010]). Without this
    check `region,from_year,to_year` lost its first record into the column names
    ("region / North"), `year,count` with values 1985..2120 did too, and a headerless file
    `1990,2005\\n1995,2010` got the header "1990 / 2005" instead of col1/col2."""
    if not _years_row(rows[j]):
        return False
    nxt = next((r for r in rows[j + 1:] if len(_cells(r)) >= 2), None)
    return nxt is None or not _years_row(nxt)


def _numeric_columns(rows: list[list]) -> set[int]:
    """Columns where the window's value rows carry numbers: over `_data_like` rows, a column is
    numeric if it has strictly more numberish cells than text ones. Empty set — the window
    has no value rows (purely textual register)."""
    num: Counter = Counter()
    txt: Counter = Counter()
    for r in rows:
        if not _data_like(r):
            continue
        for i, c in enumerate(r):
            if _is_empty(c):
                continue
            (num if is_numberish(c) else txt)[i] += 1
    return {i for i, k in num.items() if k > txt.get(i, 0)}


def _data_shaped(row: list, numeric_cols: set[int]) -> bool:
    """Row is shaped like a record: numbers or blanks in numeric columns. A header row
    (names, units, group) carries TEXT in a numeric column — that is the distinction."""
    if not numeric_cols:
        return False
    return all(_is_empty(c) or is_numberish(c)
               for i, c in enumerate(row) if i in numeric_cols)


def _has_gap(row) -> bool:
    """Empty cells BETWEEN non-empty ones, ignoring the first column — trace of a spanned
    group header (["", "Population", "", "", "Households"]). An empty first
    column is not a gap: that is how a pandas index looks in a normal table."""
    idx = [i for i, c in enumerate(row) if not _is_empty(c)]
    if len(idx) < 2:
        return False
    return any(_is_empty(row[k]) for k in range(1, idx[-1]))


def _last_nonempty(row) -> int:
    for i in range(len(row) - 1, -1, -1):
        if not _is_empty(row[i]):
            return i
    return -1


def _keep_row(r, ncols: int) -> bool:
    """A row after the block is data: not empty and not a single-cell footnote (longer than 40 chars
    or the header has three or more columns — disclaimers and "Source: …" captions)."""
    ne = _cells(r)
    if not ne:
        return False
    return not (len(ne) == 1 and (len(_text(ne[0])) > 40 or ncols >= 3))


def _data_rows(rest: list[list], ncols: int) -> list[list]:
    """Rows after the block: without empty rows and single-cell footnotes (see `_keep_row`)."""
    return [r for r in rest if _keep_row(r, ncols)]


def _prose(cell) -> bool:
    """Sentence cell: contains a space and ends with a sentence terminator. That is how
    delimiter-less prose looks (dataset description under text/plain, disclaimer); an address, name,
    code, URL or date does not end with a space-separated phrase and a period."""
    s = _text(cell)
    return bool(s) and " " in s and s[-1] in _SENTENCE_END


def _single_plan(rows: list[list]) -> tuple[list[str], int]:
    """No row with two non-empty cells: the first non-numeric cell is the header, else col1.
    → (names, index of the first data row).

    The footnote rule (single cell longer than 40 chars) does not apply here: in a
    single-column file every value is one cell, and an address list would end up with no rows.
    But prose is not a table: if at least half of the non-empty cells are sentences
    (`_prose`), return no names and zero rows."""
    idx = [i for i, r in enumerate(rows) if _cells(r)]
    if not idx:
        return [], 0
    if sum(1 for i in idx if _prose(_cells(rows[i])[0])) * 2 >= len(idx):
        return [], 0
    h = next((i for i in idx if not is_numberish(_cells(rows[i])[0])), None)
    if h is None:
        return ["col1"], 0
    return [_text(_cells(rows[h])[0])[:120] or "col1"], h + 1


def _header_plan(rows: list[list], max_header_rows: int = 5) -> tuple[list[str], int, int, bool]:
    """Header decision without materializing data: (column names, index of the first data
    row, width, single-column mode). Empty names → no table.

    Split out of `header_block`: the reader returns data rows as a list
    (`header_block`), while the counter `count_rows` STREAMS rows — a workbook sheet with a
    million rows cannot be loaded as a list. Both use the same header decision from one
    function; the rules are in the `header_block` docstring."""
    if not rows:
        return [], 0, 0, False
    start = next((i for i, r in enumerate(rows) if len(_cells(r)) >= 2), None)
    if start is None:
        names, k = _single_plan(rows)
        return names, k, 1, True

    first = rows[start]
    block = [start]
    if _years_header(rows, start):
        pass
    elif all(is_numberish(c) for c in _cells(first)):
        ncols = _last_nonempty(first) + 1
        return [f"col{j + 1}" for j in range(ncols)], start, ncols, False
    else:
        numeric_cols = _numeric_columns(rows[start + 1:])
        j = start + 1
        while j < len(rows) and len(block) < max_header_rows:
            r = rows[j]
            if len(_cells(r)) < 2:
                break
            if _years_header(rows, j):
                block.append(j)
                break
            if not _textual(r):
                break
            if not _has_gap(rows[block[-1]]) and (not numeric_cols
                                                  or _data_shaped(r, numeric_cols)):
                break
            block.append(j)
            j += 1

    width = max(_last_nonempty(rows[i]) for i in block) + 1
    grid = [[_text(rows[i][c]) if c < len(rows[i]) else "" for c in range(width)]
            for i in block]
    for g in grid[:-1]:
        for c in range(1, width):
            if not g[c]:
                g[c] = g[c - 1]
    names: list[str] = []
    for c in range(width):
        parts: list[str] = []
        for g in grid:
            if g[c] and g[c] not in parts:
                parts.append(g[c])
        names.append(" / ".join(parts).strip()[:120] or f"col{c + 1}")
    seen: Counter = Counter()
    for k, nm in enumerate(names):
        seen[nm] += 1
        if seen[nm] > 1:
            names[k] = f"{nm} ({seen[nm]})"
    return names, block[-1] + 1, width, False


def header_block(rows: list[list], max_header_rows: int = 5) -> tuple[list[str], list[list]]:
    """Multi-row header block → (column names, data rows).

    rows — sheet/file rows as lists of cells (None/str/number/datetime). Empty cell:
    None, "", "#N/A" (after strip).
      1) leading rows with < 2 non-empty cells (sheet title, blanks) are skipped;
      2) the block starts at the first row with >= 2 non-empty cells and grows down while the next
         row is "textual" (at least half of non-empty cells NOT numberish) and the block is shorter
         than max_header_rows; a row where most non-empty cells are numberish is data and ends
         the block. Exception — a row of years 1900..2100 (>= 2 of them): it joins as the last row;
      3) vertical merge: in block rows except the bottom one, an empty cell inherits the
         nearest non-empty cell to its left (that is how group headers span); column name =
         " / ".join(distinct non-empty parts top to bottom); empty → col{j+1}; duplicates get
         suffix " (2)", " (3)";
      4) data = everything after the block, without empty rows and single-cell footnotes;
      5) edges: rows empty → ([], []); all rows single-cell → see _single_plan.

    Three refinements to rule 2. The first two exist because of tables whose data rows are "textual"
    (organization registers, name/city lists, mixed text+number half and half): for them
    the literal rule would grow the header to five rows, merging names with the first four
    records. A textual row joins the block only if it is not shaped like a record: in columns
    where the window's value rows carry numbers (`_numeric_columns`), it has text
    (units "人", group "Population") — see `_data_shaped`; a row with numbers or blanks
    in those columns is data and ends the block. The earlier check "there is a value row below
    in the window" could not tell this apart: in a name,city,age,salary table one empty
    text cell in row 40 made that row alone a "value row", and the three records above it
    a "header continuation". Without value rows in the window (purely textual register) the block does not
    grow at all; exception — a bottom block row with gaps between cells (a group
    header awaiting a subheader). Third: a first block row where all non-empty cells are numberish and
    it is not a year header is headerless data, named col1..colN (the "header is names" rule
    of earlier readers); a year header only applies when the row below is not
    another year row (`_years_header`).

    The header decision lives in `_header_plan` (shared with the `count_rows` counter)."""
    rows = [list(r) for r in rows]
    names, k, width, single = _header_plan(rows, max_header_rows)
    if not names:
        return [], []
    if single:
        return names, [[_cells(r)[0]] for r in rows[k:] if _cells(r)]
    return names, _data_rows(rows[k:], width)


def rows_to_records(names: list[str], data_rows: list[list], n: int) -> list[dict]:
    """zip names with rows; drop None/"" values; drop empty dicts; first n."""
    out: list[dict] = []
    for r in data_rows:
        rec = {}
        for k, v in zip(names, r):
            if _is_empty(v) or isinstance(v, bytes):
                continue
            rec[k] = _value(v)
        if rec:
            out.append(rec)
            if len(out) >= n:
                break
    return out


def _records_from_rows(rows: list[list] | None, n: int) -> list[dict] | None:
    if not rows:
        return None
    names, data = header_block(rows)
    if not names:
        return None
    return rows_to_records(names, data, n) or [{"columns": names}]


def _row_counts(r, names: list[str], width: int, single: bool) -> bool:
    """Row yields a record in `rows_to_records`: passes `_keep_row` and has a non-empty value
    (not bytes) within the header width. In single-column mode — any non-empty cell."""
    if single:
        return bool(_cells(r))
    if not _keep_row(r, width):
        return False
    return any(not _is_empty(v) and not isinstance(v, bytes) for v in list(r)[:len(names)])


def _count_from_rows(rows, limit: int | None = None) -> int:
    """Record count of a row stream: the header is decided on the first HEAD_ROWS rows (same
    `_header_plan` the reader sees with n=5), after that rows are only counted —
    exactly those from which `rows_to_records` would build a non-empty record. limit caps
    rows read (including the header)."""
    rows = iter(rows)
    head = [list(r) for r in islice(rows, HEAD_ROWS)]
    names, k, width, single = _header_plan(head)
    if not names:
        return 0
    n = 0
    for i, r in enumerate(chain(head, rows)):
        if limit is not None and i >= limit:
            break
        if i < k:
            continue
        if _row_counts(r, names, width, single):
            n += 1
    return n


# ── body kind ────────────────────────────────────────────────────────────────
def _utf16_guess(body: bytes) -> str | None:
    """UTF-16 without BOM: NUL every other byte in the first 4 KB — at least a quarter of bytes, and nearly all
    (≥ 90%) on one parity. "a\\x00" — high byte on the right, LE; "\\x00a" — BE.

    The reader used to return such bodies as "text" with no rows (NUL in the first 4 KB is
    a binary sign), while the counter counted line breaks. The parity threshold rejects binary
    files with many NULs scattered randomly."""
    head = body[:4096]
    if len(head) < 8:
        return None
    nul = head.count(b"\x00")
    if nul * 4 < len(head):
        return None
    odd = head[1::2].count(b"\x00")
    even = nul - odd
    if max(odd, even) * 10 < nul * 9:
        return None
    return "utf-16-le" if odd >= even else "utf-16-be"


def _head_text(body: bytes, chars: int) -> str:
    """Body head as text for sniffing: BOM stripped, UTF-16 (with or without BOM) decoded."""
    if body[:3] == b"\xef\xbb\xbf":
        return body[3:3 + chars].decode("utf-8", "replace")
    if body[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return body[:2 + 2 * chars].decode("utf-16", "replace")
    enc16 = _utf16_guess(body)
    if enc16:
        return body[:2 * chars].decode(enc16, "replace")
    return body[:chars].decode("utf-8", "replace")


def _ns_short(prefix: str, uri: str) -> str:
    """Short name of the root namespace: the prefix if it is in META_NS, otherwise by URI."""
    p = (prefix or "").lower()
    if p in META_NS:
        return p
    u = (uri or "").lower()
    for short, mark in zip(("ows", "atom", "rdf", "gmd"), _META_NS_URI):
        if mark in u:
            return short
    return p


def _url_share(recs: list[dict]) -> float:
    """Share of record values starting with http(s)://; no values → 0.0."""
    vals = [str(v).strip().lower() for r in recs for v in r.values()]
    if not vals:
        return 0.0
    return sum(1 for v in vals if v.startswith(_URL_PREFIXES)) / len(vals)


def is_xml_meta(root_tag, ns: str = "", records: list[dict] | None = None,
                tags=None) -> str | None:
    """Is the XML a description rather than data? → label of the matched rule, or None (data, or
    undecidable from these signals).

    Both sample extraction and row counting use these rules in order:
      1) root in META_ROOTS (case-insensitive) or with suffix "…Capabilities" /
         "…ExceptionReport" (WCS 1.0 `WCS_Capabilities` and other OGC of the same family)
         → "root RDF";
      2) root namespace in META_NS — prefix (ows, atom, rdf, gmd) or URI
         (`_META_NS_URI`) → "ns ows";
      3) kml root without a Placemark element → "kml root without Placemark": KML
         of ListStyle/NetworkLink, i.e. styles and layer links, not points; with
         Placemark the KML stays data. Requires `tags` (local element names of the tree)
         or a root Element in `root_tag` to take them from; without them the rule does not
         apply — it cannot be decided from the body head, `sniff_kind` keeps "xml", and the
         parse in `records`/`count_rows` decides;
      4) ≥ 50% of values of the first URL_SAMPLE records are URLs → "URL share 0.67": a feed of links to
         files (dataset resource list, Atom without a feed root).

    root_tag — local root name, ElementTree tag "{uri}local", or the root Element itself;
    ns — prefix or URI of the root namespace (for a "{uri}local" tag the URI is already in the tag);
    records — `xml_records` output; the first URL_SAMPLE are inspected, independent of the caller's n.

    NOT a description (test fixtures): GML/WFS FeatureCollection (declares ows next to
    wfs, but the root is wfs), SDMX-ML GenericData, Latvian elections results/district, KML with
    Placemark, SpreadsheetML."""
    el = root_tag if hasattr(root_tag, "tag") else None
    tag = str(el.tag) if el is not None else str(root_tag or "")
    local, uri, prefix = _local(tag), _ns_uri(tag), ""
    if ns:
        if "/" in ns or ":" in ns:
            uri = uri or ns
        else:
            prefix = ns
    low = local.lower()
    if low in _META_ROOTS_LOW or low.endswith(_META_SUFFIXES):
        return f"root {local}"
    short = _ns_short(prefix, uri)
    if short in META_NS:
        return f"ns {short}"
    if low == "kml":
        if tags is None and el is not None:
            tags = {_local(e.tag) for e in el.iter()}
        if tags is not None and not any(str(t).lower() == "placemark" for t in tags):
            return "kml root without Placemark"
    share = _url_share(list(records or [])[:URL_SAMPLE])
    if share >= 0.5:
        return f"URL share {share:.2f}"
    return None


def _xml_head_meta(text: str) -> bool:
    """Metadata root detected from the body head (no parsing): root tag, its prefix and the URI
    declared for that prefix (or the default xmlns) in the root attributes.
    Rules 3-4 of `is_xml_meta` (kml without Placemark, link-only records) cannot be
    decided from the head; parsing in `records`/`count_rows` applies them."""
    m = _ROOT_TAG_RE.search(_COMMENT_RE.sub("", text))
    if not m:
        return False
    prefix, local, attrs = m.group(1) or "", m.group(2), m.group(3) or ""
    uri = ""
    for p, u in _XMLNS_RE.findall(attrs):
        if (p or "") == prefix:
            uri = u
            break
    return is_xml_meta(f"{{{uri}}}{local}" if uri else local, prefix) is not None


def sniff_kind(body: bytes, content_type: str = "") -> str:
    """Body kind BY CONTENT; the response content type is only a final hint.

    The order matters. Some portals serve an xlsx workbook with a text/csv header, and
    parsing by header counted 1224 "rows" of binary garbage. Byte magic wins over the header
    everywhere: pdf, zip (xlsx), OLE (xls), parquet, gzip, bz2, binaries with no reader
    (sqlite/HDF5/7z/rar/PNG/TIFF -> "binary") - and only AFTER them the text kinds
    (html, turtle, ntriples, json, xml / xml-meta) by the start of the text, where UTF-16
    without BOM is decoded by NUL at every other byte (otherwise GeoTIFF passed as UTF-16);
    everything else is csv. "xml-meta" here is decided by the root in the head (rules 1-2 of
    `is_xml_meta`); kml without Placemark and link feeds are decided by parsing in
    `records`/`count_rows`. "gzip"/"bz2" are WRAPPER kinds: `records`/`count_rows` unwrap
    them and sniff the content again; sniff_kind itself does not look inside."""
    if not body or body.isspace():
        return "empty"
    head = body[:8]
    if head[:4] == b"%PDF":
        return "pdf"
    if head[:2] == b"PK":                  # zip container: a workbook or an archive with csv inside
        # ODS stores the `mimetype` member first and uncompressed, so the type is visible in the first bytes.
        if body[30:38] == b"mimetype" and _ODS_MIME in body[38:120]:
            return "ods"
        return "xlsx"
    if head == _OLE:
        return "xls"
    if head[:4] == b"PAR1":
        return "parquet"
    if head[:2] == b"\x1f\x8b":
        return "gzip"
    if head[:3] == b"BZh" and head[3:4].isdigit() and head[3:4] != b"0":
        return "bz2"
    if body.startswith(_BINARY_MAGIC):
        return "binary"
    if _dbf_header(body) is not None:      # dBase: field header is consistent with record length
        return "dbf"
    text = _head_text(body, 400).lstrip()
    low = text.lower()
    if low.startswith("<!doctype html") or _HTML_TAG_RE.search(low[:200]):
        return "html"
    # Leading `#` comments are common in Turtle/N-Triples; for these two checks
    # the first non-comment line counts as the first line.
    first = next((ln.strip() for ln in text.splitlines()
                  if ln.strip() and not ln.lstrip().startswith("#")), "")
    if first.lower().startswith(("@prefix", "@base")) or first.startswith(("PREFIX ", "BASE ")):
        return "turtle"
    if _NT_RE.match(first) and "</" not in first:
        return "ntriples"
    if text[:1] in ("{", "["):
        return "json"
    if text[:1] == "<":
        # The root is checked in the first 4 KB: in GetCapabilities and RDF catalogs the root
        # tag with its xmlns declarations is longer than 400 bytes.
        return "xml-meta" if _xml_head_meta(_head_text(body, 4096)) else "xml"
    from ._recipe_runtime import is_px_text
    if is_px_text(body[:65536].decode("ascii", "replace")):
        return "px"
    if "json" in (content_type or "").lower():
        return "json"
    return "csv"


def unwrap(body: bytes) -> bytes | None:
    """Content of a gzip/bz2 wrapper. None - not a wrapper, broken archive, or unpacked size
    above the locally configured unpack cap: kind "archive", zero rows.

    A body truncated by the read cap is unpacked up to the cut - like a truncated
    csv, the reader sees its beginning. For multi-member gzip the first member is used."""
    try:
        if body[:2] == b"\x1f\x8b":
            out = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(body, _unpack_cap() + 1)
        elif body[:3] == b"BZh":
            out = bz2.BZ2Decompressor().decompress(body, _unpack_cap() + 1)
        else:
            return None
    except Exception:                                                 # noqa: BLE001
        return None
    return None if len(out) > _unpack_cap() else out


def _unwrapped(body: bytes, content_type: str) -> tuple[str, bytes]:
    """(kind, body) after unwrapping: gzip/bz2 -> content and its kind; failed to unwrap or
    another wrapper inside -> "archive"."""
    kind = sniff_kind(body, content_type)
    if kind not in WRAPPERS:
        return kind, body
    inner = unwrap(body)
    if inner is None:
        return "archive", body
    kind = sniff_kind(inner, content_type)
    if kind in WRAPPERS:
        return "archive", inner
    return kind, inner


# ── text ────────────────────────────────────────────────────────────────────
def decode_text(body: bytes, declared: str | None = None) -> tuple[str, str]:
    """-> (text, encoding used). A fallback ladder without frequency-based guessing.

    Try a BOM first, then UTF-16 without a BOM (alternating NUL bytes), followed by
    the declared encoding and strict UTF-8. Accept cp1251 only if three consecutive
    Cyrillic letters appear, then try cp1252 and finally Latin-1.

    A body truncated by the cap in the middle of a multibyte character is still UTF-8: an
    error in the last three bytes does not push the file to cp1252."""
    if not body:
        return "", ""
    if body.startswith(b"\xef\xbb\xbf"):
        return body[3:].decode("utf-8", "replace"), "utf-8-sig"
    if body[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return body.decode("utf-16", "replace"), "utf-16"
    enc16 = _utf16_guess(body)
    if enc16:
        return body.decode(enc16, "replace"), enc16
    for enc in ([declared] if declared else []) + ["utf-8"]:
        try:
            return body.decode(enc), enc
        except UnicodeDecodeError as e:
            if enc == "utf-8" and e.start >= len(body) - 3:
                return body[:e.start].decode("utf-8", "replace"), "utf-8"
        except LookupError:
            continue
    from ._recipe_runtime import decode_cp932
    japanese = decode_cp932(body)
    if japanese is not None:
        return japanese, "cp932"
    try:
        cyr = body.decode("cp1251")
        if _CYR.search(cyr):
            return cyr, "cp1251"
    except UnicodeDecodeError:
        pass
    try:
        return body.decode("cp1252"), "cp1252"
    except UnicodeDecodeError:
        return body.decode("latin-1"), "latin-1"


def _delimiter(text: str) -> str:
    """Delimiter giving the most stable column count over the first 20 non-empty lines;
    on a tie, the most frequent one. Lines are parsed with csv.reader so a comma inside
    quotes is not counted as a delimiter."""
    lines = [ln for ln in text.splitlines() if ln.strip()][:20]
    best, best_key = ",", None
    for sep in _SEPS:
        counts = []
        for ln in lines:
            try:
                row = next(csv.reader([ln], delimiter=sep), [])
            except csv.Error:
                row = ln.split(sep)
            counts.append(len(row))
        if not counts:
            continue
        mode, freq = Counter(counts).most_common(1)[0]
        if mode < 2:
            continue
        key = (freq / len(counts), sum(ln.count(sep) for ln in lines))
        if best_key is None or key > best_key:
            best, best_key = sep, key
    return best


def _csv_limit() -> None:
    try:
        csv.field_size_limit(10_000_000)
    except (OverflowError, ValueError):
        pass


def _csv_rows_iter(text: str, sep: str):
    """Stream csv.reader rows. The newline="" stream goes first: without it csv.reader failed
    on line breaks inside quotes ("new-line character seen in unquoted field").
    An error mid-file ends the stream without discarding rows already yielded;
    an error before the first row retries with the second stream."""
    _csv_limit()
    for stream in (io.StringIO(text, newline=""), io.StringIO(text)):
        got = False
        try:
            for row in csv.reader(stream, delimiter=sep):
                got = True
                yield row
        except csv.Error:
            if got:
                return
            continue
        return


def _read_csv(text: str, sep: str, limit: int) -> list[list]:
    """First `limit` rows of `_csv_rows_iter` as a list."""
    return list(islice(_csv_rows_iter(text, sep), limit))


def _csv_text(body) -> str | None:
    """CSV text from the body: bytes are decoded via `decode_text`, str is taken as
    already decoded. None - empty, or binary posing as text (NUL in the first 4 KB)."""
    if isinstance(body, (bytes, bytearray)):
        text, _ = decode_text(bytes(body))
    else:
        text = str(body)
    text = text.lstrip(_BOM)
    if not text.strip() or "\x00" in text[:4096]:
        return None
    return text


def csv_records(body, n: int = 5, max_bytes: int = 400_000) -> list[dict] | None:
    """Read CSV/TSV bytes or decoded text. A header-only file returns [{"columns": names}]."""
    cut = isinstance(body, (bytes, bytearray)) and len(body) > max_bytes
    text = _csv_text(body[:max_bytes] if isinstance(body, (bytes, bytearray)) else body)
    if text is None:
        return None
    rows = _read_csv(text, _delimiter(text), n + WINDOW)
    # Text was cut by the cap mid-line, so the last row is almost certainly incomplete.
    if cut and rows and len(rows) < n + WINDOW:
        rows.pop()
    return _records_from_rows(rows, n)


def _csv_count(body, max_bytes: int = 400_000) -> int:
    """CSV data rows over the FULL body: delimiter from the same first 400 KB the reader
    sees, header from the first HEAD_ROWS rows, then streamed up to CSV_ROW_LIMIT."""
    text = _csv_text(body)
    if text is None:
        return 0
    return _count_from_rows(_csv_rows_iter(text, _delimiter(text[:max_bytes])), CSV_ROW_LIMIT)


# ── workbooks ────────────────────────────────────────────────────────────────────
def _close(obj, method: str) -> None:
    try:
        getattr(obj, method)()
    except Exception:                                                 # noqa: BLE001
        pass


def _xlsx_best(body: bytes):
    """(workbook, densest sheet | None) or None - not a workbook or no openpyxl. The caller
    closes the workbook.

    The sheet is the densest one (most non-empty cells in the first 60 rows; first on a
    tie), not the first: some workbooks have an empty "#N/A" cover sheet and the table
    on the second. read_only avoids loading the workbook into memory, data_only returns formula values."""
    try:
        import openpyxl
    except ImportError:
        return None
    try:
        with _ArchiveZip(body, limit=_unpack_cap()) as archive:
            if "xl/workbook.xml" not in archive.namelist():
                return None
            archive.check_workbook()
        wb = openpyxl.load_workbook(io.BytesIO(body), read_only=True, data_only=True)
    except ResourceLimitError:
        raise
    except Exception:                                                 # noqa: BLE001
        return None
    try:
        best, best_n = None, 0
        for ws in wb.worksheets:
            if ws.max_row == 1 and ws.max_column == 1:
                # A <dimension ref="A1"/> marker on a sheet with 95 rows:
                # read_only trusts it and returns one row. Resetting dimensions forces
                # openpyxl to read the whole sheet; a real one-cell sheet is
                # unaffected.
                try:
                    ws.reset_dimensions()
                except Exception:                                     # noqa: BLE001
                    pass
            k = sum(1 for r in ws.iter_rows(min_row=1, max_row=WINDOW, values_only=True)
                    for c in r if not _is_empty(c))
            if k > best_n:
                best, best_n = ws, k
        return wb, best
    except Exception:                                                 # noqa: BLE001
        _close(wb, "close")
        return None


def _xlsx_rows(body: bytes, limit: int) -> list[list] | None:
    """First `limit` rows of the densest sheet of an xlsx workbook; None - not a workbook or no
    openpyxl; [] - all sheets are empty."""
    got = _xlsx_best(body)
    if got is None:
        return None
    wb, ws = got
    try:
        if ws is None:
            return []
        return [list(r) for r in ws.iter_rows(min_row=1, max_row=limit, values_only=True)]
    except Exception:                                                 # noqa: BLE001
        return None
    finally:
        _close(wb, "close")


def _xlsx_count(body: bytes) -> int | None:
    """Data rows of the densest sheet, streamed; None - not a workbook or no openpyxl."""
    got = _xlsx_best(body)
    if got is None:
        return None
    wb, ws = got
    try:
        if ws is None:
            return 0
        return _count_from_rows(ws.iter_rows(values_only=True))
    except Exception:                                                 # noqa: BLE001
        return 0
    finally:
        _close(wb, "close")


def _zip_pick(z) -> tuple[str, str] | None:
    """(extension, name) of the first archive member by extension order, or None.

    Extension order instead of "first found": archives often have readme.txt next to
    data.csv, and it came first alphabetically."""
    members = [nm for nm in z.namelist()
               if not nm.endswith("/") and "__macosx" not in nm.lower()]
    for ext in _ZIP_ORDER:
        for nm in members:
            if nm.lower().endswith(ext):
                return ext, nm
    return None


def _zip_oversize(z, nm: str) -> bool:
    """Archive member larger than UNPACK_CAP when unpacked - checked from the directory, BEFORE reading."""
    return z.getinfo(nm).file_size > _unpack_cap()


def _zip_member(body: bytes, cap: int | None):
    """First archive member (`_zip_pick`): (extension, bytes, name) or None - not an archive, no
    tabular member, member unreadable, or larger than UNPACK_CAP when unpacked.
    The name is needed by the .dbf reader: the attribute table encoding comes from a sibling .cpg (`_zip_cpg`).

    The optional cap limits text samples. Read whole workbooks because their ZIP directory
    is at the end of the file. All selected members remain subject to the unpack limit.
    """
    try:
        z = _ArchiveZip(body, limit=_unpack_cap())
    except Exception:                                                 # noqa: BLE001
        return None
    with z:
        got = _zip_pick(z)
        if got is None:
            return None
        ext, nm = got
        try:
            if _zip_oversize(z, nm):
                return None
            if ext in (".xlsx", ".xlsm", ".xls", ".px") or cap is None:
                data = z.read(nm)
            else:
                data = z.read_prefix(nm, cap)
        except ResourceLimitError:
            raise
        except Exception:                                             # noqa: BLE001
            return None
        return ext, data, nm


def _codec_name(text: str) -> str | None:
    """Encoding name from .cpg ("UTF-8", "ISO-8859-1", "1252", "windows-1251") -> a name known
    to codecs, or None."""
    s = (text or "").strip().strip("\x00").lower()
    if not s:
        return None
    if "utf" in s and "8" in s:
        return "utf-8"
    if s.isdigit():
        s = "cp" + s
    s = s.replace("windows-", "cp").replace("windows", "cp")
    try:
        codecs.lookup(s)
    except LookupError:
        return None
    return s


def _zip_cpg(body: bytes, nm: str) -> str | None:
    """.dbf encoding from a sibling .cpg with the same name (it sits next to it in a shapefile zip)."""
    stem = nm[:-4].lower()
    try:
        with _ArchiveZip(body, limit=_unpack_cap()) as z:
            for cand in z.namelist():
                if cand.lower().endswith(".cpg") and cand[:-4].lower() == stem:
                    return _codec_name(z.read_prefix(cand, 64).decode("ascii", "replace"))
    except ResourceLimitError:
        raise
    except Exception:                                                 # noqa: BLE001
        pass
    return None


def _zip_shape(body: bytes) -> str | None:
    """Zip type: "book" - xlsx/xlsm workbook (has xl/workbook.xml), "tabular" - has a member
    with an extension from _ZIP_ORDER, "other" - archive without a table (shapes, images, geodatabase:
    kind "binary"), None - kind "archive": the directory is unreadable (broken archive or truncated
    by the body cap - the zip directory is at the END of the file) or the tabular member exceeds
    UNPACK_CAP unpacked - it cannot be read without unpacking a bomb into memory."""
    try:
        with _ArchiveZip(body, limit=_unpack_cap()) as z:
            names = [nm.lower() for nm in z.namelist()]
            got = _zip_pick(z)
            if got is not None and got[0] == ".dbf":
                # A .dbf name alone is not a table: the header must validate (`_dbf_header`),
                # otherwise it is a shape without attributes, kind "other" -> binary.
                with z.open(got[1]) as f:
                    if _dbf_header(f.read(65536)) is None:
                        got = None
            oversize = got is not None and _zip_oversize(z, got[1])
    except Exception:                                                 # noqa: BLE001
        return None
    if "xl/workbook.xml" in names:
        return "book"
    if got is not None:
        return None if oversize else "tabular"
    return "other"


def _zip_records(body: bytes, n: int) -> list[dict] | None:
    """Not a workbook - a plain archive: first csv/tsv member (then workbook, then txt)."""
    m = _zip_member(body, 400_000 + 1)
    if m is None:
        return None
    ext, data, nm = m
    if ext in (".xlsx", ".xlsm"):
        return _records_from_rows(_xlsx_rows(data, n + WINDOW), n)
    if ext == ".xls":
        return xls_records(data, n)
    if ext == ".dbf":
        return dbf_records(data, n, encoding=_zip_cpg(body, nm))
    if ext == '.px':
        from ._recipe_runtime import px_records
        return px_records(data, n)
    return csv_records(data, n)


def _zip_count(body: bytes) -> int:
    """Rows of the first archive member, using the same extension order as `_zip_records`.
    Read whole but no more than UNPACK_CAP: a larger member gives zero rows (kind archive), as with gzip."""
    m = _zip_member(body, None)
    if m is None:
        return 0
    ext, data, nm = m
    if ext in (".xlsx", ".xlsm"):
        return _xlsx_count(data) or 0
    if ext == ".xls":
        return _xls_count(data)
    if ext == ".dbf":
        return _dbf_count(data, encoding=_zip_cpg(body, nm))
    if ext == '.px':
        from ._recipe_runtime import px_records
        return len(px_records(data) or [])
    return _csv_count(data)


def xlsx_records(body: bytes, n: int = 5) -> list[dict] | None:
    """xlsx workbook (densest sheet, header via header_block) or a zip with csv inside.
    Without openpyxl the workbook is unreadable (None), but a plain csv archive is still read."""
    rows = _xlsx_rows(body, n + WINDOW)
    if rows is None:
        return _zip_records(body, n)
    return _records_from_rows(rows, n)


def _xls_cell(cell, datemode: int):
    import xlrd
    t, v = cell.ctype, cell.value
    if t in (xlrd.XL_CELL_EMPTY, xlrd.XL_CELL_BLANK, xlrd.XL_CELL_ERROR):
        return None
    if t == xlrd.XL_CELL_DATE:
        try:
            return xlrd.xldate.xldate_as_datetime(v, datemode)
        except Exception:                                             # noqa: BLE001
            return v
    if t == xlrd.XL_CELL_BOOLEAN:
        return bool(v)
    if isinstance(v, float) and v.is_integer() and abs(v) < 1e15:
        return int(v)                      # xlrd returns all numbers as floats
    return v


def _xls_best(body: bytes):
    """(workbook, densest sheet | None) or None - not a workbook or no xlrd. Same rules
    as `_xlsx_best` (density over the first 60 rows, first sheet on a tie).
    The caller releases workbook resources."""
    try:
        import xlrd
    except ImportError:
        return None
    try:
        book = xlrd.open_workbook(file_contents=body)
    except Exception:                                                 # noqa: BLE001
        return None
    try:
        best, best_n = None, 0
        for sh in book.sheets():
            k = sum(1 for i in range(min(sh.nrows, WINDOW))
                    for c in sh.row_values(i) if not _is_empty(c))
            if k > best_n:
                best, best_n = sh, k
        return book, best
    except Exception:                                                 # noqa: BLE001
        _close(book, "release_resources")
        return None


def _xls_sheet_rows(book, sheet):
    return ([_xls_cell(c, book.datemode) for c in sheet.row(i)] for i in range(sheet.nrows))


def _xls_rows(body: bytes, limit: int) -> list[list] | None:
    """Read rows from the densest XLS sheet, or return None if no sheet is readable."""
    got = _xls_best(body)
    if got is None:
        return None
    book, sheet = got
    try:
        if sheet is None:
            return None
        return list(islice(_xls_sheet_rows(book, sheet), limit))
    except Exception:                                                 # noqa: BLE001
        return None
    finally:
        _close(book, "release_resources")


def _xls_count(body: bytes) -> int:
    got = _xls_best(body)
    if got is None:
        return 0
    book, sheet = got
    try:
        return 0 if sheet is None else _count_from_rows(_xls_sheet_rows(book, sheet))
    except Exception:                                                 # noqa: BLE001
        return 0
    finally:
        _close(book, "release_resources")


def xls_records(body: bytes, n: int = 5) -> list[dict] | None:
    """Legacy binary .xls workbook via xlrd: same rules - densest sheet, header_block.
    No xlrd -> None (xlrd 2.x reads only .xls)."""
    return _records_from_rows(_xls_rows(body, n + WINDOW), n)


# ── XML ──────────────────────────────────────────────────────────────────────
def _local(tag) -> str:
    tag = str(tag)
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _ns_uri(tag) -> str:
    tag = str(tag)
    return tag[1:].split("}", 1)[0] if tag.startswith("{") and "}" in tag else ""


def _el_text(el) -> str:
    """Element text, or if empty, the text of the first descendant that has text."""
    t = (el.text or "").strip()
    if t:
        return t
    for d in el.iter():
        if d is el:
            continue
        t = (d.text or "").strip()
        if t:
            return t
    return ""


def _el_value(el) -> str:
    """Record field value: text (`_el_text`), or without text the `value` attribute or
    the only attribute. This reads SDMX-ML generic (`<ObsDimension value="2020"/>
    <ObsValue value="1.5"/>`) and Atom-like `<link href="…"/>`: without it an SDMX record
    came out empty and a body with data was reported as "xml without records"."""
    t = _el_text(el)
    if t:
        return t
    a = el.attrib
    for k, v in a.items():
        if _local(k).lower() == "value" and str(v).strip():
            return str(v).strip()
    if len(a) == 1:
        return str(next(iter(a.values()))).strip()
    return ""


def _xml_root(body: bytes):
    """Root of the parsed XML or None. A UTF-16 body without BOM that expat rejected as
    bytes is re-parsed as text: the `<?xml … encoding=…?>` declaration is stripped so it
    does not conflict with the already decoded string."""
    import xml.etree.ElementTree as ET
    try:
        return ET.fromstring(body)
    except Exception:                                                 # noqa: BLE001
        pass
    enc16 = _utf16_guess(body)
    if not enc16:
        return None
    try:
        return ET.fromstring(_XML_DECL_RE.sub("", body.decode(enc16, "replace"), count=1))
    except Exception:                                                 # noqa: BLE001
        return None


def _root_meta(root) -> bool:
    """Metadata root from the parsed tree - rules 1-3 of `is_xml_meta` (root,
    namespace by URI since ElementTree drops the prefix, kml without Placemark)."""
    return is_xml_meta(root) is not None


def _is_ssml(root) -> bool:
    return _local(root.tag) == "Workbook" and str(root.tag).startswith(_SSML)


def _ssml_rows(ws):
    """Rows of an Excel 2003 XML sheet: Table/Row/Cell/Data. ss:Index on Cell skips columns -
    ignoring it shifted values left relative to the header."""
    for row in ws.iter(f"{_SSML}Row"):
        cells: list = []
        for cell in row.findall(f"{_SSML}Cell"):
            idx = cell.get(f"{_SSML}Index")
            if idx and idx.isdigit():
                while len(cells) < int(idx) - 1:
                    cells.append(None)
            d = cell.find(f"{_SSML}Data")
            cells.append("".join(d.itertext()) if d is not None else None)
        yield cells


def _ssml_best(root):
    """Densest sheet of a SpreadsheetML workbook (over the first 60 rows) or None."""
    best, best_n = None, 0
    for ws in root.iter(f"{_SSML}Worksheet"):
        k = sum(1 for r in islice(_ssml_rows(ws), WINDOW) for c in r if not _is_empty(c))
        if k > best_n:
            best, best_n = ws, k
    return best


def _spreadsheetml(root, n: int) -> list[dict] | None:
    """Excel 2003 XML: Worksheet/Table/Row/Cell/Data -> sheet rows -> header_block."""
    ws = _ssml_best(root)
    if ws is None:
        return None
    return _records_from_rows(list(islice(_ssml_rows(ws), n + WINDOW)), n)


# Attribute names that make a leaf `<X id="…" value="…"/>` a record FIELD, not a record:
# a name-value pair spread over elements (SDMX-ML generic series keys
# `<generic:Value id="FREQ" value="A"/>`, `<attribute name="…" value="…"/>`). This is exactly
# the case `_el_value` reads via the value attribute.
_KV_NAMES = frozenset({"id", "name", "key", "concept", "code", "field", "attr",
                       "attribute", "property", "param", "parameter"})


def _kv_leaf(el) -> bool:
    """`<X id|name|key… value="…"/>` with no child elements — a name/value pair."""
    if len(el) or len(el.attrib) != 2:
        return False
    names = {_local(k).lower() for k in el.attrib}
    return "value" in names and bool(names & _KV_NAMES)


def _record_tags(root) -> list:
    """Candidate record tags, best first; empty means no candidates.

    A candidate is a tag that occurs >= 2 times and whose elements have >= 2 child
    elements or >= 2 attributes. Order: non-auxiliary first, then most frequent, on a
    tie the shallowest, then first in document order (in
    <record><address>…</address></record> both tags occur equally; the record is the outer one).

    Nested properties and name/value fields rank below record elements. For example,
    a bounding box describes its enclosing feature, and a series key describes its series.
    Keep these candidates as fallbacks when the preferred elements yield no records.
    Field ranks below property: in SDMX with one observation per series, Obs and SeriesKey are both
    "properties" of Series, and the fallback after an empty Series record must be Obs, not the key bundle.
    """
    count: Counter = Counter()
    maps: Counter = Counter()               # elements whose children are all name/value pairs
    depth_of: dict = {}
    order: dict = {}
    stack = [(root, 0)]
    while stack:
        el, d = stack.pop()
        kids = list(el)
        for ch in reversed(kids):
            stack.append((ch, d + 1))
        if el is root:
            continue
        if len(kids) >= 2 or len(el.attrib) >= 2:
            count[el.tag] += 1
            if kids and all(_kv_leaf(ch) for ch in kids):
                maps[el.tag] += 1
            if el.tag not in order:
                order[el.tag] = len(order)
                depth_of[el.tag] = d
    cands = {t for t, c in count.items() if c >= 2}
    if not cands:
        return []
    # Second pass: how many elements of a candidate are the only one of their tag inside
    # the nearest candidate ancestor (property), and how many are name/value pairs inside
    # a candidate (field). The frame stack holds only candidate ancestors, memory O(depth).
    single: Counter = Counter()
    kv_in: Counter = Counter()
    frames: list = []                       # [(tag, Counter of candidate children by tag)]
    walk = [(root, False)]
    while walk:
        el, leaving = walk.pop()
        if leaving:
            _, seen = frames.pop()
            for x, k in seen.items():
                if k == 1:
                    single[x] += 1
            continue
        is_cand = el is not root and el.tag in cands
        if is_cand and frames:
            frames[-1][1][el.tag] += 1
            if _kv_leaf(el):
                kv_in[el.tag] += 1
        if is_cand:
            frames.append((el.tag, Counter()))
            walk.append((el, True))
        for ch in reversed(list(el)):
            walk.append((ch, False))

    def level(t) -> int:
        """0 — record, 1 — property of another record, 2 — field or bundle of fields."""
        if kv_in[t] * 2 >= count[t] or maps[t] * 2 >= count[t]:
            return 2
        return 1 if single[t] * 2 >= count[t] else 0

    return sorted(cands, key=lambda t: (level(t), -count[t], depth_of[t], order[t]))


def _record_tag(root):
    """Best record tag from `_record_tags`, or None — for body diagnostics."""
    tags = _record_tags(root)
    return tags[0] if tags else None


def _xml_iter_records(root):
    """Stream XML records: (b) "record element" — see _record_tag: record = {child local
    name: value (`_el_value`)} + attributes, namespaces stripped; (c) nothing
    matched → the most frequent child tag of the root, {tag: text}.

    The old reader took the most frequent tag among root children and returned
    {"value": "107"} — the field names were in record attributes and sibling tags.

    Candidates are tried in `_record_tags` order; the first that yields at least one non-empty
    record wins. So an auxiliary element (property or field of another record) stays a fallback
    instead of being dropped: in SDMX with one observation per series, Obs is a "property" of Series, but
    the Series record is empty (values are in grandchildren's attributes), so Obs become the records."""
    for tag in _record_tags(root):
        got = False
        for el in root.iter(tag):
            rec: dict = {}
            for ch in el:
                key = _local(ch.tag)
                val = _el_value(ch)
                if val and key not in rec:
                    rec[key] = val
            for k, v in el.attrib.items():
                key = _local(k)
                if key not in rec and str(v).strip():
                    rec[key] = str(v).strip()
            if rec:
                got = True
                yield rec
        if got:
            return
    c = Counter(ch.tag for ch in root)
    if not c:
        return
    tag = c.most_common(1)[0][0]
    for ch in root:
        if ch.tag == tag and (ch.text or "").strip():
            yield {_local(tag): ch.text.strip()}


def _url_heavy(recs: list[dict]) -> bool:
    """≥ 50% of record values are URLs: a feed of file links (dataset resource list, Atom
    without a feed root), not data. Rule 4 of `is_xml_meta`; computed over the first URL_SAMPLE
    records."""
    return _url_share(list(recs)[:URL_SAMPLE]) >= 0.5


def xml_records(body: bytes, n: int = 5) -> list[dict] | None:
    """(a) SpreadsheetML → sheet rows → header_block; (b)/(c) — see `_xml_iter_records`.
    Parse error → None. This reader is "raw": it does not filter out a metadata root or
    link-only records — `records`/`count_rows` do that (kind xml-meta), and body
    diagnostics compute the URL share from these records."""
    root = _xml_root(body)
    if root is None:
        return None
    if _is_ssml(root):
        return _spreadsheetml(root, n)
    return list(islice(_xml_iter_records(root), n)) or None


def _xml_count(body: bytes) -> int:
    """XML record count on the full body, by the same rules as `records`: metadata root → 0;
    SpreadsheetML → data rows of the densest sheet; link-only records → 0; otherwise the number
    of non-empty records by `_record_tag` (or root children as a fallback)."""
    root = _xml_root(body)
    if root is None or _root_meta(root):
        return 0
    if _is_ssml(root):
        ws = _ssml_best(root)
        return 0 if ws is None else _count_from_rows(_ssml_rows(ws))
    sample = list(islice(_xml_iter_records(root), URL_SAMPLE))
    if not sample or _url_heavy(sample):
        return 0
    return sum(1 for _ in _xml_iter_records(root))


# ── JSON ─────────────────────────────────────────────────────────────────────
# ── dBase (.dbf): shapefile attribute table ─────────────────────────────────
# About half of reader failures were zips containing
# .shp/.dbf/.prj (data.gov.lv, data.gov.au, data.gov.ie, data.overheid.nl). Geometry is
# not needed, and .dbf is a plain table with field names: fixed-width format, a 32-byte
# header + 32 bytes per field + 0x0D. Standard library only, like the whole module.
_DBF_VERSIONS = frozenset({0x02, 0x03, 0x04, 0x05, 0x07, 0x30, 0x31, 0x32, 0x43, 0x63,
                           0x83, 0x8b, 0x8e, 0xcb, 0xe5, 0xf5, 0xfb})
# Language driver id (byte 29) → encoding; unknown/0 → utf-8, then cp1252.
_DBF_LDID = {0x01: "cp437", 0x02: "cp850", 0x03: "cp1252", 0x57: "cp1252", 0x64: "cp852",
             0x65: "cp866", 0x66: "cp865", 0x67: "cp861", 0x6a: "cp737", 0x6b: "cp857",
             0x78: "cp950", 0x79: "cp949", 0x7a: "cp936", 0x7b: "cp932", 0x7c: "cp874",
             0x7d: "cp1255", 0x7e: "cp1256", 0x86: "cp737", 0x87: "cp852", 0x88: "cp857",
             0xc8: "cp1250", 0xc9: "cp1251", 0xca: "cp1254", 0xcb: "cp1253", 0xcc: "cp1257"}
_DBF_MEMO = frozenset("MBGPQW")   # references into .dbt/.fpt — not available here


def _dbf_header(body: bytes):
    """(fields [(name, type, length, decimals)], header length, record length, record count,
    encoding) or None — not dBase. The check "1 + sum of field lengths == record length"
    is the real magic check: a first byte of 0x03 alone proves nothing."""
    if len(body) < 65 or body[0] not in _DBF_VERSIONS:
        return None
    nrec = int.from_bytes(body[4:8], "little")
    hlen = int.from_bytes(body[8:10], "little")
    rlen = int.from_bytes(body[10:12], "little")
    if hlen < 65 or rlen < 2 or hlen > len(body):
        return None
    fields = []
    off = 32
    while off + 32 <= hlen and body[off] != 0x0D:
        d = body[off:off + 32]
        name = d[:11].split(b"\x00", 1)[0]
        ftype = chr(d[11])
        if not name or not name.isascii() or not ftype.isalpha() or not ftype.isupper():
            return None
        fields.append((name.decode("ascii"), ftype, d[16], d[17]))
        off += 32
    if not fields or off >= len(body) or body[off] != 0x0D:
        return None
    if 1 + sum(f[2] for f in fields) != rlen:
        return None
    return fields, hlen, rlen, nrec, _DBF_LDID.get(body[29])


def _dbf_text(raw: bytes, enc: str | None) -> str:
    raw = raw.rstrip(b"\x00")
    if enc:
        return raw.decode(enc, "replace")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("cp1252", "replace")


def _dbf_value(raw: bytes, ftype: str, dec: int, enc: str | None):
    if ftype in _DBF_MEMO:
        return None
    if ftype == "I":
        return int.from_bytes(raw[:4], "little", signed=True)
    if ftype == "L":
        c = raw[:1]
        return True if c in b"TtYy" else False if c in b"FfNn" else None
    s = _dbf_text(raw, enc).strip()
    if not s:
        return None
    if ftype in ("N", "F"):
        try:
            return int(s) if "." not in s and not dec else float(s)
        except ValueError:
            return s
    if ftype == "D" and len(s) == 8 and s.isdigit():
        return f"{s[:4]}-{s[4:6]}-{s[6:]}"
    return s


def _dbf_iter(body: bytes, encoding: str | None = None):
    """(field names, row iterator) or None — not dBase. Deleted records (flag '*')
    are skipped; a truncated body yields rows up to the cut."""
    h = _dbf_header(body)
    if h is None:
        return None
    fields, hlen, rlen, nrec, enc = h
    enc = encoding or enc

    def rows():
        off = hlen
        for _ in range(nrec):
            rec = body[off:off + rlen]
            if len(rec) < rlen:
                break
            off += rlen
            if rec[:1] == b"*":
                continue
            pos, vals = 1, []
            for _name, ftype, flen, dec in fields:
                vals.append(_dbf_value(rec[pos:pos + flen], ftype, dec, enc))
                pos += flen
            yield vals
    return [f[0] for f in fields], rows()


def dbf_records(body: bytes, n: int = 5, encoding: str | None = None) -> list[dict] | None:
    """First n records of a dBase table; None — not dBase; placeholder [{"columns": …}] — fields
    exist but no records (same as workbooks)."""
    got = _dbf_iter(body, encoding)
    if got is None:
        return None
    names, rows = got
    return rows_to_records(names, rows, n) or [{"columns": names}]


def _dbf_count(body: bytes, encoding: str | None = None) -> int:
    """Records that are neither deleted nor empty (spaces/NUL in all fields) — exactly those
    from which `rows_to_records` would build a non-empty record."""
    h = _dbf_header(body)
    if h is None:
        return 0
    _fields, hlen, rlen, nrec, _enc = h
    n, off = 0, hlen
    for _ in range(nrec):
        rec = body[off:off + rlen]
        if len(rec) < rlen:
            break
        off += rlen
        if rec[:1] == b"*" or not rec[1:].strip(b" \x00"):
            continue
        n += 1
    return n


# ── ODS: OpenDocument workbook ───────────────────────────────────────────────
# .ods files (e.g. dados.prefeitura.sp.gov.br) were seen as a zip without csv → binary.
# content.xml: table:table → table:table-row → table:table-cell; value — office:value-type
# + office:value (number/date/boolean) or the text of text:p paragraphs. Repeats
# number-columns-repeated / number-rows-repeated are expanded up to ODS_REPEAT_CAP: trailing
# empty cells up to 16,384 columns and empty rows up to 1,048,576 are filler, not data.
_ODS_MIME = b"application/vnd.oasis.opendocument.spreadsheet"
_NS_TABLE = "urn:oasis:names:tc:opendocument:xmlns:table:1.0"
_NS_OFFICE = "urn:oasis:names:tc:opendocument:xmlns:office:1.0"
_NS_TEXT = "urn:oasis:names:tc:opendocument:xmlns:text:1.0"
ODS_REPEAT_CAP = 100


def _ods_content(body: bytes) -> bytes | None:
    """content.xml of an ODS workbook, or None — not ODS (no content.xml, wrong mimetype) or
    content.xml larger than UNPACK_CAP."""
    try:
        with _ArchiveZip(body, limit=_unpack_cap()) as z:
            names = set(z.namelist())
            if "content.xml" not in names:
                return None
            if "mimetype" in names:
                ok = _ODS_MIME in z.read_prefix("mimetype", 128)
            else:
                ok = "META-INF/manifest.xml" in names and _ODS_MIME in z.read("META-INF/manifest.xml", max_bytes=65536)
            if not ok:
                return None
            return z.read("content.xml")
    except ResourceLimitError:
        raise
    except Exception:                                                 # noqa: BLE001
        return None


def _int_attr(v, default: int) -> int:
    try:
        return max(int(v), 0) if v is not None else default
    except (TypeError, ValueError):
        return default


def _ods_cell(cell):
    vt = cell.get(f"{{{_NS_OFFICE}}}value-type")
    if vt in ("float", "percentage", "currency"):
        v = cell.get(f"{{{_NS_OFFICE}}}value")
        try:
            f = float(v)
            return int(f) if f.is_integer() and "." not in (v or "") else f
        except (TypeError, ValueError):
            pass
    elif vt == "date":
        return cell.get(f"{{{_NS_OFFICE}}}date-value")
    elif vt == "time":
        return cell.get(f"{{{_NS_OFFICE}}}time-value")
    elif vt == "boolean":
        return cell.get(f"{{{_NS_OFFICE}}}boolean-value") == "true"
    text = "\n".join(t for t in ("".join(p.itertext()) for p in cell.iter(f"{{{_NS_TEXT}}}p")) if t)
    text = text.strip()
    return text or None


def _ods_rows_of(table):
    """ODS table rows as value lists: repeats expanded up to ODS_REPEAT_CAP, trailing
    empty cells trimmed, empty rows skipped."""
    row_rep = f"{{{_NS_TABLE}}}number-rows-repeated"
    col_rep = f"{{{_NS_TABLE}}}number-columns-repeated"
    cell_tags = (f"{{{_NS_TABLE}}}table-cell", f"{{{_NS_TABLE}}}covered-table-cell")
    for row in table.iter(f"{{{_NS_TABLE}}}table-row"):
        vals: list = []
        for cell in row:
            if cell.tag not in cell_tags:
                continue
            v = _ods_cell(cell)
            vals.extend([v] * min(_int_attr(cell.get(col_rep), 1), ODS_REPEAT_CAP))
        while vals and _is_empty(vals[-1]):
            vals.pop()
        if not vals:
            continue
        for _ in range(min(_int_attr(row.get(row_rep), 1), ODS_REPEAT_CAP)):
            yield list(vals)


def _ods_best(content: bytes):
    """Densest table in the workbook (non-empty cells in the first WINDOW rows), as for xlsx;
    None — content.xml did not parse or has no tables."""
    root = _xml_root(content)
    if root is None:
        return None
    best, best_n = None, -1
    for t in root.iter(f"{{{_NS_TABLE}}}table"):
        k = sum(1 for r in islice(_ods_rows_of(t), WINDOW) for c in r if not _is_empty(c))
        if k > best_n:
            best, best_n = t, k
    return best


def _ods_rows(body: bytes, limit: int) -> list[list] | None:
    """First limit rows of the densest table; None — not ODS; [] — no tables."""
    content = _ods_content(body)
    if content is None:
        return None
    t = _ods_best(content)
    return [] if t is None else list(islice(_ods_rows_of(t), limit))


def _ods_count(body: bytes) -> int | None:
    content = _ods_content(body)
    if content is None:
        return None
    t = _ods_best(content)
    return 0 if t is None else _count_from_rows(_ods_rows_of(t))


def ods_records(body: bytes, n: int = 5) -> list[dict] | None:
    rows = _ods_rows(body, n + WINDOW)
    return None if rows is None else _records_from_rows(rows, n)


# ── JSON truncated by the body size cap ──────────────────────────────────────
# Read complete list elements or JSONL lines up to the byte limit. The resulting
# count is a lower bound when the response is truncated.
_JSON_LIST_KEY_RE = re.compile(r'"(' + "|".join(LIST_KEYS) + r')"\s*:\s*\[')


def _json_partial(text: str, response_path: str | None) -> list | None:
    """Records of truncated (or line-delimited) JSON; None — no list start found."""
    s = text.lstrip("﻿ \t\r\n")
    if not s:
        return None
    if s[0] == "{":
        nl = s.find("\n")
        if nl > 0:
            try:
                jsonl = isinstance(json.loads(s[:nl]), dict)
            except ValueError:
                jsonl = False
            if jsonl:
                out = []
                for ln in s.split("\n"):
                    ln = ln.strip().rstrip(",")
                    if not ln:
                        continue
                    try:
                        out.append(json.loads(ln))
                    except ValueError:
                        break
                return out
    head = s[:200_000]
    key = (response_path or "").split(".")[-1]
    if key:
        m = re.search(r'"' + re.escape(key) + r'"\s*:\s*\[', head)
        start = m.end() - 1 if m else None
    elif s[0] == "[":
        start = 0
    else:
        m = _JSON_LIST_KEY_RE.search(head)
        start = m.end() - 1 if m else None
    if start is None:
        return None
    dec = json.JSONDecoder()
    out, i, n = [], start + 1, len(s)
    while i < n:
        while i < n and s[i] in " \t\r\n,":
            i += 1
        if i >= n or s[i] == "]":
            break
        try:
            obj, i = dec.raw_decode(s, i)
        except ValueError:
            break
        out.append(obj)
    return out


def _strip_bom(body: bytes) -> bytes:
    # json.loads on bytes with a BOM fails ("Unexpected UTF-8 BOM") even though the body is valid
    return body[3:] if body[:3] == b"\xef\xbb\xbf" else body


def _first_list(node: dict, depth: int = 2):
    """First record list under a known key; if none found, return the node unchanged."""
    for k in LIST_KEYS:
        v = node.get(k)
        if isinstance(v, list):
            return v
    if depth > 0:
        for k in LIST_KEYS:
            v = node.get(k)
            if isinstance(v, dict):
                down = _first_list(v, depth - 1)
                if isinstance(down, list):
                    return down
    return node


def _descend(node, response_path: str | None):
    for part in (response_path or "").split("."):
        if part and isinstance(node, dict):
            node = node.get(part)
    if isinstance(node, dict):
        node = _first_list(node)
    return node


def _resource_list(node: list, response_path: str | None = None) -> bool:
    """Dataset resource list: the first element is an object with url and format keys
    (CKAN `result.resources`). File links, not data: several recipes were
    built from one such dataset page."""
    from ._recipe_runtime import is_resource_list
    return is_resource_list(node, str(response_path or '').rsplit('.', 1)[-1] == 'resources')


def json_records(body: bytes, response_path: str | None):
    """json.loads; descend response_path by dots; dict → descend by LIST_KEYS
    (first list found); return the list, otherwise the node; broken json → None."""
    raw = _strip_bom(body) if isinstance(body, (bytes, bytearray)) else body
    try:
        j = json.loads(raw)
    except Exception:                                                 # noqa: BLE001
        text = raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else raw
        return _json_partial(text, response_path)
    return _descend(j, response_path)


# ── common entry point ───────────────────────────────────────────────────────
def records(body: bytes, content_type: str = "", response_path: str | None = None,
            n: int = 5) -> tuple[str, list[dict] | None, str]:
    """(kind, records or None, text tail). Kinds from NOT_DATA and "empty" → no records.

    A gzip/bz2 wrapper is removed (`unwrap`), the content is sniffed again, and the kind is the
    content's kind; not removable → "archive". json: list → first n elements as is;
    dataset resource list → "json-resources" + list json; broken → "json-broken" +
    first 2000 chars; not a list → "json-not-list" + node json. xml: metadata root →
    "xml-meta"; records where ≥ 50% of values are URLs → also "xml-meta" (share over the first
    URL_SAMPLE records, independent of n). xlsx/xls/csv — via their own functions; csv with no
    rows → "text" + body head. A zip with neither a workbook nor a csv (`_zip_shape`) →
    "binary"; a zip with an unreadable directory (broken, truncated by the cap) → "archive"."""
    kind, body = _unwrapped(body, content_type)
    if kind == "empty":
        return "empty", None, ""
    if kind in NOT_DATA:
        return kind, None, ""
    if kind == "px":
        from ._recipe_runtime import px_records
        return "px", px_records(body, n), ""
    if kind == "json":
        try:
            j = json.loads(_strip_bom(body))
        except Exception:                                             # noqa: BLE001
            # List truncated by the cap, or JSONL — records up to the cut (`_json_partial`).
            part = _json_partial(_strip_bom(body).decode("utf-8", "replace"), response_path)
            if not part:
                return "json-broken", None, body[:2000].decode("utf-8", "replace")
            j, response_path = {"records": part}, "records"
        node = _descend(j, response_path)
        if isinstance(node, list):
            if _resource_list(node, response_path):
                return "json-resources", None, json.dumps(node, ensure_ascii=False,
                                                        default=str)[:2000]
            return "json", node[:n], ""
        return "json-not-list", None, json.dumps(node, ensure_ascii=False, default=str)[:2000]
    if kind == "xlsx":
        rows = _xlsx_rows(body, n + WINDOW)
        if rows is not None:
            return "xlsx", _records_from_rows(rows, n), ""
        orows = _ods_rows(body, n + WINDOW)          # ODS without the mimetype member first
        if orows is not None:
            return "ods", _records_from_rows(orows, n), ""
        m = _zip_member(body, 400_000 + 1)
        if m is not None and m[0] == ".dbf":
            # Read the full bounded DBF member so its row count includes the entire table.
            m = _zip_member(body, None)
            recs = dbf_records(m[1], n, encoding=_zip_cpg(body, m[2]))
            if recs is not None:
                return "dbf", recs, ""
            # a .dbf member exists but is not dBase — a shape without a table, becomes binary below
        recs = _zip_records(body, n)
        if recs is None:
            shape = _zip_shape(body)
            if shape is None:
                return "archive", None, ""
            if shape == "other":
                return "binary", None, ""
        return "xlsx", recs, ""
    if kind == "ods":
        return "ods", ods_records(body, n), ""
    if kind == "dbf":
        return "dbf", dbf_records(body, n), ""
    if kind == "xls":
        return "xls", xls_records(body, n), ""
    if kind == "xml":
        root = _xml_root(body)
        if root is None:
            return "xml", None, ""
        if _root_meta(root):
            return "xml-meta", None, ""
        if _is_ssml(root):
            return "xml", _spreadsheetml(root, n), ""
        gen = _xml_iter_records(root)
        sample = list(islice(gen, URL_SAMPLE))
        if not sample:
            return "xml", None, ""
        if _url_heavy(sample):
            return "xml-meta", None, ""
        recs = sample[:n] if n <= URL_SAMPLE else sample + list(islice(gen, n - URL_SAMPLE))
        return "xml", recs, ""
    recs = csv_records(body, n)
    if recs is None:
        return "text", None, body[:1500].decode("utf-8", "replace")
    return "csv", recs, ""


def count_rows(body: bytes, content_type: str = "", response_path: str | None = None) -> int:
    """Number of DATA rows on the full body — with the same parsing as the `records` sample.

    Invariant (parity test): count_rows(body) > 0 ⇔ records(body)[1] is non-empty. One
    deliberate exception: the placeholder [{"columns": […]}] for a "header but no records" body —
    records are non-empty, yet the row count is zero (it is a schema, not data).

    By kind: kind is `sniff_kind` after unwrapping; NOT_DATA/empty → 0; json — list length
    after descending (resource list {"url","format"} → 0); csv — data rows by
    `header_block` on the full body (streaming csv.reader, without the 400 KB cap, but at most
    CSV_ROW_LIMIT = 2,000,000 rows); xlsx/xls — densest sheet, data rows after the
    header block; zip — first member in the same order as the reader; xml — number of record
    elements by `_record_tag`."""
    kind, body = _unwrapped(body, content_type)
    if kind == "empty" or kind in NOT_DATA:
        return 0
    if kind == "px":
        from ._recipe_runtime import px_records
        return len(px_records(body) or [])
    if kind == "json":
        node = json_records(body, response_path)
        if not isinstance(node, list) or _resource_list(node, response_path):
            return 0
        return len(node)
    if kind == "xlsx":
        n = _xlsx_count(body)
        if n is not None:
            return n
        o = _ods_count(body)
        return _zip_count(body) if o is None else o
    if kind == "ods":
        return _ods_count(body) or 0
    if kind == "dbf":
        return _dbf_count(body)
    if kind == "xls":
        return _xls_count(body)
    if kind == "xml":
        return _xml_count(body)
    return _csv_count(body)
