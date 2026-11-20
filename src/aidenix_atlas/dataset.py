"""Download datasets into a local DuckDB table and query them with SQL.

The client caches each table on disk and checks the publisher for updates after
the refresh interval. To query a workbook from Python:

    from aidenix_atlas import dataset
    db = dataset.open('https://www.dol.gov/media/LCA_Disclosure_Data_FY2026_Q3.xlsx',
                      fetch='impersonate', refresh_days=30)
    rows = db.query('SELECT EMPLOYER_NAME, count(*) n FROM data '
                    'WHERE RECEIVED_DATE BETWEEN ? AND ? GROUP BY 1', ('2026-04-01', '2026-04-30'))

Formats: csv/tsv/txt, parquet and json/ndjson (DuckDB), xlsx (openpyxl), xls (xlrd),
XML (the tabular reader); zip and tar (first member with a known table extension,
or `member` as a regular expression on the file name), gzip/bz2/xz around any of them. JSON that is
an object: `json_path` (dotted) points to the list of records, otherwise the longest list is taken.
The table is called `data`; its columns are the header row as written by the publisher.

Cache: `ATLAS_DATASET_CACHE` (default ~/.cache/aidenix-atlas/datasets), limited to
`ATLAS_DATASET_CACHE_GB` (default 5): the least recently used tables go first.

Libraries come with the package (duckdb, openpyxl, xlrd, curl_cffi). Nothing is installed at run
time: when one is missing, `MissingCapability` carries the install command for the agent, and
`missing(capabilities)` lists them before a run.

A broken download (a proxy or the network drops the connection mid-file) resumes from the
received byte with an HTTP Range request, up to 6 attempts, when the server accepts ranges.

Hooks: `before_fetch` receives the method and URL and may refuse a request.
`on_fetch` receives the method, URL, status, response bytes and final URL.
"""
from __future__ import annotations

import bz2
import csv
import datetime as _dt
import decimal
import gzip
import hashlib
import io
import json
import lzma
import os
import re
import shutil
import tarfile
import time
import zipfile
from pathlib import Path
from urllib.parse import urlencode, urlsplit

DEFAULT_MAX_MB = 256.0
DEFAULT_TIMEOUT_S = 300.0
UA = 'Aidenix-Atlas/1.0 (+https://aidenix.com)'
before_fetch: list = []
on_fetch: list = []


def cache_dir() -> Path:
    root = os.environ.get('ATLAS_DATASET_CACHE') or os.path.join(
        os.path.expanduser('~'), '.cache', 'aidenix-atlas', 'datasets')
    path = Path(root)
    path.mkdir(parents=True, exist_ok=True)
    return path


def _key(url: str, sheet, member, header_row, json_path=None) -> str:
    ident = json.dumps([url, sheet, member, header_row, json_path], sort_keys=True)
    return hashlib.sha256(ident.encode()).hexdigest()[:24]


def _notify(method, url, status, body, final_url):
    for hook in list(on_fetch):
        hook(method, url, status, body, final_url)


# What a capability needs on the client. The mapping lives in the package, never in a recipe:
# a recipe names a capability, and a package name from the server is never installed.
CAPABILITIES = {
    'duckdb': ('duckdb', 'duckdb'),
    'xlsx': ('openpyxl', 'openpyxl'),
    'xls': ('xlrd', 'xlrd'),
    'impersonate': ('curl_cffi.requests', 'curl_cffi'),
}


class MissingCapability(RuntimeError):
    """The machine lacks what a step needs. `install` is the command for the agent (or the person)."""

    def __init__(self, capability: str, package: str):
        self.capability, self.package = capability, package
        self.install = 'pip install %s' % package
        super().__init__('missing capability %s: run `%s`' % (capability, self.install))


def need(capability: str):
    """Import what `capability` needs, or raise MissingCapability with the install command.
    The runtime never installs anything itself: the agent runs the command."""
    import importlib
    module, package = CAPABILITIES[capability]
    try:
        return importlib.import_module(module)
    except ImportError:
        raise MissingCapability(capability, package) from None


def missing(capabilities) -> list[dict]:
    """Preflight for an agent: [{capability, package, install}] for what this machine lacks."""
    import importlib.util
    out = []
    for cap in capabilities or []:
        if cap not in CAPABILITIES:
            continue
        module, package = CAPABILITIES[cap]
        if importlib.util.find_spec(module.split('.')[0]) is None:
            out.append({'capability': cap, 'package': package, 'install': 'pip install %s' % package})
    return out


class _Broken(Exception):
    """The connection dropped after `got` bytes."""


def _request(method: str, url: str, fetch: str, max_bytes: int, timeout: float, headers: dict | None = None):
    """(status, headers, body, final_url). A dropped GET resumes with Range from the received byte;
    a server that ignores Range sends the whole file again and the buffer restarts."""
    buf, first, stalls = bytearray(), None, 0
    while True:
        hdrs = dict(headers or {})
        if buf:
            hdrs['Range'] = 'bytes=%d-' % len(buf)
        before = len(buf)
        try:
            status, rh, final_url = _once(method, url, fetch, max_bytes, timeout, hdrs, buf, seen := [])
        except _Broken:
            if first is None and seen:
                first = seen[0]
            # a slow link drops every minute or so: keep resuming while bytes arrive, stop after 3 empty tries
            stalls = 0 if len(buf) > before else stalls + 1
            if method != 'GET' or stalls >= 3:
                raise RuntimeError('dataset download broken after %d bytes: %s' % (len(buf), url)) from None
            continue
        if first is None:
            first = (rh, final_url)
        if status == 206:
            return 200, first[0], bytes(buf), first[1]
        return status, rh, bytes(buf) if method == 'GET' else None, final_url


def _once(method, url, fetch, max_bytes, timeout, hdrs, buf, seen=None):
    ranged = 'Range' in hdrs
    if fetch == 'impersonate':
        _cr = need('impersonate')
        try:
            r = _cr.request(method, url, impersonate='chrome', timeout=timeout, headers=hdrs,
                            allow_redirects=True, stream=method == 'GET')
        except Exception as exc:  # curl errors carry no common base we can import without curl_cffi
            if buf:
                raise _Broken() from exc
            raise
        try:
            rh = {k.lower(): v for k, v in r.headers.items()}
            if seen is not None and r.status_code == 200:
                seen.append((rh, str(r.url)))
            if method == 'GET':
                if ranged and r.status_code != 206:
                    del buf[:]
                for chunk in r.iter_content(1 << 16):
                    buf.extend(chunk)
                    if len(buf) > max_bytes:
                        raise ValueError('dataset larger than %d MB' % (max_bytes >> 20))
        except ValueError:
            raise
        except Exception as exc:
            if buf:
                raise _Broken() from exc
            raise
        finally:
            r.close()
        return r.status_code, rh, str(r.url)
    if fetch != 'plain':
        raise ValueError('fetch must be plain or impersonate')
    import httpx
    with httpx.Client(timeout=timeout, follow_redirects=True, headers={'User-Agent': UA, **hdrs}) as client:
        try:
            with client.stream(method, url) as r:
                rh = {k.lower(): v for k, v in r.headers.items()}
                if seen is not None and r.status_code == 200:
                    seen.append((rh, str(r.url)))
                if method == 'GET':
                    if ranged and r.status_code != 206:
                        del buf[:]
                    for chunk in r.iter_bytes(1 << 16):
                        buf.extend(chunk)
                        if len(buf) > max_bytes:
                            raise ValueError('dataset larger than %d MB' % (max_bytes >> 20))
                return r.status_code, rh, str(r.url)
        except httpx.TransportError as exc:
            if buf:
                raise _Broken() from exc
            raise


def _call(method, url, fetch, max_bytes, timeout):
    watched = fetch == 'impersonate'
    if watched:
        for hook in list(before_fetch):
            hook(method, url)
    status, headers, body, final_url = _request(method, url, fetch, max_bytes, timeout)
    if watched:
        _notify(method, url, status, body, final_url)
    if not 200 <= status < 300:
        raise RuntimeError('dataset %s %s: HTTP %s' % (method, url, status))
    return headers, body


# ── laying the file out into a local DuckDB table ────────────────────────────

def _json_safe(v):
    if isinstance(v, (_dt.datetime, _dt.date, _dt.time)):
        return v.isoformat()
    if isinstance(v, decimal.Decimal):
        return float(v)
    if isinstance(v, (bytes, bytearray)):
        return v.decode('utf-8', 'replace')
    return v


def _kind(name: str, body: bytes) -> str:
    """Format by extension, then by content."""
    for ext, kind in (('.csv', 'csv'), ('.tsv', 'csv'), ('.txt', 'csv'), ('.xlsx', 'xlsx'), ('.xlsm', 'xlsx'),
                      ('.xls', 'xls'), ('.parquet', 'parquet'), ('.ndjson', 'json'), ('.jsonl', 'json'),
                      ('.json', 'json'), ('.xml', 'xml')):
        if name.endswith(ext):
            return kind
    head = body[:512].lstrip()
    if body[:4] == b'PAR1':
        return 'parquet'
    if body[:4] == b'PK\x03\x04':
        return 'xlsx'
    if body[:8] == b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1':
        return 'xls'
    if head[:1] in (b'[', b'{'):
        return 'json'
    if head[:1] == b'<':
        return 'xml'
    return 'csv'


def _unwrap(body: bytes, url: str, member: str | None) -> tuple[bytes, str]:
    """(file bytes, format) after removing gzip/bz2/xz, zip and tar wrappers."""
    name = urlsplit(url).path.lower()
    for magic, mod, ext in ((b'\x1f\x8b', gzip, '.gz'), (b'BZh', bz2, '.bz2'), (b'\xfd7zXZ', lzma, '.xz')):
        if body.startswith(magic):
            body = mod.decompress(body)
            name = name[:-len(ext)] if name.endswith(ext) else name
            if name.endswith('.tgz'):
                name = name[:-4] + '.tar'
    known = ('.csv', '.tsv', '.txt', '.xlsx', '.xlsm', '.xls', '.parquet', '.json', '.jsonl', '.ndjson', '.xml')

    def pick(names):
        if member:
            hit = [n for n in names if re.fullmatch(member, n.split('/')[-1], re.I)]
        else:
            hit = [n for n in names if n.lower().endswith(known)]
        if not hit:
            raise ValueError('archive has no table member' + (' matching ' + member if member else ''))
        return hit[0]

    if body[:4] == b'PK\x03\x04' and not name.endswith(('.xlsx', '.xlsm')):
        zf = zipfile.ZipFile(io.BytesIO(body))
        names = [n for n in zf.namelist() if not n.endswith('/')]
        if not member and any(n == '[Content_Types].xml' for n in names):
            return body, 'xlsx'
        chosen = pick(names)
        return zf.read(chosen), _kind(chosen.lower(), b'')
    if name.endswith('.tar') or body[257:262] == b'ustar':
        tf = tarfile.open(fileobj=io.BytesIO(body))
        files = [m for m in tf.getmembers() if m.isfile()]
        chosen = pick([m.name for m in files])
        return tf.extractfile(chosen).read(), _kind(chosen.lower(), b'')
    return body, _kind(name, body)


def _sheet_rows(body: bytes, kind: str, sheet):
    if kind == 'xlsx':
        openpyxl = need('xlsx')
        wb = openpyxl.load_workbook(io.BytesIO(body), read_only=True, data_only=True)
        ws = wb[sheet] if isinstance(sheet, str) else wb.worksheets[sheet or 0]
        for row in ws.iter_rows(values_only=True):
            yield [_json_safe(v) for v in row]
        wb.close()
        return
    xlrd = need('xls')
    book = xlrd.open_workbook(file_contents=body)
    ws = book.sheet_by_name(sheet) if isinstance(sheet, str) else book.sheet_by_index(sheet or 0)
    for i in range(ws.nrows):
        yield [xlrd.xldate.xldate_as_datetime(c.value, book.datemode).isoformat()
               if c.ctype == xlrd.XL_CELL_DATE else c.value for c in ws.row(i)]


def _columns(header) -> list[str]:
    names, seen = [], {}
    for i, h in enumerate(header):
        name = re.sub(r'\s+', ' ', str(h if h is not None else '')).strip() or 'column_%d' % (i + 1)
        if name.lower() in seen:
            seen[name.lower()] += 1
            name = '%s_%d' % (name, seen[name.lower()])
        else:
            seen[name.lower()] = 1
        names.append(name)
    return names


def _json_rows(body: bytes, json_path: str | None):
    text = body.decode('utf-8-sig')
    try:
        data = json.loads(text)
    except ValueError:
        return [json.loads(line) for line in text.splitlines() if line.strip()]  # NDJSON
    for key in [k for k in (json_path or '').split('.') if k]:
        data = data[int(key)] if isinstance(data, list) else data[key]
    if isinstance(data, dict):
        lists = [v for v in data.values() if isinstance(v, list) and v and isinstance(v[0], dict)]
        if not lists:
            raise ValueError('json has no list of records; set json_path')
        data = max(lists, key=len)
    return data


def _stage(body: bytes, kind: str, work: Path, sheet, header_row: int, json_path) -> tuple[Path, str]:
    """Write the file in a form DuckDB reads natively: (path, reader SQL)."""
    def q(p):
        return "'%s'" % str(p).replace("'", "''")
    if kind == 'parquet':
        path = work / 'in.parquet'
        path.write_bytes(body)
        return path, 'read_parquet(%s)' % q(path)
    if kind in ('json', 'xml'):
        if kind == 'json':
            rows = _json_rows(body, json_path)
        else:
            from . import tabular
            root = tabular._xml_root(body)
            if root is None:
                raise ValueError('xml could not be parsed')
            rows = list(tabular._xml_iter_records(root))
        path = work / 'in.ndjson'
        with path.open('w', encoding='utf-8') as f:
            for r in rows:
                f.write(json.dumps(r if isinstance(r, dict) else {'value': r}, default=str) + '\n')
        return path, 'read_json_auto(%s, format=\'newline_delimited\', sample_size=-1)' % q(path)
    path = work / 'in.csv'
    skip = max(0, header_row - 1)
    if kind in ('xlsx', 'xls'):
        rows = _sheet_rows(body, kind, sheet)
        for _ in range(skip):
            next(rows, None)
        header = next(rows, None)
        if not header:
            raise ValueError('dataset has no header row')
        cols = _columns(header)
        with path.open('w', encoding='utf-8', newline='') as f:
            w = csv.writer(f)
            w.writerow(cols)
            width = len(cols)
            for row in rows:
                row = list(row[:width]) + [None] * (width - len(row))
                if any(v not in (None, '') for v in row):
                    w.writerow(row)
        skip = 0
    else:
        try:
            body.decode('utf-8')
            path.write_bytes(body)
        except UnicodeDecodeError:
            path.write_text(body.decode('cp1252', 'replace'), encoding='utf-8')
    return path, ('read_csv(%s, header=true, skip=%d, sample_size=-1, ignore_errors=true, null_padding=true)'
                  % (q(path), skip))


def _load(body: bytes, url: str, path: Path, sheet, member, header_row: int, json_path, meta: dict) -> int:
    duckdb = need('duckdb')
    data, kind = _unwrap(body, url, member)
    work = path.with_suffix('.work')
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir()
    tmp = path.with_suffix('.tmp')
    tmp.unlink(missing_ok=True)
    try:
        staged, reader = _stage(data, kind, work, sheet, header_row, json_path)
        con = duckdb.connect(str(tmp))
        try:
            con.execute('CREATE TABLE data AS SELECT * FROM ' + reader)
            cols = [r[0] for r in con.execute('DESCRIBE data').fetchall()]
            con.execute('DELETE FROM data WHERE ' + ' AND '.join(  # blank lines of a csv
                '"%s" IS NULL' % c.replace('"', '""') for c in cols))
            n = con.execute('SELECT count(*) FROM data').fetchone()[0]
            con.execute('CREATE TABLE _meta (k VARCHAR PRIMARY KEY, v VARCHAR)')
            con.executemany('INSERT INTO _meta VALUES (?, ?)',
                            [(k, json.dumps(v)) for k, v in {**meta, 'format': kind, 'rows': n, 'columns': cols}.items()])
        finally:
            con.close()
    finally:
        shutil.rmtree(work, ignore_errors=True)
    os.replace(tmp, path)
    return n


def _meta(path: Path) -> dict:
    con = need('duckdb').connect(str(path), read_only=True)
    try:
        return {k: json.loads(v) for k, v in con.execute('SELECT k, v FROM _meta').fetchall()}
    finally:
        con.close()


def _set_meta(path: Path, **values):
    con = need('duckdb').connect(str(path))
    try:
        for k, v in values.items():
            con.execute('INSERT OR REPLACE INTO _meta VALUES (?, ?)', (k, json.dumps(v)))
    finally:
        con.close()


def _evict(keep: Path):
    try:
        limit = float(os.environ.get('ATLAS_DATASET_CACHE_GB') or 5) * (1 << 30)
    except ValueError:
        limit = 5.0 * (1 << 30)
    files = sorted(cache_dir().glob('*.duckdb'), key=lambda p: p.stat().st_mtime, reverse=True)
    total = 0
    for f in files:
        total += f.stat().st_size
        if total > limit and f != keep:
            f.unlink(missing_ok=True)


class Table:
    """A laid-out dataset: `query(sql, params)` → list of dicts over the table `data` (DuckDB SQL)."""

    def __init__(self, path: Path, meta: dict, source: str):
        self.path, self.meta, self.source = path, meta, source

    @property
    def columns(self) -> list[str]:
        return list(self.meta.get('columns') or [])

    @property
    def rows(self) -> int:
        return int(self.meta.get('rows') or 0)

    def query(self, sql: str, params=()) -> list[dict]:
        con = need('duckdb').connect(str(self.path), read_only=True)
        try:
            cur = con.execute(sql, list(params))
            names = [d[0] for d in cur.description]
            return [{k: _json_safe(v) for k, v in zip(names, row)} for row in cur.fetchall()]
        finally:
            con.close()

    def provenance(self) -> dict:
        return {'url': self.meta.get('url'), 'fetched_at': self.meta.get('fetched_at'),
                'last_modified': self.meta.get('last_modified'), 'size_bytes': self.meta.get('size_bytes'),
                'format': self.meta.get('format'), 'rows': self.rows, 'from': self.source}


def open(url: str, *, fetch: str = 'plain', refresh_days: float = 30, sheet=None, member: str | None = None,  # noqa: A001
         header_row: int = 1, json_path: str | None = None, max_mb: float = DEFAULT_MAX_MB,
         timeout: float = DEFAULT_TIMEOUT_S) -> Table:
    """Return the dataset at `url` as a local table, downloading it only when needed.

    Fresh (younger than `refresh_days`) → the disk. Older → a HEAD request: if the publisher's
    Last-Modified is present and unchanged, the disk again; otherwise a new download."""
    parsed = urlsplit(url)
    if parsed.scheme not in ('http', 'https'):
        raise ValueError('dataset url must be http(s)')
    path = cache_dir() / ('%s.duckdb' % _key(url, sheet, member, header_row, json_path))
    max_bytes = int(max_mb * (1 << 20))
    if path.exists():
        try:
            meta = _meta(path)
            age = (time.time() - _dt.datetime.fromisoformat(meta['fetched_at']).timestamp()) / 86400
            if age < refresh_days:
                os.utime(path)
                return Table(path, meta, 'cache')
            headers, _ = _call('HEAD', url, fetch, max_bytes, timeout)
            same = headers.get('last-modified') and headers['last-modified'] == meta.get('last_modified')
            if same:
                now = _dt.datetime.now(_dt.timezone.utc).isoformat()
                _set_meta(path, fetched_at=now)
                meta['fetched_at'] = now
                os.utime(path)
                return Table(path, meta, 'cache-revalidated')
        except Exception:  # a damaged cache file or a failed check: download again
            pass
    headers, body = _call('GET', url, fetch, max_bytes, timeout)
    meta = {'url': url, 'fetched_at': _dt.datetime.now(_dt.timezone.utc).isoformat(),
            'last_modified': headers.get('last-modified'), 'size_bytes': len(body),
            'sha256': hashlib.sha256(body).hexdigest()}
    _load(body, url, path, sheet, member, header_row, json_path, meta)
    _evict(path)
    return Table(path, _meta(path), 'download')


# ── one request with a browser TLS fingerprint, for connectors ───────────────

class Response:
    """What `fetch` returns: status_code, headers (lower-case keys), content, text, url, json()."""

    def __init__(self, status_code: int, headers: dict, content: bytes, url: str):
        self.status_code, self.headers, self.content, self.url = status_code, headers, content, url

    @property
    def text(self) -> str:
        m = re.search(r'charset=([\w-]+)', self.headers.get('content-type') or '')
        return self.content.decode(m.group(1) if m else 'utf-8', 'replace')

    def json(self):
        return json.loads(self.content)

    def raise_for_status(self):
        if not 200 <= self.status_code < 300:
            raise RuntimeError('HTTP %s %s' % (self.status_code, self.url))


class Session:
    """Cookies kept between `fetch` calls: sites that answer a search only to a client that got their
    cookie on the first page. `with dataset.Session() as s: s.fetch(...)`; same arguments as `fetch`."""

    def __init__(self, profile: str = 'chrome'):
        self.profile, self._s = profile, None

    def fetch(self, method: str, url: str, **kw) -> Response:
        if self._s is None:
            self._s = need('impersonate').Session(impersonate=kw.get('profile') or self.profile)
        return fetch(method, url, _session=self._s, **kw)

    def close(self):
        if self._s is not None:
            self._s.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def fetch(method: str, url: str, *, params: dict | None = None, headers: dict | None = None,
          json_body=None, data=None, profile: str = 'chrome', use_proxy: bool = False,
          max_mb: float = 16.0, timeout: float = 30.0, _session=None) -> Response:
    """One HTTP request with a browser TLS fingerprint (curl_cffi), for a site that refuses
    ordinary clients: any method, own headers, a JSON or form body.

    `use_proxy=True` sends it through the client's own proxy (ATLAS_PROXY_URL), the same proxy
    the runtime uses for steps with needs_proxy; without the variable the request goes direct.
    Hooks receive the URL with its query parameters. Use Session to retain cookies between calls."""
    method = method.upper()
    if params:
        parts = urlsplit(url)
        query = '&'.join(q for q in (parts.query, urlencode(params, doseq=True)) if q)
        url = parts._replace(query=query).geturl()
    if urlsplit(url).scheme not in ('http', 'https'):
        raise ValueError('fetch url must be http(s)')
    cr = _session or need('impersonate')
    for hook in list(before_fetch):
        hook(method, url)
    proxy = os.environ.get('ATLAS_PROXY_URL') if use_proxy else None
    max_bytes = int(max_mb * (1 << 20))
    r = cr.request(method, url, impersonate=profile, timeout=timeout, headers=dict(headers or {}),
                   json=json_body, data=data, allow_redirects=True, stream=True,
                   proxies={'http': proxy, 'https': proxy} if proxy else None)
    buf = bytearray()
    try:
        for chunk in r.iter_content(1 << 16):
            buf.extend(chunk)
            if len(buf) > max_bytes:
                raise ValueError('response larger than %d MB' % (max_bytes >> 20))
        rh = {k.lower(): v for k, v in r.headers.items()}
        status, final_url = r.status_code, str(r.url)
    finally:
        r.close()
    _notify(method, url, status, bytes(buf), final_url)
    return Response(status, rh, bytes(buf), final_url)
