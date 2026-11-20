"""atlas.dataset: a file laid out once into a local table, read from disk afterwards."""
import gzip
import io
import zipfile

import pytest

from aidenix_atlas import dataset


@pytest.fixture
def served(monkeypatch, tmp_path):
    monkeypatch.setenv('ATLAS_DATASET_CACHE', str(tmp_path / 'cache'))
    state = {'body': b'', 'calls': [], 'last_modified': 'Mon, 01 Jan 2026 00:00:00 GMT'}

    def fake(method, url, fetch, max_bytes, timeout, headers=None):
        state['calls'].append((method, url, fetch))
        body = state['body'] if method == 'GET' else None
        if body is not None and len(body) > max_bytes:
            raise ValueError('dataset larger than limit')
        return 200, {'last-modified': state['last_modified'], 'content-length': str(len(state['body']))}, body, url

    monkeypatch.setattr(dataset, '_request', fake)
    return state


CSV = b'Name,Date,Jobs\nAcme,2026-10-02,10\nBeta,2026-11-05,20\n,,\nGamma,2026-11-07,\n'


def test_downloads_once_then_reads_disk(served):
    served['body'] = CSV
    t = dataset.open('https://x.gov/f.csv')
    assert (t.source, t.rows, t.columns) == ('download', 3, ['Name', 'Date', 'Jobs'])
    again = dataset.open('https://x.gov/f.csv')
    assert again.source == 'cache' and len(served['calls']) == 1
    rows = again.query('SELECT Name FROM data WHERE Date BETWEEN ? AND ? ORDER BY 1', ('2026-11-01', '2026-11-30'))
    assert [r['Name'] for r in rows] == ['Beta', 'Gamma']


def test_stale_cache_revalidates_without_download(served):
    served['body'] = CSV
    dataset.open('https://x.gov/f.csv')
    t = dataset.open('https://x.gov/f.csv', refresh_days=0)
    assert t.source == 'cache-revalidated'
    assert [c[0] for c in served['calls']] == ['GET', 'HEAD']


def test_new_file_is_downloaded_again(served):
    served['body'] = CSV
    dataset.open('https://x.gov/f.csv')
    served['body'] = CSV + b'Delta,2026-11-09,5\n'
    served['last_modified'] = 'Tue, 02 Jan 2026 00:00:00 GMT'
    t = dataset.open('https://x.gov/f.csv', refresh_days=0)
    assert (t.source, t.rows) == ('download', 4)


@pytest.mark.parametrize('last_modified', ['Tue, 02 Jan 2026 00:00:00 GMT', None])
def test_same_size_file_downloaded_when_date_changed_or_missing(served, last_modified):
    served['body'] = b'Name,Jobs\nAcme,150\n'
    dataset.open('https://x.gov/f.csv')
    served['body'] = b'Name,Jobs\nAcme,180\n'
    served['last_modified'] = last_modified

    t = dataset.open('https://x.gov/f.csv', refresh_days=0)

    assert t.source == 'download'
    assert t.query('SELECT Jobs FROM data') == [{'Jobs': 180}]
    assert t.meta['last_modified'] == last_modified
    assert [c[0] for c in served['calls']] == ['GET', 'HEAD', 'GET']


def test_zip_and_gzip_wrappers(served):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        z.writestr('readme.pdf', b'%PDF')
        z.writestr('data/notices.csv', CSV)
    served['body'] = buf.getvalue()
    assert dataset.open('https://x.gov/a.zip').rows == 3
    served['body'] = gzip.compress(CSV)
    assert dataset.open('https://x.gov/b.csv.gz').rows == 3


def test_xlsx_dates_become_iso(served):
    openpyxl = pytest.importorskip('openpyxl')
    import datetime as dt
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.append(['Employer', 'Received'])
    ws.append(['Acme', dt.datetime(2026, 4, 2)])
    out = io.BytesIO()
    wb.save(out)
    served['body'] = out.getvalue()
    t = dataset.open('https://x.gov/w.xlsx')
    assert t.query('SELECT Received FROM data')[0]['Received'] == '2026-04-02T00:00:00'


def test_size_cap_and_scheme(served):
    served['body'] = CSV
    with pytest.raises(ValueError):
        dataset.open('https://x.gov/f.csv', max_mb=0.00001)
    with pytest.raises(ValueError):
        dataset.open('file:///etc/passwd')


def test_duplicate_and_blank_headers(served):
    served['body'] = b'id,id,\n1,2,3\n'
    cols = dataset.open('https://x.gov/h.csv').columns
    assert len(cols) == 3 and len(set(cols)) == 3


def test_json_xml_tar_parquet(served, tmp_path):
    import json as _j
    import tarfile as _tf
    served['body'] = _j.dumps({'meta': {}, 'result': {'items': [{'a': 1, 'b': 'x'}, {'a': 2, 'b': 'y'}]}}).encode()
    t = dataset.open('https://x.gov/j.json', json_path='result.items')
    assert t.rows == 2 and t.query('SELECT sum(a) s FROM data')[0]['s'] == 3
    served['body'] = b'{"a": 1}\n{"a": 5}\n'
    assert dataset.open('https://x.gov/n.ndjson').rows == 2
    served['body'] = b'<root><rec><name>Acme</name><n>1</n></rec><rec><name>Beta</name><n>2</n></rec></root>'
    t = dataset.open('https://x.gov/x.xml')
    assert t.rows == 2 and 'name' in t.columns
    buf = io.BytesIO()
    with _tf.open(fileobj=buf, mode='w:gz') as tf:
        info = _tf.TarInfo('dir/data.csv')
        info.size = len(CSV)
        tf.addfile(info, io.BytesIO(CSV))
    served['body'] = buf.getvalue()
    assert dataset.open('https://x.gov/a.tar.gz').rows == 3
    duckdb = pytest.importorskip('duckdb')
    pq = tmp_path / 'p.parquet'
    duckdb.connect().execute("COPY (SELECT 1 AS a UNION ALL SELECT 2) TO '%s' (FORMAT parquet)" % pq)
    served['body'] = pq.read_bytes()
    assert dataset.open('https://x.gov/p.parquet').rows == 2


def test_broken_download_resumes_with_range(monkeypatch, tmp_path):
    monkeypatch.setenv('ATLAS_DATASET_CACHE', str(tmp_path / 'cache'))
    seen = []

    def once(method, url, fetch, max_bytes, timeout, hdrs, buf, seen_=None):
        seen.append(hdrs.get('Range'))
        if not buf:
            seen_.append(({'last-modified': 'x', 'accept-ranges': 'bytes'}, url))
            buf.extend(CSV[:20])
            raise dataset._Broken()
        buf.extend(CSV[20:])
        return 206, {}, url

    monkeypatch.setattr(dataset, '_once', once)
    t = dataset.open('https://x.gov/r.csv')
    assert seen == [None, 'bytes=20-'] and t.rows == 3 and t.meta['last_modified'] == 'x'


def test_missing_capability_names_the_command(monkeypatch):
    import importlib
    real = importlib.import_module
    monkeypatch.setattr(importlib, 'import_module',
                        lambda name: (_ for _ in ()).throw(ImportError(name)) if name == 'openpyxl' else real(name))
    with pytest.raises(dataset.MissingCapability) as exc:
        dataset.need('xlsx')
    assert exc.value.install == 'pip install openpyxl'
    assert dataset.missing(['duckdb', 'unknown-capability']) == []


def test_connector_step_hands_install_command_to_agent():
    from aidenix_atlas import _recipe_runtime as runtime
    code = ('def go(date_range):\n'
            '    raise dataset.MissingCapability("xlsx", "openpyxl")\n')
    out = runtime._run_connector_step({'connector_code': code, 'in': ['date_range']}, {'date_range': 'x'})
    assert out['install'] == 'pip install openpyxl' and 'run `pip install openpyxl`' in out['error']
