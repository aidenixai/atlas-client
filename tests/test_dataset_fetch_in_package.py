"""dataset.fetch / dataset.Session in the installed package: method, body, proxy only on request, size cap."""
import pytest

from aidenix_atlas import dataset


class _Resp:
    def __init__(self, body=b'{"ok": 1}', status=200):
        self.status_code, self.headers, self.url, self._b = status, {'Content-Type': 'application/json'}, 'https://x.test/a', body

    def iter_content(self, chunk_size=65536):
        yield self._b

    def close(self):
        pass


class _Curl:
    def __init__(self, body=b'{"ok": 1}'):
        self.calls, self.body = [], body

    def request(self, method, url, **kw):
        self.calls.append((method, url, kw))
        return _Resp(self.body)


def test_fetch_post_json_and_params(monkeypatch):
    cr = _Curl()
    monkeypatch.setenv('ATLAS_PROXY_URL', 'http://u:p@proxy.test:1')
    r = dataset.fetch('POST', 'https://x.test/a', params={'q': 'a b'}, json_body={'k': 1}, _session=cr)
    method, url, kw = cr.calls[0]
    assert (method, url, kw['json'], kw['proxies']) == ('POST', 'https://x.test/a?q=a+b', {'k': 1}, None)
    assert r.json() == {'ok': 1} and r.headers['content-type'] == 'application/json'
    dataset.fetch('GET', 'https://x.test/a', use_proxy=True, _session=cr)
    assert cr.calls[1][2]['proxies'] == {'http': 'http://u:p@proxy.test:1', 'https': 'http://u:p@proxy.test:1'}


def test_fetch_size_cap_and_scheme():
    with pytest.raises(ValueError):
        dataset.fetch('GET', 'https://x.test/a', max_mb=0.000001, _session=_Curl(b'x' * 100))
    with pytest.raises(ValueError):
        dataset.fetch('GET', 'file:///etc/passwd', _session=_Curl())
