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

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


@pytest.fixture
def redirect_transport(monkeypatch):
    from types import SimpleNamespace

    transport = _Curl()
    redirect = _Resp(status=302)
    redirect.headers['Location'] = '/next'
    responses = [redirect, _Resp()]

    def request(method, url, **kw):
        transport.calls.append((method, url, kw))
        assert kw['allow_redirects'] is False
        return responses.pop(0)

    monkeypatch.setattr(transport, 'request', request)
    monkeypatch.setattr(dataset, 'need', lambda _: SimpleNamespace(
        Session=lambda **kw: transport, request=request))
    return transport.calls, responses


@pytest.mark.parametrize('session', [False, True])
@pytest.mark.parametrize('target', [
    'https://other.example/next', 'https://source.example:8443/next',
    'http://source.example/next', 'https://user@source.example/next',
])
def test_connector_refuses_redirect_before_second_request(redirect_transport, target, session):
    calls, responses = redirect_transport
    responses[0].headers['Location'] = target
    with dataset.Session() as client:
        fetch = client.fetch if session else dataset.fetch
        with pytest.raises(ValueError, match='redirect'):
            fetch('GET', 'https://source.example/start', headers={'X-Custom': 'example'})
    assert [url for _, url, _ in calls] == ['https://source.example/start']


@pytest.mark.parametrize('status,expected_method', [
    (301, 'GET'), (302, 'GET'), (303, 'GET'), (307, 'POST'), (308, 'POST'),
])
def test_connector_follows_same_origin_redirect(redirect_transport, status, expected_method):
    calls, responses = redirect_transport
    redirect = responses[0]
    redirect.status_code = status
    redirect.headers['Location'] = 'https://SOURCE.example:443/next'
    response = dataset.fetch('POST', 'https://source.example/start',
                             headers={'X-Custom': 'example', 'Content-Type': 'application/json'},
                             json_body={'q': 1})
    assert response.status_code == 200
    assert len(calls) == 2
    method, url, options = calls[-1]
    assert (method, url) == (expected_method, 'https://source.example/next')
    assert options['headers']['X-Custom'] == 'example'
    assert ('Content-Type' in options['headers']) == (method == 'POST')
    assert options['json'] == ({'q': 1} if method == 'POST' else None)


def test_connector_checks_later_hops(redirect_transport, monkeypatch):
    calls, responses = redirect_transport
    responses[1].status_code = 307
    responses[1].headers['Location'] = '//other.example/final'
    checked = []
    monkeypatch.setattr(dataset, 'before_fetch', [lambda method, url: checked.append(url)])
    with pytest.raises(ValueError, match='redirect'):
        dataset.fetch('GET', 'https://source.example/start')
    assert checked == [url for _, url, _ in calls] == [
        'https://source.example/start', 'https://source.example/next']


def test_connector_limits_redirect_loops(redirect_transport):
    calls, responses = redirect_transport
    responses[:] = [responses[0]] * 31
    with pytest.raises(ValueError, match='too many dataset redirects'):
        dataset.fetch('GET', 'https://source.example/start')
    assert len(calls) == 31


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
