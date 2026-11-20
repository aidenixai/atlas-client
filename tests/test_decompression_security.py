"""Small offline regressions for HTTP and archive decompression budgets."""
import asyncio
import bz2
import gzip
import io
import zipfile
import zlib

import httpx
import pytest

from aidenix_atlas import _recipe_runtime as rt
from aidenix_atlas import tabular as tab


def archive(members, method=zipfile.ZIP_DEFLATED):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", method) as z:
        for name, value in members.items():
            z.writestr(name, value)
    return out.getvalue()


@pytest.fixture(autouse=True)
def clean_limits(monkeypatch):
    for name in ("ATLAS_BODY_CAP_MB", "ATLAS_FETCH_DEADLINE_S", "ATLAS_UNPACK_CAP_MB"):
        monkeypatch.delenv(name, raising=False)


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("encoding", ["gzip", "deflate"])
def test_http_decoder_bounds_output_before_allocating_whole_body(monkeypatch, asynchronous, encoding):
    plain = b"A" * (2 * 1024**2)
    wire = gzip.compress(plain) if encoding == "gzip" else zlib.compress(plain)
    cap = 65536
    original = zlib.decompressobj
    sizes = []

    class Decoder:
        def __init__(self, *args, **kwargs):
            self.inner = original(*args, **kwargs)

        def decompress(self, *args, **kwargs):
            out = self.inner.decompress(*args, **kwargs)
            sizes.append(len(out))
            return out

        def __getattr__(self, name):
            return getattr(self.inner, name)

    monkeypatch.setattr(zlib, "decompressobj", Decoder)

    def handler(request):
        return httpx.Response(200, stream=httpx.ByteStream(wire),
                              headers={"content-encoding": encoding, "content-type": "text/plain"})

    ep = {"body_cap_mb": cap / 1024**2}
    if asynchronous:
        async def run():
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                return await rt._afetch(client, ep, {}, "https://source.test/data")
        result = asyncio.run(run())
    else:
        with httpx.Client(transport=httpx.MockTransport(handler)) as client:
            result = rt._fetch(client, ep, {}, "https://source.test/data")
    assert result.truncated_by == "body_cap" and result.bytes_read == cap
    assert sizes and max(sizes) <= cap + 1


def test_cpg_reads_only_the_encoding_prefix(monkeypatch):
    body = archive({"shape.cpg": b"UTF-8" + b" " * 1024**2})
    original = zipfile.ZipFile.read

    def read(self, name, *args, **kwargs):
        assert name != "shape.cpg", "CPG must not be read in full"
        return original(self, name, *args, **kwargs)

    monkeypatch.setattr(zipfile.ZipFile, "read", read)
    assert tab._zip_cpg(body, "shape.dbf") == "utf-8"


def test_ods_mimetype_reads_only_a_prefix(monkeypatch):
    body = archive({"mimetype": b"application/vnd.oasis.opendocument.spreadsheet" + b" " * 1024**2,
                    "content.xml": b"<root/>"})
    original = zipfile.ZipFile.read

    def read(self, name, *args, **kwargs):
        assert name != "mimetype", "mimetype must not be read in full"
        return original(self, name, *args, **kwargs)

    monkeypatch.setattr(zipfile.ZipFile, "read", read)
    assert tab._ods_content(body) == b"<root/>"


def test_ods_manifest_budget_is_checked_before_read(monkeypatch):
    monkeypatch.setenv("ATLAS_UNPACK_CAP_MB", "0.001")
    body = archive({"META-INF/manifest.xml": b"application/vnd.oasis.opendocument.spreadsheet" + b" " * 4096,
                    "content.xml": b"<root/>"})
    with pytest.raises(ValueError, match="[Aa]rchive"):
        tab._ods_content(body)


@pytest.mark.parametrize("pack", [gzip.compress, bz2.compress])
def test_archive_cap_is_locally_configurable(monkeypatch, pack):
    body = pack(b"a,b\n" + b"1,2\n" * 512)
    monkeypatch.setenv("ATLAS_UNPACK_CAP_MB", "0.001")
    assert tab.unwrap(body) is None
    monkeypatch.setenv("ATLAS_UNPACK_CAP_MB", "1")
    assert tab.unwrap(body).startswith(b"a,b\n")


def test_unused_large_zip_member_does_not_reject_small_table(monkeypatch):
    monkeypatch.setenv("ATLAS_UNPACK_CAP_MB", "0.001")
    body = archive({"data.csv": b"a,b\n1,2\n", "unused.shp": b"x" * 8192})
    assert tab.records(body)[1] == [{"a": "1", "b": "2"}]


def test_workbook_preflight_rejects_large_parts_before_library(monkeypatch):
    monkeypatch.setenv("ATLAS_UNPACK_CAP_MB", "0.001")
    body = archive({"xl/workbook.xml": b"x" * 4096})
    with pytest.raises(ValueError, match="[Aa]rchive"):
        rt._parse_bytes(body, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")


def test_archive_default_allows_200_mib():
    assert tab.UNPACK_CAP == 256 * 1024**2


def test_runtime_marks_archive_limit_instead_of_reporting_empty(monkeypatch):
    monkeypatch.setenv("ATLAS_UNPACK_CAP_MB", "0.001")
    body = gzip.compress(b"a,b\n" + b"1,2\n" * 4096)
    fetched = rt._finish({}, body, "application/gzip", "https://source.test/data.csv.gz", None)
    assert fetched.truncated_by == "unpack_cap" and fetched[0] is None


@pytest.mark.parametrize("method", [zipfile.ZIP_LZMA, zipfile.ZIP_BZIP2])
def test_zip_codecs_without_output_bounds_are_not_invoked(method):
    body = archive({"data.csv": b"a,b\n1,2\n"}, method)
    with pytest.raises(ValueError, match="[Aa]rchive"):
        rt._parse_bytes(body, "application/zip")


@pytest.mark.parametrize("encoding", ["identity", "gzip", "deflate", "raw-deflate", "gzip, gzip"])
def test_normal_http_encodings_keep_data_and_negotiate_bounded_codecs(encoding):
    plain = b'{"items":[{"id":1}]}'
    if encoding == "identity":
        wire = plain
    elif encoding == "gzip, gzip":
        wire = gzip.compress(gzip.compress(plain))
    elif encoding == "gzip":
        wire = gzip.compress(plain)
    elif encoding == "raw-deflate":
        wire = zlib.compress(plain)[2:-4]
    else:
        wire = zlib.compress(plain)

    def handler(request):
        assert request.headers["accept-encoding"] == "gzip, deflate"
        return httpx.Response(200, stream=httpx.ByteStream(wire),
                              headers={"content-encoding": "deflate" if encoding == "raw-deflate" else encoding,
                                       "content-type": "application/json"})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = rt._fetch(client, {}, {}, "https://source.test/data")
    assert result[0] == {"items": [{"id": 1}]} and not result.truncated


@pytest.mark.parametrize("asynchronous", [False, True])
def test_login_response_uses_bounded_decoder(monkeypatch, asynchronous):
    wire = gzip.compress(b'{"token":"' + b"x" * (2 * 1024**2) + b'"}')
    monkeypatch.setenv("ATLAS_BODY_CAP_MB", "0.001")
    monkeypatch.setattr(rt, "_address_hooks", lambda *a, **kw: {})

    def handler(request):
        return httpx.Response(200, stream=httpx.ByteStream(wire),
                              headers={"content-encoding": "gzip", "content-type": "application/json"})

    original_sync, original_async = httpx.Client, httpx.AsyncClient
    monkeypatch.setattr(rt.httpx, "Client", lambda **kw: original_sync(transport=httpx.MockTransport(handler), **kw))
    monkeypatch.setattr(rt.httpx, "AsyncClient", lambda **kw: original_async(transport=httpx.MockTransport(handler), **kw))
    auth = {"login_url": "https://source.test/login", "username": "test", "password": "fake"}
    with pytest.raises(ValueError, match="[Ll]ogin.*limit"):
        if asynchronous:
            asyncio.run(rt._login_token(auth, None, 3, force=True,
                                       credential_origin=rt._fixed_credential_origin(auth["login_url"]),
                                       data_origin=rt._fixed_credential_origin(auth["login_url"])))
        else:
            rt._login_token_sync(auth, None, 3, force=True,
                                 credential_origin=rt._fixed_credential_origin(auth["login_url"]),
                                 data_origin=rt._fixed_credential_origin(auth["login_url"]))


@pytest.mark.parametrize("status", [200, 204, 205, 304])
@pytest.mark.parametrize("encoding", ["gzip", "br", "zstd"])
def test_empty_response_with_encoding_header_needs_no_decoder_stream(status, encoding):
    def handler(request):
        return httpx.Response(status, stream=httpx.ByteStream(b""), headers={"content-encoding": encoding})
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        with client.stream("GET", "https://source.test/empty") as response:
            assert list(rt._http_chunks_sync(response, 1024)) == []


def test_raw_deflate_with_zlib_like_header_keeps_bounded_fallback():
    wire = b"\x78\x9c\x00\x63\xff" + b"A" * 156 + b"\x01\x00\x00\xff\xff"
    assert zlib.decompress(wire, -15) == b"A" * 156
    decoder = rt._HttpDecoder("deflate", 1024)
    assert decoder.decode(wire) == b"A" * 156


def test_runtime_marks_oversized_selected_binary_member(monkeypatch):
    monkeypatch.setenv("ATLAS_UNPACK_CAP_MB", "0.001")
    fetched = rt._finish({}, archive({"data.dbf": b"x" * 4096}),
                         "application/zip", "https://source.test/data.zip", None)
    assert fetched.truncated_by == "unpack_cap" and fetched[0] is None


@pytest.mark.parametrize("asynchronous", [False, True])
def test_redirect_bodies_are_closed_without_reading(monkeypatch, asynchronous):
    monkeypatch.setattr(rt, "_check_request", lambda *args: None)
    closed = []

    class RedirectBody(httpx.ByteStream):
        def __iter__(self):
            raise AssertionError("Intermediate redirect body must not be read or decoded")
            yield b""  # pragma: no cover

        async def __aiter__(self):
            raise AssertionError("Intermediate redirect body must not be read or decoded")
            yield b""  # pragma: no cover

        def close(self):
            closed.append(True)

        async def aclose(self):
            closed.append(True)

    def handler(request):
        if request.url.path == "/start":
            return httpx.Response(302, stream=RedirectBody(b""),
                                  headers={"location": "/final", "content-encoding": "gzip"})
        return httpx.Response(200, stream=httpx.ByteStream(b"[]"), headers={"content-type": "application/json"})

    if asynchronous:
        async def run():
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=True,
                                         event_hooks=rt._address_hooks(None, True)) as client:
                return await rt._afetch(client, {}, {}, "https://source.test/start")
        result = asyncio.run(run())
    else:
        with httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True,
                          event_hooks=rt._address_hooks(None)) as client:
            result = rt._fetch(client, {}, {}, "https://source.test/start")
    assert result[0] == [] and closed
