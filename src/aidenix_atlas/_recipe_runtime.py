"""Execute HTTP endpoints and multi-step Atlas recipes.

`tls_insecure: true` on an endpoint disables certificate verification for THAT source.
Needed where the server is signed by a root missing from every system trust store:
some government portals use a national CA, and without the flag the runner fails with
`CERTIFICATE_VERIFY_FAILED` where `curl -k` gets the data. The cost is real: such a request
is not protected against MITM, so set it only on sources with public data
and never where the request carries a key or personal data.
"""
from __future__ import annotations

import re
import io
import zipfile
from contextvars import ContextVar, copy_context
import threading
import time
from datetime import datetime, timezone
from contextlib import asynccontextmanager, contextmanager
from typing import Any
from urllib.parse import parse_qsl, quote, urlsplit, urlunsplit

import httpx

# Roles of `endpoints` items that are NOT operation endpoints: attached files
# (artifact role in the catalog; for CKAN, the dataset's attached resources).
# Only one value today, but kept as a set: a new artifact kind is added here,
# not in every recipe reader.
ARTIFACT_ROLES = frozenset({"data-file"})


def primary_endpoint(endpoints: Any) -> dict | None:
    """Return the first operation endpoint, or the first artifact for a file-only recipe.

    A legacy endpoint dictionary is returned directly. Empty collections have no endpoint.
    """
    if isinstance(endpoints, dict):
        return endpoints
    if not isinstance(endpoints, list) or not endpoints:
        return None
    for ep in endpoints:
        if isinstance(ep, dict) and ep.get("role") not in ARTIFACT_ROLES:
            return ep
    return next((ep for ep in endpoints if isinstance(ep, dict)), None)


_SOQL_SLOT = re.compile(r"\{(\w+)\}")
_SOQL_PAD = re.compile(r"^(.+)_pad(\d+)$")
_SOQL_IN_CHUNK = 150
# SoQL auto-pagination: page==$limit => a tail is POSSIBLE -> advance $offset += page_size, accumulate
# until batch < page_size (short batch = exhausted = COMPLETE set, truncated=False).
# Row ceiling per SoQL query (per chunk) guards against runaway; hitting it
# with a still-full page => tail unprovable -> truncated=True (honest incompleteness).
_SOQL_PAGE_CEIL_ROWS = 200000

# Operator contact is passed only explicitly via recipe headers.
DEFAULT_UA = "SourceClient/0.1"
DEFAULT_TIMEOUT = 15.0


# ─────────────────────────────────────────────────────────────────────────────
# Public internet only. The recipe comes from the network but runs on the client:
# without this check a recipe (or a source redirect) could point the runner at
# localhost, LAN addresses or the cloud metadata address 169.254.169.254 and read
# what is visible only inside the client's network. Every request is checked, including every
# redirect; the hostname is resolved and every address is checked. Behind a proxy the proxy
# resolves names, so only numeric addresses and local names are checked.
# Debugging your own services: ATLAS_ALLOW_PRIVATE_ADDRESSES=1.
# ─────────────────────────────────────────────────────────────────────────────
class BlockedAddress(httpx.RequestError):
    """Request to a non-public address: the runner does not send it."""


def _private_allowed() -> bool:
    import os as _os
    return _os.environ.get("ATLAS_ALLOW_PRIVATE_ADDRESSES", "").strip().lower() in ("1", "true", "yes")


def _non_public(ip: str) -> bool:
    import ipaddress as _ip
    try:
        addr = _ip.ip_address(ip.split("%", 1)[0])
    except ValueError:
        return False
    mapped = getattr(addr, "ipv4_mapped", None)
    return not (mapped or addr).is_global


def address_refusal(url: str, *, resolve: bool = True) -> str | None:
    """Refusal reason for the address, or None if it is public."""
    if _private_allowed():
        return None
    import ipaddress as _ip
    import socket as _socket
    parts = urlsplit(str(url))
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        return None  # httpx rejects an empty host itself
    if host == "localhost" or host.endswith((".localhost", ".internal", ".local", ".home.arpa")):
        return "local host %s" % host
    try:
        _ip.ip_address(host.split("%", 1)[0])
        literal = True
    except ValueError:
        literal = False
    if literal:
        return "non-public address %s" % host if _non_public(host) else None
    if not resolve:
        return None
    try:
        infos = _socket.getaddrinfo(host, parts.port or None, type=_socket.SOCK_STREAM)
    except (OSError, UnicodeError):
        return None  # unresolved: the request fails on its own, client network untouched
    for info in infos:
        if _non_public(str(info[4][0])):
            return "%s resolves to non-public address %s" % (host, info[4][0])
    return None


def _check_request(request: httpx.Request, resolve: bool) -> None:
    why = address_refusal(str(request.url), resolve=resolve)
    if why:
        raise BlockedAddress("refused: " + why, request=request)


def _address_hooks(proxy_url: str | None, is_async: bool = False,
                   credential_origin: tuple | None = None) -> dict:
    """httpx hooks: check every request, including redirects."""
    resolve = not proxy_url
    if is_async:
        async def hook(request):
            import asyncio as _aio
            _deadline_check()
            _check_credential_origin(str(request.url), credential_origin)
            await _aio.to_thread(_check_request, request, resolve)  # name resolution does not block the loop
            _deadline_check()
    else:
        def hook(request):
            _deadline_check()
            _check_credential_origin(str(request.url), credential_origin)
            _check_request(request, resolve)
            _deadline_check()
    return {"request": [hook]}

# ─────────────────────────────────────────────────────────────────────────────
# Stream responses within the byte and time budgets. For truncated CSV and NDJSON,
# keep complete lines. A truncated JSON document yields no parsed records.
# ─────────────────────────────────────────────────────────────────────────────
DEFAULT_BODY_CAP_MB = 256.0
DEFAULT_FETCH_DEADLINE_S = 300.0
DEFAULT_MAX_CONCURRENCY = 6
DEFAULT_UNPACK_CAP_MB = 256.0
_CHUNK = 65536


def _now() -> float:
    return time.monotonic()


def _now_iso() -> str:
    """UTC wall-clock time at receipt, in ISO 8601 format with a Z suffix."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _positive_number(value, default):
    import math
    try:
        number = float(value)
        return number if math.isfinite(number) and number > 0 else default
    except (TypeError, ValueError, OverflowError):
        return default


def _local_ceiling(env: str, default: float, requested=None) -> float:
    import os
    ceiling = _positive_number(os.environ.get(env), default)
    return min(ceiling, _positive_number(requested, ceiling))


def _limits_of(ep: dict) -> tuple[int, float]:
    """Local ceilings can be raised by the operator, only narrowed by a recipe."""
    cap_mb = _local_ceiling("ATLAS_BODY_CAP_MB", DEFAULT_BODY_CAP_MB, (ep or {}).get("body_cap_mb"))
    dl = _local_ceiling("ATLAS_FETCH_DEADLINE_S", DEFAULT_FETCH_DEADLINE_S, (ep or {}).get("deadline_s"))
    return max(1, int(cap_mb * 1024 * 1024)), max(1.0, dl)


def _archive_cap(default: int = int(DEFAULT_UNPACK_CAP_MB * 1024**2)) -> int:
    return max(1, int(_local_ceiling("ATLAS_UNPACK_CAP_MB", default / 1024**2) * 1024**2))


def _concurrency_limit(requested=None) -> int:
    return max(1, int(_local_ceiling("ATLAS_MAX_CONCURRENCY", DEFAULT_MAX_CONCURRENCY, requested)))


_CURRENT_DEADLINE = ContextVar("atlas_request_deadline", default=None)


class _DeadlineExpired(TimeoutError):
    def __init__(self, budget):
        super().__init__("Request deadline exceeded")
        self.budget = budget


class _UntrackedConnection(httpx.RequestError):
    """An idle connection was not created under this synchronous operation's budget."""


class _RequestDeadline:
    """A single clock across slot waits, redirects and retries, with owned-socket abort."""

    def __init__(self, seconds):
        self.ends_at = _now() + seconds
        self.cancelled, self.done = threading.Event(), threading.Event()
        self.lock = threading.Lock()
        self.sockets, self.abort_callbacks = [], []
        self.body = b""
        self.content_type = self.url = ""
        self.good_response = False

    def remaining(self):
        remaining = self.ends_at - _now()
        if self.cancelled.is_set() or remaining <= 0:
            raise _DeadlineExpired(self)
        return remaining

    def stop(self):
        self.cancelled.set()
        with self.lock:
            sockets, callbacks = self.sockets[:], self.abort_callbacks[:]
        for sock in sockets:
            _FtpTransfer.close(sock)  # shutdown, not just close, wakes a blocked recv.
        for callback in callbacks:
            callback()

    def trace(self, event, info, track_socket):
        if event.endswith(".failed") or "response_closed" in event:
            return
        if event.endswith(".complete") and track_socket:
            stream = info.get("return_value")
            if hasattr(stream, "get_extra_info"):
                sock = stream.get_extra_info("socket")
                if sock is not None:
                    with self.lock:
                        self.sockets.append(sock)
                    if self.cancelled.is_set():
                        _FtpTransfer.close(sock)
        remaining = self.remaining()
        if track_socket and event == "http11.send_request_headers.started" and not self.sockets:
            # Fail before sending bytes; httpcore closes the unclaimed pooled connection.
            raise _UntrackedConnection("A fresh connection is required for request deadline ownership")
        if "timeout" in info:
            previous = info["timeout"]
            info["timeout"] = remaining if previous is None else min(previous, remaining)

    def capture_response(self, response):
        self.body = b""
        self.content_type = response.headers.get("content-type", "")
        self.url = str(response.url)
        self.good_response = response.is_success


def _deadline_check():
    budget = _CURRENT_DEADLINE.get()
    if budget is not None:
        budget.remaining()


def _deadline_sleep(seconds):
    budget = _CURRENT_DEADLINE.get()
    if budget is None:
        time.sleep(seconds)
    else:
        budget.cancelled.wait(min(seconds, budget.remaining()))
        budget.remaining()


def _sync_deadline_call(function, seconds):
    """Bound the caller and stop real network I/O, rather than merely abandon its result."""
    budget = _RequestDeadline(seconds)
    outcome = []

    def work():
        token = _CURRENT_DEADLINE.set(budget)
        try:
            budget.remaining()
            outcome.append((True, function()))
        except BaseException as error:
            outcome.append((False, error))
        finally:
            _CURRENT_DEADLINE.reset(token)
            budget.done.set()

    threading.Thread(target=copy_context().run, args=(work,), name="atlas-request", daemon=True).start()
    try:
        if not budget.done.is_set() and not budget.done.wait(budget.remaining()):
            raise _DeadlineExpired(budget)
        success, value = outcome[0]
        if not success:
            raise value
        return value
    except BaseException:
        budget.stop()
        budget.done.wait(0.1)  # Bounded grace for socket and slot cleanup, never an unbounded join.
        raise


async def _async_deadline_call(operation, seconds):
    import asyncio
    budget = _RequestDeadline(seconds)
    token = _CURRENT_DEADLINE.set(budget)
    timeout = asyncio.timeout(seconds)
    try:
        async with timeout:
            return await operation
    except TimeoutError as error:
        if isinstance(error, _DeadlineExpired) or timeout.expired():
            budget.stop()
            raise _DeadlineExpired(budget) from None
        raise
    except asyncio.CancelledError:
        budget.stop()
        raise
    finally:
        _CURRENT_DEADLINE.reset(token)


def _deadline_result(ep, budget):
    if budget.good_response:
        return _finish(ep, bytes(budget.body), budget.content_type, budget.url, "deadline")
    return _fetched((None, "timeout", None), "deadline", 0)


def _prepare_deadline_request(request, is_async=False):
    budget = _CURRENT_DEADLINE.get()
    if budget is None:
        return
    remaining = budget.remaining()
    configured = request.extensions.get("timeout", {})
    request.extensions["timeout"] = {
        name: remaining if configured.get(name) is None else min(configured[name], remaining)
        for name in ("connect", "read", "write", "pool")}
    if not is_async:
        # A fresh HTTP/1.1 connection gives this request exclusive ownership for socket abort.
        request.headers["Connection"] = "close"
        with budget.lock:
            budget.sockets.clear()
    previous = request.extensions.get("trace")
    if getattr(previous, "_atlas_deadline", None) is budget:
        return
    if is_async:
        async def trace(event, info):
            budget.trace(event, info, False)
            if previous:
                await previous(event, info)
    else:
        def trace(event, info):
            budget.trace(event, info, True)
            if previous:
                previous(event, info)
    trace._atlas_deadline = budget
    request.extensions["trace"] = trace


_REQUEST_CONDITION = threading.Condition()
_ACTIVE_REQUESTS = 0


class _RequestSlot:
    """One shared HTTP/FTP ceiling, including nested fanouts and mixed sync/async calls."""

    def __enter__(self):
        global _ACTIVE_REQUESTS
        with _REQUEST_CONDITION:
            while _ACTIVE_REQUESTS >= _concurrency_limit():
                _deadline_check()
                _REQUEST_CONDITION.wait(0.05)
            _deadline_check()
            _ACTIVE_REQUESTS += 1
        return self

    async def __aenter__(self):
        global _ACTIVE_REQUESTS
        import asyncio
        while True:
            with _REQUEST_CONDITION:
                _deadline_check()
                if _ACTIVE_REQUESTS < _concurrency_limit():
                    _ACTIVE_REQUESTS += 1
                    return self
            await asyncio.sleep(0.01)

    def __exit__(self, *args):
        global _ACTIVE_REQUESTS
        with _REQUEST_CONDITION:
            _ACTIVE_REQUESTS -= 1
            _REQUEST_CONDITION.notify_all()

    async def __aexit__(self, *args):
        self.__exit__(*args)


class ResourceLimitError(ValueError):
    """An input cannot be decoded within the locally configured resource budget."""

    def __init__(self, message, reason="unpack_cap"):
        super().__init__(message)
        self.reason = reason


class _ArchiveZip(zipfile.ZipFile):
    """Bound selected reads before decompression; preflight libraries that own their reads."""

    def __init__(self, body: bytes, limit: int | None = None, workbook: bool = False):
        super().__init__(io.BytesIO(body))
        self.remaining = _archive_cap() if limit is None else limit
        if workbook:
            try:
                self.check_workbook()
            except Exception:
                self.close()
                raise

    def check_workbook(self):
        total = 0
        for info in self.infolist():
            self._check_method(info)
            total += info.file_size
            if total > self.remaining:
                raise ResourceLimitError("Archive exceeds the unpacked byte limit")

    @staticmethod
    def _check_method(info):
        # ZipExtFile bounds DEFLATE internally, but not its BZIP2/LZMA adapters on Python 3.12.
        if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            raise ResourceLimitError("Archive compression method cannot be decoded with a bounded output",
                                     "unsupported_compression")

    def open(self, name, mode="r", pwd=None, *, force_zip64=False):
        info = name if isinstance(name, zipfile.ZipInfo) else self.getinfo(name)
        self._check_method(info)
        return super().open(info, mode, pwd, force_zip64=force_zip64)

    def read(self, name, pwd=None, *, max_bytes=None):
        info = name if isinstance(name, zipfile.ZipInfo) else self.getinfo(name)
        limit = self.remaining if max_bytes is None else min(self.remaining, max_bytes)
        if info.file_size > limit:
            raise ResourceLimitError("Archive exceeds the unpacked byte limit")
        with self.open(info, pwd=pwd) as stream:
            data = stream.read(limit + 1)
        if len(data) > limit:
            raise ResourceLimitError("Archive exceeds the unpacked byte limit")
        self.remaining -= len(data)
        return data

    def read_prefix(self, name, length: int):
        length = min(length, self.remaining)
        with self.open(name) as stream:
            data = stream.read(length)
        self.remaining -= len(data)
        return data


class _Fetched(tuple):
    """(payload, fmt, raw_text) + body-read flags. A tuple so that `payload, fmt, raw = _fetch(...)`
    keeps working for all consumers; flags are read via getattr (mocks return a plain tuple)."""
    truncated: bool = False
    truncated_by: str | None = None
    bytes_read: int = 0
    refusal: str | None = None        # refusal text that arrived with a 2xx (detected from json structure)
    refusal_kind: str | None = None   # needs_key | gone | bad_request


def _fetched(parsed, why: str | None, n: int) -> _Fetched:
    f = _Fetched(parsed)
    f.truncated, f.truncated_by, f.bytes_read = why is not None, why, n
    return f


def _coverage_of(ep: dict, params: dict) -> dict:
    """Which client params actually went into the request (consumed) and which the recipe dropped
    (unbound), using the same binding that executes the call (input_coverage). Empty if no params."""
    user = {k: v for k, v in (params or {}).items()
            if not str(k).startswith("_") and v not in (None, "", [])}
    if not user:
        return {}
    cov = input_coverage(ep, params)
    return {"consumed": cov["consumed"], "unbound": cov["unbound"],
            **({"fixed": cov["fixed"]} if cov.get("fixed") else {})}


def _blank(v) -> bool:
    return v is None or v == [] or v == {} or (isinstance(v, str) and not v.strip())


def _missing_required(ep: dict, params: dict, args: dict) -> list[str]:
    """Required recipe inputs (`endpoint.params_required`, set by the catalog) that have
    no value either in the request args (defaults and aliases already applied) or in client params."""
    got = {k for k, v in (args or {}).items() if not _blank(v)}
    got |= {k for k, v in (params or {}).items() if not _blank(v)}
    for src, dst in (ep.get("param_aliases") or {}).items():
        if src in got:
            got.add(dst)
    return [n for n in (ep.get("params_required") or []) if n not in got]


def _unfilled_result(url: str, ep: dict, params: dict, args: dict | None = None) -> dict | None:
    """An unfilled path token remains in the URL: neither params nor the
    recipe default supplied it. Previously the runtime sent `/weather/%7Bcity%7D` literally and the source
    answered 200 with junk (goweather: three "records" for `{city}`). Skip the request and
    say what is missing. None = everything filled.
    Same for a required query-string or body input (`params_required`): USPTO without
    an owner was sent with an empty body and answered 200 with 30 unrelated recent filings."""
    left = _PATH_PARAM.findall(url)
    if left:
        return {"records": None, "count": None, "raw": None, "format": None, "raw_text": None,
                "unfilled": left, **_coverage_of(ep, params),
                "error": "path token(s) %s have no value: pass them in params"
                         % ", ".join("{%s}" % t for t in left)}
    need = _missing_required(ep, params, args) if args is not None else []
    if need:
        return {"records": None, "count": None, "raw": None, "format": None, "raw_text": None,
                "unfilled": need, **_coverage_of(ep, params),
                "error": "required param(s) %s have no value: pass them in params" % ", ".join(need)}
    return None


def _refusal_result(fetched, payload, fmt, raw_text, ep: dict, params: dict) -> dict:
    """Result for an in-body refusal: no records, body attached, refusal kind and text."""
    return {"records": None, "count": None, "raw": payload, "format": fmt, "raw_text": raw_text,
            "refusal": getattr(fetched, "refusal_kind", None) or "bad_request",
            "refusal_message": getattr(fetched, "refusal", None),
            **_coverage_of(ep, params), **_body_flags(fetched)}


def _body_flags(fetched) -> dict:
    """Truncation flags for the run_recipe result; empty if the body was read in full."""
    if not getattr(fetched, "truncated", False):
        return {}
    return {"truncated": True, "truncated_by": getattr(fetched, "truncated_by", None),
            "bytes_read": getattr(fetched, "bytes_read", 0)}


class _HttpDecoder:
    """Content-Encoding decoding with a bound at every layer, before output allocation."""

    def __init__(self, encoding: str, cap: int):
        import zlib
        self.encoding, self.remaining = encoding, cap
        self.decoder = zlib.decompressobj(16 + zlib.MAX_WBITS) if encoding == "gzip" else None
        self.prefix = b""
        self.first = True

    def decode(self, data: bytes) -> bytes:
        import zlib
        if self.decoder is None:
            self.prefix += data
            if len(self.prefix) < 2:
                return b""
            data, self.prefix = self.prefix, b""
            # HTTP deflate exists with both zlib framing and a raw DEFLATE stream.
            wrapped = data[0] & 15 == 8 and int.from_bytes(data[:2], "big") % 31 == 0
            self.decoder = zlib.decompressobj(zlib.MAX_WBITS if wrapped else -zlib.MAX_WBITS)
        try:
            output = self.decoder.decompress(data, self.remaining + 1)
        except zlib.error as error:
            if self.encoding != "deflate" or not self.first:
                raise httpx.DecodingError("Invalid compressed response") from error
            self.decoder = zlib.decompressobj(-zlib.MAX_WBITS)
            try:
                output = self.decoder.decompress(data, self.remaining + 1)
            except zlib.error as raw_error:
                raise httpx.DecodingError("Invalid compressed response") from raw_error
        self.first = False
        self.remaining -= len(output)
        return output

    def finish(self):
        if self.decoder is None or not self.decoder.eof:
            raise httpx.DecodingError("Incomplete compressed response")


@contextmanager
def _stream_sync(client, method, url, **kwargs):
    """HTTPX otherwise reads and auto-decodes redirect bodies before returning the stream."""
    request = client.build_request(method, url, **kwargs)
    response = _send_sync(client, request)
    history = []
    try:
        while response.has_redirect_location and client.follow_redirects:
            if len(history) >= client.max_redirects:
                raise httpx.TooManyRedirects("Exceeded maximum allowed redirects", request=response.request)
            request = response.next_request
            history.append(response)
            response.close()
            response = _send_sync(client, request)
        response.history = history
        yield response
    finally:
        response.close()


def _send_sync(client, request):
    while True:
        _prepare_deadline_request(request)
        try:
            return client.send(request, stream=True, follow_redirects=False)
        except _UntrackedConnection:
            # No request bytes were sent. Retry only while the same deadline has time left.
            _deadline_check()


@asynccontextmanager
async def _stream_async(client, method, url, **kwargs):
    request = client.build_request(method, url, **kwargs)
    _prepare_deadline_request(request, True)
    response = await client.send(request, stream=True, follow_redirects=False)
    history = []
    try:
        while response.has_redirect_location and client.follow_redirects:
            if len(history) >= client.max_redirects:
                raise httpx.TooManyRedirects("Exceeded maximum allowed redirects", request=response.request)
            request = response.next_request
            _prepare_deadline_request(request, True)
            history.append(response)
            await response.aclose()
            response = await client.send(request, stream=True, follow_redirects=False)
        response.history = history
        yield response
    finally:
        await response.aclose()


def _http_decoders(response, cap):
    encodings = [value.strip().lower() for value in response.headers.get("content-encoding", "").split(",")
                 if value.strip() and value.strip().lower() != "identity"]
    if len(encodings) > 4 or any(value not in ("gzip", "deflate") for value in encodings):
        raise httpx.DecodingError("Response compression is not supported by the bounded decoder")
    return [_HttpDecoder(value, cap) for value in reversed(encodings)]


def _decode_http_chunk(chunk, decoders):
    for index, decoder in enumerate(decoders):
        chunk = decoder.decode(chunk)
        if decoder.remaining < 0 and index < len(decoders) - 1:
            raise ResourceLimitError("Compressed response layer exceeds the byte limit")
    return chunk


def _http_chunks_sync(response, cap):
    if response.is_stream_consumed:  # An explicitly supplied, already-read response (e.g. MockTransport).
        yield from response.iter_bytes(_CHUNK)
        return
    decoders = None
    wire = 0
    for chunk in response.iter_raw():
        _deadline_check()
        if decoders is None:
            decoders = _http_decoders(response, cap)
        wire += len(chunk)
        if wire > cap and decoders:
            raise ResourceLimitError("Compressed response exceeds the downloaded byte limit")
        yield _decode_http_chunk(chunk, decoders)
    if wire:
        for decoder in decoders:
            decoder.finish()


async def _http_chunks_async(response, cap):
    if response.is_stream_consumed:
        async for chunk in response.aiter_bytes(_CHUNK):
            yield chunk
        return
    decoders = None
    wire = 0
    async for chunk in response.aiter_raw():
        _deadline_check()
        if decoders is None:
            decoders = _http_decoders(response, cap)
        wire += len(chunk)
        if wire > cap and decoders:
            raise ResourceLimitError("Compressed response exceeds the downloaded byte limit")
        yield _decode_http_chunk(chunk, decoders)
    if wire:
        for decoder in decoders:
            decoder.finish()


def _capped_body_sync(chunks, t0: float, cap: int, deadline: float) -> tuple[bytes, str | None]:
    """Collect the body from a stream up to the byte ceiling or deadline -> (bytes, cut reason | None)."""
    buf, size, why = [], 0, None
    try:
        for chunk in chunks:
            buf.append(chunk[:max(0, cap - size)])
            size += len(chunk)
            if size >= cap:
                why = "body_cap"
                break
            if _now() - t0 > deadline:
                why = "deadline"
                break
    finally:
        body = b"".join(buf)
        budget = _CURRENT_DEADLINE.get()
        if budget is not None:
            budget.body = body
    return (body[:cap] if why == "body_cap" else body), why


async def _capped_body_async(chunks, t0: float, cap: int, deadline: float) -> tuple[bytes, str | None]:
    buf, size, why = [], 0, None
    try:
        async for chunk in chunks:
            buf.append(chunk[:max(0, cap - size)])
            size += len(chunk)
            if size >= cap:
                why = "body_cap"
                break
            if _now() - t0 > deadline:
                why = "deadline"
                break
    finally:
        body = b"".join(buf)
        budget = _CURRENT_DEADLINE.get()
        if budget is not None:
            budget.body = body
    return (body[:cap] if why == "body_cap" else body), why


def _snapshot(r: httpx.Response, body: bytes) -> httpx.Response:
    """A read copy of a streamed response with the already collected (capped) body, so that
    `raise_for_status()` and `e.response.text` work for consumers as with `c.get`. httpx has already
    removed transport compression, so content-encoding/-length no longer match the copy; drop them."""
    hdrs = [(k, v) for k, v in r.headers.multi_items()
            if k.lower() not in ("content-encoding", "content-length", "transfer-encoding")]
    return httpx.Response(r.status_code, headers=hdrs, content=body, request=r.request)

# ─────────────────────────────────────────────────────────────────────────────
# Access protocol (endpoints[].access): a source's access discipline.
# The knowledge lives in the RECIPE (forbidden_params / max_concurrency / min_interval_ms / retry_empty),
# the RUNNER enforces it: prepare_call strips forbidden_params; semaphore+pacing+penalty live here.
# Key = URL host (upstream burst limits are per host, not per endpoint). retry_empty
# is enforced by the consumer (emptiness depends on its parsing). Other runners must replicate these semantics.
# Apply pacing and penalties only to endpoints with an explicit access policy.
_ACCESS_PENALTY_S = 60.0  # 429/420 -> leave the host alone for N s unless the recipe sets its own penalty_ms
_access_lock = threading.Lock()
_access_state: dict[str, dict] = {}  # host → {active, next_free, penalty_until}


def _access_of(ep: dict) -> dict:
    a = ep.get("access")
    return a if isinstance(a, dict) else {}


def _access_st(host: str) -> dict:
    return _access_state.setdefault(
        host, {"active": 0, "next_free": 0.0, "penalty_until": 0.0})


def _access_note_status(host: str, status: int, access: dict | None = None) -> None:
    """429/420 from a source with an access block -> host penalty box (fail fast without hitting it).

    How long to stay quiet is a source property (`access.penalty_ms`): the default minute can be
    longer than the whole crawl and kill the remaining requests even though the source recovers in seconds.
    """
    if status in (420, 429):
        with _access_lock:
            cooldown = (access or {}).get("penalty_ms")
            hush = float(cooldown) / 1000.0 if cooldown else _ACCESS_PENALTY_S
            _access_st(host)["penalty_until"] = time.time() + hush


def _access_acquire_sync(host: str, access: dict) -> bool:
    """Penalty check + semaphore (max_concurrency) + pacing (min_interval_ms) before a request.
    True = slot taken, _access_release required. Raises source_penalty while a penalty is active."""
    limit = access.get("max_concurrency")
    interval = (access.get("min_interval_ms") or 0) / 1000.0
    with _access_lock:
        if time.time() < _access_st(host)["penalty_until"]:
            raise RuntimeError(f"source_penalty:{host}")
    if not limit and not interval:
        return False
    while True:
        _deadline_check()
        with _access_lock:
            st = _access_st(host)
            if time.time() < st["penalty_until"]:
                raise RuntimeError(f"source_penalty:{host}")
            now = time.time()
            wait = max(0.0, st["next_free"] - now) if interval else 0.0
            if (not limit or st["active"] < int(limit)) and wait <= 0:
                _deadline_check()
                st["active"] += 1
                if interval:
                    st["next_free"] = now + interval
                return True
        # Reserve only when ready; a cancelled waiter must not move future windows.
        _deadline_sleep(min(0.05, wait) if wait > 0 else 0.05)


def _access_release(host: str) -> None:
    with _access_lock:
        st = _access_state.get(host)
        if st and st["active"] > 0:
            st["active"] -= 1


async def _access_wait_async(host: str, access: dict) -> None:
    """Apply the host penalty and pacing delay for an asynchronous request."""
    import asyncio as _aio
    interval = (access.get("min_interval_ms") or 0) / 1000.0
    while True:
        _deadline_check()
        with _access_lock:
            st = _access_st(host)
            now = time.time()
            if now < st["penalty_until"]:
                raise RuntimeError(f"source_penalty:{host}")
            wait = max(0.0, st["next_free"] - now) if interval else 0.0
            if wait <= 0:
                _deadline_check()
                if interval:
                    st["next_free"] = now + interval
                return
        await _aio.sleep(min(0.05, wait))
# {key} in the path: placeholder name = word chars + hyphen/dot/colon (`{sub-id}`, `{api.v}`,
# `{ns:id}`). Previously `\w+` broke hyphenated names -> token stayed literal in the URL -> 4xx.
_PATH_PARAM = re.compile(r"\{([\w.:-]+)\}")


def _subst_path(url: str, params: dict) -> tuple[str, set]:
    """Substitute {key} in URL path segments from params (url-encoded). Returns (resolved_url, consumed_keys).
    Lifts the declarative limitation on path params ({cik}/{subreddit}/{subscriptionId}...).
    Unresolved {k} (no value) stay as is -> HTTP answers 4xx."""
    consumed: set = set()

    def _rep(m: "re.Match") -> str:
        k = m.group(1)
        v = params.get(k)
        if v not in (None, ""):
            consumed.add(k)
            return quote(str(v), safe="")
        return m.group(0)

    return _PATH_PARAM.sub(_rep, url), consumed


def _dig(obj: Any, path: str) -> Any:
    """Get a nested value by dotted path ('message.items'). '' -> the whole object.

    A '<key>[]' segment expands a list; the rest of the path applies to each element:
    'features[].attributes' = ArcGIS FeatureServer -> flat list of attribute dicts
    (GeoJSON: 'features[].properties'). Bare 'features[]' = the list itself. This way a nested source
    yields the same flat records as Socrata, with no special code in the executor."""
    if not path:
        return obj
    parts = path.split(".")
    for i, part in enumerate(parts):
        if part.endswith("[]"):
            key = part[:-2]
            if key:
                if not isinstance(obj, dict):
                    return None
                obj = obj.get(key)
            if not isinstance(obj, list):
                return None
            rest = ".".join(parts[i + 1:])
            got = [_dig(el, rest) for el in obj]
            if "[]" in rest:
                # a second `[]` further down the path (Google Patents `results.cluster[].result[].patent`):
                # records are elements of the inner lists, not one list per cluster
                flat: list = []
                for v in got:
                    if isinstance(v, list):
                        flat.extend(v)
                    elif v is not None:
                        flat.append(v)
                return flat
            return got
        if isinstance(obj, dict):
            obj = obj.get(part)
        else:
            return None
    return obj


def _build_args(ep: dict, params: dict, auth: dict, api_key: str | None) -> dict:
    """Atlas params -> source args: defaults + passthrough + aliases + appends + strip empty.

    The only knowledge of the request shape lives in the declarative endpoint; the wiring is generic.
    """
    out: dict = dict(ep.get("param_defaults") or {})
    for f in ep.get("params_passthrough") or []:
        v = params.get(f)
        if v not in (None, ""):
            out[f] = v
    for src, dst in (ep.get("param_aliases") or {}).items():
        # An alias beats the default and yields only to an explicit params[dst]: same rule as
        # path substitution in prepare_call. The old `dst not in out`
        # blocked the alias for any recipe with param_defaults[dst]: defaults {q: DEFAULT} +
        # alias company_name->q + call {company_name: Acme} went out as q=DEFAULT.
        v = params.get(src)
        if v in (None, "", []) or dst in params:
            continue
        out[dst] = v
        # don't duplicate the source name: if it got into out via passthrough it would be sent
        # along with the alias (company_name=Acme&q=Acme). A default under the source name is kept.
        if src != dst and src in out and src not in (ep.get("param_defaults") or {}):
            out.pop(src, None)
    for src, dst in (ep.get("param_appends") or {}).items():
        if params.get(src):
            out[dst] = (out.get(dst) or []) + list(params[src])
    # Trusted same-host passthrough (opt-in `_pass=all`): any explicit call param not covered by
    # defaults/passthrough/aliases goes to the source as is (reserved `_*` and the auth name excluded).
    # Lets a consumer reproduce native curation (sortBy/severity/start/per_page...) without a manual
    # passthrough list. Flag-gated -> commercial paths (MCP/api) without the flag are unaffected.
    if str(params.get("_pass") or "") == "all":
        _auth_q = auth.get("name") if auth.get("type") in ("query", "header") else None
        for _k, _v in (params or {}).items():
            if _k.startswith("_") or _k == _auth_q or _k in out:
                continue
            if _v not in (None, "", []):
                out[_k] = _v
    out = {k: v for k, v in out.items() if v not in (None, "", [])}
    if auth.get("type") == "query" and api_key:
        out[auth["name"]] = api_key
    return out


def _headers(ep: dict, auth: dict, api_key: str | None) -> dict[str, str]:
    h = {"User-Agent": DEFAULT_UA, "Accept": "application/json, */*;q=0.8"}
    h.update(ep.get("static_headers") or {})
    if auth.get("type") == "header" and api_key:
        # prefix for "Authorization: ApiKey <key>" / "Bearer <key>" schemes (OpenSanctions, OAuth).
        # Empty default -> backward compatible with a bare header key (hibp-api-key etc.).
        h[auth["name"]] = (auth.get("prefix") or "") + api_key
    return h


def _endpoint_url(ep: dict) -> str:
    """Absolute HTTP(S) or anonymous FTP endpoint URL, under `url` or `path`.
    Relative/descriptive recipes are not executable; FTP's strict GET-only contract
    is validated by prepare_call and the bounded transport before connecting."""
    u = ep.get("url") or ep.get("path") or ""
    if not (u.startswith(("http://", "https://")) or u.lower().startswith("ftp://")):
        raise ValueError(
            f"endpoint not executable: url/path={u!r} is a relative path / unsupported scheme / "
            "descriptive spec (not a verified executable recipe). An absolute http(s)/ftp url is required.")
    return u


def _ep_executable(ep) -> bool:
    """Return whether an endpoint or endpoint list contains an executable HTTP(S) or FTP URL."""
    eps = ep if isinstance(ep, list) else [ep]
    for e in eps:
        if isinstance(e, dict):
            url = str(e.get("url") or e.get("path") or "")
            if url.startswith(("http://", "https://")) or url.lower().startswith("ftp://"):
                return True
    return False


def _xml_obj(el):
    """ElementTree element -> dict/str (namespaces stripped, repeats -> list)."""
    node: dict = {}
    for k, v in el.attrib.items():
        node["@" + k.split("}", 1)[-1]] = v
    kids = list(el)
    if not kids:
        txt = (el.text or "").strip()
        if not node:
            return txt
        if txt:
            node["#text"] = txt
        return node
    for ch in kids:
        t = ch.tag.split("}", 1)[-1]
        val = _xml_obj(ch)
        if t in node:
            if not isinstance(node[t], list):
                node[t] = [node[t]]
            node[t].append(val)
        else:
            node[t] = val
    return node


def _decompress(content: bytes, ct: str, url: str = "", recover_text_encoding: bool = False) -> tuple[str, str]:
    """Archive (body = .gz/.zip file) -> (text, inner content-type). `r.text` mangles binary,
    so raw bytes are decompressed. Top lists (domcop/umbrella/tranco) are rank-ordered:
    archive output is bounded before parsing. Transport Content-Encoding is already removed
    by the bounded HTTP decoder; archive files are detected here by magic bytes."""
    import io as _io
    CAP = _archive_cap()
    lu = (url or "").lower()
    # gzip: magic 1f 8b
    if content[:2] == b"\x1f\x8b":
        import gzip as _gz
        try:
            with _gz.GzipFile(fileobj=_io.BytesIO(content)) as g:
                data = g.read(CAP + 1)
            if len(data) > CAP:
                raise ResourceLimitError("Archive exceeds the unpacked byte limit")
        except ResourceLimitError:
            raise
        except Exception:
            return "", ct
        if is_px_text(data[:65536].decode("ascii", "replace")):
            return _px_text(data) or "", "application/x-pcaxis"
        inner = "application/json" if ".json" in lu else ("text/csv" if (".csv" in lu or ".tsv" in lu) else ct)
        return _decode_text(data, inner, recover_text_encoding), inner
    # zip: magic PK\x03\x04
    if content[:4] == b"PK\x03\x04":
        try:
            with _ArchiveZip(content) as zf:
                names = [n for n in zf.namelist() if not n.endswith("/")]
                if not names:
                    return "", ct
                # Prefer the largest table/JSON member, without reading unused files.
                def rank(n: str):
                    nl = n.lower()
                    data_file = nl.endswith((".csv", ".tsv", ".json", ".ndjson", ".px"))
                    return (0 if data_file else 1 if nl.endswith('.txt') else 2, -zf.getinfo(n).file_size)
                pick = sorted(names, key=rank)[0]
                data = zf.read(pick)
            if is_px_text(data[:65536].decode("ascii", "replace")):
                return _px_text(data) or "", "application/x-pcaxis"
            nl = pick.lower()
            inner = "application/json" if nl.endswith((".json", ".ndjson")) else \
                    ("text/csv" if nl.endswith((".csv", ".tsv")) else ct)
            return _decode_text(data, inner, recover_text_encoding), inner
        except ResourceLimitError:
            raise
        except Exception:
            return "", ct
    return content.decode("utf-8", "replace"), ct


# Workbooks and dBase files need the table reader. Without it, return the binary
# format hint before attempting generic archive extraction.
TABLE_ROW_LIMIT = 200_000           # same ceiling as for csv
_BINARY_HINT = ("table body (xlsx/xls/ods/dbf) needs the aidenix-atlas table reader: "
                "pip install 'aidenix-atlas[tabular]' (openpyxl for xlsx, xlrd for xls); "
                "a standalone rendered .py cannot read it")
_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_ZIP_TABLE_MEMBERS = ((".dbf", "dbf"), (".xlsx", "xlsx"), (".xlsm", "xlsx"), (".xls", "xls"), (".ods", "ods"))


def _table_kind(content: bytes, url: str = "") -> str | None:
    """xlsx / xls / ods / dbf by magic bytes (the response header lies: data.gov.me serves a workbook
    as text/csv). A zip with a text member is NOT a table; _decompress unpacks it."""
    head = content[:8]
    if head == _OLE_MAGIC:
        return "xls"
    if head[:4] == b"PK\x03\x04":
        if content[30:38] == b"mimetype" and b"opendocument.spreadsheet" in content[38:120]:
            return "ods"
        try:
            import io as _io
            import zipfile as _zip
            names = [n.lower() for n in _zip.ZipFile(_io.BytesIO(content)).namelist()]
        except Exception:
            return None
        if "xl/workbook.xml" in names:
            return "xlsx"
        # Archive with a table inside (shapefile .dbf, workbook, .ods): tabular reads it in its own
        # member order. A csv/tsv/json text member takes precedence (archive-with-csv, handled by
        # _decompress), but a .txt next to a shapefile (readme, license) does not cancel the table:
        # e.g. 34685_shp.zip from data.gov.au used to reach the client as text.
        if not any(n.endswith((".csv", ".tsv", ".json", ".ndjson")) for n in names):
            for suf, kind in _ZIP_TABLE_MEMBERS:
                if any(n.endswith(suf) for n in names):
                    return kind
        return None
    # bare dBase: version byte, header length = 32 + 32*fields + 1, header terminator 0x0D
    if head[:1] in (b"\x03", b"\x83", b"\x30", b"\x8b", b"\xf5") and len(content) > 33:
        hl = int.from_bytes(content[8:10], "little")
        if hl > 32 and (hl - 33) % 32 == 0 and content[hl - 1:hl] == b"\r":
            return "dbf"
    if (url or "").lower().split("?")[0].endswith(".dbf"):
        return "dbf"
    return None


def _parse_table(content: bytes, kind: str, ct: str) -> tuple[Any, str, str | None]:
    """Workbook / dBase -> (list[dict], kind, None) via the atlas.tabular reader; no module or no
    openpyxl/xlrd -> (None, "binary", None): the runtime honestly says "not read"."""
    workbook = False
    if kind == "xlsx":
        import io, zipfile
        import xml.etree.ElementTree as ET
        try:
            with _ArchiveZip(content) as archive:
                workbook = "xl/workbook.xml" in archive.namelist()
                if workbook:
                    archive.check_workbook()
                sheets = [e for e in archive.infolist() if e.filename.startswith('xl/worksheets/')
                          and e.filename.endswith('.xml')]
                if sheets and len(sheets) <= 100 and all(e.file_size <= 2_000_000 for e in sheets):
                    if all(not any(node.tag.split('}')[-1] == 'c'
                                   for node in ET.fromstring(archive.read(e)).iter()) for e in sheets):
                        return None, "empty_workbook", None
        except (zipfile.BadZipFile, KeyError, ET.ParseError, OSError):
            pass
    try:
        from . import tabular as _tab
    except ResourceLimitError:
        raise
    except Exception:
        return None, "binary", None
    try:
        if content.startswith(b"PK\x03\x04") and not workbook:
            with _ArchiveZip(content) as archive:
                selected = _tab._zip_pick(archive)
                if selected and archive.getinfo(selected[1]).file_size > _archive_cap():
                    raise ResourceLimitError("Archive exceeds the unpacked byte limit")
        _k, rows, _tail = _tab.records(content, ct, None, n=TABLE_ROW_LIMIT)
    except ResourceLimitError:
        raise
    except Exception:
        return None, "binary", None
    if not rows:
        return None, "binary", None
    return rows, kind, None


def resource_formats(resource: dict) -> set[str]:
    """Observed format labels, MIME types and file/export names, normalized together."""
    aliases = {
        "text/csv": "csv", "text/tab-separated-values": "tsv", "application/json": "json",
        "application/geo+json": "geojson", "application/zip": "zip", "application/x-zip-compressed": "zip",
        "application/vnd.ms-excel": "xls", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "xlsx",
        "application/vnd.oasis.opendocument.spreadsheet": "ods", "application/xml": "xml", "text/xml": "xml",
        "pcaxis": "px", "pc-axis": "px", "xslx": "xlsx", "json-stat": "json", "json-stat2": "json",
    }
    out = set()
    for key in ("format", "mimetype", "media_type"):
        label = str(resource.get(key) or "").strip().lower().split(";", 1)[0]
        label = re.sub(r"^https?://[^/]+/assignments/media-types/", "", label)
        label = label.strip(" .")
        if label:
            out.add(aliases.get(label, label).upper())
            if label.startswith("zip "):
                out.add("ZIP")
    for key in ("url", "name"):
        value = str(resource.get(key) or "")
        match = re.search(r"\.([A-Za-z0-9]{2,10})(?:[?#]|$)", value)
        if match:
            label = match.group(1).lower()
            out.add(aliases.get(label, label).upper())
        match = re.search(r"/exports/(csv|tsv|xlsx|xls|ods|json|geojson|xml|zip)(?:[?#]|$)", value, re.I)
        if match:
            out.add(match.group(1).upper())
    return out


def decode_cp932(content: bytes) -> str | None:
    """Strict CP932 candidate with substantial Japanese script evidence."""
    try:
        text = content.decode("cp932")
    except UnicodeDecodeError:
        return None
    non_ascii = [c for c in text if ord(c) > 127]
    japanese = sum("\u3040" <= c <= "\u30ff" or "\u4e00" <= c <= "\u9fff" for c in non_ascii)
    # Western accent + ASCII can form an isolated CP932 kanji (Français → Fran軋is).
    substantial_run = re.search(r'[\u3040-\u30ff\u4e00-\u9fff]{3,}', text)
    return text if substantial_run and japanese >= 4 and japanese >= len(non_ascii) * 0.6 else None


def is_px_text(text: str) -> bool:
    head = text[:65536].lstrip("\ufeff")
    return bool(re.search(r'(?m)^\s*(?:STUB|HEADING)(?:\[[^]]+\])?\s*=', head)
                and re.search(r'(?m)^\s*VALUES(?:\[[^]]+\])?\(', head))


def parse_px(text: str, limit: int | None = None) -> list[dict] | None:
    """Dense PC-Axis cube; validate cardinality before attaching dimensions to cells.

    Sparse KEYS, malformed statements and incomplete cubes are explicitly unsupported.
    Missing-value symbols stay as symbols; they are never converted to zero.
    Primary-language value/cell notes and precision are attached as record context.
    One terminal numeric DATA continuation is accepted only at exact cube cardinality.
    """
    import itertools
    import math
    quoted_string = r'"(?:[^"]|"")*"'
    quoted_list = re.compile(r'\s*' + quoted_string + r'(?:\s*,\s*' + quoted_string + r')*\s*')
    cell_token = re.compile(quoted_string + r'|[^\s,"]+')
    cell_separator = re.compile(r'(?:\s*,\s*|\s+)')

    def data_cells(value):
        """Consume every cell and separator; never skip malformed punctuation."""
        value = value.strip()
        cells, pos = [], 0
        while pos < len(value):
            token = cell_token.match(value, pos)
            if token is None:
                return None
            cells.append(token.group())
            pos = token.end()
            if pos == len(value):
                return cells
            separator = cell_separator.match(value, pos)
            if separator is None or separator.end() == len(value):
                return None
            pos = separator.end()
        return cells

    def quoted(value):
        if not value.strip():
            return []
        if quoted_list.fullmatch(value) is None:
            return None
        return [v.replace('""', '"') for v in re.findall(r'"((?:[^"]|"")*)"', value)]

    wrapped_note = re.compile(quoted_string + r'(?:(?:[ \t]*\r?\n)+[ \t]*' + quoted_string + r')+')

    def note_parts(value):
        parts = quoted(value)
        if parts is not None:
            return parts, False
        # Physical line wrapping of long PX text does not add a semantic newline.
        # Keep #/## markers intact; only note RHS gets this fallback.
        if wrapped_note.fullmatch(value.strip()) is not None:
            return [v.replace('""', '"') for v in re.findall(r'"((?:[^"]|"")*)"', value)], True
        return None, False

    statement = re.compile(
        r'\s*([A-Z][A-Z0-9-]*)(?:\[([^]\r\n]+)\])?(?:\(\s*('
        + quoted_string + r'(?:\s*,\s*' + quoted_string + r')*)\s*\))?'
        r'\s*=\s*((?:"(?:[^"]|"")*"|[^";])*)\s*;', re.S)
    entries = {}
    pos = 0
    key = None
    text = text.lstrip("\ufeff")
    while text[pos:].strip():
        match = statement.match(text, pos)
        if match is None:
            # A source may terminate DATA early once. The continuation must be the
            # final fragment, contain just cells and end in one terminal semicolon.
            # Cell types and total cardinality are checked below before any output.
            tail = text[pos:].strip()
            data_key = ("DATA", None, ())
            if (key == "DATA" and data_key in entries and tail.endswith(';')
                    and ';' not in tail[:-1] and data_cells(entries[data_key])
                    and data_cells(tail[:-1])):
                entries[data_key] += ' ' + tail[:-1].strip()
                break
            return None
        key, lang, args, value = match.groups()
        args = tuple(quoted(args)) if args is not None else ()
        if (key == "KEYS" or (key, lang, args) in entries
                or key == "DATA" and any(entry[0] == "DATA" for entry in entries)):
            return None
        entries[key, lang, args] = value.strip()
        pos = match.end()
    language = entries.get(("LANGUAGE", None, ()), '').strip('"') or None

    def get(key, sub=None):
        args = () if sub is None else (sub,)
        return entries.get((key, None, args), entries.get((key, language, args), ''))

    stub, heading = quoted(get("STUB")), quoted(get("HEADING"))
    if stub is None or heading is None:
        return None
    dimensions = stub + heading
    if (not dimensions or len(dimensions) != len(set(dimensions))
            or set(dimensions) & {"_value", "_notes", "_precision"}):
        return None
    axes = [quoted(get("VALUES", name)) for name in dimensions]
    if any(not axis or len(axis) != len(set(axis)) for axis in axes):
        return None
    size = math.prod(len(axis) for axis in axes)
    if size > 2_000_000:
        return None
    value_notes, precisions, cell_notes = {}, {}, {}
    selected_annotations = {}
    for (key, lang, args), value in entries.items():
        if key not in {"VALUENOTEX", "DATANOTECELL", "PRECISION"} or lang not in (None, language):
            continue
        # Unqualified statements are in LANGUAGE, just like unqualified VALUES.
        # Prefer them over a duplicate translation of the same annotation.
        if (key, args) not in selected_annotations or lang is None:
            selected_annotations[key, args] = value
    code_axes = []
    if any(key == "DATANOTECELL" for key, _ in selected_annotations):
        for dimension, axis in zip(dimensions, axes):
            codes_text = get("CODES", dimension)
            codes = quoted(codes_text) if codes_text else axis
            if not codes or len(codes) != len(axis) or len(codes) != len(set(codes)):
                return None
            code_axes.append(dict(zip(codes, axis)))
    for (key, args), value in selected_annotations.items():
        if key == "DATANOTECELL":
            if len(args) != len(dimensions) or any(code not in axis for code, axis in zip(args, code_axes)):
                return None
            labels = tuple(axis[code] for code, axis in zip(args, code_axes))
            notes, wrapped = note_parts(value)
            if not notes:
                return None
            cell_notes[labels] = {'kind': 'cell', 'text': ('' if wrapped else '\n').join(notes)}
            if len(notes) > 1:
                cell_notes[labels]['parts'] = notes
        else:
            if len(args) != 2 or args[0] not in dimensions:
                return None
            dimension, label = args
            if label not in axes[dimensions.index(dimension)]:
                return None
            if key == "PRECISION":
                if re.fullmatch(r'\d+', value) is None:
                    return None
                precisions[args] = {'dimension': dimension, 'value': label, 'decimals': int(value)}
            else:
                notes, wrapped = note_parts(value)
                if not notes:
                    return None
                value_notes[args] = {'kind': 'value', 'dimension': dimension, 'value': label,
                                     'text': ('' if wrapped else '\n').join(notes)}
                if len(notes) > 1:
                    value_notes[args]['parts'] = notes
    cells = data_cells(get("DATA"))
    if cells is None or len(cells) != size:
        return None
    values = []
    for cell in cells:
        value = cell.strip('"')
        if re.fullmatch(r'\.{1,6}|-', value):
            values.append(value)
        elif re.fullmatch(r'[+-]?\d+', value):
            values.append(int(value))
        elif re.fullmatch(r'[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?', value):
            number = float(value)
            if not math.isfinite(number):
                return None
            values.append(number)
        else:
            return None
    n = size if limit is None else max(0, min(size, limit))
    records = []
    for labels, value in itertools.islice(zip(itertools.product(*axes), values), n):
        record = dict(zip(dimensions, labels), _value=value)
        notes = [value_notes[dimension, label] for dimension, label in zip(dimensions, labels)
                 if (dimension, label) in value_notes]
        if labels in cell_notes:
            notes.append(cell_notes[labels])
        if notes:
            record['_notes'] = notes
        precision = [precisions[dimension, label] for dimension, label in zip(dimensions, labels)
                     if (dimension, label) in precisions]
        if precision:
            record['_precision'] = precision
        records.append(record)
    return records


def _px_text(content: bytes) -> str | None:
    header = content[:65536].decode("ascii", "replace")
    match = re.search(r'(?m)^\s*CODEPAGE\s*=\s*"([^"\r\n]+)"', header)
    encoding = match.group(1) if match else "utf-8"
    try:
        text = content.decode(encoding)
    except (UnicodeDecodeError, LookupError):
        if match:
            return None
        text = content.decode("latin-1")
    return text


def px_records(content: bytes, limit: int | None = None) -> list[dict] | None:
    text = _px_text(content)
    return parse_px(text, limit) if text is not None else None


def _decode_text(content: bytes, ct: str, recover: bool = False) -> str:
    """Bytes -> text using the charset from content-type (like httpx `r.text`: no charset means utf-8, errors are replaced)."""
    import os as _os
    pilot = recover or _os.environ.get("ATLAS_CKAN_ROWS_PILOT") == "1"
    if pilot:
        for bom, codec in ((b"\xff\xfe", "utf-16"), (b"\xfe\xff", "utf-16"),
                           (b"\xef\xbb\xbf", "utf-8-sig")):
            if content.startswith(bom):
                return content.decode(codec, "replace")
    m = re.search(r"charset=\"?([\w\-]+)", ct or "", re.IGNORECASE)
    enc = m.group(1) if m else "utf-8"
    if pilot:
        try:
            return content.decode(enc)
        except (UnicodeDecodeError, LookupError):
            pass
        try:
            return content.decode('utf-8')
        except UnicodeDecodeError:
            pass
        japanese = decode_cp932(content)
        if japanese is not None:
            return japanese
        for codec in ("utf-8", "cp1252", "latin-1"):
            try:
                return content.decode(codec)
            except UnicodeDecodeError:
                continue
    try:
        return content.decode(enc, "replace")
    except LookupError:
        return content.decode("utf-8", "replace")


def _trim_partial_line(text: str) -> str:
    """Truncated body: cut at the last line break, so csv/ndjson yield only whole records."""
    i = text.rfind("\n")
    return text[: i + 1] if i > 0 else text


def _salvage_array_at(s: str, i: int, dec) -> tuple[list, int]:
    """Array elements starting at `s[i] == '['`, one by one via raw_decode up to the first
    break -> (whole elements, position)."""
    n, out = len(s), []
    i += 1
    while True:
        while i < n and s[i] in " \t\r\n,":
            i += 1
        if i >= n or s[i] == "]":
            return out, i + 1
        try:
            obj, i = dec.raw_decode(s, i)
        except ValueError:
            return out, i
        out.append(obj)


def _salvage_json(text: str):
    """Truncated json -> everything whole from its start. Array: whole elements; object: whole
    keys and, for a key with a cut-off array, the whole elements of that array (GeoJSON
    `features`, CKAN `result.records`, nested). Return None when no complete value remains."""
    import json as _j
    s = text.lstrip()
    dec = _j.JSONDecoder()

    def value_at(i: int):
        """(value, position, truncated?) - a whole value or a salvaged part of an array/object."""
        try:
            v, j = dec.raw_decode(s, i)
            return v, j, False
        except ValueError:
            pass
        if s[i] == "[":
            arr, j = _salvage_array_at(s, i, dec)
            return arr, j, True
        if s[i] == "{":
            return obj_at(i), len(s), True
        raise ValueError("cut off at a scalar")

    def obj_at(i: int) -> dict:
        n, out = len(s), {}
        i += 1
        while True:
            while i < n and s[i] in " \t\r\n,":
                i += 1
            if i >= n or s[i] == "}":
                return out
            try:
                key, i = dec.raw_decode(s, i)
            except ValueError:
                return out
            while i < n and s[i] in " \t\r\n":
                i += 1
            if i >= n or s[i] != ":":
                return out
            i += 1
            while i < n and s[i] in " \t\r\n":
                i += 1
            if i >= n:
                return out
            try:
                v, i, cut = value_at(i)
            except ValueError:
                return out
            out[key] = v
            if cut:
                return out

    if s.startswith("["):
        arr, _ = _salvage_array_at(s, 0, dec)
        return arr or None
    if s.startswith("{"):
        return obj_at(0) or None
    return None


def _salvage_json_array(text: str) -> list | None:
    """Truncated json array -> whole elements (wrapper over _salvage_json; object -> None)."""
    v = _salvage_json(text)
    return v if isinstance(v, list) else None


def _parse_truncated_text(text: str, ct: str) -> tuple[Any, str, str | None]:
    """Truncated text: cut at the last line break (csv/ndjson - whole records); json - salvage
    everything whole from the start; nothing whole - an honest None (otherwise csv detection
    takes json pieces for a table)."""
    text = _trim_partial_line(text)
    head = text.lstrip()[:1]
    if head in "[{" or "json" in (ct or "").lower():
        got = _salvage_json(text)
        if got is not None:
            return got, "json", None
        if head in "[{":
            return None, "json", text[:500000]
    return _parse_body(text, ct)


def _csv_with_shape(text: str, options: dict, truncated: bool) -> tuple[Any, str, None]:
    """Explicit source schema: preserve positional columns and every complete row."""
    import csv
    import io
    names = options.get('columns')
    delim = options.get('delimiter', ',')
    if (not isinstance(names, list) or len(names) < 2 or len(names) > 1024
            or any(not isinstance(n, str) or not n.strip() or any(ord(c) < 32 for c in n)
                   or '\ufffd' in n for n in names) or len(set(names)) != len(names)
            or delim not in (',', ';', '\t', '|') or options.get('header') is not False):
        raise ValueError('csv shape requires unique columns, delimiter and header=false')
    if '\x00' in text or re.match(r'\s*(?:<!doctype\s+html\b|<html(?:\s|>)|<\?xml\b)', text, re.I):
        return None, 'csv', None
    if text.lstrip().startswith('<'):
        import xml.etree.ElementTree as et
        try:
            et.fromstring(text)
            return None, 'csv', None
        except et.ParseError:
            pass
    elif text.lstrip().startswith(('{', '[')):
        import json
        try:
            json.loads(text)
            return None, 'csv', None
        except ValueError:
            pass
    if truncated and not text.endswith(('\r', '\n')):
        text = text[:max(text.rfind('\r'), text.rfind('\n')) + 1]
    rows = []
    try:
        for cells in csv.reader(io.StringIO(text, newline=''), delimiter=delim, strict=True):
            if not any(c.strip() for c in cells):
                continue
            if len(cells) != len(names):
                return None, 'csv', None
            rows.append(dict(zip(names, cells)))
            if len(rows) >= TABLE_ROW_LIMIT:
                break
    except csv.Error as exc:
        if not (truncated and str(exc) == 'unexpected end of data'):
            return None, 'csv', None
    return rows or None, 'csv', None


def _parse_text_table(text: str, ct: str, truncated: bool, recover: bool,
                      csv_options: dict | None) -> tuple[Any, str, str | None]:
    import os
    import csv
    if csv_options is not None:
        if not isinstance(csv_options, dict):
            raise ValueError('csv shape must be an object')
        return _csv_with_shape(text, csv_options, truncated)
    parsed = _parse_truncated_text(text, ct) if truncated else _parse_body(text, ct)
    if parsed[1] not in ('text', 'html') or not (recover or os.environ.get("ATLAS_CKAN_ROWS_PILOT") == '1'):
        return parsed
    # MIME labels can be wrong. Recover only an actual headed table, never prose,
    # markup or observations whose values would be mistaken for field names.
    if text.lstrip().startswith(('<', '{', '[')) or '\x00' in text:
        return parsed
    try:
        from . import tabular
        import io
        if tabular.sniff_kind(text.encode('utf-8'), '') != 'csv':
            return parsed
        delim = _csv_delimiter(text.splitlines())
        for cells in csv.reader(io.StringIO(text, newline=''), delimiter=delim, strict=True):
            filled = [c.strip() for c in cells if c.strip()]
            if len(filled) < 2:
                continue
            numeric = [c for c in filled if tabular.is_numberish(c)]
            year_header = len(numeric) >= 2 and all(tabular._is_year(c) for c in numeric)
            if ((tabular.is_numberish(filled[0]) and not year_header)
                    or sum(not tabular._is_year(c) for c in numeric) >= 2):
                return parsed
            break
        else:
            return parsed
        if truncated and not text.endswith(('\r', '\n')):
            text = text[:max(text.rfind('\r'), text.rfind('\n')) + 1]
        rows = tabular.csv_records(text, n=TABLE_ROW_LIMIT)
        if (rows and not (len(rows) == 1 and list(rows[0]) == ['columns'])
                and len(rows[0]) >= 2
                and not any('\ufffd' in str(k) or '\x00' in str(k) for k in rows[0])):
            return rows, 'csv', None
    except (ImportError, csv.Error, ValueError, TypeError):
        pass
    return parsed


def _parse_bytes(content: bytes, ct: str, url: str = "", truncated: bool = False,
                 recover_text_encoding: bool = False,
                 csv_options: dict | None = None) -> tuple[Any, str, str | None]:
    """Body (bytes) -> (payload, format, raw_text). Binary tabular body goes to _parse_table;
    an archive body (.gz/.zip) is unpacked BEFORE parsing, otherwise decoding mangles the binary."""
    if (not content.startswith((b'PK\x03\x04', b'\x1f\x8b'))
            and is_px_text(content[:65536].decode("ascii", "replace"))):
        return px_records(content), "px", None
    if content[:5] == b"%PDF-":
        return None, "pdf", None
    if content[:4] == b"PK\x03\x04":
        import io, zipfile
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as archive:
                names = [n.lower() for n in archive.namelist() if not n.endswith('/')]
            if names and all(n.endswith('.pdf') for n in names):
                return None, "pdf_archive", None
            readable = ('.csv', '.tsv', '.json', '.jsonl', '.ndjson', '.xml', '.px', '.xlsx', '.xls', '.ods', '.dbf')
            if (any(n.endswith('.tab') for n in names) and any(n.endswith('.map') for n in names)
                    and not any(n.endswith(readable) for n in names)
                    and not any(n.endswith('.txt') and n.rsplit('/', 1)[-1] not in ('log.txt', 'readme.txt') for n in names)):
                return None, "mapinfo_archive", None
        except (zipfile.BadZipFile, OSError):
            pass
    _tk = _table_kind(content, url)
    if _tk:
        return _parse_table(content, _tk, ct)
    if content[:2] == b"\x1f\x8b" or content[:4] == b"PK\x03\x04":
        body, ct2 = _decompress(content, ct, url, recover_text_encoding)
        if ct2 == 'application/x-pcaxis':
            return parse_px(body), 'px', None
        return _parse_text_table(body, ct2, truncated, recover_text_encoding, csv_options)
    text = _decode_text(content, ct, recover_text_encoding)
    return _parse_text_table(text, ct, truncated, recover_text_encoding, csv_options)


def _parse(r: httpx.Response) -> tuple[Any, str, str | None]:
    """httpx.Response (already read) -> (payload, format, raw_text). Wrapper over _parse_bytes."""
    return _parse_bytes(r.content, r.headers.get("content-type") or "", str(r.url))


def _csv_delimiter(lines: list[str]) -> str:
    """CSV delimiter from the first lines: the one of `, ; tab |` that appears in the header line and in
    at least 60% of the first lines, with the most columns in the header. Not "in every line": a quoted
    value with an embedded line break gives a line with no delimiter at all.
    A comma inside values (`"Dew pt, C"`) loses on header column count; a trailing `;` on every
    PC-Axis line passes but yields a one-cell header, which the caller filters out."""
    rows = [ln for ln in lines if ln.strip()][:20]
    if not rows:
        return ","
    best, best_key = ",", (0.0, 0)
    for d in (",", ";", "\t", "|"):
        # the header may not be first: GENESIS/Destatis-style files have up to eight title lines
        # without a delimiter, then the table with `;`
        in_head = max(ln.count(d) for ln in rows[:8])
        if in_head < 1:
            continue
        # ratio is taken from the first line with a delimiter, so a title above the table does not dilute it
        _from = next(i for i, ln in enumerate(rows) if d in ln)
        share = sum(1 for ln in rows[_from:] if d in ln) / len(rows[_from:])
        if share < 0.6:
            continue
        key = (in_head, share)
        if key > best_key:
            best, best_key = d, key
    return best


def _csv_skip_title(lines: list[str], delim: str, max_skip: int = 8) -> int:
    """How many lines to skip before the header: a table title in one cell with a `;;;;` tail
    (e.g. "15.1.2.13. Egyes ...;;;;;;;;") - the table starts at the line with >= 2
    non-empty cells. Nothing suitable in the first max_skip+1 lines - 0 (caller decides)."""
    import csv as _csv
    import io as _io
    for i, ln in enumerate(lines[: max_skip + 1]):
        try:
            cells = next(_csv.reader(_io.StringIO(ln), delimiter=delim), [])
        except Exception:
            return 0
        if sum(1 for c in cells if (c or "").strip()) >= 2:
            return i
    return 0


def _parse_body(body: str, ct: str = "") -> tuple[Any, str, str | None]:
    """(body, content-type) -> (payload, format, raw_text). Core of the multi-format parse -
    shared by the httpx path and the playwright tier (render returns a string, not a Response). Any api,
    not json-only: json->dict/list · xml/rss/atom->dict · csv->list[dict] · otherwise->text."""
    if is_px_text(body):
        return parse_px(body), "px", None
    ct = (ct or "").lower()
    head = body.lstrip()[:6].lower()
    if "json" in ct or (head[:1] in "{[" if head else False):
        try:
            import json as _j
            return _j.loads(body), "json", None
        except Exception:
            pass
    # NDJSON (one JSON object per line) - CommonCrawl CDX, streaming APIs. Not csv, not a json array.
    if head[:1] == "{" or "ndjson" in ct or "x-ndjson" in ct:
        import json as _j
        _lines = [ln for ln in body.splitlines() if ln.strip()]
        if len(_lines) > 1:
            try:
                recs = [_j.loads(ln) for ln in _lines]
                return recs, "json", None
            except Exception:
                pass
    raw = body[:500000]
    if "html" in ct or head.startswith(("<!doc", "<html")):
        return body, "html", raw
    if "xml" in ct or "rss" in ct or "atom" in ct or head.startswith("<?xml") or head[:1] == "<":
        try:
            import xml.etree.ElementTree as ET
            # leading whitespace/newline/BOM before `<?xml` makes ET fail (the declaration must be at
            # the very start) - strip it; otherwise an RSS feed with a leading \n fell through to text.
            _xml = body.lstrip("﻿ \t\r\n")
            # ET.fromstring(str) with `encoding="..."` in the XML declaration -> ValueError ("Unicode strings
            # with encoding declaration are not supported"), so valid XML (gov-XML) silently fell through
            # to text. The string is ALREADY decoded by httpx per the HTTP charset -> strip the encoding
            # attribute from the declaration (do not re-encode to bytes: ET would reinterpret the bytes
            # per the declared encoding -> silent corruption of non-utf8).
            if _xml.startswith("<?xml"):
                _decl_end = _xml.find("?>")
                if _decl_end != -1:
                    _xml = re.sub(r'\s+encoding=["\'][^"\']*["\']', "", _xml[:_decl_end]) + _xml[_decl_end:]
            try:
                return _xml_obj(ET.fromstring(_xml)), "xml", raw
            except ET.ParseError:
                # common gov-XML defect: a raw `&` in a URL/text instead of `&amp;` -> not well-formed.
                # Escape ONLY unescaped `&` and retry once; valid XML never gets here (the first parse
                # would have passed).
                _xml2 = re.sub(r"&(?!amp;|lt;|gt;|quot;|apos;|#[0-9]+;|#x[0-9a-fA-F]+;)", "&amp;", _xml)
                return _xml_obj(ET.fromstring(_xml2)), "xml", raw
        except Exception:
            pass
    if ("csv" in ct or "tab-separated" in ct
            or (head[:1] != "<" and "\n" in body and any(s in body for s in (",", ";", "\t", "|")))):
        try:
            import csv as _csv
            import io as _io
            import re as _re2
            # BOM at the start of the body: otherwise the first column name arrives as "\ufeffjahr"
            body = body.lstrip("\ufeff")
            # strip leading #-comments and empty lines (Tor metrics, NOAA gov-CSV, RFC feeds):
            # otherwise DictReader takes "# URL: ..." as the header and loses the table.
            _bl = body.split("\n")
            _di = 0
            while _di < len(_bl) and (not _bl[_di].strip() or _bl[_di].lstrip().startswith("#")):
                _di += 1
            if _di:
                body = "\n".join(_bl[_di:])
            # Delimiter from the first lines, not "always comma": European csv files that use `;`
            # were otherwise returned as text.
            _delim = _csv_delimiter(_bl[_di:_di + 20])
            _skip = _csv_skip_title(_bl[_di:_di + 20], _delim)
            if _skip:
                body = "\n".join(_bl[_di + _skip:])
            _sio = _io.StringIO(body)
            _first = next(_csv.reader(_io.StringIO(body), delimiter=_delim), None)
            # a header with a single non-empty cell is not a table (PC-Axis `CHARSET="ANSI";`, a report
            # title with a `;;;;` tail)
            if not _first or sum(1 for _c in _first if (_c or "").strip()) < 2:
                return body, "text", raw
            # headerless CSV (topsite lists `rank,domain`, routes.dat): a bare number in the first cell
            # means data, not a header. Generate column names so no row is lost.
            _headerless = bool(_first) and len(_first) > 1 and \
                bool(_re2.fullmatch(r"-?\d+", (_first[0] or "").strip()))
            if _headerless:
                _n = len(_first)
                _names = ["rank", "domain"] if _n == 2 else [f"col{_k}" for _k in range(_n)]
                _dr = _csv.DictReader(_sio, fieldnames=_names, delimiter=_delim)
            else:
                _dr = _csv.DictReader(_sio, delimiter=_delim)
            rows = []
            for _i, _row in enumerate(_dr):
                if _i >= 200_000:  # cap against 10M-row dumps (rank-ordered topsite lists)
                    break
                rows.append(_row)
            if ((rows and len(rows[0]) > 1)
                    or not rows and not _headerless and ("csv" in ct or "tab-separated" in ct)):
                return rows, "csv", raw
        except Exception:
            pass
    return body, "text", raw


def _scrape_field(el, sel: str):
    """Extract a field from a row element. `sel` is a CSS selector relative to row; the `@attr`
    suffix takes an attribute (e.g. `a@href`), empty sel is the row itself. Otherwise text."""
    attr = None
    if "@" in sel:
        sel, attr = sel.rsplit("@", 1)
        sel, attr = sel.strip(), attr.strip()
    target = el if not sel else el.select_one(sel)
    if target is None:
        return None
    if attr:
        return target.get(attr)
    return target.get_text(" ", strip=True) or None


def _clean_html(s: str) -> str:
    """HTML fragment -> plain text: strip tags, decode entities, collapse whitespace."""
    import html as _html
    import re as _re
    s = _re.sub(r"<[^>]+>", " ", s or "")
    return _re.sub(r"\s+", " ", _html.unescape(s)).strip()


def _scrape_regex(sc: dict, payload: str, raw):
    """Regex scrape: markup that a CSS selector cannot address - gov tables label->value in
    adjacent `<td>`, blocks delimited by HTML comments (`<!--rs-->...<!--re-->`).
    `regex_fields`/`fields_regex` = {name: pat with 1 group}. With `block_regex` (1 group = block
    body) -> one record per block (list); without it -> one record for the whole page. Values
    go through _clean_html. Returns (list[dict], "scrape", raw), like the CSS path."""
    import re as _re
    fields = sc.get("fields_regex") or sc.get("regex_fields") or {}

    def _one(block: str) -> dict:
        rec = {}
        for k, pat in fields.items():
            m = _re.search(pat, block, _re.DOTALL | _re.IGNORECASE)
            rec[k] = _clean_html(m.group(1)) if m else None
        return rec

    blk = sc.get("block_regex")
    recs = []
    if blk:
        for m in _re.finditer(blk, payload, _re.DOTALL):
            body = m.group(1) if m.groups() else m.group(0)
            rec = _one(body)
            if any(v not in (None, "") for v in rec.values()):
                recs.append(rec)
                if len(recs) >= int(sc.get("limit") or 100):
                    break
    else:
        rec = _one(payload)
        if any(v not in (None, "") for v in rec.values()):
            recs.append(rec)
    return recs, "scrape", raw


def _apply_scrape(ep: dict, payload, fmt: str, raw):
    """Declarative HTML scrape: endpoint.scrape={row:<css>, fields:{name:<css[@attr]>}}
    → list[dict] of records. HTML is already fetched by the engine (_parse); this only extracts (bs4).
    regex_fields/block_regex mode (see _scrape_regex) is for markup not addressable by CSS.
    No scrape / not HTML text → return as is (the engine stays multiformat)."""
    sc = ep.get("scrape")
    if not sc or not isinstance(payload, str) or fmt not in ("html", "text"):
        return payload, fmt, raw
    if sc.get("regex_fields") or sc.get("fields_regex") or sc.get("block_regex"):
        try:
            return _scrape_regex(sc, payload, raw)
        except Exception:
            return payload, fmt, raw
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(payload, "html.parser")
        row_sel = sc.get("row") or sc.get("rows")
        fields = sc.get("fields") or {}
        rows = soup.select(row_sel) if row_sel else [soup]
        recs = []
        for el in rows:
            if fields:
                rec = {k: _scrape_field(el, s) for k, s in fields.items()}
                if any(v not in (None, "") for v in rec.values()):
                    recs.append(rec)
            else:
                txt = el.get_text(" ", strip=True)
                if txt:
                    recs.append({"text": txt})
        return recs, "scrape", raw
    except Exception:
        return payload, fmt, raw


def _apply_extract_json(ep: dict, payload, fmt: str, raw):
    """SSR sites often inline data into a JS variable (`var receivers = [...]`) —
    a machine endpoint under a human page. endpoint.extract_json={regex:<pat with 1 group>}
    → json.loads(group) as payload; response_path/_dig then work as usual.
    No extract_json / not HTML text → as is. Runs in the chain BEFORE _apply_scrape."""
    ej = ep.get("extract_json")
    if not ej or not isinstance(payload, str) or fmt not in ("html", "text"):
        return payload, fmt, raw
    import re as _re
    import json as _j
    pat = ej.get("regex") if isinstance(ej, dict) else ej
    if not pat:
        return payload, fmt, raw
    try:
        m = _re.search(pat, payload, _re.DOTALL)
        if not m:
            return payload, fmt, raw
        return _j.loads(m.group(1)), "json", raw
    except Exception:
        return payload, fmt, raw


def _apply_extract_rows(ep: dict, payload, fmt: str, raw):
    """Plain-text feed without markup (NMDB neutron ASCII, `;`/whitespace tables under a
    `# comment` header): endpoint.extract_rows={regex:<pat with N groups>, fields:[names]}
    → list[dict] line by line. Non-matching lines (header/blank) are skipped. Chained
    like extract_json; touches only text/html, leaves json/xml/csv alone."""
    er = ep.get("extract_rows")
    if not er or not isinstance(payload, str) or fmt not in ("text", "html"):
        return payload, fmt, raw
    import re as _re
    pat = er.get("regex") if isinstance(er, dict) else er
    names = (er.get("fields") if isinstance(er, dict) else None) or []
    if not pat:
        return payload, fmt, raw
    try:
        rx = _re.compile(pat)
    except _re.error:
        return payload, fmt, raw
    recs = []
    for line in payload.splitlines():
        m = rx.match(line.strip())
        if not m:
            continue
        g = m.groups()
        if names:
            recs.append({names[i]: g[i] for i in range(min(len(names), len(g)))})
        else:
            recs.append({"value": g[0] if g else line.strip()})
    return (recs, "rows", raw) if recs else (payload, fmt, raw)


# ─────────────────────────────────────────────────────────────────────────────
# Sync and async fetches share retry timing for transient errors and Retry-After.
# ─────────────────────────────────────────────────────────────────────────────
def _retry_delay(r, attempt: int) -> float:
    ra = r.headers.get("Retry-After")
    try:
        return min(float(ra), 5.0) if ra else (0.8 * (attempt + 1))
    except (TypeError, ValueError):
        return 0.8 * (attempt + 1)


def _empty_on(ep: dict, status: int) -> bool:
    """Is this status, for THIS endpoint, a legitimate "no relation/resource" rather than a failure?
    Only via a manifest flag on a specific relationship endpoint — NOT blanket.
    GLEIF /ultimate-parent returns 404 for a standalone entity (no parent) — that is
    a valid answer, not a dead source. `empty_on_status: [404]` (or legacy
    `allow_404: true`) → return an empty result instead of raising HTTPStatusError."""
    codes = ep.get("empty_on_status") or ([] if not ep.get("allow_404") else [404])
    try:
        return int(status) in {int(c) for c in codes}
    except (TypeError, ValueError):
        return False


def _empty_response(ep: dict, status: int, body: bytes, interrupted: str | None) -> bool:
    if status == 429 or interrupted:
        return False
    if _empty_on(ep, status):
        return True
    rule = ep.get("empty_on_response")
    if (not isinstance(rule, dict) or type(rule.get("status")) is not int
            or rule["status"] != status):
        return False
    expected = rule.get("json_fields")
    if (not isinstance(expected, dict) or not expected
            or any(not isinstance(path, str) or not path or value is None
                   for path, value in expected.items())):
        return False
    import json
    try:
        payload = json.loads(body)
    except (ValueError, UnicodeError):
        return False
    return all(_dig(payload, path) == value for path, value in expected.items())


_ABSENT = object()


def _render_body(tpl: Any, args: dict) -> tuple[Any, set]:
    """`endpoint.body_template` → (POST body, names of parameters consumed by the body).

    Why. A flat parameter dict cannot express the body that search POST APIs expect:
    TED takes `fields` only as a list (string '["a","b"]' → 400), EURES takes keywords as a list
    of objects `[{"keyword": …, "specificSearchCode": "EVERYWHERE"}]`, Contracts Finder a keyword
    inside `searchCriteria`. The template is the whole body; a call value replaces `{name}`.

    Rules: a string that is exactly `{name}` gets the value as is (string, number, list); a string
    with surrounding text gets textual substitution. No value (parameter not passed, no default) —
    the leaf drops out: the dict key is removed, the list item is removed, and a dict item of a list
    drops entirely if anything inside it was missing (the server rejects a keyword object without
    a keyword). Everything else in the template is constant body content."""
    used: set = set()

    def val(name: str):
        v = args.get(name)
        return _ABSENT if v in (None, "", []) else v

    def walk(node, in_list: bool):
        """(value | _ABSENT, whether something inside was missing)."""
        if isinstance(node, str):
            names = _PATH_PARAM.findall(node)
            if not names:
                return node, False
            whole = _PATH_PARAM.fullmatch(node)
            if whole:
                v = val(whole.group(1))
                if v is _ABSENT:
                    return _ABSENT, True
                used.add(whole.group(1))
                return v, False
            out = node
            for n in names:
                v = val(n)
                if v is _ABSENT:
                    return _ABSENT, True
                used.add(n)
                out = out.replace("{" + n + "}", str(v))
            return out, False
        if isinstance(node, list):
            items, lost = [], False
            for x in node:
                w, miss = walk(x, True)
                lost = lost or miss
                if w is not _ABSENT:
                    items.append(w)
            return items, lost
        if isinstance(node, dict):
            out, lost = {}, False
            for k, x in node.items():
                w, miss = walk(x, False)
                lost = lost or miss
                if w is not _ABSENT:
                    out[k] = w
            if in_list and lost:
                return _ABSENT, True
            return out, lost
        return node, False

    body, _ = walk(tpl, False)
    return ({} if body is _ABSENT else body), used


def _post_kwargs(ep: dict, args: dict) -> dict:
    """POST body: json (default) or form-urlencoded. Legacy/gov APIs, WordPress
    admin-ajax and OAuth token endpoints require application/x-www-form-urlencoded —
    then endpoint.body_encoding='form' (alias post_form=true, or Content-Type
    in static_headers) → httpx encodes the dict as a form body instead of JSON.

    `body_template` — templated body (`_render_body`); parameters not consumed by the body
    go to the query string."""
    # raw_body: raw POST body (text/plain etc.) SEPARATE from the query. param_defaults/baked query
    # go as query parameters (params=), body = raw_body as is (Content-Type from static_headers).
    # For APIs that split query (collection/limit/skip) and body (Mongo filter as a raw string):
    # EAEU tech.eaeunion.org/spd/find (json→415, filter strictly text/plain, pagination strictly in query).
    rb = ep.get("raw_body")
    if rb is not None:
        import json as _json
        body = rb if isinstance(rb, str) else _json.dumps(rb, ensure_ascii=False)
        return {"params": args, "content": body}
    tpl = ep.get("body_template")
    if tpl is not None:
        body, used = _render_body(tpl, args)
        rest = {k: v for k, v in args.items() if k not in used}
        return {"params": rest or None, "json": body}
    enc = (ep.get("body_encoding") or ("form" if ep.get("post_form") else "json")).lower()
    ct = " ".join(str(v).lower() for k, v in (ep.get("static_headers") or {}).items()
                  if k.lower() == "content-type")
    if enc == "form" or "x-www-form-urlencoded" in ct:
        return {"data": args}
    return {"json": args}


_RETRY_STATUSES = (429, 502, 503, 504)
_ERROR_BODY_CAP = 1 << 20   # error body is for diagnostics only; read at most one megabyte


def _finish(ep: dict, body: bytes, ct: str, final_url: str, why: str | None) -> _Fetched:
    try:
        parsed = _parse_bytes(body, ct, final_url, truncated=why is not None,
                              recover_text_encoding=bool(ep.get("recover_text_encoding")),
                              csv_options=ep.get('csv'))
    except ResourceLimitError as error:
        return _fetched((None, "archive", None), error.reason, len(body))
    if parsed[1] == "json" and isinstance(parsed[0], dict):
        msg = _refusal_in_body(parsed[0])
        if msg:   # provider itself declared failure — no records here, whatever the lists contain
            f = _fetched(parsed, why, len(body))
            f.refusal, f.refusal_kind = msg, _refusal_kind(msg)
            return f
    parsed = _apply_scrape(ep, *_apply_extract_rows(ep, *_apply_extract_json(ep, *parsed)))
    return _fetched(parsed, why, len(body))


class _FtpTransfer:
    """Thread-safe cancellation handoff for an anonymous FTP worker."""
    def __init__(self):
        self.stopped = threading.Event()
        self.lock = threading.Lock()
        self.connections = []

    @staticmethod
    def close(connection):
        # shutdown wakes a recv blocked in another thread; close alone need not.
        for stream in (getattr(connection, "sock", None), connection):
            shutdown = getattr(stream, "shutdown", None)
            if shutdown is not None:
                try:
                    shutdown(2)  # socket.SHUT_RDWR, without importing dependencies globally
                except OSError:
                    pass
        try:
            connection.close()
        except OSError:
            pass

    def register(self, connection):
        with self.lock:
            cancelled = self.stopped.is_set()
            if not cancelled:
                self.connections.append(connection)
        if cancelled:
            self.close(connection)
            raise httpx.ReadError("FTP transfer cancelled")

    def cancel(self):
        self.stopped.set()
        with self.lock:
            connections = self.connections[:]
        for connection in connections:
            self.close(connection)


def _ftp_download(ep: dict, args: dict, url: str,
                  _transfer: _FtpTransfer | None = None) -> tuple[bytes, dict[str, Any], str | None]:
    with _RequestSlot():
        return _ftp_download_inner(ep, args, url, _transfer)


def _ftp_download_inner(ep: dict, args: dict, url: str,
                  _transfer: _FtpTransfer | None = None) -> tuple[bytes, dict, str | None]:
    """Bounded anonymous binary FTP GET. No credentials, query or protocol fallback.

    This stdlib transport is embedded in rendered clients with the canonical parser.
    The same absolute budget covers setup, each FTP command and each data read. Partial
    transfers close both sockets immediately; QUIT/ABOR would add an unbounded wait.
    """
    import ftplib as _ftp
    import ipaddress as _ip
    import math as _math
    import socket as _socket
    from urllib.parse import unquote as _unquote

    if not isinstance(url, str) or any(ord(c) < 32 or ord(c) == 127 for c in url):
        raise httpx.UnsupportedProtocol("FTP URL contains control characters")
    try:
        parts = urlsplit(url)
        host, port = parts.hostname, parts.port if parts.port is not None else 21
        path = _unquote(parts.path, encoding="utf-8", errors="strict")
        if (parts.scheme != "ftp" or parts.username is not None or parts.password is not None
                or "?" in url or "#" in url or not host or not 1 <= port <= 65535
                or not path.startswith("/") or path.endswith("/")
                or any(ord(c) < 32 or ord(c) == 127 for c in path)):
            raise ValueError("invalid anonymous FTP URL")
        host = host.encode("idna").decode("ascii")
        try:
            _ip.ip_address(host)
        except ValueError:
            labels = host.rstrip(".").split(".")
            if len(host) > 253 or not all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", s)
                                         for s in labels):
                raise ValueError("invalid FTP hostname")
    except (ValueError, UnicodeError) as exc:
        raise httpx.UnsupportedProtocol("invalid anonymous FTP URL") from exc
    if (ep.get("method") or "GET").upper() != "GET" or args:
        raise httpx.UnsupportedProtocol("FTP supports anonymous GET without query arguments")

    cap, deadline = _limits_of(ep)
    timeout = float(ep.get("timeout") or DEFAULT_TIMEOUT)
    if not _math.isfinite(timeout) or timeout <= 0:
        timeout = DEFAULT_TIMEOUT
    started, phase, command = _now(), "connect", None
    ftp, data = None, None
    body, why = bytearray(), None
    request = httpx.Request("GET", url)
    transfer = _transfer or _FtpTransfer()

    class _Deadline(Exception):
        pass

    def budget():
        if transfer.stopped.is_set():
            raise httpx.ReadError("FTP transfer cancelled", request=request)
        remaining = deadline - (_now() - started)
        if remaining <= 0:
            raise _Deadline()
        bounded = min(timeout, remaining)
        if ftp is not None:
            ftp.timeout = bounded
            if ftp.sock is not None:
                ftp.sock.settimeout(bounded)
        return bounded

    class _BoundedFTP(_ftp.FTP):
        # ftplib's multiline replies and passive setup can issue several socket
        # operations inside a single method. Refresh their budget at each command/line.
        def putline(self, line):
            nonlocal command
            budget()
            command = line.split(" ", 1)[0].upper()
            return super().putline(line)

        def makepasv(self):
            address = super().makepasv()
            budget()  # PASV's reply wait consumed time before the data TCP connect.
            return address

        def getline(self):
            # A buffered readline only enforces an inactivity timeout; a drip-fed
            # reply can otherwise outlive the absolute deadline. Read bounded
            # chunks directly and retain bytes belonging to the next reply line.
            buffer = getattr(self, "_atlas_reply_buffer", b"")
            while b"\n" not in buffer:
                if len(buffer) > self.maxline:
                    raise _ftp.error_proto("FTP response line too long")
                budget()
                chunk = self.sock.recv(min(4096, self.maxline + 1 - len(buffer)))
                if not chunk:
                    if not buffer:
                        raise EOFError()
                    break
                buffer += chunk
            line, separator, tail = buffer.partition(b"\n")
            if len(line) + len(separator) > self.maxline:
                raise _ftp.error_proto("FTP response line too long")
            self._atlas_reply_buffer = tail
            return line.rstrip(b"\r").decode(self.encoding)

    try:
        ftp = _BoundedFTP()
        transfer.register(ftp)
        # create_connection otherwise repeats its original timeout for every A/AAAA
        # address. Resolve once and start each numeric attempt with a fresh budget.
        # The platform getaddrinfo call itself cannot be interrupted by socket timeout.
        addresses = _socket.getaddrinfo(host, port, type=_socket.SOCK_STREAM)
        # Same public-only rule as HTTP; we connect to exactly these resolved addresses.
        if not _private_allowed():
            for *_, address in addresses:
                if _non_public(str(address[0])):
                    raise BlockedAddress("refused: %s resolves to non-public address %s"
                                         % (host, address[0]), request=request)
        seen, last_connect_error = set(), None
        for family, _, _, _, address in addresses:
            if family not in (_socket.AF_INET, _socket.AF_INET6):
                continue
            numeric = address[0]
            if family == _socket.AF_INET6 and len(address) > 3 and address[3] and '%' not in numeric:
                numeric += '%' + str(address[3])
            if numeric in seen:
                continue
            seen.add(numeric)
            try:
                ftp.connect(numeric, port, timeout=budget())
                break
            except OSError as exc:
                # A failed greeting after a socket was opened is a protocol failure,
                # not a reason to reconnect through another address.
                if getattr(ftp, "sock", None) is not None:
                    raise
                last_connect_error = exc
        else:
            raise last_connect_error or OSError("FTP hostname has no TCP addresses")
        phase = "login"
        budget()
        ftp.login(user="anonymous", passwd="anonymous@")
        budget()
        ftp.set_pasv(True)
        ftp.voidcmd("TYPE I")
        phase = "transfer"
        budget()
        data = ftp.transfercmd("RETR " + path)
        transfer.register(data)
        phase = "read"
        operation = _CURRENT_DEADLINE.get()
        if operation is not None:
            operation.good_response = True
            operation.url, operation.content_type = url, "application/octet-stream"
            operation.body = body  # Share the bounded buffer; do not copy it after every read.
        while True:
            data.settimeout(budget())
            chunk = data.recv(min(_CHUNK, cap - len(body) + 1))
            left = cap - len(body)
            body.extend(chunk[:left])
            if len(chunk) > left:
                why = "body_cap"
                break
            if _now() - started >= deadline:
                why = "deadline"
                break
            if not chunk:
                data.close()
                data = None
                phase = "completion"
                budget()
                ftp.voidresp()
                break
    except _Deadline as exc:
        if phase == "read":
            why = "deadline"
        else:
            error = httpx.ConnectTimeout if phase == "connect" else httpx.ReadTimeout
            raise error("FTP deadline exhausted during " + phase, request=request) from exc
    except _socket.timeout as exc:
        if phase == "read" and _now() - started >= deadline:
            why = "deadline"
        else:
            error = httpx.ConnectTimeout if phase == "connect" else httpx.ReadTimeout
            raise error("FTP timeout during " + phase, request=request) from exc
    except _ftp.error_perm as exc:
        # 550 also means permission denied: only an explicit missing-file response
        # is eligible for a confirmed-gone verdict during read-only verification.
        if (phase == "transfer" and command == "RETR" and str(exc).startswith("550")
                and re.search(r"no such file|not found|does not exist", str(exc), re.I)):
            response = httpx.Response(404, request=request)
            raise httpx.HTTPStatusError("FTP file not found", request=request, response=response) from exc
        raise httpx.RemoteProtocolError("FTP refused " + phase, request=request) from exc
    except (OSError, EOFError, UnicodeError, _ftp.Error) as exc:
        error = httpx.ConnectError if phase == "connect" else httpx.RemoteProtocolError
        raise error("FTP transport failed during " + phase, request=request) from exc
    finally:
        for connection in (data, ftp):
            if connection is not None:
                try:
                    connection.close()
                except OSError:
                    pass
    meta = {"code": 226 if why is None else None, "transport": "ftp",
            "content_type": "application/octet-stream", "final_url": url,
            "length": None, "waf_action": None}
    return bytes(body), meta, why


def _finish_download(ep, fetched):
    if isinstance(fetched, _Fetched):
        return fetched
    body, content_type, url, why, status = fetched
    if status is not None and _empty_response(ep, status, body, why):
        return _fetched((None, "empty", None), None, 0)
    return _finish(ep, body, content_type, url, why)


async def _afetch(c: httpx.AsyncClient, ep: dict, args: dict, url: str) -> _Fetched:
    try:
        fetched = await _async_deadline_call(_afetch_inner(c, ep, args, url), _limits_of(ep)[1])
    except _DeadlineExpired as error:
        if urlsplit(url).scheme.lower() == "ftp" and not error.budget.good_response:
            raise httpx.ReadTimeout("FTP request deadline exceeded") from None
        return _deadline_result(ep, error.budget)
    return _finish_download(ep, fetched)


async def _afetch_inner(c: httpx.AsyncClient, ep: dict, args: dict, url: str) -> _Fetched:
    """Stream an async response with transient retries, a byte cap and a deadline."""
    import asyncio as _aio
    if urlsplit(url).scheme.lower() == "ftp":
        transfer = _FtpTransfer()
        worker = _aio.create_task(_aio.to_thread(_ftp_download, ep, args, url, transfer))
        try:
            body, meta, why = await _aio.shield(worker)
        except _aio.CancelledError:
            transfer.cancel()
            # The caller must not wait for a pending OS connect/resolver to return.
            # Consume the stopped worker's later exception without losing cleanup.
            def drain(completed):
                if not completed.cancelled():
                    completed.exception()
            worker.add_done_callback(drain)
            raise
        return body, meta["content_type"], meta["final_url"], why, None
    post = (ep.get("method") or "GET").upper() == "POST"
    access = _access_of(ep)
    host = urlsplit(url).netloc
    cap, deadline = _limits_of(ep)
    t0 = _now()
    if access:
        await _access_wait_async(host, access)
    last = None
    for attempt in range(3):
        _deadline_check()
        try:
            headers = {"Accept-Encoding": "gzip, deflate"}
            req = (_stream_async(c, "POST", url, headers=headers, **_post_kwargs(ep, args)) if post
                   else _stream_async(c, "GET", url, headers=headers, params=args))
            async with _RequestSlot(), req as r:
                status = r.status_code
                ok = r.is_success
                _CURRENT_DEADLINE.get().capture_response(r)
                body, why = await _capped_body_async(
                    _http_chunks_async(r, cap if ok else min(cap, _ERROR_BODY_CAP)),
                    t0, cap if ok else min(cap, _ERROR_BODY_CAP), deadline)
                ct, final_url = r.headers.get("content-type") or "", str(r.url)
                snap = r if ok else _snapshot(r, body)
        except (httpx.ConnectTimeout, httpx.ReadTimeout, httpx.WriteTimeout,
                httpx.PoolTimeout, httpx.ConnectError):
            if attempt < 2:
                await _aio.sleep(0.8 * (attempt + 1))
                continue
            raise
        if not ok and _empty_response(ep, status, body, why):
            return _fetched((None, "empty", None), None, 0)
        if status == 429 or (not ok and ep.get("stop_on_http_error")):
            if access:
                _access_note_status(host, status, access)
            snap.raise_for_status()
        if status in _RETRY_STATUSES and attempt < 2:
            last = snap
            await _aio.sleep(_retry_delay(snap, attempt))
            continue
        if access:
            _access_note_status(host, status, access)  # final 429/420 → penalty box
        if not ok:
            snap.raise_for_status()
        return body, ct, final_url, why, status
    if last is not None:
        if access:
            _access_note_status(host, last.status_code, access)
        last.raise_for_status()
    raise RuntimeError("unreachable")


def _fetch(c: httpx.Client, ep: dict, args: dict, url: str) -> _Fetched:
    try:
        fetched = _sync_deadline_call(lambda: _fetch_inner(c, ep, args, url), _limits_of(ep)[1])
    except _DeadlineExpired as error:
        if urlsplit(url).scheme.lower() == "ftp" and not error.budget.good_response:
            raise httpx.ReadTimeout("FTP request deadline exceeded") from None
        return _deadline_result(ep, error.budget)
    return _finish_download(ep, fetched)


def _fetch_inner(c: httpx.Client, ep: dict, args: dict, url: str) -> _Fetched:
    """sync single call with transient retry — twin of _afetch for the standalone client. The body
    is streamed up to a byte cap / deadline, see _limits_of."""
    if urlsplit(url).scheme.lower() == "ftp":
        transfer = _FtpTransfer()
        budget = _CURRENT_DEADLINE.get()
        with budget.lock:
            budget.abort_callbacks.append(transfer.cancel)
        body, meta, why = _ftp_download(ep, args, url, transfer)
        return body, meta["content_type"], meta["final_url"], why, None
    post = (ep.get("method") or "GET").upper() == "POST"
    access = _access_of(ep)
    host = urlsplit(url).netloc
    cap, deadline = _limits_of(ep)
    t0 = _now()
    took = _access_acquire_sync(host, access) if access else False
    try:
        last = None
        for attempt in range(3):
            _deadline_check()
            try:
                headers = {"Accept-Encoding": "gzip, deflate"}
                req = (_stream_sync(c, "POST", url, headers=headers, **_post_kwargs(ep, args)) if post
                       else _stream_sync(c, "GET", url, headers=headers, params=args))
                with _RequestSlot(), req as r:
                    status = r.status_code
                    ok = r.is_success
                    _CURRENT_DEADLINE.get().capture_response(r)
                    body, why = _capped_body_sync(
                        _http_chunks_sync(r, cap if ok else min(cap, _ERROR_BODY_CAP)),
                        t0, cap if ok else min(cap, _ERROR_BODY_CAP), deadline)
                    ct, final_url = r.headers.get("content-type") or "", str(r.url)
                    snap = r if ok else _snapshot(r, body)
            except (httpx.ConnectTimeout, httpx.ReadTimeout, httpx.WriteTimeout,
                    httpx.PoolTimeout, httpx.ConnectError):
                if attempt < 2:
                    _deadline_sleep(0.8 * (attempt + 1))
                    continue
                raise
            if not ok and _empty_response(ep, status, body, why):
                return _fetched((None, "empty", None), None, 0)
            if status == 429 or (not ok and ep.get("stop_on_http_error")):
                if access:
                    _access_note_status(host, status, access)
                snap.raise_for_status()
            if status in _RETRY_STATUSES and attempt < 2:
                last = snap
                _deadline_sleep(_retry_delay(snap, attempt))
                continue
            if access:
                _access_note_status(host, status, access)  # final 429/420 → penalty box
            if not ok:
                snap.raise_for_status()
            return body, ct, final_url, why, status
        if last is not None:
            if access:
                _access_note_status(host, last.status_code, access)
            last.raise_for_status()
        raise RuntimeError("unreachable")
    finally:
        if took:
            _access_release(host)



# ─────────────────────────────────────────────────────────────────────────────
# Some APIs return failures with a successful HTTP status. Check the parsed body
# before treating an error object or error list as data.
# These envelopes contain raw text or binary metadata rather than parsed fields.
_ENVELOPE = ("_text", "_head", "_head_hex", "_binary", "_error", "_truncated_at",
             "_unserializable")

# Envelopes we look inside one level deep. Only these two: elsewhere a nested
# object is data, not a failure report.
_NESTED = ("headers", "debug")

# Where providers put the human-readable failure text. Order is priority: text written
# for humans first, then codes.
# Names are NORMALIZED (see `_norm_keys`): lowercase, no spaces, hyphens or
# underscores. So `Error Message` (alphavantage), `error_message` (mailboxvalidator) and
# `errorMessage` (votesmart) are the same name.
_MESSAGE_KEYS = ("message", "errormessage", "errormsg", "info",
                 "description", "errordescription", "detail", "details", "reason", "msg")

_FAIL_STATUS = frozenset({"error", "fail", "failed", "failure"})

# Access failure: missing key, wrong key, quota exhausted, wrong plan.
_NEEDS_KEY = ("api key", "apikey", "api_key", "api-key", "access key", "access_key",
              "api access", "invalid key", "token", "authoriz", "unauthor", "credential",
              "subscription", "quota", "upgrade your plan", "for your plan", "sign up",
              "access denied", "permission denied")

# Endpoint failure: it no longer exists.
_GONE = ("deprecat", "no longer", "has been removed", "discontinued", "sunset",
         "method not found")


def _filled(value: Any) -> bool:
    """Whether a field is filled. Empty string, null, [], {} and false count as "not filled".

    This is exactly what separates `{"error": ""}` from comtrade (success: the field is always in the schema)
    from `{"error": "API key not found."}` from fraudlabspro (failure).
    """
    if value is None or value is False:
        return False
    if isinstance(value, (str, bytes, list, tuple, dict, set)):
        return len(value) > 0
    return True


def _norm(key: Any) -> str:
    """Field name in comparable form: lowercase, no spaces, hyphens or underscores."""
    return str(key).lower().replace(" ", "").replace("-", "").replace("_", "")


def _norm_keys(body: dict) -> dict:
    """Body with normalized field names: lowercase, no spaces, hyphens or
    underscores.

    Not cosmetic: `Errors` capitalized (npiregistry) and `Error Message` WITH A SPACE
    (alphavantage). The same field is spelled four ways across APIs, and checking
    them separately means missing a failure because of casing.
    """
    return {_norm(k): v for k, v in body.items()}


def _text_of(value: Any) -> str:
    """Extract human-readable text from a failure field value."""
    if isinstance(value, bool):
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, dict):
        low = _norm_keys(value)
        for k in _MESSAGE_KEYS:
            if _filled(low.get(k)):
                return _text_of(low[k])
        return " ".join(f"{k}={v}" for k, v in value.items() if _filled(v))[:500]
    if isinstance(value, (list, tuple)):
        return " ".join(_text_of(v) for v in value if _filled(v))[:500]
    return str(value)


# Label words: they state the failure itself, not its cause. Etherscan puts exactly `NOTOK`
# in `message` and the explanation in `result`; without this list the failure kind was taken
# from the label and "needs key" was misclassified as "bad request".
_LABEL_ONLY = frozenset({"notok", "ok", "error", "fail", "failed", "failure", "false",
                         "true", "n", "0", "1"})


def _explain(low: dict) -> str:
    """Explanation for the triggered signal — what the provider wrote for humans."""
    for k in ("error", "errors", *_MESSAGE_KEYS):
        if _filled(low.get(k)):
            t = _text_of(low[k])
            if t and t.strip().lower() not in _LABEL_ONLY:
                return t
    # No dedicated text field — collect top-level string fields. So for
    # api.waqi.info `{"data": "Invalid key", "status": "error"}` the log gets the cause,
    # not a bare "status=error". The signal has ALREADY fired by now: this only decides
    # the wording, not the verdict.
    parts = [f"{k}={v}" for k, v in low.items()
             if isinstance(v, str) and v.strip() and k not in ("status", "type")]
    return " ".join(parts)[:300]


# Fields that DESCRIBE a failure rather than carry results. Matched as substrings of the
# normalized name: recaptcha `error-codes` and slack `response_metadata` are lists,
# but lists of complaints; treating them as data would hide a real refusal.
_NOT_PAYLOAD = ("error", "message", "warning", "debug", "meta", "detail", "reason",
                "status", "code", "fault", "info", "trace", "diagnost")


def _carries_data(body: dict) -> bool:
    """Whether a non-empty result set sits next to the complaint.

    Tells a refusal from a mere warning. `onemap.gov.sg` answers a tokenless request with
    `{"error": "Authentication token missing…", "found": 1, "results": [<real address>]}`
    and the address is real (verified with a live request: 200, 551 bytes, 640 ROWELL
    ROAD). It is the only such body among 90 identified ones, and without this guard we would
    drop a working source. Counter-example: `efts.sec.gov` returns `{"hits": {"hits": []}, "error":
    "Blank search not valid"}`: the envelope is there, no results, so it is a refusal.

    Looks one level deep: results are often wrapped (`hits.hits`).
    """
    for k, v in body.items():
        if any(w in _norm(k) for w in _NOT_PAYLOAD):
            continue
        if isinstance(v, (list, tuple)) and v:
            return True
        if isinstance(v, dict):
            for k2, v2 in v.items():
                if any(w in _norm(k2) for w in _NOT_PAYLOAD):
                    continue
                if isinstance(v2, (list, tuple)) and v2:
                    return True
    return False


def _signal(low: dict) -> str | None:
    """Name of the triggered failure signal, or None. Works on a single nesting level."""
    if "success" in low and (low["success"] is False
                             or str(low["success"]).strip().lower() == "false"):
        return "success=false"
    if "ok" in low and (low["ok"] is False or str(low["ok"]).strip().lower() == "false"):
        return "ok=false"
    if str(low.get("status", "")).strip().lower() in _FAIL_STATUS:
        return "status=error"
    # Etherscan convention: success is status "1", failure is "0" with NOTOK. Neither alone
    # counts as a signal: for other APIs a zero status can also mean success.
    if (str(low.get("status", "")).strip() == "0"
            and str(low.get("message", "")).strip().upper() == "NOTOK"):
        return "status=0 NOTOK"
    if "error" in low and _filled(low["error"]):
        return "error"
    if isinstance(low.get("errors"), (list, tuple)) and low["errors"]:
        return "errors[]"
    for k in ("errormessage", "errormsg"):
        if _filled(low.get(k)):
            return k
    code = low.get("statuscode")
    if isinstance(code, bool):
        code = None
    if isinstance(code, (int, float)) or (isinstance(code, str) and code.strip().isdigit()):
        if int(code) >= 400:
            return "statusCode>=400"
    return None


def _refusal_in_body(body: Any) -> str | None:
    """Refusal text if the response body is a refusal; otherwise None.

    The returned string is always non-empty (for a signal without explanation, the signal
    name itself), so the result can be truth-tested without confusing "refusal without
    explanation" with "not a refusal".
    """
    if not isinstance(body, dict) or not body:
        return None
    if any(k in body for k in _ENVELOPE):
        return None
    if _carries_data(body):
        return None

    low = _norm_keys(body)
    sig = _signal(low)
    if sig:
        return _explain(low) or sig

    for env in _NESTED:
        inner = low.get(env)
        if isinstance(inner, dict) and inner:
            inner_low = _norm_keys(inner)
            inner_sig = _signal(inner_low)
            if inner_sig:
                return _explain(inner_low) or f"{env}: {inner_sig}"
    return None


def _refusal_kind(message: str) -> str:
    """Kind of refusal: 'needs_key' · 'gone' · 'bad_request'.

    Words are searched ONLY inside the already identified refusal text, not the whole body:
    on the whole body the same search gives 28 false positives out of 28. The kind affects the
    operation status, not the verdict: proof is withdrawn either way, since we saw no data.
    """
    m = (message or "").lower()
    if any(w in m for w in _GONE):
        return "gone"
    if any(w in m for w in _NEEDS_KEY):
        return "needs_key"
    return "bad_request"


# ─────────────────────────────────────────────────────────────────────────────
# Orchestration: prepare (shared, pure) + sync run_recipe (embedded in the client).
# ─────────────────────────────────────────────────────────────────────────────
def prepare_call(ep: dict, params: dict, auth: dict, api_key: str | None):
    """Pure request preparation: params → (url, args, response_path, pagination, timeout).
    Shared by sync/async: the single place for build_args + path-subst + baked-query merge."""
    if ep.get("tls_insecure") and (auth.get("type") not in (None, "", "none") or auth.get("login_url")
                                   or auth.get("env") or api_key):
        raise ValueError("tls_insecure endpoints must not carry credentials: "
                         "certificate checks are off, so a key or password could be intercepted")
    original_url = str(ep.get("url") or ep.get("path") or "")
    if original_url.lower().startswith("ftp://"):
        if "?" in original_url or "#" in original_url:
            raise httpx.UnsupportedProtocol("FTP URL must not contain a query or fragment")
        if auth.get("type") not in (None, "", "none") or auth.get("login_url"):
            raise httpx.UnsupportedProtocol("FTP recipes require anonymous auth")
    params = {k: v for k, v in (params or {}).items()
              if not str(k).startswith("_") or k == "_pass"}
    args = _build_args(ep, params, auth, api_key)
    # PATH substitution: path_defaults / param_defaults as fallback (path token {cik}
    # is filled by a default on an empty call, e.g. probe/verify, and overridden by params) +
    # param_aliases. Priority (low → high): path_defaults < param_defaults < params;
    # path_defaults (only NON-identifiers: year and the like) yields both to an explicit
    # call value and to a query default with the same name.
    _subst_src = {**(ep.get("path_defaults") or {}), **(ep.get("param_defaults") or {}), **params}
    # auth type=path: the key lives in a path token {MAP_KEY} (FIRMS/MODIS); inject it into the subst source
    # (query/header keys are injected in _build_args/_headers; path is not, else the token is sent literally → 400)
    if auth.get("type") == "path" and api_key:
        _an = auth.get("name") or ""
        _subst_src[_an] = api_key
        # Case tolerance for the key name in the manifest: URL token {MAP_KEY} with auth.name
        # "map_key" (or vice versa) would otherwise be sent literally → 400. Fill only tokens that
        # match the key name case-insensitively; narrow, leaves other path params alone.
        for _tok in _PATH_PARAM.findall(_endpoint_url(ep)):
            if _tok not in _subst_src and _tok.lower() == _an.lower():
                _subst_src[_tok] = api_key
    for _src, _dst in (ep.get("param_aliases") or {}).items():
        # Explicit destination values take precedence over aliases, and aliases override defaults.
        if _src in params and _dst not in params:
            _subst_src[_dst] = params[_src]
    url, consumed = _subst_path(_endpoint_url(ep), _subst_src)
    for k in consumed:
        args.pop(k, None)  # do not duplicate path params in the query
    # Merge the baked query in the recipe url (?latitude=50.45) into args: otherwise httpx get(url, params=args)
    # OVERWRITES the existing query entirely → silent 200 with an empty body. args win over the baked sample.
    _q = urlsplit(url)
    if _q.query:
        _baked = dict(parse_qsl(_q.query, keep_blank_values=True))
        _baked.update(args)
        args = _baked
        url = urlunsplit((_q.scheme, _q.netloc, _q.path, "", _q.fragment))
    # Remove forbidden parameters after merging defaults, including those embedded in the URL.
    for _fp in _access_of(ep).get("forbidden_params") or []:
        args.pop(_fp, None)
    timeout = min(_positive_number(ep.get("timeout"), DEFAULT_TIMEOUT), _limits_of(ep)[1])
    return url, args, ep.get("response_path") or "", ep.get("pagination"), timeout


def input_coverage(ep: dict, params: dict) -> dict:
    """Preflight contract: which user `params` ACTUALLY reach the request (consumed)
    and which are SILENTLY lost (unbound). Computed by the SAME binding the recipe executes
    (`_build_args`: passthrough/aliases/appends + path-subst), not a heuristic. Empty values
    and internal `_` keys are ignored.

    Check `unbound` before relying on a filtered result."""
    ep = ep or {}
    user = {k: v for k, v in (params or {}).items()
            if not str(k).startswith("_") and v not in (None, "", [])}
    if not user:
        return {"consumed": [], "unbound": [], "coverage": 1.0}
    consumed: set = set()
    for f in ep.get("params_passthrough") or []:
        if f in user:
            consumed.add(f)
    aliases = ep.get("param_aliases") or {}
    for src, dst in aliases.items():
        if src in user and dst not in user:      # same condition as in _build_args
            consumed.add(src)
    for src in ep.get("param_appends") or {}:
        if src in user:
            consumed.add(src)
    # path tokens: the same subst source as in prepare_call (path_defaults + param_defaults +
    # params + alias-dst)
    subst_src = {**(ep.get("path_defaults") or {}), **(ep.get("param_defaults") or {}), **params}
    for src, dst in aliases.items():
        if src in params and dst not in params:  # same condition as in prepare_call
            subst_src[dst] = params[src]
    try:
        _, path_consumed = _subst_path(_endpoint_url(ep), subst_src)
    except Exception:
        path_consumed = set()
    for tok in path_consumed:
        if tok in user:
            consumed.add(tok)
        for src, dst in aliases.items():  # user-src → alias → path-dst
            if dst == tok and src in user:
                consumed.add(src)
    # A collection's own ID is identity, not a dropped search filter. Recognise only
    # an exact Socrata resource path, never an ID appearing in a query or other text.
    fixed: set = set()
    resource = re.fullmatch(r"/resource/([a-z0-9]{4}-[a-z0-9]{4})\.(?:json|csv|geojson)",
                            urlsplit(_endpoint_url(ep)).path)
    if (resource and "dataset_id" in user and "dataset_id" not in consumed
            and user["dataset_id"] == resource.group(1)):
        fixed.add("dataset_id")
    unbound = sorted(set(user) - consumed - fixed)
    return {"consumed": sorted(consumed), "unbound": unbound,
            **({"fixed": sorted(fixed)} if fixed else {}),
            "coverage": round(len(consumed | fixed) / len(user), 3)}


def _defaulted_of(ep: dict, params: dict) -> dict:
    """The path was filled by a recipe default (`path_defaults`), not by explicit call `params`;
    the client must be told (otherwise it silently assumes the question was about a specific year,
    while it was "this year by default": nager.at `/PublicHolidays/{year}/{cc}` with no year asked).

    Path tokens use the same regex as substitution (`_PATH_PARAM`). A token covered by explicit
    `params` OR by a `param_defaults` query default with the same name is not listed:
    `path_defaults` has the lowest priority (see `prepare_call`). Empty → `{}`."""
    src = ep.get("path_defaults") or {}
    if not src:
        return {}
    url = ep.get("url") or ep.get("path") or ""
    param_defaults = ep.get("param_defaults") or {}
    defaulted: list = []
    for tok in _PATH_PARAM.findall(url):
        if tok in defaulted:
            continue
        if (tok in src and tok not in param_defaults
                and (params or {}).get(tok) in (None, "")):
            defaulted.append(tok)
    return {"defaulted": defaulted} if defaulted else {}


def _jsonstat_dims(ds: Any) -> tuple[list, list] | None:
    """(id, size) of a JSON-stat dataset, or None if it is not one. 2.0 keeps `id`/`size` at the
    dataset root, 1.x inside `dimension`. A dataset needs `value` (list or dict) and a description
    of every dimension in `id`: metadata without values and `class: collection` do not count."""
    if not isinstance(ds, dict) or not isinstance(ds.get("dimension"), dict):
        return None
    if not isinstance(ds.get("value"), (list, dict)) or ds.get("class") not in (None, "dataset"):
        return None
    dim = ds["dimension"]
    ids, sizes = (ds.get("id"), ds.get("size")) if "id" in ds else (dim.get("id"), dim.get("size"))
    if not (isinstance(ids, list) and isinstance(sizes, list) and ids and len(ids) == len(sizes)):
        return None
    if not all(isinstance(d, str) and isinstance(dim.get(d), dict) for d in ids):
        return None
    if not all(isinstance(n, int) and not isinstance(n, bool) and n >= 0 for n in sizes):
        return None
    return ids, sizes


def _jsonstat_datasets(obj: Any) -> list | None:
    """JSON-stat datasets in the body: [(name | None, dataset)]. A 2.0 or 1.x dataset on its own; a 1.x
    "bundle" (`{"dataset": {…}}` from Statistics Denmark) gives all its datasets. Not JSON-stat → None."""
    if _jsonstat_dims(obj):
        return [(None, obj)]
    if isinstance(obj, dict) and obj and all(_jsonstat_dims(v) for v in obj.values()):
        return list(obj.items())
    return None


def _is_jsonstat(obj: Any) -> bool:
    """Return whether the body or a nested node contains a JSON-stat cube."""
    return _jsonstat_datasets(obj) is not None


def _jsonstat_codes(d: dict, n: int) -> list[str]:
    """Dimension category codes for positions 0..n-1. `category.index` is a list of codes or a dict
    code → position; without `index` (single category), the keys of `category.label`. A position without a code gets its number."""
    cat = d.get("category") if isinstance(d.get("category"), dict) else {}
    idx, lab = cat.get("index"), cat.get("label")
    codes: list = [None] * n
    if isinstance(idx, list):
        for i, c in enumerate(idx[:n]):
            codes[i] = c
    elif isinstance(idx, dict):
        for c, i in idx.items():
            if isinstance(i, int) and 0 <= i < n:
                codes[i] = c
    elif isinstance(lab, dict):
        for i, c in enumerate(list(lab)[:n]):
            codes[i] = c
    return [str(c) if c is not None else str(i) for i, c in enumerate(codes)]


def _jsonstat_records(obj: Any, limit: int | None = None) -> list | None:
    """JSON-stat cube → one record per observation (mode `objectify: "jsonstat"`).

    Why. Eurostat, CSO Ireland and Statistics Denmark return a cube, not records: dimensions
    (`id`, `size`, `dimension.<d>.category.index/label`) and `value` values by cell number.
    Without unfolding, the client got a zip of two parallel lists `id`/`size`
    (`[{"id": "freq", "size": 1}, …]` from Eurostat DEMO_R_D3DENS) or a path to links to
    other formats (`link.alternate` at CSO), and the observations never reached it.

    Record: each dimension's code under its `id`, its label under `<id>_label` (if the dimension
    has labels), the value under `value`, the cell status under `status` (if any). The cell number
    is decomposed by `size` in `id` order, the last dimension varying fastest. `value`
    is either a list (empty cell = null) or a sparse dict {"number": value}; an empty
    cell without status is skipped, so both forms of the same cube give the same records.
    A 1.x "bundle" of several datasets yields consecutive records with a `dataset` field. The cap is the same as
    for csv and workbooks (TABLE_ROW_LIMIT). Empty cube → [] (response present, no observations); not JSON-stat → None."""
    sets = _jsonstat_datasets(obj)
    if sets is None:
        return None
    cap = TABLE_ROW_LIMIT if limit is None else limit
    out: list = []
    for name, ds in sets:
        ids, sizes = _jsonstat_dims(ds)
        dim = ds["dimension"]
        cols = []
        for d, n in zip(ids, sizes):
            codes = _jsonstat_codes(dim[d], n)
            cat = dim[d].get("category") if isinstance(dim[d].get("category"), dict) else {}
            lab = cat.get("label") if isinstance(cat.get("label"), dict) else None
            key = f"{d}_code" if d in ("value", "status", "dataset") else d   # do not overwrite reserved keys
            cols.append((key, f"{d}_label" if lab is not None else None, codes,
                         [str(lab.get(c, c)) for c in codes] if lab is not None else None))
        strides = [1] * len(sizes)
        for i in range(len(sizes) - 2, -1, -1):
            strides[i] = strides[i + 1] * sizes[i + 1]
        total = strides[0] * sizes[0] if sizes else 0
        val, st = ds["value"], ds.get("status")
        if isinstance(val, dict):
            cells = sorted((int(k), v) for k, v in val.items() if str(k).isdigit())
        else:
            cells = enumerate(val)
        for pos, v in cells:
            if pos >= total:
                break
            s = (st[pos] if isinstance(st, list) and pos < len(st)
                 else st.get(str(pos)) if isinstance(st, dict) else None)
            if v is None and s is None:
                continue
            rec: dict = {"dataset": name} if len(sets) > 1 else {}
            rem = pos
            for (key, lkey, codes, labels), stride in zip(cols, strides):
                j, rem = divmod(rem, stride)
                rec[key] = codes[j]
                if lkey:
                    rec[lkey] = labels[j]
            rec["value"] = v
            if s is not None or isinstance(st, str):
                rec["status"] = s if s is not None else st
            out.append(rec)
            if len(out) >= cap:
                return out
    return out


def _objectify(obj: Any, mode: str | None = None) -> list | None:
    """Non-list shapes → list[dict]. Common patterns (statistics/weather/sensors worldwide):
      auto  — parallel lists of equal length (open-meteo hourly:{time:[],temp:[]}) → zip by index;
      'kv'  — dict of scalars (er-api rates:{USD:1,EUR:.9}) → [{key,value}];
      'flatten' — dict of dicts (imf values.IND:{country:{year:val}}) → one row per outer key;
      'table' — columns + row arrays ({fields:[cik,name], data:[[1,"a"],…]} from sec.gov
                company_tickers_exchange) → one dict per row;
      'object' — the whole object is one record (issuer card at data.sec.gov/submissions):
                without the flag the only nested list (`formerNames`) was taken as the records,
                and address, industry, tickers never reached the client;
      'jsonstat' — JSON-stat cube (Eurostat, CSO, Statistics Denmark) → one record per
                observation, see `_jsonstat_records`.
    auto is safe (parallel arrays are unambiguous); kv/flatten/table/object/jsonstat only via the
    `objectify` flag in the recipe."""
    if not isinstance(obj, dict) or not obj:
        return None
    if mode == "object":
        return [obj]
    if mode == "jsonstat":
        return _jsonstat_records(obj)
    if mode == "table":
        cols = next((obj[k] for k in ("fields", "columns", "headers", "header")
                     if isinstance(obj.get(k), list) and obj[k] and all(isinstance(c, str) for c in obj[k])), None)
        rows = next((v for k, v in obj.items() if k not in ("fields", "columns", "headers", "header")
                     and isinstance(v, list) and v and all(isinstance(r, list) for r in v[:5])), None)
        if cols and rows:
            return [dict(zip(cols, r)) for r in rows if isinstance(r, list)]
        return None
    arrs = {k: v for k, v in obj.items() if isinstance(v, list)}
    if (mode in (None, "auto", "zip")) and len(arrs) >= 2:
        L = len(next(iter(arrs.values())))
        if L >= 2 and all(len(v) == L for v in arrs.values()):
            return [{k: arrs[k][i] for k in arrs} for i in range(L)]
    if mode == "kv":
        sc = [(k, v) for k, v in obj.items()
              if v is None or isinstance(v, (str, int, float, bool))]
        if len(sc) >= 3:
            return [{"key": k, "value": v} for k, v in sc]
    if mode == "flatten":
        dd = {k: v for k, v in obj.items() if isinstance(v, dict)}
        if len(dd) >= 2:
            return [{"_key": k, **v} for k, v in dd.items()]
        # dict of lists (URLhaus json_recent: {id:[record]}) → concatenate all lists
        dl = {k: v for k, v in obj.items() if isinstance(v, list)}
        if len(dl) >= 2:
            out = []
            for k, lst in dl.items():
                for it in lst:
                    out.append({"_key": k, **it} if isinstance(it, dict) else {"_key": k, "value": it})
            return out
    return None


def _single_record_array(obj: dict) -> list | None:
    """The only top-level array of objects = the response records.

    Use this fallback when the response path is absent. Multiple object arrays are
    ambiguous, and lists of scalars are columns handled by `_objectify`.
    """
    arrs = [v for v in obj.values()
            if isinstance(v, list) and v and all(isinstance(x, dict) for x in v[:5])]
    return arrs[0] if len(arrs) == 1 else None


def is_resource_list(node, descriptor_context: bool = False) -> bool:
    """CKAN/Frictionless file descriptors are metadata, not observations."""
    return isinstance(node, list) and bool(node) and all(
        isinstance(row, dict) and (
            {"url", "format"} <= row.keys()
            or descriptor_context and "path" in row and bool({"name", "format", "schema", "profile"} & row.keys())
        ) for row in node[:5])


def _records_of(payload, response_path, objectify: str | None = None):
    """payload + response_path (+ the recipe's objectify mode) → list[dict] | None."""
    descriptor_context = str(response_path or '').rsplit('.', 1)[-1] == 'resources'
    if response_path and isinstance(payload, dict):
        payload = _dig(payload, response_path)
    if isinstance(payload, list):
        return None if is_resource_list(payload, descriptor_context) else payload
    if isinstance(payload, dict):  # columnar/parallel-array shape → auto-zip
        # order matters: the existing logic first, the fallback only where it returned None,
        # otherwise the change would alter recipes that work today
        # Prefer the declared object shape. A two-column table can otherwise be mistaken
        # for two parallel arrays.
        rows = _objectify(payload, objectify) if objectify else None
        if rows is None:
            rows = _objectify(payload) or _single_record_array(payload)
        descriptor_context = descriptor_context or rows is payload.get('resources')
        return None if is_resource_list(rows, descriptor_context) else rows
    return None


# names of row-cap params in a single GET without a pagination block (Socrata $limit, generic limit).
# len(records) == effective cap ⇒ the tail MAY have been cut ⇒ truncated, completeness cannot be proven.
_LIMIT_KEYS = ("$limit", "limit", "per_page", "pageSize", "page_size", "rows", "count", "size", "maxRecords")


def _single_get_completeness(records, args: dict) -> dict:
    """Honest completeness flag for a NON-paginated single GET (deterministic output must
    signal "full set" / "truncated"). The cap comes from args (recipe/SoQL $limit).
    len==cap ⇒ truncated=true (tail unprovable); len<cap ⇒ truncated=false; no cap ⇒ unknown.
    Non-list payload (single object): completeness does not apply, no flag set."""
    if not isinstance(records, list):
        return {}
    cap = None
    for k in _LIMIT_KEYS:
        if k in (args or {}):
            try:
                cap = int(args[k])
                break
            except (TypeError, ValueError):
                continue
    if cap is None:
        # no limit set by the recipe: a single GET returned what it returned; completeness is UNKNOWN
        # (this used to be false, and the client read it as "full set")
        return {"truncated": None}
    truncated = len(records) >= cap
    out: dict = {"truncated": truncated}
    if truncated:
        out["limit"] = cap
        out["truncated_by"] = "limit"
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Pagination for synchronous and asynchronous requests is configured by endpoint.pagination.
#   follow_last_page (bool) + last_page_path (dotted path to meta.…lastPage) —
#   "walk to the last page" mode: read lastPage from the response and go up to it,
#   WITHOUT cutting at size*pages_max (without it a chain silently stopped at page 1:
#   default max_pages=1 → target=size). pages_max is ONLY a runaway guard,
#   not a regular limit. In follow mode max_results/max_pages are ignored:
#   the recipe must return the FULL deterministic set by itself.
# ─────────────────────────────────────────────────────────────────────────────
def _pg_plan(pg: dict, params: dict) -> dict:
    """Expand pagination config + runtime params into a traversal plan (shared sync/async)."""
    follow = bool(pg.get("follow_last_page"))
    page = int(params.get(pg["page_param"]) or 1)
    size = min(int(params.get(pg["size_param"]) or pg.get("size_default", 25)), pg["size_max"])
    cap = int(pg["pages_max"])  # hard anti-runaway guard, not a regular limit
    if follow:
        # full traversal: ceiling = guard; target = ∞ (no cut by size)
        return {"follow": True, "page": page, "size": size, "ceiling": cap,
                "target": None, "last_page_path": pg.get("last_page_path"),
                "has_next_path": pg.get("has_next_path"), "next_params": pg.get("next_params") or {}}
    pages_max = min(int(params.get("max_pages") or 1), cap)
    target = int(params.get("max_results") or size * pages_max)
    # more pages requested than the recipe's pages_max guard allows: the target is already
    # clipped, and reaching it means "stopped at the ceiling", not "got what was requested"
    clipped = int(params.get("max_pages") or 1) > cap and not params.get("max_results")
    return {"follow": False, "page": page, "size": size, "ceiling": pages_max,
            "target": target, "last_page_path": None, "clipped": clipped}


def _pg_should_stop(plan: dict, payload, items_len: int, offset: int, last_page: int | None) -> bool:
    """Decide whether to stop traversal AFTER processing page offset (0-based).
    follow: up to last_page (from meta) inclusive, or while data keeps coming, within ceiling.
    legacy: target reached or empty page."""
    if plan["follow"]:
        current_page = plan["page"] + offset
        if plan.get("has_next_path"):
            has_next = _dig(payload, plan["has_next_path"])
            if type(has_next) is not bool:
                raise ValueError("Pagination response has no boolean continuation flag")
            plan["exhausted"] = not has_next
            if has_next:
                cursor = {name: _dig(payload, path) for name, path in plan["next_params"].items()}
                if any(value is None for value in cursor.values()):
                    raise ValueError("Pagination response has an incomplete continuation cursor")
                plan["cursor"] = cursor
            return not has_next
        if last_page is not None and current_page >= last_page:
            return True
        return False  # without a known lastPage, an empty batch stops traversal (see caller)
    return items_len >= plan["target"]


def _pg_completeness(plan: dict, out: list, last_batch_len: int, pages_used: int,
                     total, last_page) -> dict:
    """Honest completeness flag for a paginated traversal (deterministic output must prove
    "full set" / "truncated").
      follow: completeness is proven if the known lastPage was reached within ceiling. If
        the ceiling (guard) was hit BEFORE reaching lastPage — truncated.
      legacy: truncated if exactly target was collected AND the last page was FULL
        (size): the tail beyond target is unprovable. Empty/partial last batch ⇒ exhausted."""
    if plan["follow"]:
        if plan.get("has_next_path"):
            if plan.get("exhausted") is True:
                return {"truncated": False}
            return {"truncated": True, "truncated_by": "pages_ceiling" if pages_used >= plan["ceiling"] else "continuation"}
        hit_ceiling = pages_used >= plan["ceiling"]
        reached_last = last_page is not None and (plan["page"] + pages_used - 1) >= last_page
        truncated = hit_ceiling and not reached_last and last_batch_len > 0
        return {"truncated": True, "truncated_by": "pages_ceiling"} if truncated else {"truncated": False}
    target = plan["target"]
    full_last_page = last_batch_len >= plan["size"]
    hit_ceiling = pages_used >= plan["ceiling"]
    if len(out) >= target and full_last_page:
        # collected exactly what was requested, last page full: the tail beyond is unprovable;
        # if the request was clipped by the pages_max guard, this is the page ceiling, not the limit
        return {"truncated": True, "limit": target,
                "truncated_by": "pages_ceiling" if plan.get("clipped") else "limit"}
    if hit_ceiling and full_last_page and len(out) < target:
        # more was requested than the recipe's pages_max guard allowed; this used to be
        # false, and a traversal stopped at the ceiling looked like a full set
        return {"truncated": True, "limit": target, "truncated_by": "pages_ceiling"}
    return {"truncated": False}


def resource_result_reason(result: dict) -> str | None:
    """Why a fetched file is not usable observation rows (None means usable)."""
    if result.get("refusal"):
        return "source_refusal"
    raw = result.get("raw")
    if is_resource_list(raw) or isinstance(raw, dict) and is_resource_list(raw.get("resources"), True):
        return "resource_metadata"
    if result.get("truncated_by") and not result.get("records"):
        return "limit_" + str(result["truncated_by"])
    rows = result.get("records")
    if not isinstance(rows, list) or not rows or not all(isinstance(row, dict) for row in rows):
        return "no_rows_" + str(result.get("format") or "unknown")
    if is_resource_list(rows):
        return "resource_metadata"
    if any("\x00" in str(key) or "\ufffd" in str(key) for row in rows[:25] for key in row):
        return "damaged_headers"
    return None


def _resource_candidates(ep: dict) -> list[dict]:
    first = {key: value for key, value in ep.items() if key != "alternatives"}
    limit = max(1, min(20, int(ep.get("resource_attempt_limit") or 4)))
    choices = [first] + [dict(item) for item in ep.get("alternatives") or [] if isinstance(item, dict)]
    return [{**item, "stop_on_429": True} for item in choices[:limit]]


def _resource_attempt(ep, result=None, error=None):
    return {"url": ep.get("url"), "format": (result or {}).get("format"),
            "reason": type(error).__name__ if error else resource_result_reason(result or {}),
            **({"http_code": error.response.status_code} if isinstance(error, httpx.HTTPStatusError) else {})}


def _resource_outcome(result, attempts, selected=None):
    if selected is not None:
        return {**result, "selected_resource_url": selected.get("url"), "resource_attempts": attempts,
                "delivery_status": "rows"}
    return {**(result or {}), "records": None, "count": 0, "raw": None, "raw_text": None,
            "resource_attempts": attempts, "delivery_status": "no_usable_resource"}


def _run_resource_candidates(ep, auth, params, api_key, proxy_url, credential_origin=None):
    attempts, result = [], None
    for candidate in _resource_candidates(ep):
        try:
            result = _run_recipe(candidate, auth, params, api_key, proxy_url, credential_origin)
        except httpx.HTTPError as exc:
            if isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code == 429:
                raise
            attempts.append(_resource_attempt(candidate, error=exc))
            continue
        attempts.append(_resource_attempt(candidate, result))
        if attempts[-1]["reason"] is None:
            return _resource_outcome(result, attempts, candidate)
    return _resource_outcome(result, attempts)


async def _arun_resource_candidates(ep, auth, params, api_key, proxy_url, credential_origin=None):
    attempts, result = [], None
    for candidate in _resource_candidates(ep):
        try:
            result = await _arun_recipe(candidate, auth, params, api_key, proxy_url, credential_origin)
        except httpx.HTTPError as exc:
            if isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code == 429:
                raise
            attempts.append(_resource_attempt(candidate, error=exc))
            continue
        attempts.append(_resource_attempt(candidate, result))
        if attempts[-1]["reason"] is None:
            return _resource_outcome(result, attempts, candidate)
    return _resource_outcome(result, attempts)


def run_recipe(ep: dict, auth: dict, params: dict, api_key: str | None = None,
               proxy_url: str | None = None) -> dict[str, Any]:
    """Execute an endpoint; SDK-managed credentials require an Atlas endpoint+auth signature."""
    import copy
    ep, auth = copy.deepcopy((ep, auth))
    origin = _authorize_http_step(ep, auth, api_key)
    return _run_recipe(ep, auth, params, api_key, proxy_url, origin)


def _run_recipe(ep: dict, auth: dict, params: dict, api_key: str | None = None,
                proxy_url: str | None = None, credential_origin: tuple | None = None) -> dict[str, Any]:
    """SYNC execution of a declarative endpoint, embedded verbatim in the standalone client.
    Multiformat (_parse) + retry + pagination + proxy(env-URL). Returns {records, count, ...}.
    A successful response (single or paginated) carries `fetched_at`: the moment THIS response
    was received, not the recipe's probe time; unfilled/refusal-without-data results do not carry it.
    `endpoint.path_defaults` is a default for a NON-identifier {token} in the path (year and
    the like); if it filled a token, the successful response carries `defaulted: [names]`.
    No server-side dependencies: the playwright tier (server-only, costly) is NOT needed by the client."""
    import os as _os
    if _uses_credentials(ep, auth, api_key) and credential_origin is None:
        raise ValueError("Credential requests require a valid Atlas step signature")
    if credential_origin is not None and ep.get("tls_insecure"):
        raise ValueError("Credential requests require verified HTTPS")
    if "alternatives" in ep:
        return _run_resource_candidates(ep, auth, params, api_key, proxy_url, credential_origin)
    _login_url = auth.get("login_url")
    if auth.get("env") and not api_key and not _login_url:
        api_key = _os.environ.get(auth["env"], "")
    if auth.get("env") and not api_key and not _login_url:
        raise ValueError(f"endpoint requires {auth['env']} env var")
    # A fanout step sends one request per item.
    if ep.get("fanout"):
        return _run_fanout_sync(ep, ep["fanout"], auth, params, api_key, proxy_url, credential_origin)
    url, args, response_path, pg, timeout = prepare_call(ep, params, auth, api_key)
    _check_credential_origin(url, credential_origin)
    _unfilled = _unfilled_result(url, ep, params, args)
    if _unfilled:
        return _unfilled
    if proxy_url is None and ep.get("needs_proxy"):
        proxy_url = _os.environ.get("ATLAS_PROXY_URL") or None
    token_header = auth.get("token_header") or "Authorization"
    for _login_attempt in range(2 if _login_url else 1):
        hdrs = _headers(ep, auth, api_key)
        if _login_url:
            hdrs = {**hdrs, token_header: _login_token_sync(
                auth, proxy_url, timeout, force=_login_attempt > 0,
                credential_origin=_fixed_credential_origin(_login_url), data_origin=credential_origin,
                deadline_s=_limits_of(ep)[1])}
        try:
            with httpx.Client(timeout=timeout, headers=hdrs, proxy=proxy_url,
                              event_hooks=_address_hooks(proxy_url, credential_origin=credential_origin),
                              follow_redirects=True, verify=not ep.get("tls_insecure")) as c:
                if not pg:
                    fetched = _fetch(c, ep, args, url)
                    payload, fmt, raw_text = fetched
                    if getattr(fetched, "refusal", None):
                        return _refusal_result(fetched, payload, fmt, raw_text, ep, params)
                    records = _records_of(payload, response_path, ep.get("objectify"))
                    return {"records": records, "count": len(records) if isinstance(records, list) else None,
                            "raw": payload if records is None or isinstance(payload, dict) else None,
                            "format": fmt, "raw_text": raw_text,
                            "fetched_at": _now_iso(),
                            **_single_get_completeness(records, args),
                            **_body_flags(fetched),
                            **_coverage_of(ep, params),
                            **_defaulted_of(ep, params),
                            **({"hint": _BINARY_HINT} if fmt == "binary" else {})}
                plan = _pg_plan(pg, params)
                items: list = []
                total = None
                last_page = None
                pages_used = 0
                last_batch_len = 0
                body_cut: dict = {}
                refused = None
                for offset in range(plan["ceiling"]):
                    args[pg["page_param"]] = plan["page"] + offset
                    args[pg["size_param"]] = plan["size"]
                    args.update(plan.get("cursor") or {})
                    fetched = _fetch(c, ep, args, url)
                    payload, _fmt, _rt = fetched
                    if getattr(fetched, "refusal", None):
                        if not items:   # refusal on the very first page: no records
                            return _refusal_result(fetched, payload, _fmt, _rt, ep, params)
                        refused = fetched
                        break           # refusal mid-traversal: return what was collected and report the refusal
                    batch = _dig(payload, pg["items_path"])
                    if plan.get("has_next_path") and not isinstance(batch, list):
                        raise ValueError("Pagination response has no record list")
                    batch = batch or []
                    last_batch_len = len(batch)
                    items.extend(batch)
                    total = _dig(payload, pg["total_path"]) if pg.get("total_path") else None
                    if plan["last_page_path"]:
                        _lp = _dig(payload, plan["last_page_path"])
                        last_page = int(_lp) if _lp is not None else last_page
                    pages_used = offset + 1
                    body_cut = _body_flags(fetched)
                    stop = False if body_cut else _pg_should_stop(plan, payload, len(items), offset, last_page)
                    if body_cut or not batch or stop:
                        break   # truncated page: stop paging, the tail is already unprovable
                out = items if plan["target"] is None else items[: plan["target"]]
                return {"records": out, "count": len(out),
                        "total_estimated": total, "pages_used": pages_used, "format": "json",
                        "fetched_at": _now_iso(),
                        **_pg_completeness(plan, out, last_batch_len, pages_used, total, last_page),
                        **body_cut, **_coverage_of(ep, params), **_defaulted_of(ep, params),
                        **({"refusal": refused.refusal_kind, "refusal_message": refused.refusal,
                            "refusal_after_page": pages_used} if refused is not None else {})}
        except httpx.HTTPStatusError as e:
            if (_login_url and _login_attempt == 0 and e.response is not None
                    and e.response.status_code in (401, 403)):
                continue
            raise
    raise RuntimeError("run_recipe: login retry exhausted")


def _fanout_plan(fan_ep: dict, fan: dict, params: dict, proxy_url: str | None) -> dict:
    """Prepare the items, endpoints and concurrency for synchronous or asynchronous fanout.
    Fanout keys: `items`, `url` with `{item}` or `as_param`,
    `extract`, `response_path`, `static_headers`, `params_passthrough`, `param_defaults`,
    `timeout`, `needs_proxy`/`proxy_country`, `concurrency`."""
    import os as _os
    items = list(fan.get("items") or [])
    tmpl = fan.get("url") or fan_ep.get("url")
    as_param = fan.get("as_param")
    rp = fan.get("response_path") or ""
    hdrs = fan.get("static_headers") or fan_ep.get("static_headers") or {}
    passthrough = fan.get("params_passthrough") or []
    pass_vals = {k: params[k] for k in passthrough if params and k in params}
    fanproxy = proxy_url
    if fan.get("needs_proxy") and fanproxy is None:
        fanproxy = _os.environ.get("ATLAS_PROXY_URL") or None

    def leg(item) -> dict:
        ep2 = {"method": "GET", "param_defaults": dict(fan.get("param_defaults") or {}),
               "params_passthrough": passthrough, "response_path": rp, "static_headers": hdrs,
               "timeout": fan.get("timeout") or 30}
        for name in ("body_cap_mb", "deadline_s"):
            candidates = [value for value in (fan_ep.get(name), fan.get(name))
                          if _positive_number(value, None) is not None]
            if candidates:
                ep2[name] = min(float(value) for value in candidates)
        if fan.get("needs_proxy"):
            ep2["needs_proxy"] = True
            ep2["proxy_country"] = fan.get("proxy_country") or "US"
        if as_param:
            ep2["url"] = tmpl
            ep2["param_defaults"][as_param] = item
        else:
            ep2["url"] = str(tmpl).replace("{item}", str(item))
        return ep2

    return {"items": items, "leg": leg, "pass_vals": pass_vals, "proxy_url": fanproxy,
            "extract": fan.get("extract"),
            "concurrency": min(_concurrency_limit(fan.get("concurrency")), max(1, len(items)))}


def _fanout_rows(item, r: dict | None, extract: str | None) -> list | None:
    """One leg's response → rows tagged `_item`: records / `extract` from raw / raw object; else None."""
    if not r:
        return None
    recs = r.get("records")
    if isinstance(recs, list):
        return [{**x, "_item": item} if isinstance(x, dict) else x for x in recs]
    raw = r.get("raw")
    if extract and isinstance(raw, (dict, list)):
        v = _dig(raw, extract)
        if v is not None:
            return [{"_item": item, "value": v}]
    if isinstance(raw, dict):
        return [{**raw, "_item": item}]
    return None


def _fanout_result(parts) -> dict[str, Any]:
    """Assemble the fanout from (leg rows | None, leg truncated_by | None) in items order."""
    recs: list = []
    cut: list = []
    for rows, why in parts:
        if isinstance(rows, list):
            recs.extend(rows)
        if why:
            cut.append(why)   # any leg truncated by a cap ⇒ fanout is incomplete
    return {"records": recs, "count": len(recs), "raw": None, "format": "json", "raw_text": None,
            **({"truncated": True, "truncated_by": cut[0], "truncated_items": len(cut)} if cut else {})}


def _run_fanout_sync(fan_ep: dict, fan: dict, auth: dict, params: dict,
                     api_key: str | None = None, proxy_url: str | None = None,
                     credential_origin: tuple | None = None) -> dict[str, Any]:
    """SYNC fanout: list of items → one request per item (parallel) → one table tagged _item.
    Registry-sweep primitive (Socrata and any group of same-shaped endpoints); passthrough
    keys ($q/$limit…) come from the call params → one input (entity) fans out over N registries."""
    from concurrent.futures import ThreadPoolExecutor
    plan = _fanout_plan(fan_ep, fan, params, proxy_url)

    def one(item):
        try:
            r = _run_recipe(plan["leg"](item), auth, plan["pass_vals"], api_key,
                            proxy_url=plan["proxy_url"], credential_origin=credential_origin)
        except Exception:
            return None, None
        return _fanout_rows(item, r, plan["extract"]), r.get("truncated_by")

    with ThreadPoolExecutor(max_workers=plan["concurrency"]) as ex:
        parts = []
        for start in range(0, len(plan["items"]), plan["concurrency"]):
            parts.extend(ex.map(one, plan["items"][start:start + plan["concurrency"]]))
    return _fanout_result(parts)


async def _run_fanout_async(fan_ep: dict, fan: dict, auth: dict, params: dict,
                            api_key: str | None = None, proxy_url: str | None = None,
                            credential_origin: tuple | None = None) -> dict[str, Any]:
    """ASYNC twin of _run_fanout_sync — for `arun_recipe` (client execute_step, `atlas export
    --run`). Same pure part (_fanout_plan / _fanout_rows / _fanout_result), legs run via arun_recipe
    under a width semaphore."""
    import asyncio as _aio
    plan = _fanout_plan(fan_ep, fan, params, proxy_url)
    sem = _aio.Semaphore(plan["concurrency"])

    async def one(item):
        async with sem:
            try:
                r = await _arun_recipe(plan["leg"](item), auth, plan["pass_vals"], api_key,
                                       proxy_url=plan["proxy_url"], credential_origin=credential_origin)
            except Exception:
                return None, None
        return _fanout_rows(item, r, plan["extract"]), r.get("truncated_by")

    parts = []
    for start in range(0, len(plan["items"]), plan["concurrency"]):
        parts.extend(await _aio.gather(*[one(it) for it in plan["items"][start:start + plan["concurrency"]]]))
    return _fanout_result(parts)


# ─────────────────────────────────────────────────────────────────────────────
# Run legacy and SoQL chains locally using their declared steps and edges.
# out_map → deterministic bundle assembly (no LLM). edges[].code (a verified transform)
# runs BEFORE the dependent step, mutating ctx for downstream param_map.
# ─────────────────────────────────────────────────────────────────────────────
def _cv_dig(obj: Any, path: str) -> Any:
    """Walk a dotted path inside ONE record ('entities.*.labels.en.value').
    Numeric segment = list index. '*' = any dict key (dynamic key, like Wikidata
    entities.{QID}, where QID differs per company) / first list element. None on miss."""
    for part in path.split("."):
        if part == "*":
            if isinstance(obj, dict):
                obj = next(iter(obj.values()), None)
            elif isinstance(obj, list):
                obj = obj[0] if obj else None
            else:
                return None
        elif isinstance(obj, dict):
            obj = obj.get(part)
        elif isinstance(obj, list) and part.lstrip("-").isdigit():
            i = int(part)
            obj = obj[i] if -len(obj) <= i < len(obj) else None
        else:
            return None
        if obj is None:
            return None
    return obj


def _cv_extract(result: Any, path: str) -> Any:
    """Deterministic extraction of an out field by explicit path (chain-step out_map). Base = records
    (else raw). Prefix '[].' = map over the record list → list of values (children/sets);
    otherwise take the first record (or the object itself if the response is a single dict)."""
    if not isinstance(result, dict):
        return None
    base = result.get("records")
    if base is None:
        base = result.get("raw")
    if base is None:
        return None
    if path == "[]":
        # whole step records: a declarative step (instead of a connector) returns API records, not
        # a summary dict, and the chain output is the records themselves (USPTO marks, Form D filings);
        # splitting by `[].x` fields would give parallel lists that drift apart on empty fields
        seq = base if isinstance(base, list) else [base]
        return [el for el in seq if el is not None] or None
    if path.startswith("[]."):
        seq = base if isinstance(base, list) else [base]
        vals = [_cv_dig(el, path[3:]) for el in seq]
        return [v for v in vals if v is not None] or None
    node = base[0] if isinstance(base, list) and base else base
    value = _cv_dig(node, path)
    # Auto-selected records can hide a sibling scan object or a ranks root.
    # Fall back to the raw root only when records were not filtered.
    raw = result.get("raw")
    if value is None and isinstance(base, list) and base and isinstance(raw, dict):
        root = raw.get(path.split(".", 1)[0])
        if (isinstance(root, dict) and "." in path
                or isinstance(root, list) and root == base):
            value = _cv_dig(raw, path)
    return value


def _run_connector_step(st: dict, ctx: dict) -> dict:
    """Client-tool step (connector_code, empty ep): exec the connector → entry function → call with
    the step's in-field. Entry = the def whose first arg matches the step's in[0] (holehe_lookup(email),
    email_check(email), socid_lookup(url)); else the last public def. The result is wrapped
    in {records|raw} for out_map. Requires the tool to be installed (client-side / verify-install) —
    ModuleNotFoundError = tool not installed (an explicit error, not a crash of the whole chain)."""
    import types as _types
    code = st.get("connector_code") or ""
    ns: dict = {"__builtins__": __builtins__}
    try:
        # A connector reaches a downloadable file through `dataset` (atlas.dataset): one download,
        # a local table, SQL. Handed in by name, so the same code runs in the engine and in the
        # client package, whose module path differs.
        from . import dataset as _dataset
        ns["dataset"] = _dataset
    except ImportError:
        pass
    try:
        exec(code, ns)
    except Exception as e:
        return {"records": None, "count": None, "error": "connector exec: %s" % (str(e)[:140])}
    funcs = [v for v in ns.values()
             if isinstance(v, _types.FunctionType) and not v.__name__.startswith("_")
             and getattr(v, "__code__", None) is not None
             and v.__code__.co_filename == "<string>"]
    if not funcs:
        return {"records": None, "count": None, "error": "connector: no entry function"}
    ins = st.get("in") or []
    entry = None
    for f in funcs:
        args = list(f.__code__.co_varnames[:f.__code__.co_argcount])
        if args and (args[0] in ins):
            entry = f
            break
    entry = entry or funcs[-1]
    a0 = entry.__code__.co_varnames[0] if entry.__code__.co_argcount else None
    val = (ctx.get(ins[0]) if ins else None)
    if val is None and a0:
        val = ctx.get(a0)
    try:
        if len(ins) > 1:
            import inspect as _inspect
            values = [ctx.get(name) for name in ins]
            if any(value is None for value in values):
                raise ValueError('missing connector input: ' + ', '.join(name for name, value in zip(ins, values) if value is None))
            _inspect.signature(entry).bind(*values)
            res = entry(*values)
        else:
            res = entry(val)
    except ModuleNotFoundError as e:
        return {"records": None, "count": None,
                "error": "tool not installed: %s (client-side)" % (str(e)[:80])}
    except Exception as e:
        install = getattr(e, "install", None)
        if install:  # atlas.dataset.MissingCapability: the agent runs this command and repeats the step
            return {"records": None, "count": None, "install": install,
                    "error": "tool not installed: %s (client-side), run `%s`" % (e.capability, install)}
        return {"records": None, "count": None, "error": "connector run: %s" % (str(e)[:140])}
    if isinstance(res, list):
        return {"records": res, "count": len(res), "raw": None, "fetched_at": _now_iso()}
    return {"records": None, "count": None, "raw": res, "fetched_at": _now_iso()}


# ── composite step parameter built from ctx fields ─────────────────────────────
# A step's `static_params` may carry a template: `"data": "[out:json];nwr[amenity~\"{poi|stem}\",i](around:800,{lat},{lon});out;"`,
# `"geoDistance": "{lat},{lon},10km"`. Placeholder `{name}` is filled from ctx (seed + out_map
# of earlier steps), filters `|lower` and `|stem` (lowercase, plural stripped, ≤6 chars —
# "Pharmacies" → "pharma", "ATMs" → "atm"). Previously a composite Overpass/OSRM/GBIF input was only possible
# via edge exec code; a literal without a known placeholder stays as is, a template with an unfilled
# placeholder is DROPPED (the param is not sent, the call is honestly empty instead of carrying garbage).
# `|padN` — left-pad a number with zeros to N chars (`{cik|pad10}`: "37996" → "0000037996"; same as SoQL `_padN`)
# and `|core` — organization name without a trailing legal form and without a leading The
# ("Eli Lilly and Company" → "Eli Lilly"). Reason: EDGAR company search requires every
# query word to be in the name (SEC has "ELI LILLY & Co", and "Company" matches nothing) and returns CIK without zeros,
# while data.sec.gov accepts only the ten-digit form.
_TPL = re.compile(r"\{([A-Za-z_][\w]*)(?:\|(lower|stem|core|pad\d{1,2}))?\}")

# Legal forms that `|core` strips from the end of a name (no dots, lowercase: "S.A." → "sa").
_LEGAL_FORMS = frozenset((
    "inc", "incorporated", "corp", "corporation", "co", "company", "cos", "companies", "ltd", "limited",
    "llc", "plc", "lp", "llp", "ag", "sa", "se", "nv", "bv", "gmbh", "spa", "sas", "sarl", "srl", "ab",
    "asa", "oyj", "kk", "pte", "pty", "bhd", "kgaa", "a/s"))


def _core_name(v) -> str:
    """Name without a trailing legal form ("Honda Motor Co., Ltd." → "Honda Motor") and without a leading
    The; a conjunction left at the end ("Eli Lilly and") is dropped too. A single word is kept — "Co" stays
    "Co": an empty query is worse than an unstripped form."""
    words = " ".join(str(v).split()).split(" ")
    if len(words) > 1 and words[0].lower() == "the":
        words = words[1:]
    while len(words) > 1:
        w = words[-1].strip(",.;:").lower().replace(".", "")
        if w not in _LEGAL_FORMS and w not in ("and", "&"):
            break
        words = words[:-1]
    return " ".join(words).strip(" ,.;:-") or str(v)


def _pad(v, n: int) -> str:
    """Left-pad a number with zeros to n chars; non-numbers as is (corrupting a value is worse than a clean miss)."""
    s = str(v).strip()
    return s.zfill(n) if s.isdigit() else s


def _stem(v: str) -> str:
    v = str(v).strip().lower()
    for suf, rep in (("ies", "y"), ("shes", "sh"), ("ches", "ch"), ("sses", "ss"), ("s", "")):
        if v.endswith(suf) and len(v) > len(suf) + 2:
            v = v[: -len(suf)] + rep
            break
    return v[:6]


def _static_needs(static: dict) -> set:
    """Names of ctx fields required by static_params templates (`{lat}`, `{search_query|stem}`)."""
    names: set = set()
    for v in (static or {}).values():
        if isinstance(v, str) and "{" in v:
            names |= {m.group(1) for m in _TPL.finditer(v)}
    return names


def _render_static(static: dict, ctx: dict, unfilled: list | None = None) -> dict:
    """Render static parameters and record unresolved template names in `unfilled`.

    Missing values are reported so that a caller can avoid using unrelated endpoint defaults.
    """
    out = {}
    for k, v in static.items():
        if not isinstance(v, str) or "{" not in v:
            out[k] = v
            continue
        missing = False

        def _sub(m):
            nonlocal missing
            val = ctx.get(m.group(1))
            if val in (None, "", [], {}):
                missing = True
                return ""
            if isinstance(val, (list, tuple)):
                val = val[0] if val else ""
            f = m.group(2) or ""
            if f == "stem":
                return _stem(val)
            if f == "lower":
                return str(val).lower()
            if f == "core":
                return _core_name(val)
            if f.startswith("pad"):
                return _pad(val, int(f[3:]))
            return str(val)

        rendered = _TPL.sub(_sub, v)
        if _TPL.search(v) is None:
            out[k] = v
        elif not missing:
            out[k] = rendered
        elif unfilled is not None:
            unfilled.append(k)
    return out


def _run_step(st: dict, ctx: dict, blocked: str | None = None) -> dict:
    """One step of a legacy chain: param_map (seed_field→manifest_param) + static_params →
    run_recipe. 404 = no relation/resource (GLEIF has no parent/children) → empty, not a crash;
    any other HTTP/transport/BYO-key (ValueError) error of one source does not take down its neighbours.
    `blocked` — the reason recipe code must not run (code gate): a connector step
    then does not run and returns an explicit error."""
    if st.get("skip_reason"):
        return {"records": None, "count": None, "skipped": True, "reason": st["skip_reason"]}
    # client-tool step: connector_code present AND no EXECUTABLE http endpoint → run the connector.
    # `_ep_executable` covers both an empty ep {} and a descriptive stub ({_reference:true} without url/path):
    # such an ep would fail in _endpoint_url as "not executable" anyway, and connector_code is the right path.
    # A manifest with a real absolute url stays on the declarative path (drug/cert/GLEIF/SoQL unaffected).
    if st.get("connector_code") and not _ep_executable(st.get("ep") or {}):
        if blocked:
            return {"records": None, "count": None, "error": "connector " + blocked, "code_blocked": True}
        return _run_connector_step(st, ctx)
    p = dict(ctx)
    required = (st.get("ep") or {}).get("params_required") or []
    bindings, absent = {}, {}
    for key, param in (st.get("param_map") or {}).items():
        value = ctx.get(key)
        if value is None or (param in required and _blank(value)):
            absent.setdefault(param, []).append(key)
        elif param not in bindings or not _blank(value):
            bindings[param] = value
    # Several seed names can be alternatives for the same endpoint parameter.
    missing = sorted(key for param, keys in absent.items() if param not in bindings for key in keys)
    if missing:
        # An explicit chain binding must never fall back to an endpoint's probe example.
        return {"records": None, "count": None, "raw": None, "unfilled": missing,
                "error": "unfilled chain input: " + ", ".join(missing)}
    p.update(bindings)
    _unf: list = []
    p.update(_render_static(st.get("static_params") or {}, ctx, _unf))
    if _unf:
        # step template not filled (no lat/lon from the geocoder, no object kind) → explicit "unfilled",
        # like a path token; otherwise the endpoint would go out with defaults and return unrelated data
        return {"records": None, "count": None, "raw": None, "unfilled": sorted(_unf),
                "error": "unfilled static template: " + ", ".join(sorted(_unf))}
    try:
        endpoint = st.get("ep") or {}
        if "signature" not in endpoint:
            endpoint = {**endpoint, "stop_on_http_error": True}
        res = run_recipe(endpoint,
                         st.get("auth") or {"type": "none"}, p)
        if isinstance(res, dict) and "unbound" in res:
            declared = set((st.get("param_map") or {}).values()) | set(st.get("static_params") or {})
            res["unbound"] = sorted(set(res["unbound"]) & declared)
        return res
    except httpx.HTTPStatusError as e:
        sc = e.response.status_code if e.response is not None else 0
        if sc == 404:
            return {"records": None, "count": None, "raw": None, "http": 404}
        return {"records": None, "count": None, "http": sc,
                "error": "HTTP %s: %s" % (sc, str(e)[:100])}
    except Exception as e:
        return {"records": None, "count": None, "error": "%s: %s" % (type(e).__name__, str(e)[:120])}


# ─────────────────────────────────────────────────────────────────────────────
# Recipe code runs with the caller's process permissions. By default the code gate
# requires a verified code revision and signature. Callers may opt into unsigned code.
# These public keys verify Atlas recipe signatures.
RECIPE_PUBLIC_KEYS: dict[str, str] = {
    "78f47b11eb42a70f": "7/1Jlcne3DodwgRomf8z+U3dvl9awAI2PYGyj+0vL4I=",
}


def recipe_public_keys() -> dict[str, str]:
    """Pinned roots plus keys explicitly configured by the local operator, never the recipe."""
    import json
    import os
    configured = os.environ.get("ATLAS_RECIPE_PUBLIC_KEYS")
    if not configured:
        return RECIPE_PUBLIC_KEYS
    try:
        extra = json.loads(configured)
        if not isinstance(extra, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in extra.items()):
            raise ValueError("invalid key map")
    except (TypeError, ValueError):
        raise ValueError("Invalid recipe signature key configuration") from None
    return {**RECIPE_PUBLIC_KEYS, **extra}


def recipe_signature_message(recipe: dict, metadata: dict) -> bytes:
    """RFC 8785 canonical bytes; authenticate the entire recipe and signature metadata."""
    import rfc8785
    return rfc8785.dumps({"context": "aidenix.atlas.recipe.v1",
                          "recipe": {k: v for k, v in recipe.items() if k != "signature"},
                          "signature": metadata})


def verify_recipe_signature(recipe: dict) -> None:
    """Validate against locally pinned keys, never a key/URL supplied by the recipe."""
    import base64
    import binascii
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    signature = recipe.get("signature")
    fields = {"version", "algorithm", "key_id", "issued_at", "expires_at", "value"}
    if (not isinstance(signature, dict) or set(signature) != fields
            or type(signature["version"]) is not int or signature["version"] != 1
            or signature["algorithm"] != "Ed25519"):
        raise ValueError("Invalid recipe signature format")
    keys = recipe_public_keys()
    kid = signature["key_id"]
    if not isinstance(kid, str) or kid not in keys:
        raise ValueError("Unknown recipe signature key")
    issued, expires = signature["issued_at"], signature["expires_at"]
    now = time.time()
    if (type(issued) is not int or type(expires) is not int
            or expires <= issued or expires - issued > 86400 or issued > now + 300):
        raise ValueError("Invalid recipe signature validity period")
    if expires <= now:
        raise ValueError("Invalid recipe signature: expired; fetch a new recipe")
    try:
        public = base64.b64decode(keys[kid], validate=True)
        value = base64.b64decode(signature["value"], validate=True)
        message = recipe_signature_message(recipe, {k: v for k, v in signature.items() if k != "value"})
        Ed25519PublicKey.from_public_bytes(public).verify(value, message)
    except (InvalidSignature, ValueError, TypeError, binascii.Error):
        raise ValueError("Invalid recipe signature: content was changed or signature is invalid") from None


def _uses_credentials(ep: dict, auth: dict, api_key: str | None = None) -> bool:
    auth = auth or {}
    if (api_key or auth.get("env") or auth.get("login_url") or auth.get("password")
            or auth.get("type") not in (None, "", "none", "anonymous")):
        return True
    try:
        target = urlsplit(str(ep.get("url") or ep.get("path") or ""))
        if target.scheme.lower() in ("http", "https") and target.username is not None:
            return True
        if target.scheme.lower() == "ftp":
            return False  # HTTP headers are never transmitted by the anonymous FTP transport.
    except ValueError:
        pass
    secret_headers = {"authorization", "proxy-authorization", "cookie", "x-api-key", "api-key",
                      "apikey", "x-auth-token", "x-access-token"}
    if any(str(name).lower() in secret_headers for name in (ep.get("static_headers") or {})):
        return True
    fan = ep.get("fanout") or {}
    if isinstance(fan, dict) and any(str(name).lower() in secret_headers for name in (fan.get("static_headers") or {})):
        return True
    return any(_uses_credentials(candidate, {}) for candidate in ep.get("alternatives") or []
               if isinstance(candidate, dict))


def http_step_document(ep: dict, auth: dict) -> dict:
    """The signature binds the full endpoint and its auth declaration as one document."""
    return {"type": "http_step", "ep": {k: v for k, v in ep.items() if k != "signature"},
            "auth": auth or {"type": "none"}}


def _fixed_credential_origin(url: str) -> tuple:
    try:
        parts = urlsplit(str(url))
        address = httpx.URL(str(url))
        if (address.scheme != "https" or not address.host or address.userinfo
                or any(char in parts.netloc for char in "{}")):
            raise ValueError("not a fixed HTTPS recipient")
        return address.scheme, address.host.lower(), address.port or 443
    except (ValueError, TypeError, httpx.InvalidURL):
        raise ValueError("Credential requests require a fixed HTTPS origin") from None


def _check_credential_origin(url: str, expected: tuple | None) -> None:
    if expected is not None and _fixed_credential_origin(url) != expected:
        raise ValueError("Credential request recipient differs from the signed origin")


def _authorize_http_step(ep: dict, auth: dict, api_key: str | None = None) -> tuple | None:
    if "signature" in ep:
        verify_recipe_signature({**http_step_document(ep, auth), "signature": ep["signature"]})
    if not _uses_credentials(ep, auth, api_key):
        return None
    if str(ep.get("url") or ep.get("path") or "").lower().startswith("ftp://"):
        raise httpx.UnsupportedProtocol("FTP recipes require anonymous auth")
    if "signature" not in ep:
        raise ValueError("Credential requests require a valid Atlas step signature")
    if ep.get("tls_insecure"):
        raise ValueError("Credential requests require verified HTTPS")
    target = (ep.get("fanout") or {}).get("url") or _endpoint_url(ep)
    origin = _fixed_credential_origin(target)
    if auth.get("login_url"):
        _fixed_credential_origin(auth["login_url"])
    return origin


def _code_gate(recipe: dict, allow: bool | None) -> tuple[bool, str]:
    """(may recipe code run, block reason)."""
    import os as _os
    if allow is True:
        return True, ""
    trust = (recipe or {}).get("code_trust") or "unknown"
    if allow is None and (_os.environ.get("ATLAS_ALLOW_UNTRUSTED_CODE") or "").strip().lower() in ("1", "true", "yes"):
        return True, ""
    if trust == "verified":
        if type(recipe.get("code_revision")) is int:
            if "signature" not in recipe:
                return False, "untrusted code blocked: verified recipe has no signature; fetch a signed recipe"
            verify_recipe_signature(recipe)
            return True, ""
        return False, ("untrusted code blocked: this recipe has no verified code revision; "
                       "fetch a new recipe or pass allow_untrusted_code=True")
    return False, ("untrusted code blocked (code_trust=%s): the chain's edge/connector code was not "
                   "verified by Atlas; pass allow_untrusted_code=True or set "
                   "ATLAS_ALLOW_UNTRUSTED_CODE=1 to run it" % trust)


def apply_step_gates(recipe: dict) -> dict:
    """Remove calls and incident wires denied by the catalog, including for older SDKs."""
    gates = {}
    for gate in recipe.get("step_gates") or []:
        key = str(gate.get("step"))
        # Ambiguous step numbers cannot identify which operation was approved.
        gates[key] = {} if key in gates else gate
    denied = {key for key, gate in gates.items() if gate.get("executable") is not True}
    steps = []
    for step in recipe.get("steps") or []:
        key = str(step.get("step"))
        gate = gates.get(key)
        reason = step.get("skip_reason")
        if gate is not None:
            if gate.get("executable") is not True or any(
                    gate.get(k) and gate[k] != step.get(k) for k in ("source_id", "slug")):
                reason = gate.get("reason") or "missing source verification"
        elif "step_gates" in recipe and (step.get("source_id") or step.get("slug")
                                         or step.get("ep") or step.get("base") or step.get("connector_code")):
            reason = "missing source verification"
        if reason:
            denied.add(key)
            step = {k: step[k] for k in ("step", "source_id", "slug", "optional", "out", "out_map") if k in step}
            step.update(skip_reason=reason)
            if recipe.get("kind") == "soql":
                step.update(base="", path="")
            else:
                step.update(ep={}, connector_code=None)
        steps.append(step)
    if not denied:
        return recipe
    edges = [e for e in recipe.get("edges") or []
             if str(e.get("from_step")) not in denied and str(e.get("to_step")) not in denied]
    return {**recipe, "steps": steps, "edges": edges}


def run_chain_recipe(recipe: dict, seed: dict, *, allow_untrusted_code: bool | None = None) -> dict:
    """SINGLE chain runner: recipe {kind, steps, edges} + seed → {bundle, steps}.
    The client holds THIS module; the server sends only the recipe (~KB) instead of an embedded script.
    One orchestrator for BOTH patterns (dispatch by kind):
      - kind == 'soql'  → SoQL fan-out-join (Socrata): _run_chain_soql
      - otherwise ('legacy') → declarative endpoint per step + edges[].code wiring: _run_chain_legacy
    `allow_untrusted_code` — gate for recipe code (see _code_gate): None = by the recipe's code_trust
    and the environment, True = run, False = verified only.
    The top level of the result ALWAYS carries `bundle`/`steps` (empty bundle = {}, not a bare
    dict of steps) + `fetched_at` (chain completion time, UTC ISO-8601)."""
    runtime = _chain_runtime()
    return runtime._run_chain_recipe(recipe, seed, allow_untrusted_code=allow_untrusted_code)


def _chain_runtime():
    """Give each run its own module bindings, including imports made by recipe code.

    Legacy recipes install helpers with exec(code, rt.__dict__) and replace rt.run_recipe
    and rt._run_step. Rebind runtime functions to a private namespace so both the chain
    and its worker threads use those helpers without changing the imported module.
    Shared transport caches/locks remain shared; this is execution isolation, not a sandbox.
    """
    import builtins
    import types

    source = globals()
    runtime = types.ModuleType(__name__)
    namespace = runtime.__dict__
    namespace.update(source)
    packages = {}

    def local_import(name, globals=None, locals=None, fromlist=(), level=0):
        if not level and name in ("atlas", "aidenix_atlas", "atlas._recipe_runtime",
                                  "aidenix_atlas._recipe_runtime"):
            if name.endswith("._recipe_runtime") and fromlist:
                return runtime
            package_name = name.split(".")[0]
            original = builtins.__import__(package_name, globals, locals,
                                           fromlist if name == package_name else (), level)
            if package_name not in packages:
                package = types.ModuleType(package_name)
                package.__dict__.update(vars(original))
                package.__getattr__ = lambda key: getattr(original, key)
                package._recipe_runtime = runtime
                packages[package_name] = package
            for key, value in list(vars(original).items()):
                if isinstance(value, types.FunctionType) and value.__globals__ is source:
                    packages[package_name].__dict__[key] = namespace.get(value.__name__, value)
            return packages[package_name]
        return builtins.__import__(name, globals, locals, fromlist, level)

    namespace["__builtins__"] = {**vars(builtins), "__import__": local_import}
    for name, value in list(source.items()):
        if (isinstance(value, types.FunctionType) and value.__globals__ is source
                and name not in ("run_chain_recipe", "_chain_runtime")):
            clone = types.FunctionType(value.__code__, namespace, value.__name__,
                                       value.__defaults__, value.__closure__)
            clone.__kwdefaults__ = value.__kwdefaults__
            clone.__annotations__ = value.__annotations__
            clone.__dict__.update(value.__dict__)
            namespace[name] = clone
    return runtime


def _run_chain_recipe(recipe: dict, seed: dict, *, allow_untrusted_code: bool | None = None) -> dict:
    import copy
    recipe = copy.deepcopy(recipe)
    if "signature" in recipe:
        verify_recipe_signature(recipe)
    elif any(_uses_credentials(step.get("ep") or {}, step.get("auth") or {})
             for step in recipe.get("steps") or []):
        raise ValueError("Credential-bearing chains require a valid Atlas recipe signature")
    if "accepts_params" in recipe or "accepts_inputs" in recipe:
        # Named parameters distinguish input roles when older type names overlap outputs.
        inputs = set(recipe.get("accepts_params") or recipe.get("accepts_inputs") or [])
        derived = set(recipe.get("returns_outputs") or [])
        derived.update(edge.get("to_field") for edge in recipe.get("edges") or [])
        # A server may already have removed a gated wire. Its reserved inputs still
        # belong to the recipe, even when the client cannot see their producer.
        seed = {key: value for key, value in (seed or {}).items()
                if key in inputs or (key not in derived and not str(key).startswith("_atlas_"))}
    _started = time.monotonic()
    if recipe.get("kind") == "soql":
        recipe = apply_step_gates(recipe)
        result = _run_chain_soql(recipe, seed)
    else:
        result = _run_chain_legacy(recipe, seed, allow_untrusted_code)
        recipe = apply_step_gates(recipe)
    result = _mark_unavailable(recipe, result)
    send_run_report(recipe, result, int((time.monotonic() - _started) * 1000))
    return result


def _mark_unavailable(recipe: dict, result: dict) -> dict:
    """bundle.unavailable_data for chains with optional or gated steps."""
    if any(s.get("optional") is True or s.get("skip_reason") for s in recipe.get("steps", [])):
        bundle = result.setdefault("bundle", {})
        unavailable = []
        for step in recipe["steps"]:
            observed = result["steps"].get("step%s" % step.get("step")) or {}
            fields = list(dict.fromkeys([*(step.get("out") or []), *(step.get("out_map") or {})]))
            missing = [f for f in fields if bundle.get(f) is None]
            if not missing and not observed.get("skipped") and not observed.get("error"):
                continue
            raw = observed.get("raw") if isinstance(observed.get("raw"), dict) else {}
            reason = (observed.get("reason") or observed.get("error") or raw.get("note")
                      or ("HTTP %s" % observed["http"] if observed.get("http") else None)
                      or "source returned no value for these fields")
            unavailable.append({"step": step.get("step"), "source_id": step.get("source_id"),
                                "slug": step.get("slug"), "optional": step.get("optional") is True,
                                "status": "skipped" if observed.get("skipped") else "unavailable",
                                "reason": reason, "fields": missing or fields})
        bundle["unavailable_data"] = unavailable
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Run report. A chain recipe issued by the public Atlas API carries `report.url` — a one-time
# address. After the run the runner posts a summary there so Atlas learns whether the recipe
# worked on the client: per-step status, HTTP code, record count and truncation, the NAMES of
# filled outputs, duration. Never seed values, never data. ATLAS_TELEMETRY=0 turns it off;
# a recipe without `report` (internal runs, older servers) sends nothing. A failed send is
# silent and never changes the result.
# ─────────────────────────────────────────────────────────────────────────────
RUNNER_VERSION = "runtime-2026-11-18.1"


def _step_status(res: dict) -> str:
    if res.get("code_blocked"):
        return "blocked"
    if res.get("skipped"):
        return "skipped"
    if res.get("error") or (type(res.get("http")) is int and res["http"] >= 400 and res["http"] != 404):
        return "error"
    count = res.get("count")
    if count is None and isinstance(res.get("records"), list):
        count = len(res["records"])
    if count == 0 or (count is None and res.get("raw") in (None, "", [], {})):
        return "empty"
    return "ok"


def run_report(recipe: dict, result: dict, duration_ms: int | None = None) -> dict:
    """Summary of one chain run, safe to send: statuses and counts, no inputs, no data."""
    steps_out = (result or {}).get("steps") or {}
    bundle = (result or {}).get("bundle") or {}
    steps = []
    for cfg in recipe.get("steps") or []:
        res = steps_out.get("step%s" % cfg.get("step")) or {}
        count = res.get("count")
        if count is None and isinstance(res.get("records"), list):
            count = len(res["records"])
        status = _step_status(res) if res else "skipped"
        # Free-form diagnostics may contain inputs or keys; keep them local only.
        steps.append({"step": cfg.get("step"), "source_id": cfg.get("source_id"), "status": status,
                      "http": res.get("http") if type(res.get("http")) is int else None,
                      "records": count if type(count) is int else None,
                      "truncated": bool(res.get("truncated")), "optional": cfg.get("optional") is True})
    declared = list(recipe.get("returns_outputs") or [])
    filled = [k for k in declared if bundle.get(k) not in (None, "", [], {})]
    required = [s for s in steps if not s["optional"]]
    if bundle.get("code_blocked"):
        outcome = "blocked"
    elif declared and len(filled) == len(declared) and all(s["status"] in ("ok", "empty") for s in required):
        outcome = "ok"
    elif filled:
        outcome = "partial"
    elif steps and all(s["status"] in ("empty", "skipped") for s in steps):
        outcome = "empty"
    else:
        outcome = "failed"
    return {"outcome": outcome, "runner_version": RUNNER_VERSION, "duration_ms": duration_ms,
            "outputs_filled": filled, "outputs_total": len(declared),
            "edge_errors": len(bundle.get("edge_errors") or []), "steps": steps}


def _run_report_url(value: Any) -> str | None:
    """Only Atlas may receive telemetry, including from unsigned recipes."""
    if not isinstance(value, str):
        return None
    try:
        url = urlsplit(value)
        if (url.scheme != "https" or url.hostname != "atlas.aidenix.com"
                or url.port not in (None, 443) or url.username is not None
                or url.query or url.fragment
                or not re.fullmatch(r"/v1/runs/[A-Za-z0-9_-]{32}", url.path)):
            return None
    except ValueError:
        return None
    # Rebuild the destination so only the validated token comes from the recipe.
    return "https://atlas.aidenix.com" + url.path


def send_run_report(recipe: dict, result: dict, duration_ms: int | None = None) -> bool:
    """Post a summary only to Atlas's one-time report endpoint; failures are silent."""
    import os as _os
    report = (recipe or {}).get("report")
    url = _run_report_url(report.get("url")) if isinstance(report, dict) else None
    if url is None:
        return False
    if (_os.environ.get("ATLAS_TELEMETRY") or "").strip().lower() in ("0", "false", "no", "off"):
        return False
    try:
        r = httpx.post(url, json=run_report(recipe, result, duration_ms), timeout=5.0,
                       follow_redirects=False)
        return r.status_code == 204
    except Exception:
        return False


def _run_chain_legacy(recipe: dict, seed: dict, allow_untrusted_code: bool | None = None) -> dict:
    """Legacy pattern: declarative endpoint per step + edges[].code wiring → {bundle, steps}.
    Between steps ctx is mutated ONLY by edges[].code (downstream wiring); bundle comes from out_map.

    Steps WITHOUT an incoming edge are independent (they read only seed + already applied edge mutations of ctx) →
    run them CONCURRENTLY (broadcast legs are I/O-bound; latency goes from the sum to the max). An edge is a
    barrier: before a step with an edge, wait for the accumulated batch (its outputs feed the edge code + ctx is stable),
    apply the edge, then start a new batch. Edge order and ctx mutations are preserved — same semantics.

    Returns `bundle`, `steps` and `fetched_at` even when the bundle is empty."""
    import json as _json
    import os as _os
    from concurrent.futures import ThreadPoolExecutor
    _code_ok, _code_why = _code_gate(recipe, allow_untrusted_code)
    recipe = apply_step_gates(recipe)
    steps = sorted(recipe.get("steps") or [], key=lambda s: s.get("step", 0))
    edges = recipe.get("edges") or []
    ctx = dict(seed or {})
    out: dict = {}
    _edge_errs: list = []  # edge exceptions are NOT swallowed: collected → ctx + bundle.edge_errors
    _blocked = None if _code_ok else _code_why
    _blocked_edges = 0
    _blocked_seen: set = set()   # one edge can be both pre-step (to_step) and terminal (from_step) — count once

    def _fold(batch):
        # Make the mapped outputs of completed steps available to downstream edges.
        for st in batch:
            res = out.get("step%s" % st.get("step")) or {}
            for of, path in (st.get("out_map") or {}).items():
                v = _cv_extract(res, path)
                if v is not None and of not in ctx:
                    ctx[of] = v

    def _flush(batch):
        # batch of independent steps → concurrently (_run_step is read-only on ctx, own httpx per thread).
        if not batch:
            return
        if len(batch) == 1:
            st = batch[0]
            out["step%s" % st.get("step")] = _run_step(st, ctx, _blocked)
            _fold(batch)
            return
        with ThreadPoolExecutor(max_workers=min(len(batch), _concurrency_limit())) as ex:
            futs = {ex.submit(_run_step, st, ctx, _blocked): st for st in batch}
            for f in futs:
                st = futs[f]
                try:
                    out["step%s" % st.get("step")] = f.result()
                except Exception as e:  # leg failed → empty, do not take down the whole broadcast
                    out["step%s" % st.get("step")] = {"records": None, "count": None,
                                                      "error": "%s: %s" % (type(e).__name__, str(e)[:100])}
        _fold(batch)

    batch: list = []
    batch_out: set = set()   # out_map fields of the current batch's steps — not yet folded into ctx
    for st in steps:
        n = st.get("step")
        incoming = [e for e in edges if e.get("to_step") == n and (e.get("code") or "").strip()]
        # Finish the batch before a step reads its output through param_map or a static template.
        # Steps that read only the seed can still run concurrently.
        needs = (set((st.get("param_map") or {}).keys()) | _static_needs(st.get("static_params") or {})) & batch_out
        if incoming or needs:
            _flush(batch)  # barrier: batch done (outputs ready for edge code / folded into ctx), ctx stable
            batch = []
            batch_out = set()
        if incoming:
            for e in incoming:
                if _blocked:
                    if id(e) not in _blocked_seen:
                        _blocked_seen.add(id(e))
                        _blocked_edges += 1
                        _edge_errs.append({"phase": "blocked", "to_step": n, "to_field": e.get("to_field"),
                                           "error": _blocked})
                    continue
                try:
                    exec(e["code"], {"__builtins__": __builtins__, "json": _json,
                                     "re": re, "os": _os}, {"out": out, "ctx": ctx})
                except Exception as _ex:
                    _edge_errs.append({"phase": "pre", "to_step": n, "to_field": e.get("to_field"),
                                       "error": "%s: %s" % (type(_ex).__name__, str(_ex)[:120])})
        batch.append(st)
        batch_out |= set((st.get("out_map") or {}).keys())
    _flush(batch)
    # Terminal edges can consume earlier errors and fill fields left unset by pre-step edges.
    ctx["_edge_errors"] = _edge_errs
    for e in sorted(edges, key=lambda x: (x.get("from_step") or 0)):
        tf = e.get("to_field")
        code = (e.get("code") or "").strip()
        if e.get("from_step") is None or not tf or not code or tf in ctx:
            continue
        if _blocked:
            if id(e) not in _blocked_seen:
                _blocked_seen.add(id(e))
                _blocked_edges += 1
                _edge_errs.append({"phase": "blocked", "from_step": e.get("from_step"), "to_field": tf,
                                   "error": _blocked})
            continue
        try:
            exec(code, {"__builtins__": __builtins__}, {"out": out, "ctx": ctx})
        except Exception as _ex:
            _edge_errs.append({"phase": "post", "from_step": e.get("from_step"), "to_field": tf,
                               "error": "%s: %s" % (type(_ex).__name__, str(_ex)[:120])})
    bundle: dict = {}
    for st in steps:
        res = out.get("step%s" % st.get("step")) or {}
        for of, path in (st.get("out_map") or {}).items():
            v = _cv_extract(res, path)
            if v is not None:
                bundle[of] = v
    # Include declared outputs produced by edges as well as outputs mapped directly from steps.
    for k in (recipe.get("returns_outputs") or []):
        if k not in bundle and ctx.get(k) is not None:
            bundle[k] = ctx[k]
    if _edge_errs:
        bundle["edge_errors"] = _edge_errs
    _blocked_steps = sum(1 for v in out.values() if isinstance(v, dict) and v.get("code_blocked"))
    if _blocked and (_blocked_edges or _blocked_steps):   # code gate fired — report what and why
        bundle["code_blocked"] = {"edges": _blocked_edges, "steps": _blocked_steps,
                                  "code_trust": recipe.get("code_trust") or "unknown", "reason": _blocked}
    return {"bundle": bundle, "steps": out, "fetched_at": _now_iso()}


# ─────────────────────────────────────────────────────────────────────────────
# SoQL fanout and joins use each step's where, list_slot and out_map fields.
#   - {slot} ← upstream out (scalar = first value); _padN derive for zero-padding
#   - fan-out: in({list_slot}) = a LIST from upstream → chunks ≤150, loop, accumulate
#   - join: a list_slot shared by ≥2 steps → group all records by it
#   - bundle = out_map (returns_field → socrata_field), aggregated across steps
# HTTP is delegated to run_recipe (retry/Retry-After/proxy/multiformat); 404 = no record → [].
# ─────────────────────────────────────────────────────────────────────────────
def parse_call(call: str) -> tuple[str, str, dict]:
    """'GET /resource/x.json?$where=...&$limit=50' → (method, path, {soql params}).
    Split only before a new $parameter so ampersands inside quoted values are preserved."""
    method, _, rest = call.strip().partition(" ")
    sp = urlsplit(rest)
    q: dict = {}
    if sp.query:
        for part in re.split(r"&(?=\$\w+=)", sp.query):
            k, _, v = part.partition("=")
            q[k] = v
    return method.upper(), sp.path, q


def is_soql_step(s: dict) -> bool:
    """A step goes to the SoQL runner ONLY if it is a Socrata SoQL resource: a fixed
    4x4 dataset in the path (`/resource/<id>.json`, no path {slot}) + at least one $ param.
    Filters out non-SoQL calls (ensembl/espn/MediaWiki/greenhouse) → legacy."""
    call = s.get("call") or ""
    if not call:
        return False
    _m, path, q = parse_call(call)
    if "/resource/" not in path or "{" in path:        # 4x4 fixed, not {domain}/{dataset_id}
        return False
    return any(k.startswith("$") for k in q)


def _soql_q(v: Any) -> str:                         # SoQL string-literal quote
    return "'" + str(v).replace("'", "''") + "'"


def _soql_scalar(tmpl: str, ctx: dict) -> str:      # {slot} → first upstream value
    def rep(m: "re.Match") -> str:
        vals = ctx.get(m.group(1)) or []
        return str(vals[0]) if vals else ""
    return _SOQL_SLOT.sub(rep, tmpl)


def _soql_params(cfg: dict, where: str) -> dict:
    p = {"$where": where}
    if cfg.get("select"):
        p["$select"] = cfg["select"]
    if cfg.get("order"):
        p["$order"] = cfg["order"]
    p["$limit"] = cfg.get("limit") or "50000"
    return p


def _soql_derive_pad(ctx: dict, slots) -> None:     # Socrata join keys are zero-padded (DOB block/lot)
    for s in slots:
        if ctx.get(s):
            continue
        m = _SOQL_PAD.match(s)
        if m and ctx.get(m.group(1)):
            n = int(m.group(2))
            ctx[s] = [str(v).zfill(n) for v in ctx[m.group(1)]]


def _soql_http(base: str, path: str, params: dict, needs_proxy: bool, proxy_country: str | None) -> tuple[list, bool]:
    """SoQL GET via the shared run_recipe with AUTO-PAGINATION over $offset: $-params are passed through,
    an HTTP failure does not mean an empty result; proxy for portals (needs_proxy ->
    ATLAS_PROXY_URL, client brings its own).
    Completeness rule: never present a capped result as complete. page==$limit => a tail is POSSIBLE ->
    advance $offset += page_size and accumulate until batch < page_size (a short batch = exhausted
    = COMPLETE set). Stop on: a short batch (completeness proven, truncated=False) OR the
    _SOQL_PAGE_CEIL_ROWS ceiling with a still-full page (tail unprovable, truncated=True).
    Returns (records, truncated)."""
    ep = {"url": base + path, "params_passthrough": ["$where", "$select", "$order", "$limit", "$offset"],
          "stop_on_http_error": True, "timeout": 45}
    if needs_proxy:
        ep["needs_proxy"] = True
        if proxy_country:
            ep["proxy_country"] = proxy_country
    try:
        page_size = int(params.get("$limit"))
    except (TypeError, ValueError):
        page_size = 0
    base_params = {k: v for k, v in params.items() if k != "$offset"}
    out: list = []
    offset = 0
    while True:
        p = dict(base_params)
        if page_size > 0:
            p["$offset"] = str(offset)
        res = run_recipe(ep, {"type": "none"}, p)
        if (res.get("error") or res.get("refusal") or res.get("unfilled") or res.get("partial")
                or isinstance(res.get("http"), int) and res["http"] >= 400):
            raise ValueError("SoQL source failed: " + str(res.get("error") or res.get("refusal")
                                                       or res.get("unfilled") or res.get("http") or "partial response"))
        batch = res.get("records")
        if not isinstance(batch, list):
            raise ValueError("SoQL source did not return a record list")
        out += batch
        if res.get("truncated") and not (
                res.get("truncated_by") == "limit" and page_size > 0 and len(batch) == page_size):
            return out, True
        if page_size <= 0 or len(batch) < page_size:                       # short batch => exhausted => COMPLETE
            return out, False
        offset += page_size
        if offset >= _SOQL_PAGE_CEIL_ROWS:               # safety cap: full page at the ceiling => tail unprovable
            return out, True


def _soql_exec_step(cfg: dict, ctx: dict) -> tuple[list, bool] | None:
    """One SoQL step: {slot} substitution from ctx + _padN derivation + fan-out over in({list_slot}).
    None = upstream ran dry (some {slot} has no value -> do not send broken SoQL).
    Returns (recs, truncated): truncated=True => at least one chunk hit $limit
    (tail unprovable; never present a truncated result as a complete set)."""
    where = cfg.get("where") or ""
    need = set(_SOQL_SLOT.findall(where))
    _soql_derive_pad(ctx, need)
    if any(not ctx.get(s) for s in need):
        return None
    ls = cfg.get("list_slot")
    np = bool(cfg.get("needs_proxy"))
    pc = cfg.get("proxy_country")
    base, path = cfg.get("base") or "", cfg.get("path") or ""
    if ls:
        vals, seen = [], set()
        for v in ctx.get(ls) or []:
            sv = str(v)
            if sv not in seen:
                seen.add(sv)
                vals.append(sv)
        recs: list = []
        trunc = False
        for i in range(0, len(vals), _SOQL_IN_CHUNK):
            ins = ",".join(_soql_q(v) for v in vals[i:i + _SOQL_IN_CHUNK])
            w = _soql_scalar(where.replace("{" + ls + "}", ins), ctx)
            chunk, ct = _soql_http(base, path, _soql_params(cfg, w), np, pc)
            recs += chunk
            trunc = trunc or ct
        return recs, trunc
    return _soql_http(base, path, _soql_params(cfg, _soql_scalar(where, ctx)), np, pc)


def _run_chain_soql(recipe: dict, seed: dict) -> dict:
    """SoQL fan-out/join runner -> {bundle, steps}. ctx = seed (everything as lists for fan-out);
    step out -> ctx (project step.out, dedupe); join on a shared list_slot; bundle from out_map.
    Carries `fetched_at` (completion time); the {bundle?, steps} shape is kept unchanged."""
    from collections import Counter
    steps = sorted(recipe.get("steps") or [], key=lambda s: s.get("step", 0))
    ctx = {k: (v if isinstance(v, list) else [v]) for k, v in (seed or {}).items()}
    step_recs: dict = {}
    out_steps: dict = {}
    any_truncated = False
    for cfg in steps:
        n = cfg.get("step")
        if cfg.get("skip_reason"):
            out_steps["step%s" % n] = {"source": cfg.get("source_id"), "count": 0,
                                       "skipped": True, "reason": cfg["skip_reason"]}
            continue
        try:
            res = _soql_exec_step(cfg, ctx)
        except Exception as e:
            out_steps["step%s" % n] = {"source": cfg.get("source_id"), "dataset": cfg.get("path"),
                                       "count": 0, "error": "%s: %s" % (type(e).__name__, str(e)[:140])}
            continue
        if res is None:
            out_steps["step%s" % n] = {"source": cfg.get("source_id"), "dataset": cfg.get("path"),
                                       "count": 0, "skipped": "no upstream input"}
            continue
        recs, truncated = res
        any_truncated = any_truncated or truncated
        step_recs[n] = recs
        out_steps["step%s" % n] = {"source": cfg.get("source_id"), "dataset": cfg.get("path"),
                                   "count": len(recs), "truncated": truncated, "sample": recs[:2]}
        for f in cfg.get("out") or []:                 # project out → ctx (dedupe, keep order)
            vs, seen = [], set()
            for r in recs:
                if isinstance(r, dict) and r.get(f) not in (None, "") and r[f] not in seen:
                    seen.add(r[f])
                    vs.append(r[f])
            if vs:
                ctx[f] = vs
    # join: list_slot shared by >=2 steps
    lc = Counter(c["list_slot"] for c in steps if c.get("list_slot"))
    join_key = next((k for k, v in lc.items() if v >= 2), None)
    if join_key:
        joined: dict = {}
        for st, recs in step_recs.items():
            for r in recs:
                jk = r.get(join_key) if isinstance(r, dict) else None
                if jk is not None:
                    joined.setdefault(jk, {}).setdefault("step%s" % st, []).append(r)
        out_steps["joined_by"] = join_key
        out_steps["join_count"] = len(joined)
    # bundle per contract: out_map (returns_field -> socrata_field), aggregated across steps
    bundle: dict = {}
    for cfg in steps:
        if cfg.get("step") not in step_recs:
            continue
        recs = step_recs[cfg.get("step")]
        for of, field in (cfg.get("out_map") or {}).items():
            if field == "[]":
                bundle.setdefault(of, []).extend(recs)
                continue
            cur = bundle.get(of) or []                 # >=2 sources into one returns field -> accumulate
            seen = set(cur)
            for r in recs:
                v = r.get(field) if isinstance(r, dict) else None
                if v not in (None, "") and v not in seen:
                    seen.add(v)
                    cur.append(v)
            if cur:
                bundle[of] = cur
    out_steps["truncated"] = any_truncated  # chain-level: any step hit $limit => set is NOT complete
    _fetched_at = _now_iso()   # timestamp only; the {bundle?, steps} shape of this branch stays unchanged
    return ({"bundle": bundle, "steps": out_steps, "fetched_at": _fetched_at} if bundle
            else {"steps": out_steps, "fetched_at": _fetched_at})


# ── login-token auth: exchange (baked/BYO) credentials for a short-lived bearer ────────
# For sources whose data endpoint needs a JWT obtained via POST /login (credentials in the
# body -> token in a response header). Public government registries and
# similar: auth carries login_url + user + (password | env). The token is cached until JWT exp; on
# 401/403 from a data request, a forced re-login (in arun_recipe below). Login flow:
# username/password -> JSON body -> token from the Authorization header.
_LOGIN_CACHE: dict[str, tuple[str, float]] = {}


def _login_cache_key(auth: dict, password: str, data_origin: tuple | None) -> str:
    import hashlib
    import json
    if data_origin is None:
        raise ValueError("Credential login requires a verified recipient")
    identity = json.dumps([auth, password, data_origin], sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _login_password(auth: dict) -> str:
    pw = auth.get("password")
    if pw is None and auth.get("env"):
        import os as _os
        pw = _os.environ.get(auth["env"], "")
    return pw or ""


async def _login_token(auth: dict, proxy_url: str | None, timeout: float, force: bool = False,
                       credential_origin: tuple | None = None, data_origin: tuple | None = None,
                       deadline_s: float | None = None) -> str:
    try:
        return await _async_deadline_call(
            _login_token_inner(auth, proxy_url, timeout, force, credential_origin, data_origin),
            _limits_of({"deadline_s": deadline_s})[1])
    except _DeadlineExpired:
        raise httpx.ReadTimeout("Login request deadline exceeded") from None


async def _login_token_inner(auth: dict, proxy_url: str | None, timeout: float, force: bool = False,
                             credential_origin: tuple | None = None, data_origin: tuple | None = None) -> str:
    """POST login_url {username,password} -> bearer from a response header (or body). Cached until exp."""
    import time as _t, json as _j, base64 as _b64
    if credential_origin is None:
        raise ValueError("Credential login requires a verified endpoint")
    login_url = auth["login_url"]
    _check_credential_origin(login_url, credential_origin)
    login_origin = _fixed_credential_origin(login_url)
    user = auth.get("user") or auth.get("username") or "anonymous"
    th = auth.get("token_header") or "Authorization"
    password = _login_password(auth)
    key = _login_cache_key(auth, password, data_origin)
    now = _t.time()
    if not force:
        c = _LOGIN_CACHE.get(key)
        if c and c[1] - 30 > now:                    # 30s margin before expiry
            return c[0]
    body = {(auth.get("username_field") or "username"): user,
            (auth.get("password_field") or "password"): password}
    async with httpx.AsyncClient(timeout=timeout, proxy=proxy_url, follow_redirects=True,
                                 event_hooks=_address_hooks(proxy_url, True, login_origin),
                                 headers={"User-Agent": DEFAULT_UA,
                                          "Accept": "application/json, */*"}) as cli:
        async with _RequestSlot(), _stream_async(cli, "POST", login_url, json=body,
                              headers={"Accept-Encoding": "gzip, deflate"}) as r:
            r.raise_for_status()
            token = r.headers.get(th) or ""
            if not token:
                cap, deadline = _limits_of({})
                try:
                    raw, why = await _capped_body_async(_http_chunks_async(r, cap), _now(), cap, deadline)
                except ResourceLimitError as error:
                    raise ValueError("Login response exceeds the local byte limit") from error
                if why:
                    raise ValueError("Login response exceeds the local resource limit")
                try:
                    jd = _j.loads(raw)
                    token = jd.get("token") or jd.get("access_token") or jd.get(th) or ""
                except (ValueError, AttributeError):
                    token = ""
    if not token:
        raise ValueError(f"login {login_url}: token not found in header {th!r} or response body")
    exp = now + 1800                                 # default 30 min if exp is unreadable
    try:                                             # JWT exp (claims.exp) -> exact TTL
        seg = token.split()[-1].split(".")[1]
        seg += "=" * (-len(seg) % 4)
        claims = _j.loads(_b64.urlsafe_b64decode(seg))
        if claims.get("exp"):
            exp = float(claims["exp"])
    except Exception:
        pass
    _LOGIN_CACHE[key] = (token, exp)
    return token


def _login_token_sync(auth: dict, proxy_url: str | None, timeout: float, force: bool = False,
                      credential_origin: tuple | None = None, data_origin: tuple | None = None,
                      deadline_s: float | None = None) -> str:
    try:
        return _sync_deadline_call(
            lambda: _login_token_sync_inner(auth, proxy_url, timeout, force, credential_origin, data_origin),
            _limits_of({"deadline_s": deadline_s})[1])
    except _DeadlineExpired:
        raise httpx.ReadTimeout("Login request deadline exceeded") from None


def _login_token_sync_inner(auth: dict, proxy_url: str | None, timeout: float, force: bool = False,
                            credential_origin: tuple | None = None, data_origin: tuple | None = None) -> str:
    """Obtain and cache a bearer token for a synchronous request until it expires."""
    import time as _t, json as _j, base64 as _b64
    if credential_origin is None:
        raise ValueError("Credential login requires a verified endpoint")
    login_url = auth["login_url"]
    _check_credential_origin(login_url, credential_origin)
    login_origin = _fixed_credential_origin(login_url)
    user = auth.get("user") or auth.get("username") or "anonymous"
    th = auth.get("token_header") or "Authorization"
    password = _login_password(auth)
    key = _login_cache_key(auth, password, data_origin)
    now = _t.time()
    if not force:
        c = _LOGIN_CACHE.get(key)
        if c and c[1] - 30 > now:
            return c[0]
    body = {(auth.get("username_field") or "username"): user,
            (auth.get("password_field") or "password"): password}
    with httpx.Client(timeout=timeout, proxy=proxy_url, follow_redirects=True,
                       event_hooks=_address_hooks(proxy_url, credential_origin=login_origin),
                      headers={"User-Agent": DEFAULT_UA,
                               "Accept": "application/json, */*"}) as cli:
        with _RequestSlot(), _stream_sync(cli, "POST", login_url, json=body,
                        headers={"Accept-Encoding": "gzip, deflate"}) as r:
            r.raise_for_status()
            token = r.headers.get(th) or ""
            if not token:
                cap, deadline = _limits_of({})
                try:
                    raw, why = _capped_body_sync(_http_chunks_sync(r, cap), _now(), cap, deadline)
                except ResourceLimitError as error:
                    raise ValueError("Login response exceeds the local byte limit") from error
                if why:
                    raise ValueError("Login response exceeds the local resource limit")
                try:
                    jd = _j.loads(raw)
                    token = jd.get("token") or jd.get("access_token") or jd.get(th) or ""
                except (ValueError, AttributeError):
                    token = ""
    if not token:
        raise ValueError(f"login {login_url}: token not found in header {th!r} or response body")
    exp = now + 1800
    try:
        seg = token.split()[-1].split(".")[1]
        seg += "=" * (-len(seg) % 4)
        claims = _j.loads(_b64.urlsafe_b64decode(seg))
        if claims.get("exp"):
            exp = float(claims["exp"])
    except Exception:
        pass
    _LOGIN_CACHE[key] = (token, exp)
    return token


async def arun_recipe(ep: dict, auth: dict, params: dict, api_key: str | None = None,
                      proxy_url: str | None = None) -> dict:
    """Async endpoint execution with the same signed-credential policy as run_recipe."""
    import copy
    ep, auth = copy.deepcopy((ep, auth))
    origin = _authorize_http_step(ep, auth, api_key)
    return await _arun_recipe(ep, auth, params, api_key, proxy_url, origin)


async def _arun_recipe(ep: dict, auth: dict, params: dict, api_key: str | None = None,
                       proxy_url: str | None = None, credential_origin: tuple | None = None) -> dict:
    """Run an endpoint asynchronously with the same request preparation and pagination as run_recipe.
    login-token auth (auth.login_url): obtain a bearer by logging in; on 401/403, one re-login.
    `endpoint.path_defaults` is a default for a NON-identifier {token} in the path (year and
    similar); if it filled the token, a successful response carries `defaulted: [names]`."""
    import os as _os
    if _uses_credentials(ep, auth, api_key) and credential_origin is None:
        raise ValueError("Credential requests require a valid Atlas step signature")
    if credential_origin is not None and ep.get("tls_insecure"):
        raise ValueError("Credential requests require verified HTTPS")
    if "alternatives" in ep:
        return await _arun_resource_candidates(ep, auth, params, api_key, proxy_url, credential_origin)
    login_url = auth.get("login_url")
    if auth.get("env") and not api_key and not login_url:
        api_key = _os.environ.get(auth["env"], "")
    if auth.get("env") and not api_key and not login_url:
        raise ValueError(f"endpoint requires {auth['env']} env var")
    if ep.get("fanout"):   # fan-out in the async twin too (previously hit the bare url)
        return await _run_fanout_async(ep, ep["fanout"], auth, params, api_key, proxy_url, credential_origin)
    url, args, response_path, pg, timeout = prepare_call(ep, params, auth, api_key)
    _check_credential_origin(url, credential_origin)
    _unfilled = _unfilled_result(url, ep, params, args)
    if _unfilled:
        return _unfilled
    if proxy_url is None and ep.get("needs_proxy"):
        proxy_url = _os.environ.get("ATLAS_PROXY_URL") or None

    token_header = auth.get("token_header") or "Authorization"
    for _login_attempt in range(2 if login_url else 1):
        hdrs = _headers(ep, auth, api_key)
        if login_url:
            hdrs = {**hdrs, token_header: await _login_token(
                auth, proxy_url, timeout, force=_login_attempt > 0,
                credential_origin=_fixed_credential_origin(login_url), data_origin=credential_origin,
                deadline_s=_limits_of(ep)[1])}
        try:
            async with httpx.AsyncClient(timeout=timeout, headers=hdrs, proxy=proxy_url,
                                         event_hooks=_address_hooks(proxy_url, True, credential_origin),
                                         follow_redirects=True,
                                         verify=not ep.get("tls_insecure")) as c:
                if not pg:
                    fetched = await _afetch(c, ep, args, url)
                    payload, fmt, raw_text = fetched
                    if getattr(fetched, "refusal", None):
                        return _refusal_result(fetched, payload, fmt, raw_text, ep, params)
                    records = _records_of(payload, response_path, ep.get("objectify"))
                    return {"records": records, "count": len(records) if isinstance(records, list) else None,
                            "raw": payload if records is None or isinstance(payload, dict) else None,
                            "format": fmt, "raw_text": raw_text,
                            "fetched_at": _now_iso(),   # same as the sync twin run_recipe
                            **_single_get_completeness(records, args),
                            **_body_flags(fetched),
                            **_coverage_of(ep, params),
                            **_defaulted_of(ep, params),
                            **({"hint": _BINARY_HINT} if fmt == "binary" else {})}
                plan = _pg_plan(pg, params)
                items: list = []
                total = None
                last_page = None
                pages_used = 0
                last_batch_len = 0
                body_cut: dict = {}
                refused = None
                for offset in range(plan["ceiling"]):
                    args[pg["page_param"]] = plan["page"] + offset
                    args[pg["size_param"]] = plan["size"]
                    args.update(plan.get("cursor") or {})
                    fetched = await _afetch(c, ep, args, url)
                    payload, _fmt, _rt = fetched
                    if getattr(fetched, "refusal", None):
                        if not items:   # refusal on the very first page: no records
                            return _refusal_result(fetched, payload, _fmt, _rt, ep, params)
                        refused = fetched
                        break           # refusal mid-walk: return what was collected and report the refusal
                    batch = _dig(payload, pg["items_path"])
                    if plan.get("has_next_path") and not isinstance(batch, list):
                        raise ValueError("Pagination response has no record list")
                    batch = batch or []
                    last_batch_len = len(batch)
                    items.extend(batch)
                    total = _dig(payload, pg["total_path"]) if pg.get("total_path") else None
                    if plan["last_page_path"]:
                        _lp = _dig(payload, plan["last_page_path"])
                        last_page = int(_lp) if _lp is not None else last_page
                    pages_used = offset + 1
                    body_cut = _body_flags(fetched)
                    stop = False if body_cut else _pg_should_stop(plan, payload, len(items), offset, last_page)
                    if body_cut or not batch or stop:
                        break   # truncated page: stop paging, the tail is unprovable
                out = items if plan["target"] is None else items[: plan["target"]]
                return {"records": out, "count": len(out),
                        "total_estimated": total, "pages_used": pages_used, "format": "json",
                        "fetched_at": _now_iso(),   # same as the sync twin run_recipe
                        **_pg_completeness(plan, out, last_batch_len, pages_used, total, last_page),
                        **body_cut, **_coverage_of(ep, params), **_defaulted_of(ep, params),
                        **({"refusal": refused.refusal_kind, "refusal_message": refused.refusal,
                            "refusal_after_page": pages_used} if refused is not None else {})}
        except httpx.HTTPStatusError as e:
            if (login_url and _login_attempt == 0 and e.response is not None
                    and e.response.status_code in (401, 403)):
                continue                             # token expired -> forced re-login, 1 retry
            raise
    raise RuntimeError("arun_recipe: login retry exhausted")


# ─────────────────────────────────────────────────────────────────────────────
# Route fallback steps. Step 1 of a route may carry an `alternates` field with
# 1-2 fallback steps. The client runs step 1; if it delivered no data (error, timeout, unfilled
# input, refusal in the body, 0 records and no object), the next one runs. Mode `fail+value` also
# falls through when the data contains none of the question's values (plan `seed_values`): the first
# step whose data contains a value is taken, otherwise the first one that delivered data, so a
# non-answer is not passed off as an answer.
# All attempts run locally using the caller's inputs.
# ─────────────────────────────────────────────────────────────────────────────
FALLBACK_MODES = ("off", "fail", "fail+value")

# Value types that may not appear verbatim in response data: dates and periods (different format),
# free text and topic (a search phrase, not a value), numbers and coordinates (different notation),
# the dataset's own identifier (not from the question). For these, "value absent" would be a false negative.
_SEED_SKIP_TYPES = frozenset({
    "date", "date_range", "datetime", "month", "year", "search_query", "topic", "funding_topic",
    "indicator", "product_category", "condition", "latitude", "longitude", "lat_lng", "bbox",
    "revenue", "employee_count", "timezone", "dataset_id", "query", "keyword", "full_text_query",
    "free_text_query",
})


class NoEndpointError(ValueError):
    """Recipe has no executable endpoint (empty recipe, card without a body)."""


def fallback_mode(mode: Any) -> str:
    """Fallback mode name: off | fail | fail+value; unknown -> off."""
    m = str(mode or "off").strip().lower()
    return m if m in FALLBACK_MODES else "off"


def _records_count(res: dict) -> int:
    """Count dictionary records in a response. A list of scalars is a column."""
    recs = res.get("records")
    if not isinstance(recs, list) or not recs:
        return 0
    if not all(isinstance(x, dict) for x in recs[:5]):
        return 0
    return len(recs)


def attempt_outcome(res: dict | None) -> dict:
    """Whether a step delivered data: {delivered, rows, object, why}. why: ok | unfilled | refusal:<kind> | empty.
    Data = dict records or a non-empty object, with no refusal in the body and no unfilled input."""
    res = res or {}
    rows = _records_count(res)
    raw = res.get("raw")
    obj = bool(isinstance(raw, dict) and raw and not res.get("refusal"))
    if res.get("unfilled"):
        why = "unfilled"
    elif res.get("refusal"):
        why = "refusal:" + str(res.get("refusal"))
    elif not (rows or obj):
        why = "empty"
    else:
        why = "ok"
    return {"delivered": why == "ok", "rows": rows, "object": obj, "why": why}


def seed_values_of(task_signals: dict | None) -> list[str]:
    """Question values worth looking for in response data: plan `seed_values` and chain-only values
    (`chain_seed_values`), excluding `_SEED_SKIP_TYPES`, at least two characters long.
    Ordered by type name, so the same plan yields the same list."""
    sig = task_signals or {}
    out: list[str] = []
    for bag in (sig.get("seed_values"), sig.get("chain_seed_values")):
        if not isinstance(bag, dict):
            continue
        for typ in sorted(bag, key=str):
            if str(typ).lower() in _SEED_SKIP_TYPES:
                continue
            vals = bag[typ] if isinstance(bag[typ], list) else [bag[typ]]
            for v in vals:
                if isinstance(v, bool) or not isinstance(v, (str, int, float)):
                    continue
                s = str(v).strip()
                if len(s) >= 2 and s not in out:
                    out.append(s)
    return out


def _norm_text(s: Any) -> str:
    from urllib.parse import unquote_plus
    return (unquote_plus(str(s or "")).casefold().replace("_", " ").replace("+", " ")
            .replace("/", " ").replace("-", " "))


def seed_seen(seeds: list | None, res: dict | None) -> bool | None:
    """Check whether response data contains any seed after case and separator normalization.

    A multi-word seed matches when all its words longer than one character appear.
    Return None when there are no values or response data to compare.
    """
    import json as _j
    vals = [str(s) for s in (seeds or []) if str(s).strip()]
    if not vals or not isinstance(res, dict):
        return None
    body = res.get("records") if res.get("records") is not None else res.get("raw")
    if body is None:
        return None
    try:
        hay = _norm_text(_j.dumps(body, ensure_ascii=False, default=str))
    except Exception:  # noqa: BLE001
        return None
    for s in vals:
        v = _norm_text(s)
        words = [w for w in v.split() if len(w) > 1]
        if v and (v in hay or (len(words) > 1 and all(w in hay for w in words))):
            return True
    return False


def chain_data(res: dict | None) -> dict:
    """Chain result -> data of its last step that has data (dict records or an object without a
    refusal), plus the chain `bundle`. No such step -> {}."""
    if not isinstance(res, dict):
        return {}
    steps = res.get("steps", res)
    last: dict = {}
    for v in (steps.values() if isinstance(steps, dict) else []):
        if isinstance(v, dict) and (_records_count(v) or (isinstance(v.get("raw"), dict) and v.get("raw")
                                                          and not v.get("refusal"))):
            last = v
    if last and res.get("bundle"):
        last = {**last, "bundle": res["bundle"]}
    return last


def error_code(e: BaseException) -> str:
    """Call failure code: HTTP status, needs_key (no key in the environment), no_endpoints, or the exception name."""
    resp = getattr(e, "response", None)
    if isinstance(e, httpx.HTTPStatusError) and resp is not None:
        return str(resp.status_code)
    if isinstance(e, NoEndpointError):
        return "no_endpoints"
    if isinstance(e, ValueError) and "requires" in str(e):
        return "needs_key"
    return type(e).__name__


def execute_attempt(attempt: dict, *, api_key: str | None = None, proxy_url: str | None = None,
                    allow_untrusted_code: bool | None = None) -> dict:
    """Run one attempt: a thin chain recipe (`runnable`) via the resident runner, otherwise the recipe's
    primary endpoint via `run_recipe`. HTTP errors, timeouts and empty recipes raise."""
    import copy
    rec = copy.deepcopy(attempt.get("recipe") or {})
    if "signature" in rec:
        verify_recipe_signature(rec)
    params = dict(attempt.get("params") or {})
    if rec.get("runnable") and rec.get("steps") is not None and not rec.get("endpoints"):
        return chain_data(run_chain_recipe(rec, params, allow_untrusted_code=allow_untrusted_code))
    ep = primary_endpoint(rec.get("endpoints"))
    if ep is None:
        raise NoEndpointError("recipe has no executable endpoint")
    return run_recipe(ep, rec.get("auth") or {"type": "none"}, params, api_key=api_key, proxy_url=proxy_url)


def _fallback_more(log: list[dict], mode: str) -> bool:
    """Whether to try the next step: fail - while none delivered data; fail+value - while no step has data
    in which a question value is visible (or there is nothing to check)."""
    if mode == "fail":
        return not any(e["delivered"] for e in log)
    return not any(e["delivered"] and e.get("seen") is not False for e in log)


def fallback_pick(log: list[dict], mode: str) -> int | None:
    """Which step to return: fail - first that delivered data; fail+value - first with data where a value is visible
    (or nothing to check), else first that delivered data; None - none delivered data."""
    mode = fallback_mode(mode)
    if mode == "fail+value":
        for e in log:
            if e["delivered"] and e.get("seen") is not False:
                return e["i"]
    for e in log:
        if e["delivered"]:
            return e["i"]
    return None


def run_with_fallback(attempts: list[dict], *, mode: str = "fail", seeds: list | None = None,
                      execute=None, known: dict | None = None, **exec_kw) -> dict:
    """Step 1 and its fallbacks in order until data is delivered (modes: `FALLBACK_MODES`).

    attempts - [{"ref", "recipe", "params", ...}] (`attempts_from_payload`); execute(attempt) -> a
    `run_recipe` result or an exception (default `execute_attempt`); known - {index: ready log entry}
    (fields delivered/rows/object/why/code/seen, optionally result): reuse that entry without executing
    the step again. Returns {"chosen": index | None, "result": the chosen step's response
    (or step 1's if no data), "attempts": [{i, ref, executed, delivered, rows, object, why, code, seen, ms}]}."""
    mode = fallback_mode(mode)
    run = execute or (lambda a: execute_attempt(a, **exec_kw))
    known = known or {}
    log: list[dict] = []
    results: dict[int, Any] = {}
    for i, att in enumerate(attempts or []):
        if i > 0 and (mode == "off" or not _fallback_more(log, mode)):
            break
        entry = {"i": i, "ref": att.get("ref") or att.get("id"), "executed": i not in known}
        t0 = _now()
        if i in known:
            k = dict(known[i])
            results[i] = k.pop("result", None)
            entry.update({"delivered": bool(k.get("delivered")), "rows": k.get("rows") or 0,
                          "object": bool(k.get("object")),
                          "why": k.get("why") or ("ok" if k.get("delivered") else "empty"),
                          "code": k.get("code"), "seen": k.get("seen")})
        else:
            try:
                res = run(att)
                oc = attempt_outcome(res)
                code = "unfilled" if (res or {}).get("unfilled") else str((res or {}).get("http") or 200)
                entry.update(oc, code=code, seen=seed_seen(seeds, res) if oc["delivered"] else None)
                results[i] = res
            except Exception as e:  # noqa: BLE001 - a failed step means try the fallback, not crash
                entry.update({"delivered": False, "rows": 0, "object": False, "why": "error",
                              "code": error_code(e), "seen": None})
                results[i] = None
        entry["ms"] = int((_now() - t0) * 1000)
        log.append(entry)
    chosen = fallback_pick(log, mode)
    return {"chosen": chosen, "result": results.get(chosen if chosen is not None else 0), "attempts": log}


def attempts_from_payload(payload: dict, resolve=None) -> list[dict]:
    """`route_signals` plan -> attempts for `run_with_fallback`: step 1 and its `alternates`. The recipe comes from
    payload["recipes"] by source_id; if missing, a card without a body, or a chain step without a thin
    recipe, resolve(recipe_ref or source_id) is called, keeping the chosen recipe form
    (e.g. the client's get_recipe with runnable=True). A two-step
    route (step 2 consumes step 1's output) and an abstain are not eligible for fallback -> []."""
    plan = (payload or {}).get("plan") or {}
    steps = plan.get("steps") or []
    if plan.get("abstain") or len(steps) != 1:
        return []
    recipes = (payload or {}).get("recipes") or {}
    out: list[dict] = []
    for st in [steps[0], *(steps[0].get("alternates") or [])]:
        sid = st.get("source_id")
        rec = recipes.get(sid)
        need = (not rec or rec.get("body_omitted")
                or (st.get("kind") == "chain" and not rec.get("runnable")))
        if need and resolve is not None:
            rec = resolve(st.get("recipe_ref") or sid)
        out.append({"ref": sid, "kind": st.get("kind"), "recipe": rec, "params": st.get("params") or {}})
    return out
