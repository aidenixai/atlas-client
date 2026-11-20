"""Real loopback sockets: the logical request deadline bounds slow reads and retries."""
import asyncio
import threading
import time
import zlib
import httpx
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from aidenix_atlas import _recipe_runtime as rt


@pytest.fixture
def source(monkeypatch, request, tmp_path):
    monkeypatch.setenv("ATLAS_ALLOW_PRIVATE_ADDRESSES", "1")
    monkeypatch.setenv("ATLAS_TELEMETRY", "0")
    monkeypatch.setenv("ATLAS_FETCH_DEADLINE_S", "1")
    monkeypatch.setenv("ATLAS_MAX_CONCURRENCY", "6")
    seen = []
    peer_closed = threading.Event()
    csv = b"id,name\n1,one\n"

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        def log_message(self, *args):
            pass

        def handle(self):
            try:
                super().handle()
            except OSError:
                pass  # Expected peer shutdown after the deadline, including on Windows.

        def reply_headers(self, status=200, length=None, encoding=None, location=None):
            self.send_response(status)
            self.send_header("Content-Type", "text/csv")
            if length is not None:
                self.send_header("Content-Length", str(length))
            else:
                self.send_header("Connection", "close")
                self.close_connection = True
            if encoding:
                self.send_header("Content-Encoding", encoding)
            if location:
                self.send_header("Location", location)
            self.end_headers()

        def do_GET(self):
            seen.append(self.path)
            try:
                if self.path == "/headers":
                    time.sleep(2)
                    self.reply_headers(length=len(csv))
                    self.wfile.write(csv)
                elif self.path == "/header-drip":
                    self.connection.sendall(b"HTTP/1.1 200 OK\r\n")
                    header = f"Content-Length: {len(csv)}\r\nContent-Type: text/csv\r\n\r\n".encode()
                    for byte in header:
                        time.sleep(0.12)
                        self.connection.sendall(bytes([byte]))
                    self.connection.sendall(csv)
                elif self.path == "/medium":
                    time.sleep(1.3)
                    self.reply_headers(length=len(csv))
                    self.wfile.write(csv)
                elif self.path == "/retry":
                    time.sleep(0.35)
                    self.reply_headers(503, length=0)
                elif self.path.startswith("/redirect/"):
                    number = int(self.path.rsplit("/", 1)[1])
                    if number < 4:
                        time.sleep(0.5)
                        self.reply_headers(302, length=0, location=f"/redirect/{number + 1}")
                    else:
                        self.reply_headers(length=len(csv))
                        self.wfile.write(csv)
                elif self.path == "/stall":
                    self.reply_headers(length=100)
                    self.wfile.write(b"a")
                    self.wfile.flush()
                    self.connection.settimeout(2.5)
                    try:
                        if self.connection.recv(1) == b"":
                            peer_closed.set()
                    except (ConnectionResetError, OSError):
                        peer_closed.set()
                elif self.path == "/compressed":
                    self.reply_headers(encoding="gzip")
                    encoder = zlib.compressobj(wbits=16 + zlib.MAX_WBITS)
                    for _ in range(20):
                        time.sleep(0.12)
                        self.wfile.write(encoder.compress(b"x") + encoder.flush(zlib.Z_SYNC_FLUSH))
                        self.wfile.flush()
                    self.wfile.write(encoder.flush())
                elif self.path == "/partial":
                    self.reply_headers(length=len(csv) + 6)
                    self.wfile.write(csv)
                    self.wfile.flush()
                    for byte in b"2,two\n":
                        time.sleep(0.35)
                        self.wfile.write(bytes([byte]))
                        self.wfile.flush()
                elif self.path == "/drip":
                    body = b"id,x\n1,okay\n"
                    self.reply_headers(length=len(body))
                    for byte in body:
                        time.sleep(0.18)
                        self.wfile.write(bytes([byte]))
                        self.wfile.flush()
                else:
                    self.reply_headers(length=len(csv))
                    self.wfile.write(csv)
            except (BrokenPipeError, ConnectionResetError, OSError):
                if self.path == "/header-drip":
                    peer_closed.set()
                pass

        def do_POST(self):
            seen.append(self.path)
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            body = b'{"token":"x"}'
            try:
                self.reply_headers(length=len(body))
                for byte in body:
                    time.sleep(0.18)
                    self.wfile.write(bytes([byte]))
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                peer_closed.set()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    secure = getattr(request, "param", False)
    if secure:
        import datetime
        import ipaddress
        import ssl
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        now = datetime.datetime.now(datetime.UTC)
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=1))
                .not_valid_after(now + datetime.timedelta(hours=1))
                .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), True).sign(key, hashes.SHA256()))
        cert_path, key_path = tmp_path / "local-ca.pem", tmp_path / "local-key.pem"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_path, key_path)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        monkeypatch.setenv("SSL_CERT_FILE", str(cert_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"{'https' if secure else 'http'}://127.0.0.1:{server.server_port}", seen, peer_closed
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


def execute(source, path, asynchronous=False, **ep):
    endpoint = {"url": source[0] + path, "timeout": 4, "deadline_s": 86400, **ep}
    auth = {"type": "none"}
    if asynchronous:
        async def run():
            start = time.monotonic()
            result = await rt.arun_recipe(endpoint, auth, {})
            return result, time.monotonic() - start
        return asyncio.run(run())
    start = time.monotonic()
    result = rt.run_recipe(endpoint, auth, {})
    return result, time.monotonic() - start


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("path", ["/drip", "/headers", "/compressed", "/redirect/0", "/retry"])
def test_one_budget_bounds_each_network_phase(source, path, asynchronous):
    result, elapsed = execute(source, path, asynchronous)
    assert result.get("truncated_by") == "deadline", result
    assert 0.8 <= elapsed < 1.6, (path, elapsed)
    if path == "/retry":
        time.sleep(0.3)
        assert source[1].count("/retry") == 1, "A retry started after the deadline"


@pytest.mark.parametrize("asynchronous", [False, True])
def test_expiry_closes_the_actual_socket_and_releases_slot(source, asynchronous):
    result, elapsed = execute(source, "/stall", asynchronous)
    assert result.get("truncated_by") == "deadline", result
    assert elapsed < 1.6
    assert source[2].wait(0.3), "The server still has a live connection after the timeout"
    assert rt._ACTIVE_REQUESTS == 0
    assert execute(source, "/ok", asynchronous)[0]["count"] == 1


@pytest.mark.parametrize("asynchronous", [False, True])
def test_partial_csv_keeps_only_complete_rows(source, asynchronous):
    result, elapsed = execute(source, "/partial", asynchronous)
    assert result.get("truncated_by") == "deadline", result
    assert elapsed < 1.6
    assert result["records"] == [{"id": "1", "name": "one"}]


@pytest.mark.parametrize("asynchronous", [False, True])
def test_slot_wait_is_included_in_deadline(source, monkeypatch, asynchronous):
    monkeypatch.setenv("ATLAS_MAX_CONCURRENCY", "1")
    entered, release = threading.Event(), threading.Event()

    def hold():
        with rt._RequestSlot():
            entered.set()
            release.wait(2)

    holder = threading.Thread(target=hold)
    holder.start()
    assert entered.wait(1)
    try:
        result, elapsed = execute(source, "/ok", asynchronous)
        assert result.get("truncated_by") == "deadline", result
        assert elapsed < 1.6 and not source[1]
    finally:
        release.set()
        holder.join(timeout=3)


@pytest.mark.parametrize("asynchronous", [False, True])
def test_user_can_raise_deadline_for_a_legitimate_slow_response(source, monkeypatch, asynchronous):
    monkeypatch.setenv("ATLAS_FETCH_DEADLINE_S", "4")
    result, elapsed = execute(source, "/drip", asynchronous)
    assert result["count"] == 1 and not result.get("truncated_by"), result
    assert elapsed > 1.6


@pytest.mark.parametrize("asynchronous", [False, True])
def test_delayed_request_hook_cannot_send_after_expiry(source, monkeypatch, asynchronous):
    original = rt._check_request

    def delayed(*args, **kwargs):
        time.sleep(1.8)  # Models a blocking OS resolver without touching external DNS.
        return original(*args, **kwargs)

    monkeypatch.setattr(rt, "_check_request", delayed)
    result, elapsed = execute(source, "/ok", asynchronous)
    assert result.get("truncated_by") == "deadline", result
    assert elapsed < 1.6
    time.sleep(1)
    assert not source[1], "A timed-out operation sent an HTTP request later"


def test_warm_sync_client_can_abort_a_slow_header_stream(source):
    with httpx.Client(timeout=4, follow_redirects=True, event_hooks=rt._address_hooks(None)) as client:
        assert client.get(source[0] + "/ok").status_code == 200
        start = time.monotonic()
        result = rt._fetch(client, {}, {}, source[0] + "/header-drip")
        assert result.truncated_by == "deadline"
        assert time.monotonic() - start < 1.6
        assert source[2].wait(0.4), "Slow headers continued after expiry"


def test_one_expiry_does_not_close_another_requests_connection(source, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    monkeypatch.setenv("ATLAS_FETCH_DEADLINE_S", "3")
    with httpx.Client(timeout=4, follow_redirects=True, event_hooks=rt._address_hooks(None)) as client:
        with ThreadPoolExecutor(max_workers=2) as pool:
            slow = pool.submit(rt._fetch, client, {"deadline_s": 1}, {}, source[0] + "/stall")
            normal = pool.submit(rt._fetch, client, {"deadline_s": 2}, {}, source[0] + "/medium")
            assert slow.result().truncated_by == "deadline"
            result = normal.result()
            assert result[0] == [{"id": "1", "name": "one"}] and not result.truncated


@pytest.mark.parametrize("source", [True], indirect=True)
@pytest.mark.parametrize("asynchronous", [False, True])
def test_login_uses_the_same_total_deadline(source, asynchronous):
    auth = {"login_url": source[0] + "/login", "username": "test", "password": "fake"}
    origin = rt._fixed_credential_origin(auth["login_url"])
    start = time.monotonic()
    with pytest.raises(httpx.ReadTimeout, match="deadline"):
        if asynchronous:
            asyncio.run(rt._login_token(auth, None, 0.5, force=True, credential_origin=origin, data_origin=origin))
        else:
            rt._login_token_sync(auth, None, 0.5, force=True, credential_origin=origin, data_origin=origin)
    assert time.monotonic() - start < 1.6


@pytest.mark.parametrize("asynchronous", [False, True])
def test_completed_network_response_is_parsed_once_outside_network_budget(source, monkeypatch, asynchronous):
    original = rt._finish
    calls = []

    def parse(*args, **kwargs):
        calls.append(args[-1])
        time.sleep(1.2)
        return original(*args, **kwargs)

    monkeypatch.setattr(rt, "_finish", parse)
    result, _ = execute(source, "/ok", asynchronous)
    assert result["count"] == 1 and not result.get("truncated_by"), result
    assert calls == [None], "A completed response was parsed twice on deadline expiry"


@pytest.mark.parametrize("asynchronous", [False, True])
def test_success_body_rules_are_evaluated_after_network_completion(source, monkeypatch, asynchronous):
    def body_rule(*args):
        time.sleep(1.2)
        return False

    monkeypatch.setattr(rt, "_empty_response", body_rule)
    result, _ = execute(source, "/ok", asynchronous)
    assert result["count"] == 1 and not result.get("truncated_by"), result


@pytest.mark.parametrize("asynchronous", [False, True])
def test_cancelled_pacing_wait_does_not_reserve_future_windows(asynchronous):
    host = "deadline-pacing-test"
    start_at = time.time() + 2
    rt._access_state[host] = {"active": 0, "next_free": start_at, "penalty_until": 0}
    policy = {"max_concurrency": 1, "min_interval_ms": 2000}
    try:
        for _ in range(3):
            with pytest.raises(rt._DeadlineExpired):
                if asynchronous:
                    asyncio.run(rt._async_deadline_call(rt._access_wait_async(host, policy), 0.05))
                else:
                    rt._sync_deadline_call(lambda: rt._access_acquire_sync(host, policy), 0.05)
            assert rt._access_state[host]["active"] == 0
            assert rt._access_state[host]["next_free"] == start_at
    finally:
        rt._access_state.pop(host, None)


def test_sync_worker_preserves_callers_contextvars():
    from contextvars import ContextVar
    identity = ContextVar("deadline-test-identity", default=None)
    token = identity.set("local-test-context")
    try:
        assert rt._sync_deadline_call(identity.get, 1) == "local-test-context"
    finally:
        identity.reset(token)
