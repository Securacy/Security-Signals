"""Tests for HTTP client."""

import asyncio
import socket
import pytest
from app.common import http_client as http_client_module
from app.common.http_client import (
    _is_private_address, SSRFError, HTTPError, HTTPClient, resolve_hostname_safe
)


class _FakeLoop:
    """Stands in for asyncio's event loop, returning a fixed getaddrinfo()
    result set - lets these tests deterministically control DNS resolution
    order without touching real DNS or real sockets."""

    def __init__(self, results):
        self._results = results

    async def getaddrinfo(self, host, port, family=0, type=0):
        return self._results


def _ipv6_result(ip: str):
    return (socket.AF_INET6, socket.SOCK_STREAM, 6, '', (ip, 443, 0, 0))


def _ipv4_result(ip: str):
    return (socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip, 443))


def _reader(data: bytes) -> asyncio.StreamReader:
    """In-memory StreamReader pre-loaded with data, for testing body-framing
    logic without a real socket/transport."""
    reader = asyncio.StreamReader()
    reader.feed_data(data)
    reader.feed_eof()
    return reader


class TestPrivateAddresses:
    """Private IP detection tests."""
    
    def test_loopback_ipv4(self):
        """127.0.0.1 is private."""
        assert _is_private_address('127.0.0.1') is True
    
    def test_loopback_ipv6(self):
        """::1 is private."""
        assert _is_private_address('::1') is True
    
    def test_private_10_range(self):
        """10.0.0.0/8 is private."""
        assert _is_private_address('10.0.0.1') is True
        assert _is_private_address('10.255.255.255') is True
    
    def test_private_172_range(self):
        """172.16.0.0/12 is private."""
        assert _is_private_address('172.16.0.1') is True
        assert _is_private_address('172.31.255.255') is True
    
    def test_private_192_range(self):
        """192.168.0.0/16 is private."""
        assert _is_private_address('192.168.1.1') is True
    
    def test_aws_metadata(self):
        """AWS metadata is private."""
        assert _is_private_address('169.254.169.254') is True
    
    def test_public_ip_allowed(self):
        """Public IP is not private."""
        assert _is_private_address('8.8.8.8') is False
        assert _is_private_address('1.1.1.1') is False


@pytest.mark.asyncio
async def test_localhost_rejected():
    """Localhost rejected."""
    with pytest.raises(SSRFError):
        await resolve_hostname_safe('localhost')


@pytest.mark.asyncio
async def test_127_rejected():
    """127.0.0.1 rejected."""
    with pytest.raises(SSRFError):
        await resolve_hostname_safe('127.0.0.1')


class TestIPv4PreferredOverIPv6:
    """Regression tests for the real IPv6-hangs-then-times-out bug found by
    comparing curl (succeeds instantly) against this client (times out)
    against real feeds - traced to getaddrinfo(family=0) returning IPv6
    first for hosts whose IPv6 route isn't actually usable in this
    environment, and the old code pinning to whichever result came first."""

    @pytest.mark.asyncio
    async def test_prefers_ipv4_when_both_families_resolve(self, monkeypatch):
        results = [_ipv6_result('2606:4700::1111'), _ipv4_result('93.184.216.34')]
        monkeypatch.setattr(http_client_module.asyncio, "get_event_loop", lambda: _FakeLoop(results))

        ip = await resolve_hostname_safe('example.com')

        assert ip == '93.184.216.34'

    @pytest.mark.asyncio
    async def test_prefers_ipv4_regardless_of_result_order(self, monkeypatch):
        results = [_ipv4_result('93.184.216.34'), _ipv6_result('2606:4700::1111')]
        monkeypatch.setattr(http_client_module.asyncio, "get_event_loop", lambda: _FakeLoop(results))

        ip = await resolve_hostname_safe('example.com')

        assert ip == '93.184.216.34'

    @pytest.mark.asyncio
    async def test_falls_back_to_ipv6_when_no_ipv4_available(self, monkeypatch):
        results = [_ipv6_result('2606:4700::1111')]
        monkeypatch.setattr(http_client_module.asyncio, "get_event_loop", lambda: _FakeLoop(results))

        ip = await resolve_hostname_safe('ipv6only.example.com')

        assert ip == '2606:4700::1111'

    @pytest.mark.asyncio
    async def test_ipv4_preference_does_not_bypass_private_ip_rejection(self, monkeypatch):
        results = [_ipv6_result('2606:4700::1111'), _ipv4_result('10.0.0.5')]
        monkeypatch.setattr(http_client_module.asyncio, "get_event_loop", lambda: _FakeLoop(results))

        with pytest.raises(SSRFError):
            await resolve_hostname_safe('rebinding.example.com')

    @pytest.mark.asyncio
    async def test_ipv6_only_private_result_still_rejected(self, monkeypatch):
        results = [_ipv6_result('::1')]
        monkeypatch.setattr(http_client_module.asyncio, "get_event_loop", lambda: _FakeLoop(results))

        with pytest.raises(SSRFError):
            await resolve_hostname_safe('rebinding6.example.com')


class TestIsRetryable:
    """Regression tests: which errors the retry loop treats as transient."""

    def test_close_notify_race_is_retryable(self):
        """Real error observed against usn.ubuntu.com - a TLS teardown race,
        not a permanent failure (confirmed to succeed on immediate retry)."""
        client = HTTPClient()
        msg = "Fetch failed: [SSL: APPLICATION_DATA_AFTER_CLOSE_NOTIFY] application data after close notify (_ssl.c:2841)"

        assert client._is_retryable(msg) is True

    def test_permanent_client_error_not_retryable(self):
        client = HTTPClient()
        assert client._is_retryable("HTTP 404 (no retry)") is False

    def test_known_transient_keywords_still_retryable(self):
        client = HTTPClient()
        for msg in ["Connection refused", "HTTP 429", "HTTP 503", "DNS timeout: example.com"]:
            assert client._is_retryable(msg) is True


class TestChunkedBodyDecoding:
    """Regression tests for HTTP/1.1 chunked-transfer-encoding decoding.

    Discovered via real ingestion against api.github.com, which
    intermittently responds Transfer-Encoding: chunked even over HTTP/1.1
    with Connection: close. The client previously read raw bytes until the
    connection closed, so chunk-size lines and CRLF framing leaked into the
    body - invisible to feedparser's lenient XML parsing (which silently
    absorbs the noise) but fatal to strict json.loads(), which is how this
    was found (b'8000\\r\\n[{"ghsa_id":...' - a real captured chunk-size
    prefix corrupting what should have been a clean JSON array).
    """

    @pytest.mark.asyncio
    async def test_single_chunk_decoded(self):
        client = HTTPClient()
        payload = b'{"hello": "world"}'
        raw = f"{len(payload):x}\r\n".encode() + payload + b"\r\n0\r\n\r\n"

        body = await client._read_chunked_body(_reader(raw))

        assert body == payload

    @pytest.mark.asyncio
    async def test_multiple_chunks_concatenated(self):
        client = HTTPClient()
        part1, part2 = b'[{"a":1},', b'{"b":2}]'
        raw = (
            f"{len(part1):x}\r\n".encode() + part1 + b"\r\n"
            + f"{len(part2):x}\r\n".encode() + part2 + b"\r\n"
            + b"0\r\n\r\n"
        )

        body = await client._read_chunked_body(_reader(raw))

        assert body == part1 + part2

    @pytest.mark.asyncio
    async def test_chunk_extension_after_semicolon_ignored(self):
        """A chunk size may carry an extension after ';' (RFC 7230 §4.1.1),
        which must not be parsed as part of the hex size."""
        client = HTTPClient()
        payload = b"data"
        raw = f"{len(payload):x};ignored-extension=1\r\n".encode() + payload + b"\r\n0\r\n\r\n"

        body = await client._read_chunked_body(_reader(raw))

        assert body == payload

    @pytest.mark.asyncio
    async def test_trailer_headers_consumed(self):
        client = HTTPClient()
        payload = b"data"
        raw = (
            f"{len(payload):x}\r\n".encode() + payload + b"\r\n"
            + b"0\r\nX-Trailer: value\r\n\r\n"
        )

        body = await client._read_chunked_body(_reader(raw))

        assert body == payload

    @pytest.mark.asyncio
    async def test_malformed_chunk_size_rejected(self):
        client = HTTPClient()
        raw = b"not-hex\r\ndata\r\n0\r\n\r\n"

        with pytest.raises(HTTPError):
            await client._read_chunked_body(_reader(raw))

    @pytest.mark.asyncio
    async def test_missing_chunk_terminator_rejected(self):
        client = HTTPClient()
        payload = b"data"
        # No trailing \r\n after the chunk data before the next size line.
        raw = f"{len(payload):x}\r\n".encode() + payload + b"0\r\n\r\n"

        with pytest.raises(HTTPError):
            await client._read_chunked_body(_reader(raw))

    @pytest.mark.asyncio
    async def test_truncated_chunked_body_rejected(self):
        client = HTTPClient()
        raw = b"10\r\nshort"  # declares 16 bytes, provides fewer, then EOF

        with pytest.raises(HTTPError):
            await client._read_chunked_body(_reader(raw))

    @pytest.mark.asyncio
    async def test_oversized_chunked_body_rejected(self):
        client = HTTPClient()
        big_size = client.MAX_SIZE + 1
        raw = f"{big_size:x}\r\n".encode()

        with pytest.raises(HTTPError):
            await client._read_chunked_body(_reader(raw))


class TestContentLengthAndCloseTerminatedReads:
    """Regression tests for exact-length reads: Content-Length is now
    honored when present instead of always reading until connection close,
    which also avoids racing the peer's TLS close_notify."""

    @pytest.mark.asyncio
    async def test_read_exact_reads_declared_length(self):
        client = HTTPClient()
        payload = b"exactly ten"[:10]

        body = await client._read_exact(_reader(payload), 10)

        assert body == payload
        assert len(body) == 10

    @pytest.mark.asyncio
    async def test_read_exact_rejects_early_close(self):
        client = HTTPClient()

        with pytest.raises(HTTPError):
            await client._read_exact(_reader(b"short"), 100)

    @pytest.mark.asyncio
    async def test_read_until_close_returns_all_bytes(self):
        client = HTTPClient()
        payload = b"no framing headers, read until EOF"

        body = await client._read_until_close(_reader(payload))

        assert body == payload

    @pytest.mark.asyncio
    async def test_read_until_close_rejects_oversized_body(self):
        client = HTTPClient()
        reader = _reader(b"x" * (client.MAX_SIZE + 1))

        with pytest.raises(HTTPError):
            await client._read_until_close(reader)
