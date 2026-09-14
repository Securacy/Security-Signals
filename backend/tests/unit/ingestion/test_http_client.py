"""Tests for HTTP client."""

import asyncio
import pytest
from app.common.http_client import (
    _is_private_address, SSRFError, HTTPError, HTTPClient, resolve_hostname_safe
)


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
