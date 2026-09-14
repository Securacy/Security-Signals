"""Secure HTTP client with SSRF protection, retries, DNS rebinding prevention."""

import asyncio
import logging
import ssl
import random
from typing import Optional
from urllib.parse import urlparse, urljoin
import ipaddress

logger = logging.getLogger(__name__)


class HTTPError(Exception):
    """HTTP operation failed."""
    pass


class SSRFError(HTTPError):
    """SSRF: target is private/loopback/metadata."""
    pass


def _is_private_address(ip_str: str) -> bool:
    """Check if IP is private/loopback/reserved."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    
    return (
        addr.is_loopback or
        addr.is_private or
        addr.is_link_local or
        addr.is_multicast or
        addr.is_unspecified or
        addr.is_reserved or
        (addr.version == 4 and str(addr) == '169.254.169.254')
    )


async def resolve_hostname_safe(hostname: str, timeout: float = 5.0) -> str:
    """Resolve hostname. Reject private addresses."""
    if hostname.lower() in ('localhost', '127.0.0.1', '::1'):
        raise SSRFError(f"Loopback rejected: {hostname}")
    
    try:
        addr = ipaddress.ip_address(hostname)
        if _is_private_address(hostname):
            raise SSRFError(f"Private IP rejected: {hostname}")
        return hostname
    except ValueError:
        pass
    
    try:
        loop = asyncio.get_event_loop()
        results = await asyncio.wait_for(
            loop.getaddrinfo(hostname, 443, family=0, type=1),
            timeout=timeout
        )
        
        if not results:
            raise SSRFError(f"No addresses resolved: {hostname}")
        
        ip = results[0][4][0]
        if _is_private_address(ip):
            raise SSRFError(f"Resolved to private: {hostname} → {ip}")
        
        return ip
    except asyncio.TimeoutError:
        raise SSRFError(f"DNS timeout: {hostname}")
    except OSError as e:
        raise SSRFError(f"DNS failed: {hostname}: {e}")


class HTTPClient:
    """Secure HTTP client."""
    
    MAX_RETRIES = 3
    MAX_SIZE = 10 * 1024 * 1024
    TIMEOUT = 10.0
    
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
    
    async def fetch(self, url: str) -> bytes:
        """Fetch URL with retries and SSRF protection."""
        parsed = urlparse(url)
        
        if parsed.scheme not in ('http', 'https'):
            raise HTTPError(f"Unsupported scheme: {parsed.scheme}")
        if parsed.username or parsed.password:
            raise HTTPError("URL has credentials")
        
        hostname = parsed.hostname
        if not hostname:
            raise HTTPError("No hostname")
        
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        
        # Resolve once
        pinned_ip = await resolve_hostname_safe(hostname, self.timeout)
        
        # Retry loop
        last_error = None
        for attempt in range(self.MAX_RETRIES + 1):
            try:
                return await self._fetch_single(url, hostname, pinned_ip, port, parsed.scheme)
            except (HTTPError, SSRFError) as e:
                last_error = e
                
                if not self._is_retryable(str(e)):
                    raise
                
                if attempt < self.MAX_RETRIES:
                    backoff = min(2 ** attempt, 60) + random.uniform(0, 1)
                    logger.warning(f"Retry ({attempt+1}/{self.MAX_RETRIES}): {e}")
                    await asyncio.sleep(backoff)
        
        raise HTTPError(f"Max retries: {last_error}")
    
    def _is_retryable(self, error_str: str) -> bool:
        """Check if error is transient.

        'close_notify' covers a real, observed intermittent TLS teardown
        race (confirmed against usn.ubuntu.com: "[SSL:
        APPLICATION_DATA_AFTER_CLOSE_NOTIFY] application data after close
        notify") where the peer's TLS close_notify and our own read/write on
        the same connection cross paths - transient, and confirmed to
        succeed on an immediate retry, not a permanent server failure.
        """
        transient = {'timeout', 'connection', 'reset', '429', '503', '502', 'close_notify'}
        return any(t in error_str.lower() for t in transient)

    async def _read_exact(self, reader: asyncio.StreamReader, n: int) -> bytes:
        """Read exactly n bytes."""
        data = b''
        while len(data) < n:
            chunk = await asyncio.wait_for(reader.read(min(65536, n - len(data))), timeout=self.TIMEOUT)
            if not chunk:
                raise HTTPError("Connection closed before body complete")
            data += chunk
        return data

    async def _read_until_close(self, reader: asyncio.StreamReader) -> bytes:
        """Read until the connection closes. Used only when the response has
        neither Content-Length nor Transfer-Encoding: chunked."""
        body = b''
        while True:
            chunk = await asyncio.wait_for(reader.read(65536), timeout=self.TIMEOUT)
            if not chunk:
                break
            body += chunk
            if len(body) > self.MAX_SIZE:
                raise HTTPError("Response too large")
        return body

    async def _read_chunked_body(self, reader: asyncio.StreamReader) -> bytes:
        """Decode an HTTP/1.1 chunked-transfer-encoded body (RFC 7230 §4.1):
        a sequence of `<hex size>\\r\\n<that many bytes>\\r\\n`, terminated by
        a zero-size chunk and an optional trailer section."""
        body = b''
        while True:
            size_line = await asyncio.wait_for(reader.readline(), timeout=self.TIMEOUT)
            if not size_line:
                raise HTTPError("Chunked body ended unexpectedly")

            size_str = size_line.split(b';', 1)[0].strip()
            try:
                chunk_size = int(size_str, 16)
            except ValueError:
                raise HTTPError(f"Invalid chunk size: {size_line!r}")

            if chunk_size == 0:
                # Consume the trailer section (if any) up to the final blank line.
                while True:
                    trailer_line = await asyncio.wait_for(reader.readline(), timeout=self.TIMEOUT)
                    if not trailer_line or trailer_line == b'\r\n':
                        break
                break

            if len(body) + chunk_size > self.MAX_SIZE:
                raise HTTPError("Response too large")

            body += await self._read_exact(reader, chunk_size)

            trailing = await asyncio.wait_for(reader.readline(), timeout=self.TIMEOUT)
            if trailing != b'\r\n':
                raise HTTPError("Malformed chunk terminator")

        return body
    
    async def _fetch_single(self, url: str, hostname: str, pinned_ip: str, port: int, scheme: str) -> bytes:
        """Fetch single URL."""
        try:
            if scheme == 'https':
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = True
                ssl_ctx.verify_mode = ssl.CERT_REQUIRED
                
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(pinned_ip, port, ssl=ssl_ctx, server_hostname=hostname),
                    timeout=self.TIMEOUT
                )
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(pinned_ip, port),
                    timeout=self.TIMEOUT
                )
            
            # Build request
            parsed = urlparse(url)
            path = parsed.path or '/'
            if parsed.query:
                path += '?' + parsed.query
            
            # A User-Agent and Accept header are required by some real feed
            # hosts (e.g. github.com returns 406 Not Acceptable to requests
            # with neither) - both are standard, legitimate identifiers for
            # a feed-fetching client, not spoofing. Note this does not
            # resolve github.com/advisories.atom specifically - that
            # endpoint returns 406 for every header combination tried
            # (verified 2026-09-12, see app/ingestion/sources.py) because
            # it's discontinued, not because of missing headers. Deliberately
            # no Accept-Encoding: gzip, since this client reads the raw body
            # bytes without decompressing them.
            request = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {hostname}\r\n"
                f"User-Agent: SecuritySignalsBot/1.0 (security news aggregator; RSS/Atom feed reader)\r\n"
                f"Accept: application/rss+xml, application/atom+xml, application/xml, text/xml, */*;q=0.8\r\n"
                f"Connection: close\r\n\r\n"
            )
            writer.write(request.encode())
            await writer.drain()
            
            # Read status
            status_line = await asyncio.wait_for(reader.readline(), timeout=self.TIMEOUT)
            if not status_line:
                raise HTTPError("Empty response")
            
            status_code = int(status_line.decode().split()[1])
            
            # Read headers
            headers = {}
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=self.TIMEOUT)
                if not line or line == b'\r\n':
                    break
                
                line_str = line.decode('utf-8', errors='replace').strip()
                if ':' in line_str:
                    key, val = line_str.split(':', 1)
                    headers[key.lower()] = val.strip()
            
            # Handle redirects
            if status_code in (301, 302, 303, 307, 308):
                location = headers.get('location')
                if not location:
                    raise HTTPError("Redirect without Location")
                
                redirect_url = urljoin(url, location)
                writer.close()
                await writer.wait_closed()
                
                # Validate redirect
                r_parsed = urlparse(redirect_url)
                if r_parsed.hostname:
                    await resolve_hostname_safe(r_parsed.hostname, self.timeout)
                
                return await self.fetch(redirect_url)
            
            # Handle errors
            if status_code == 429:
                raise HTTPError("HTTP 429")
            if status_code >= 500:
                raise HTTPError(f"HTTP {status_code}")
            if 400 <= status_code < 500:
                raise HTTPError(f"HTTP {status_code} (no retry)")
            
            # Read body. Some real hosts (confirmed: api.github.com,
            # intermittently) respond with Transfer-Encoding: chunked even
            # over HTTP/1.1 with Connection: close - reading raw bytes until
            # the connection closes then includes the chunk-size lines and
            # CRLF framing as body garbage. A lenient XML parser silently
            # absorbs that noise, which is how this went unnoticed; a strict
            # JSON parser does not, which is how it was found. Content-Length
            # is honored when present so the read stops exactly at the
            # declared body size instead of waiting on connection close,
            # which also avoids racing the peer's TLS close_notify.
            transfer_encoding = headers.get('transfer-encoding', '').lower()
            content_length_header = headers.get('content-length')

            if 'chunked' in transfer_encoding:
                body = await self._read_chunked_body(reader)
            elif content_length_header is not None:
                try:
                    content_length = int(content_length_header)
                except ValueError:
                    raise HTTPError(f"Invalid Content-Length: {content_length_header}")
                if content_length > self.MAX_SIZE:
                    raise HTTPError("Response too large")
                body = await self._read_exact(reader, content_length)
            else:
                body = await self._read_until_close(reader)

            writer.close()
            await writer.wait_closed()
            return body
        
        except (HTTPError, SSRFError):
            raise
        except Exception as e:
            raise HTTPError(f"Fetch failed: {e}")
