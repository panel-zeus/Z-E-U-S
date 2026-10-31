"""Optional authenticated, bounded WebSocket-to-TCP egress companion.

There is deliberately no unauthenticated health endpoint, proxy discovery, UDP,
arbitrary listening address, or destination/credential logging.  Production
always validates and resolves destinations before opening a source-bound socket.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import ipaddress
import logging
import os
import re
import socket
import sys
from dataclasses import dataclass, field
from typing import Awaitable, Callable

from aiohttp import WSMsgType, web

MAX_FRAME = 64 * 1024
MAX_CONNECTIONS = 64
CONNECT_TIMEOUT = 8.0
IO_TIMEOUT = 15.0
IDLE_TIMEOUT = 180.0
ALLOWED_PORTS = frozenset((80, 443))
ALWAYS_BLOCKED = frozenset()
TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{32,256}\Z", re.ASCII)
LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z", re.ASCII)


class InvalidDestination(ValueError):
    """Destination is malformed or outside the public-Internet policy."""


@dataclass(frozen=True)
class Config:
    token_sha256: bytes
    source_ipv4: str
    blocked_ipv4: frozenset[ipaddress.IPv4Address] = ALWAYS_BLOCKED
    max_connections: int = MAX_CONNECTIONS
    connect_timeout: float = CONNECT_TIMEOUT
    io_timeout: float = IO_TIMEOUT
    idle_timeout: float = IDLE_TIMEOUT

    @classmethod
    def from_env(cls) -> "Config":
        digest = os.environ.get("EXIT_TOKEN_SHA256", "")
        if not re.fullmatch(r"[a-fA-F0-9]{64}", digest):
            raise ValueError("invalid token hash")
        source = ipaddress.IPv4Address(os.environ.get("EXIT_SOURCE_IPV4", ""))
        if source.is_unspecified or source.is_multicast or source.is_reserved:
            raise ValueError("invalid source address")
        # Prevent direct reflection to the bound address. NAT/public addresses
        # and other host addresses must also be listed in EXIT_BLOCKED_IPV4.
        blocked = {source}
        for raw in os.environ.get("EXIT_BLOCKED_IPV4", "").split(","):
            if raw.strip():
                blocked.add(ipaddress.IPv4Address(raw.strip()))
        return cls(bytes.fromhex(digest), str(source), frozenset(blocked))


def authenticated(headers, expected_hash: bytes) -> bool:
    values = headers.getall("Authorization", [])
    if len(values) != 1 or not values[0].startswith("Bearer "):
        return False
    token = values[0][7:]
    if not TOKEN_RE.fullmatch(token):
        return False
    return hmac.compare_digest(hashlib.sha256(token.encode("ascii")).digest(), expected_hash)


def parse_destination(headers) -> tuple[str, int]:
    hosts = headers.getall("X-Exit-Host", [])
    ports = headers.getall("X-Exit-Port", [])
    if len(hosts) != 1 or len(ports) != 1 or ports[0] not in ("80", "443"):
        raise InvalidDestination()
    host = hosts[0]
    if not host or len(host) > 253 or not host.isascii() or host != host.strip():
        raise InvalidDestination()
    host = host.lower()
    if host.endswith("."):
        host = host[:-1]
    if not host or any(not LABEL_RE.fullmatch(label) for label in host.split(".")):
        raise InvalidDestination()
    # IPv6 literals, URL syntax, credentials, whitespace and control characters
    # are rejected by the DNS-label grammar. Numeric IPv4 is checked below.
    return host, int(ports[0])


def is_public_ipv4(raw: str, blocked=ALWAYS_BLOCKED) -> bool:
    try:
        addr = ipaddress.IPv4Address(raw)
    except ipaddress.AddressValueError:
        return False
    return (
        addr.is_global
        and not addr.is_private
        and not addr.is_reserved
        and not addr.is_loopback
        and not addr.is_link_local
        and not addr.is_multicast
        and not addr.is_unspecified
        and addr not in blocked
    )


async def resolve_public_ipv4(host: str, port: int, config: Config, resolver=None) -> str:
    if port not in ALLOWED_PORTS:
        raise InvalidDestination()
    try:
        literal = ipaddress.IPv4Address(host)
    except ipaddress.AddressValueError:
        literal = None
    if literal is not None:
        address = str(literal)
        if not is_public_ipv4(address, config.blocked_ipv4):
            raise InvalidDestination()
        return address
    resolve = resolver or asyncio.get_running_loop().getaddrinfo
    entries = await resolve(host, port, family=socket.AF_INET, type=socket.SOCK_STREAM,
                            proto=socket.IPPROTO_TCP)
    addresses = []
    for family, socktype, proto, _canonical, sockaddr in entries:
        if family != socket.AF_INET or socktype != socket.SOCK_STREAM:
            raise InvalidDestination()
        address = sockaddr[0]
        if not is_public_ipv4(address, config.blocked_ipv4):
            # Reject mixed public/private answers instead of choosing around
            # private answers. Never resolve the name again when connecting.
            raise InvalidDestination()
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise InvalidDestination()
    return addresses[0]


async def open_source_bound_connection(host: str, port: int, config: Config):
    address = await resolve_public_ipv4(host, port, config)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    try:
        # The operator chooses this source address and its routing policy.
        # Never fall back to an unbound socket if the address disappears.
        sock.bind((config.source_ipv4, 0))
        sock.setblocking(False)
        await asyncio.get_running_loop().sock_connect(sock, (address, port))
        reader, writer = await asyncio.open_connection(sock=sock, limit=MAX_FRAME)
    except BaseException:
        sock.close()
        raise
    writer.transport.set_write_buffer_limits(high=MAX_FRAME, low=MAX_FRAME // 4)
    return reader, writer


Connector = Callable[[str, int, Config], Awaitable[tuple[asyncio.StreamReader, asyncio.StreamWriter]]]


@dataclass
class Runtime:
    config: Config
    connector: Connector
    active: int = 0
    stopping: bool = False
    handlers: set[asyncio.Task] = field(default_factory=set)
    websockets: set[web.WebSocketResponse] = field(default_factory=set)


RUNTIME = web.AppKey("wss_relay_runtime", Runtime)


def denied(status: int) -> web.Response:
    return web.Response(status=status, text="Request unavailable.\n",
                        headers={"Cache-Control": "no-store"})


async def relay(ws: web.WebSocketResponse, reader, writer, config: Config):
    loop = asyncio.get_running_loop()
    last_activity = loop.time()
    send_lock = asyncio.Lock()

    async def send(data, *, text=False):
        async with asyncio.timeout(config.io_timeout):
            async with send_lock:
                if text:
                    await ws.send_str(data)
                else:
                    await ws.send_bytes(data)

    async def client_to_tcp():
        nonlocal last_activity
        acknowledged = 0
        async for message in ws:
            if message.type == WSMsgType.BINARY:
                if not message.data or len(message.data) > MAX_FRAME:
                    return 1008
                writer.write(message.data)
                async with asyncio.timeout(config.io_timeout):
                    await writer.drain()
                acknowledged += len(message.data)
                last_activity = loop.time()
                await send(f"ack:{acknowledged}", text=True)
            elif message.type == WSMsgType.TEXT:
                return 1008
            elif message.type == WSMsgType.ERROR:
                return ws.close_code if ws.close_code in (1008, 1009) else 1011
        return 1000

    async def tcp_to_client():
        nonlocal last_activity
        while True:
            chunk = await reader.read(MAX_FRAME)
            if not chunk:
                return 1000
            await send(chunk)
            last_activity = loop.time()

    async def idle_watch():
        while True:
            remaining = config.idle_timeout - (loop.time() - last_activity)
            if remaining <= 0:
                return 1001
            await asyncio.sleep(remaining)

    tasks = {asyncio.create_task(client_to_tcp()), asyncio.create_task(tcp_to_client()),
             asyncio.create_task(idle_watch())}
    try:
        finished, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        codes = []
        for task in finished:
            try:
                codes.append(task.result())
            except Exception:
                codes.append(1011)
        return next((code for code in codes if code not in (1000, 1001)), max(codes))
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def handle_exit(request: web.Request):
    runtime = request.app[RUNTIME]
    config = runtime.config
    if not authenticated(request.headers, config.token_sha256):
        return denied(401)
    if request.query_string:
        return denied(400)
    try:
        host, port = parse_destination(request.headers)
    except InvalidDestination:
        return denied(400)
    # aiohttp's parser rejects sizes >= max_msg_size; permit exactly 64 KiB.
    # The application separately enforces <= MAX_FRAME for version stability.
    ws = web.WebSocketResponse(timeout=2.0, max_msg_size=MAX_FRAME + 1, compress=False,
                               autoclose=True, autoping=True)
    if not ws.can_prepare(request).ok:
        return denied(400)
    if runtime.stopping or runtime.active >= config.max_connections:
        return denied(503)
    runtime.active += 1
    handler = asyncio.current_task()
    runtime.handlers.add(handler)
    writer = None
    prepared = False
    try:
        try:
            async with asyncio.timeout(config.connect_timeout):
                reader, writer = await runtime.connector(host, port, config)
        except InvalidDestination:
            return denied(403)
        except Exception:
            return denied(502)
        # A 101 response means outbound TCP already exists and passed policy.
        await ws.prepare(request)
        prepared = True
        runtime.websockets.add(ws)
        close_code = await relay(ws, reader, writer, config)
        await ws.close(code=close_code, drain=False)
        return ws
    except asyncio.CancelledError:
        raise
    except Exception:
        if prepared:
            with contextlib.suppress(Exception):
                await ws.close(code=1011, drain=False)
            return ws
        return denied(502)
    finally:
        runtime.websockets.discard(ws)
        try:
            if writer is not None:
                writer.close()
                with contextlib.suppress(Exception):
                    async with asyncio.timeout(2.0):
                        await writer.wait_closed()
        finally:
            # CancelledError is a BaseException. A cancellation during TCP close
            # must propagate without leaking an admission slot or handler entry.
            runtime.active -= 1
            runtime.handlers.discard(handler)


async def shutdown(app: web.Application):
    runtime = app[RUNTIME]
    runtime.stopping = True
    await asyncio.gather(*(ws.close(code=1001, drain=False)
                           for ws in tuple(runtime.websockets)), return_exceptions=True)
    tasks = tuple(runtime.handlers)
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)


def create_app(config: Config, *, connector: Connector = open_source_bound_connection):
    """Connector injection is only for tests; the CLI always uses production."""
    app = web.Application(client_max_size=MAX_FRAME)
    app[RUNTIME] = Runtime(config, connector)
    app.router.add_route("GET", "/tcp-relay", handle_exit)
    app.on_shutdown.append(shutdown)
    return app


def main() -> int:
    try:
        config = Config.from_env()
    except (ValueError, TypeError):
        print("Invalid relay configuration.", file=sys.stderr)
        return 2
    # Access logs could contain destinations or credential-bearing requests.
    # All expected failures have generic responses and no exception logging.
    logging.getLogger("aiohttp.access").disabled = True
    logging.getLogger("aiohttp.server").disabled = True
    web.run_app(create_app(config), host="127.0.0.1", port=9080,
                access_log=None, print=None, shutdown_timeout=5.0,
                handler_cancellation=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
