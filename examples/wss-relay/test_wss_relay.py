import asyncio
import dataclasses
import hashlib
import ipaddress
import socket
import unittest
from unittest.mock import patch

from aiohttp import ClientSession, WSMsgType, WSServerHandshakeError
from aiohttp.test_utils import TestServer
from multidict import CIMultiDict

import wss_relay as relay


TOKEN = "test_only_token_not_a_live_credential_1234567890"
CONFIG = relay.Config(hashlib.sha256(TOKEN.encode()).digest(), "127.0.0.1",
                     blocked_ipv4=frozenset((ipaddress.IPv4Address("9.9.9.9"),)), io_timeout=0.5, idle_timeout=1.0)


def headers(**updates):
    value = {"Authorization": "Bearer " + TOKEN, "X-Exit-Host": "example.invalid",
             "X-Exit-Port": "443"}
    value.update(updates)
    return value


class PolicyTests(unittest.IsolatedAsyncioTestCase):
    def test_only_public_unicast_ipv4(self):
        for address in ("1.1.1.1", "8.8.8.8", "93.184.216.34"):
            self.assertTrue(relay.is_public_ipv4(address), address)
        for address in ("0.0.0.0", "127.0.0.1", "10.0.0.1", "172.16.1.1", "192.168.1.1",
                        "169.254.169.254", "100.64.0.1", "192.0.2.1", "198.51.100.1",
                        "203.0.113.1", "224.0.0.1", "240.0.0.1", "255.255.255.255",
                        "::1", "::ffff:8.8.8.8", "bad"):
            self.assertFalse(relay.is_public_ipv4(address), address)
        self.assertFalse(relay.is_public_ipv4("1.1.1.1", {ipaddress.IPv4Address("1.1.1.1")}))

    def test_strict_authentication(self):
        self.assertTrue(relay.authenticated(CIMultiDict(headers()), CONFIG.token_sha256))
        for value in ("", "Bearer", "Bearer short", "Basic " + TOKEN, "Bearer " + TOKEN + "=",
                      "Bearer " + TOKEN + " ", "Bearer " + "a" * 300, "Bearer " + "ی" * 40):
            self.assertFalse(relay.authenticated(CIMultiDict({"Authorization": value}), CONFIG.token_sha256))
        duplicate = CIMultiDict(headers())
        duplicate.add("Authorization", "Bearer " + TOKEN)
        self.assertFalse(relay.authenticated(duplicate, CONFIG.token_sha256))
        self.assertFalse(relay.authenticated(CIMultiDict(), CONFIG.token_sha256))

    def test_header_validation(self):
        self.assertEqual(relay.parse_destination(CIMultiDict(headers())), ("example.invalid", 443))
        self.assertEqual(relay.parse_destination(CIMultiDict(headers(**{"X-Exit-Host": "EXAMPLE.INVALID."}))),
                         ("example.invalid", 443))
        for host in ("", " example.invalid", "example.invalid ", "a..com", "-a.com", "a-.com", "a/b",
                     "http://example.invalid", "user@example.invalid", "::1", "[::1]", "a\n.com",
                     "a_b.com", "فارسی.ir", "a" * 64 + ".com"):
            with self.assertRaises(relay.InvalidDestination, msg=host):
                relay.parse_destination(CIMultiDict(headers(**{"X-Exit-Host": host})))
        for port in ("22", "8080", "0443", "+443", "443 ", "0", "", "65536"):
            with self.assertRaises(relay.InvalidDestination, msg=port):
                relay.parse_destination(CIMultiDict(headers(**{"X-Exit-Port": port})))
        duplicate = CIMultiDict(headers())
        duplicate.add("X-Exit-Host", "second.example")
        with self.assertRaises(relay.InvalidDestination):
            relay.parse_destination(duplicate)

    async def test_dns_resolves_once_and_mixed_answers_fail_closed(self):
        calls = []

        async def resolve(*args, **kwargs):
            calls.append((args, kwargs))
            return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("1.1.1.1", 443))]

        self.assertEqual(await relay.resolve_public_ipv4("example.invalid", 443, CONFIG, resolve), "1.1.1.1")
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][1]["family"], socket.AF_INET)
        self.assertEqual(await relay.resolve_public_ipv4("8.8.8.8", 443, CONFIG, resolve), "8.8.8.8")
        self.assertEqual(len(calls), 1)

        async def mixed(*args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (value, 443))
                    for value in ("1.1.1.1", "127.0.0.1")]

        with self.assertRaises(relay.InvalidDestination):
            await relay.resolve_public_ipv4("example.invalid", 443, CONFIG, mixed)
        with self.assertRaises(relay.InvalidDestination):
            await relay.resolve_public_ipv4("9.9.9.9", 443, CONFIG, resolve)

    async def test_source_bind_failure_does_not_fall_back(self):
        class FailingSocket:
            closed = False
            bound = None

            def bind(self, source):
                self.bound = source
                raise OSError("test bind failure")

            def close(self):
                self.closed = True

        outbound = FailingSocket()
        with patch.object(relay.socket, "socket", return_value=outbound):
            with self.assertRaises(OSError):
                await relay.open_source_bound_connection("1.1.1.1", 443, CONFIG)
        self.assertEqual(outbound.bound, (CONFIG.source_ipv4, 0))
        self.assertTrue(outbound.closed)


class FakeReader:
    def __init__(self):
        self.queue = asyncio.Queue()

    async def read(self, size):
        return await self.queue.get()


class FakeWriter:
    def __init__(self):
        self.data = []
        self.drain_started = asyncio.Event()
        self.drain_allowed = asyncio.Event()
        self.closed = asyncio.Event()

    def write(self, data):
        self.data.append(data)

    async def drain(self):
        self.drain_started.set()
        await self.drain_allowed.wait()

    def close(self):
        self.closed.set()

    async def wait_closed(self):
        await self.closed.wait()


class EndpointTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.reader = FakeReader()
        self.writer = FakeWriter()
        self.connect_calls = []

        async def connector(host, port, config):
            self.connect_calls.append((host, port))
            return self.reader, self.writer

        self.app = relay.create_app(CONFIG, connector=connector)
        self.server = TestServer(self.app)
        await self.server.start_server()
        self.client = ClientSession()
        self.url = self.server.make_url("/tcp-relay")

    async def asyncTearDown(self):
        await self.client.close()
        await self.server.close()

    async def handshake_status(self, value, status, url=None):
        with self.assertRaises(WSServerHandshakeError) as caught:
            await self.client.ws_connect(url or self.url, headers=value)
        self.assertEqual(caught.exception.status, status)

    async def test_anonymous_invalid_auth_and_headers_never_connect(self):
        await self.handshake_status({}, 401)
        await self.handshake_status(headers(Authorization="Bearer " + "x" * 40), 401)
        await self.handshake_status(headers(**{"X-Exit-Port": "22"}), 400)
        await self.handshake_status(headers(), 400, self.server.make_url("/tcp-relay?token=bad"))
        async with self.client.get(self.url, headers=headers()) as response:
            self.assertEqual(response.status, 400)
        self.assertEqual(self.connect_calls, [])
        self.assertEqual(self.app[relay.RUNTIME].active, 0)

    async def test_binary_max_frame_ack_after_drain_and_bidirectional_data(self):
        ws = await self.client.ws_connect(self.url, headers=headers())
        self.assertEqual(self.connect_calls, [("example.invalid", 443)])
        data = b"x" * relay.MAX_FRAME
        await ws.send_bytes(data)
        await asyncio.wait_for(self.writer.drain_started.wait(), 0.5)
        pending = asyncio.create_task(ws.receive())
        finished, _ = await asyncio.wait({pending}, timeout=0.04)
        self.assertFalse(finished, "ACK must not precede TCP drain")
        self.writer.drain_allowed.set()
        message = await asyncio.wait_for(pending, 0.5)
        self.assertEqual((message.type, message.data), (WSMsgType.TEXT, "ack:65536"))
        await ws.send_bytes(b"xy")
        self.assertEqual((await ws.receive()).data, "ack:65538")
        await self.reader.queue.put(b"return traffic")
        message = await ws.receive()
        self.assertEqual((message.type, message.data), (WSMsgType.BINARY, b"return traffic"))
        self.assertEqual(self.writer.data, [data, b"xy"])
        await self.reader.queue.put(b"")
        message = await ws.receive()
        self.assertEqual((message.type, message.data), (WSMsgType.CLOSE, 1000))
        await ws.close()
        await asyncio.wait_for(self.writer.closed.wait(), 0.5)

    async def test_text_and_oversized_messages_rejected(self):
        ws = await self.client.ws_connect(self.url, headers=headers())
        await ws.send_str("unauthorized protocol message")
        message = await ws.receive()
        self.assertEqual((message.type, message.data), (WSMsgType.CLOSE, 1008))
        await ws.close()
        self.assertEqual(self.writer.data, [])
        ws = await self.client.ws_connect(self.url, headers=headers())
        await ws.send_bytes(b"x" * (relay.MAX_FRAME + 1))
        message = await ws.receive()
        self.assertEqual((message.type, message.data), (WSMsgType.CLOSE, 1009))
        await ws.close()
        self.assertEqual(self.writer.data, [])

    async def test_idle_and_shutdown_clean_up(self):
        self.app[relay.RUNTIME].config = dataclasses.replace(CONFIG, idle_timeout=0.06)
        ws = await self.client.ws_connect(self.url, headers=headers())
        message = await asyncio.wait_for(ws.receive(), 0.5)
        self.assertEqual((message.type, message.data), (WSMsgType.CLOSE, 1001))
        await ws.close()
        await asyncio.wait_for(self.writer.closed.wait(), 0.5)
        self.app[relay.RUNTIME].config = CONFIG
        ws = await self.client.ws_connect(self.url, headers=headers())
        await relay.shutdown(self.app)
        self.assertEqual(self.app[relay.RUNTIME].active, 0)
        self.assertFalse(self.app[relay.RUNTIME].handlers)
        self.assertFalse(self.app[relay.RUNTIME].websockets)
        await ws.close()

    async def test_cap_includes_connecting_and_connect_failure_has_no_upgrade(self):
        started = asyncio.Event()

        async def stalled(host, port, config):
            started.set()
            await asyncio.Event().wait()

        runtime = self.app[relay.RUNTIME]
        runtime.connector = stalled
        runtime.config = dataclasses.replace(CONFIG, connect_timeout=0.1, max_connections=1)
        first = asyncio.create_task(self.handshake_status(headers(), 502))
        await started.wait()
        await self.handshake_status(headers(), 503)
        await first
        self.assertEqual(runtime.active, 0)
        self.assertFalse(runtime.handlers)

    async def test_cancelled_wait_closed_releases_admission_for_next_tunnel(self):
        class CancelledCloseWriter(FakeWriter):
            async def wait_closed(self):
                await self.closed.wait()
                raise asyncio.CancelledError("Synthetic cancellation during TCP cleanup")

        runtime = self.app[relay.RUNTIME]
        runtime.config = dataclasses.replace(CONFIG, max_connections=1)
        self.writer = CancelledCloseWriter()
        first_writer = self.writer
        ws = await self.client.ws_connect(self.url, headers=headers())
        self.assertEqual(runtime.active, 1)
        self.assertEqual(len(runtime.handlers), 1)
        first_handler = next(iter(runtime.handlers))
        await ws.close()
        finished, _ = await asyncio.wait({first_handler}, timeout=0.5)
        self.assertIn(first_handler, finished, "The cancelled cleanup handler must finish")
        self.assertTrue(first_writer.closed.is_set())
        cleanup_state = (runtime.active, first_handler in runtime.handlers,
                         len(runtime.websockets))

        # Exercise admission again, not just the internal counter. A leaked slot
        # returns 503 here although the service and authentication remain healthy.
        self.reader, self.writer = FakeReader(), FakeWriter()
        try:
            next_ws = await self.client.ws_connect(self.url, headers=headers())
        except WSServerHandshakeError as error:
            next_status = error.status
        else:
            next_status = 101
            next_handlers = set(runtime.handlers) - {first_handler}
            await next_ws.close()
            if next_handlers:
                finished, _ = await asyncio.wait(next_handlers, timeout=0.5)
                self.assertEqual(finished, next_handlers)

        self.assertEqual(cleanup_state, (0, False, 0),
                         f"Cancellation leaked admission state; next handshake={next_status}")
        self.assertEqual(next_status, 101, "A fresh authorized tunnel must not receive 503")
        self.assertEqual(runtime.active, 0)
        self.assertFalse(runtime.handlers)
        self.assertFalse(runtime.websockets)

    async def test_disallowed_destination_fails_before_upgrade(self):
        self.app[relay.RUNTIME].connector = relay.open_source_bound_connection
        await self.handshake_status(headers(**{"X-Exit-Host": "127.0.0.1"}), 403)
        await self.handshake_status(headers(**{"X-Exit-Host": "9.9.9.9"}), 403)
        self.assertEqual(self.app[relay.RUNTIME].active, 0)

    async def test_stalled_tcp_drain_closes_and_cleans_up(self):
        self.app[relay.RUNTIME].config = dataclasses.replace(CONFIG, io_timeout=0.06)
        ws = await self.client.ws_connect(self.url, headers=headers())
        await ws.send_bytes(b"payload")
        message = await asyncio.wait_for(ws.receive(), 0.5)
        self.assertEqual((message.type, message.data), (WSMsgType.CLOSE, 1011))
        await ws.close()
        await asyncio.wait_for(self.writer.closed.wait(), 0.5)

    async def test_real_tcp_echo_and_client_disconnect_cleanup(self):
        tcp_closed = asyncio.Event()

        async def echo(reader, writer):
            try:
                while data := await reader.read(8192):
                    writer.write(data)
                    await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()
                tcp_closed.set()

        tcp_server = await asyncio.start_server(echo, "127.0.0.1", 0)
        tcp_port = tcp_server.sockets[0].getsockname()[1]

        async def local_test_connector(host, port, config):
            return await asyncio.open_connection("127.0.0.1", tcp_port)

        self.app[relay.RUNTIME].connector = local_test_connector
        try:
            ws = await self.client.ws_connect(self.url, headers=headers())
            for payload, cumulative in ((b"a" * 65536, 65536), (b"b" * 1024, 66560)):
                await ws.send_bytes(payload)
                returned = bytearray()
                acknowledged = False
                while not acknowledged or len(returned) < len(payload):
                    message = await asyncio.wait_for(ws.receive(), 1.0)
                    if message.type == WSMsgType.TEXT:
                        self.assertEqual(message.data, f"ack:{cumulative}")
                        acknowledged = True
                    else:
                        self.assertEqual(message.type, WSMsgType.BINARY)
                        returned.extend(message.data)
                self.assertEqual(bytes(returned), payload)
            await ws.close()
            await asyncio.wait_for(tcp_closed.wait(), 0.5)
        finally:
            tcp_server.close()
            await tcp_server.wait_closed()


if __name__ == "__main__":
    unittest.main(verbosity=2)
