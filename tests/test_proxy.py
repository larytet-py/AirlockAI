"""Egress proxy allowlist behaviour, exercised in-process with a local echo server."""
import asyncio
import importlib
import socket


async def _roundtrip(proxy, target, payload=b"ping"):
    r, w = await asyncio.open_connection("127.0.0.1", proxy)
    w.write(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
    head = await r.readuntil(b"\r\n\r\n")
    if b" 200 " not in head:
        return head
    w.write(payload)
    return await asyncio.wait_for(r.read(10), 3)


def test_allowlist(monkeypatch):
    async def run():
        async def echo(r, w):
            w.write(await r.read(10))
            await w.drain()
            w.close()
        echo_srv = await asyncio.start_server(echo, "127.0.0.1", 0)
        eport = echo_srv.sockets[0].getsockname()[1]
        monkeypatch.setenv("ALLOW", f"127.0.0.1:{eport},example.com:443")
        proxy = importlib.import_module("airlock.egress_proxy")
        importlib.reload(proxy)
        srv = await asyncio.start_server(proxy.handle, "127.0.0.1", 0)
        pport = srv.sockets[0].getsockname()[1]
        assert await _roundtrip(pport, f"127.0.0.1:{eport}") == b"ping"          # allowed literal ip:port
        assert b"403" in await _roundtrip(pport, f"127.0.0.1:{eport + 1}")        # other port on allowed ip
        assert b"403" in await _roundtrip(pport, "93.184.216.34:443")             # other host
        assert b"403" in await _roundtrip(pport, "192.0.2.10:22")              # other ssh host
        # plain (non-CONNECT) HTTP is refused
        r, w = await asyncio.open_connection("127.0.0.1", pport)
        w.write(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
        assert b"403" in await r.readuntil(b"\r\n\r\n")
    asyncio.run(run())
