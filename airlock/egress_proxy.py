"""Egress gateway: HTTP CONNECT proxy that tunnels only to an exact host:port allowlist.

Runs in its own container with two networks (agent-internal and outbound). Stdlib only, so it
runs in a plain python image. ALLOW="api.anthropic.com:443,10.0.1.11:22"
"""
import asyncio
import ipaddress
import os
import socket
import sys

ALLOW = {a.strip().lower() for a in os.environ.get("ALLOW", "").split(",") if a.strip()}
BAD_NETS = [ipaddress.ip_network(n) for n in ("127.0.0.0/8", "169.254.0.0/16", "::1/128", "fe80::/10")]


def log(*a):
    print(*a, flush=True)


def literal_ip(host):
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


async def pipe(r, w):
    try:
        while data := await r.read(65536):
            w.write(data)
            await w.drain()
    except (ConnectionError, asyncio.CancelledError):
        pass
    finally:
        try:
            w.close()
        except Exception:
            pass


async def handle(cr, cw):
    peer = cw.get_extra_info("peername")
    try:
        head = await asyncio.wait_for(cr.readuntil(b"\r\n\r\n"), 15)
        first = head.split(b"\r\n", 1)[0].decode(errors="replace")
        parts = first.split()
        if len(parts) != 3 or parts[0].upper() != "CONNECT":
            log("DENY non-connect", peer, first[:80])
            cw.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            return
        target = parts[1].lower()
        host, _, port = target.rpartition(":")
        host = host.strip("[]")
        if target not in ALLOW:
            log("DENY", peer, target)
            cw.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            return
        if literal_ip(host) is None:  # a hostname must not resolve into loopback / metadata ranges
            infos = await asyncio.get_running_loop().getaddrinfo(host, int(port), type=socket.SOCK_STREAM)
            if any(any(ipaddress.ip_address(i[4][0]) in n for n in BAD_NETS) for i in infos):
                log("DENY resolves-to-blocked-range", peer, target)
                cw.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                return
        try:
            ur, uw = await asyncio.wait_for(asyncio.open_connection(host, int(port)), 15)
        except Exception as e:
            log("FAIL", peer, target, e)
            cw.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            return
        log("ALLOW", peer, target)
        cw.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await cw.drain()
        await asyncio.gather(pipe(cr, uw), pipe(ur, cw))
    except Exception as e:
        log("ERR", peer, repr(e))
    finally:
        try:
            cw.close()
        except Exception:
            pass


async def main():
    srv = await asyncio.start_server(handle, "0.0.0.0", 3128)
    log("egress proxy up; allow =", sorted(ALLOW))
    async with srv:
        await srv.serve_forever()


if __name__ == "__main__":
    if not ALLOW:
        sys.exit("ALLOW is empty")
    asyncio.run(main())
