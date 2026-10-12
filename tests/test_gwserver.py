"""MCP over HTTP: bearer auth, tools/list, tool calls, errors, patterns live without a restart."""
import asyncio
import json
import socket
import threading
import time

import pytest
import uvicorn
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

from airlock import gwserver
from airlock import patterns as P
from tests.test_gateway import Fake, ORDERS, env, G, Config, PatternStore, Audit  # noqa: F401


@pytest.fixture
def server(tmp_path, monkeypatch):
    monkeypatch.setattr("airlock.audit.HOME", tmp_path)
    store = PatternStore(tmp_path / "db.sqlite", tmp_path / "snap" / "snapshot.json")
    gw = G.Gateway(env(), Config(), session_id="m1", snapshot=store.snapshot, inbox=tmp_path / "inbox", backends=Fake(),
                   secrets={"PG_DSN": "postgres://u:pw@db/x"})
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    srv = uvicorn.Server(uvicorn.Config(gwserver.make_app(gw, gwserver.token_hash("tok-123")), host="127.0.0.1", port=port, log_level="error"))
    th = threading.Thread(target=srv.run, daemon=True)
    th.start()
    for _ in range(100):
        if srv.started:
            break
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}/mcp/", store, gw
    srv.should_exit = True
    th.join(5)


def run(coro):
    return asyncio.run(coro)


def test_bearer_token_required(server):
    import urllib.request, urllib.error
    url = server[0]
    for hdr in ({}, {"Authorization": "Bearer wrong"}):
        req = urllib.request.Request(url, data=b"{}", headers={"Content-Type": "application/json", **hdr}, method="POST")
        with pytest.raises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(req)
        assert e.value.code == 401


def test_list_and_call_over_mcp(server):
    url, store, gw = server

    async def go():
        async with streamablehttp_client(url, headers={"Authorization": "Bearer tok-123"}) as (r, w, _):
            async with ClientSession(r, w) as s:
                await s.initialize()
                names = {t.name for t in (await s.list_tools()).tools}
                assert {"query.list", "sql.query", "kubernetes.get"} <= names and "sql.orders_by_status" not in names
                store.upsert(ORDERS)          # added in the UI: visible on the next tools/list, no restart
                tools = {t.name: t for t in (await s.list_tools()).tools}
                assert "sql.orders_by_status" in tools
                assert tools["sql.orders_by_status"].inputSchema["properties"]["hours"]["maximum"] == 168
                ok = await s.call_tool("sql.orders_by_status", {"hours": 3})
                assert not ok.isError and "new" in ok.content[0].text
                bad = await s.call_tool("sql.query", {"sql": "drop table orders"})
                assert bad.isError and "match" in bad.content[0].text
                k = await s.call_tool("kubernetes.get", {"resource": "secrets", "namespace": "app"})
                assert k.isError and "denied" in k.content[0].text
    run(go())
    assert [c[0] for c in gw.backends.calls] == ["sql"]   # the DROP and the secrets request never reached a backend
