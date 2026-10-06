from pathlib import Path

import pytest

from airlock import config as C

ROOT = Path(__file__).resolve().parent.parent
LINKS = """
version: 1
defaults:
  exec: {mode: ssh, user: "${USER_NAME}"}
  links:
    docs: "https://docs-{instance_id}.dev.example.com/"
    web:  "https://web-{instance_id}.dev.example.com/"
    ssh:  "ssh://{user}@{instance_id}.example.com"
    plain: "https://{host}/status"
nodes:
  - {name: FromHost, host: i-0123456789abcdef0.example.com, exec: {user: alice}}
  - {name: FromTag,  host: 10.0.0.2, tags: {aws_instance_id: i-0aaaaaaaa}, exec: {user: bob}}
  - {name: FromField, host: 10.0.0.3, instance_id: i-0bbbbbbbb, exec: {user: carol}}
  - {name: FromName-i-0cccccccc, host: 10.0.0.4, exec: {user: dave}}
  - {name: NoInstance, host: 10.0.0.5, exec: {user: erin}}
"""


def load(tmp_path, text=LINKS):
    p = tmp_path / "c.yaml"
    p.write_text(text)
    return C.load_config(p)


def test_pattern_expands_with_the_ec2_name(tmp_path):
    n = load(tmp_path).node("FromHost")
    assert n.links == {"docs": "https://docs-i-0123456789abcdef0.dev.example.com/",
                       "web": "https://web-i-0123456789abcdef0.dev.example.com/",
                       "ssh": "ssh://alice@i-0123456789abcdef0.example.com",
                       "plain": "https://i-0123456789abcdef0.example.com/status"}


def test_instance_id_sources_in_priority_order(tmp_path):
    cfg = load(tmp_path)
    assert cfg.node("FromTag").resolved_instance_id() == "i-0aaaaaaaa"
    assert cfg.node("FromField").links["web"] == "https://web-i-0bbbbbbbb.dev.example.com/"
    assert cfg.node("FromName-i-0cccccccc").resolved_instance_id() == "i-0cccccccc"
    both = load(tmp_path, LINKS.replace("instance_id: i-0bbbbbbbb", "instance_id: i-0bbbbbbbb, tags: {aws_instance_id: i-0zzzzzzzz}"))
    assert both.node("FromField").resolved_instance_id() == "i-0bbbbbbbb"       # explicit field beats the tag


def test_node_without_instance_id_only_gets_links_that_do_not_need_it(tmp_path):
    n = load(tmp_path).node("NoInstance")
    assert set(n.links) == {"plain"} and n.links["plain"] == "https://10.0.0.5/status"


def test_explicit_node_urls_override_and_may_use_placeholders(tmp_path):
    text = LINKS.replace("{name: NoInstance, host: 10.0.0.5, exec: {user: erin}}",
                         "{name: Over, host: i-0dddddddd, exec: {user: x}, urls: {web: 'https://custom/{name}', grafana: 'https://g-{instance_id}.x/'}}")
    n = load(tmp_path, text).node("Over")
    assert n.links["web"] == "https://custom/Over" and n.links["grafana"] == "https://g-i-0dddddddd.x/"
    assert n.links["docs"] == "https://docs-i-0dddddddd.dev.example.com/"      # untouched templates still apply


def test_user_from_environment_reference(tmp_path, monkeypatch):
    text = LINKS.replace("exec: {user: alice}", "exec: {user: '${USER_NAME}'}")
    monkeypatch.setenv("USER_NAME", "alice")
    assert load(tmp_path, text).node("FromHost").links["ssh"] == "ssh://alice@i-0123456789abcdef0.example.com"
    monkeypatch.delenv("USER_NAME")
    assert "ssh" not in load(tmp_path, text).node("FromHost").links              # unknown user: no half-built link


def test_bad_templates_are_refused_at_load(tmp_path):
    with pytest.raises(C.ConfigError, match=r"unknown placeholder.*\{instnace_id\}"):
        load(tmp_path, LINKS.replace("{instance_id}.example.com\"\n    plain", "{instnace_id}.example.com\"\n    plain"))
    with pytest.raises(C.ConfigError, match="must start with"):
        load(tmp_path, LINKS.replace('"https://docs-', '"javascript:alert(1)//docs-'))
    with pytest.raises(C.ConfigError, match="unknown placeholder"):
        load(tmp_path, LINKS.replace("https://custom", "x").replace("exec: {user: erin}}", "exec: {user: erin}, urls: {a: 'https://{secret}/'}}"))


def test_export_keeps_the_patterns_and_does_not_bake_links(tmp_path):
    out = C.export_config(load(tmp_path))
    assert "{instance_id}" in out and "i-0123456789abcdef0.dev" not in out


def test_template_file_is_valid_and_documents_the_pattern():
    cfg = C.load_config(ROOT / "airlock.example.yaml")
    john, jane = cfg.node("JohnTestApi"), cfg.node("JaneTestGateway")
    assert john.links["web"] == "https://web-i-0123456789abcdef0.dev.example.com/"
    assert jane.links["docs"] == "https://docs-i-0fedcba9876543210.dev.example.com/"
    assert jane.links["grafana"] == "https://grafana-i-0fedcba9876543210.dev.example.com/"
    assert jane.exec.mode == "ssh_sudo"
    text = (ROOT / "airlock.example.yaml").read_text()
    assert "qspark" not in text and "alice" not in text                          # no real hostnames or people in the repo
    assert not C.find_literal_secrets(__import__("yaml").safe_load(text))


def test_ui_renders_links_and_drops_unsafe_schemes(tmp_path, monkeypatch):
    from starlette.testclient import TestClient

    import airlock.ui as ui
    from airlock import nodestats
    monkeypatch.setattr(nodestats, "collect", lambda nodes: {})
    p = tmp_path / "c.yaml"
    p.write_text(LINKS)
    page = TestClient(ui.make_app(str(p)), base_url="http://127.0.0.1:8800").get("/").text
    assert 'href="https://docs-i-0123456789abcdef0.dev.example.com/"' in page
    assert 'href="ssh://alice@i-0123456789abcdef0.example.com"' in page
    assert page.count('href="ssh://') >= 5                                         # every node has an ssh link (pattern or fallback)
