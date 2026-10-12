"""airlock.example.yaml stays valid (SPEC 7.3), including the Mode 2 sections."""
from pathlib import Path

from airlock import cli, envs
from airlock.config import load_config
from airlock.selftest import run_selftest

EXAMPLE = Path(__file__).resolve().parent.parent / "airlock.example.yaml"


def test_example_loads_and_validates(monkeypatch, capsys):
    monkeypatch.setenv("USER_NAME", "me")
    monkeypatch.setenv("USER_PASSWORD", "pw")
    cfg = load_config(EXAMPLE)
    assert [e.name for e in envs.environments(cfg)] == ["uat"] and len(cfg.query_patterns) == 3
    class A: pass
    assert cli.cmd_validate(A(), cfg) == 0
    assert "3 query patterns" in capsys.readouterr().out


def test_policy_selftest_passes_on_the_example(monkeypatch):
    monkeypatch.setenv("USER_NAME", "me")
    cfg = load_config(EXAMPLE)
    for env in envs.environments(cfg):
        assert run_selftest(env, cfg) == []


def test_validate_rejects_a_bad_pattern(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("USER_NAME", "me")
    monkeypatch.setenv("USER_PASSWORD", "pw")
    p = tmp_path / "a.yaml"
    p.write_text(EXAMPLE.read_text().replace('template: "HGETALL session:{{ id:str }}"', 'template: "DEL session:{{ id:str }}"'))

    class A:
        pass
    assert cli.cmd_validate(A(), load_config(p)) == 1
    assert "always denied" in capsys.readouterr().err
