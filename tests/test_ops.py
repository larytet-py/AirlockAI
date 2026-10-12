import pytest

from airlock import ops
from airlock.config import ConfigError

CAT = ops.load_operations()


def test_starter_library_loads():
    assert {"cpu", "mem", "disk", "docker-ps", "docker-purge", "journal-tail", "restart-service", "top-ports", "reboot"} <= set(CAT)
    assert CAT["docker-purge"].risk == "destructive" and CAT["cpu"].risk == "read"


def test_bind_defaults_and_ranges():
    assert "until=24h" in CAT["docker-purge"].bind({})
    assert "until=5h" in CAT["docker-purge"].bind({"keep_hours": "5"})
    with pytest.raises(ConfigError):
        CAT["docker-purge"].bind({"keep_hours": "0"})
    with pytest.raises(ConfigError):
        CAT["docker-purge"].bind({"keep_hours": "1h; reboot"})


@pytest.mark.parametrize("bad", ["api; reboot", "$(id)", "a b", "`id`", "x\nreboot", "a|b", ""])
def test_string_params_cannot_inject(bad):
    with pytest.raises(ConfigError):
        CAT["journal-tail"].bind({"unit": bad})


def test_unknown_and_missing_params():
    with pytest.raises(ConfigError):
        CAT["cpu"].bind({"x": "1"})
    with pytest.raises(ConfigError):
        CAT["restart-service"].bind({})


def test_destructive_needs_confirmation():
    from airlock import config as C
    cfg = C.Config(nodes=[C.Node(name="N", host="h", tags={"env": "test"})])
    with pytest.raises(ConfigError, match="--yes"):
        ops.run_operation(cfg, CAT["reboot"], cfg.nodes, {})
