"""Source folders mounted into agent containers: Settings tab, safety checks, docker arguments."""
import pytest
from starlette.testclient import TestClient

from airlock import config as C
from airlock import sources, ui


@pytest.fixture
def home(tmp_path, monkeypatch):
    h = tmp_path / "userhome"
    h.mkdir()
    monkeypatch.setattr(sources.Path, "home", classmethod(lambda cls: h))
    monkeypatch.setenv("HOME", str(h))
    for d in ("myapp", "mylib", ".ssh", ".aws/x", "proj/nested"):
        (h / d).mkdir(parents=True)
    return h


def test_defaults_are_mounted(home, monkeypatch):
    monkeypatch.setattr(sources, "DEFAULTS", [{"path": "~/myapp", "mode": "ro", "enabled": True}, {"path": "~/mylib", "mode": "ro", "enabled": True}])
    ms = sources.mounts(sandbox=True)
    assert [m["container"] for m in ms] == ["/src/myapp", "/src/mylib"] and all(m["ro"] for m in ms)
    assert sources.docker_args(ms)[:2] == ["-v", f"{home / 'myapp'}:/src/myapp:ro"]
    (home / "mylib").rmdir()
    assert [m["container"] for m in sources.mounts(True)] == ["/src/myapp"]          # a missing folder is skipped, not an error


def test_add_update_remove_and_rw_only_for_sandbox(home):
    sources.add("~/proj", "rw")
    sources.add(str(home / "myapp"))                                                    # absolute path is normalised to ~/
    assert [s.path for s in sources.load()] == ["~/proj", "~/myapp"]
    sb = {m["path"]: m for m in sources.mounts(sandbox=True)}
    gw = {m["path"]: m for m in sources.mounts(sandbox=False)}
    assert sb["~/proj"]["ro"] is False and gw["~/proj"]["ro"] is True                       # PROD is always read-only
    assert sources.docker_args([sb["~/proj"]]) == ["-v", f"{home / 'proj'}:/src/proj"]
    sources.update("~/proj", enabled=False)
    assert all(m["path"] != "~/proj" for m in sources.mounts(True))
    sources.remove("~/proj")
    assert [s.path for s in sources.load()] == ["~/myapp"]


@pytest.mark.parametrize("bad", ["", "/", "~", "~/.ssh", "~/.aws/x", "~/nope", "/etc/../"])
def test_dangerous_or_missing_folders_refused(home, bad):
    with pytest.raises(C.ConfigError):
        sources.add(bad)


def test_duplicates_and_name_clash_and_symlink_into_credentials(home):
    sources.add("~/proj")
    with pytest.raises(C.ConfigError, match="already listed"):
        sources.add("~/proj")
    (home / "other" / "proj").mkdir(parents=True)
    with pytest.raises(C.ConfigError, match="already mounted as /src/proj"):
        sources.add("~/other/proj")
    (home / "sneaky").symlink_to(home / ".ssh")
    with pytest.raises(C.ConfigError, match="credentials"):
        sources.add("~/sneaky")                                                             # symlink resolved before the check
    (home / "proj2").mkdir()
    sources.add("~/proj2")
    (home / "proj2").rename(home / "gone")
    (home / "proj2").symlink_to(home / ".aws")                                              # swapped for a link after it was added
    assert all(m["path"] != "~/proj2" for m in sources.mounts(True))                        # never mounted silently


def test_settings_tab_manages_folders(home, tmp_path):
    p = tmp_path / "a.yaml"
    p.write_text("version: 1\n")
    c = TestClient(ui.make_app(str(p)), base_url="http://127.0.0.1:8800", follow_redirects=True)
    page = c.get("/settings").text
    assert "Source code mounted into agents" in page and "No folders" in page
    r = c.post("/settings/sources", data={"action": "add", "path": "~/proj", "mode": "ro"})
    assert "<code>~/proj</code>" in r.text and "/src/proj" in r.text
    c.post("/settings/sources", data={"action": "mode", "path": "~/proj", "mode": "rw"})
    assert sources.load()[0].mode == "rw"
    c.post("/settings/sources", data={"action": "toggle", "path": "~/proj"})
    assert sources.load()[0].enabled is False
    assert "overlaps ~/.ssh" in c.post("/settings/sources", data={"action": "add", "path": "~/.ssh"}).text
    c.post("/settings/sources", data={"action": "remove", "path": "~/proj"})
    assert sources.load() == []
    assert c.post("/settings/sources", data={"action": "add", "path": "~/proj"}, headers={"origin": "https://evil.example"}).status_code == 403
