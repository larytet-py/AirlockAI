"""Tests must never touch the real ~/.airlock or ~/.ssh: the ssh config/key paths are redirected for every test."""
import pytest

from airlock import audit, sources, sshaccess


@pytest.fixture(autouse=True)
def isolated_ssh_paths(tmp_path, monkeypatch):
    monkeypatch.setattr(sshaccess, "KEY", tmp_path / "_ssh" / "id_ed25519")
    monkeypatch.setattr(sshaccess, "CONFIG", tmp_path / "_ssh_config")
    monkeypatch.setattr(sshaccess, "USER_SSH_CONFIG", tmp_path / "_dot_ssh" / "config")

    monkeypatch.setattr(sources, "HOME", tmp_path / "_home")          # settings.json of the test, not the user
    monkeypatch.setattr(audit, "HOME", tmp_path / "_home")            # and its audit log
    monkeypatch.setattr(sources, "DEFAULTS", [])                      # and none of the user's default folders

TEST_UI_TOKEN = "test-ui-token"


@pytest.fixture
def raw_ui():
    """Ask for this fixture to get the UI exactly as a stranger sees it: no token cookie, no default Origin."""


@pytest.fixture(autouse=True)
def ui_test_defaults(request, monkeypatch):
    """The UI refuses requests without its per-start token and without an Origin on POST. Tests act as the signed-in browser
    (cookie + same-origin Origin) unless they ask for `raw_ui`."""
    if "raw_ui" in request.fixturenames:
        return
    from starlette.testclient import TestClient
    from airlock import ui

    make = ui.make_app
    monkeypatch.setattr(ui, "make_app", lambda cfg=None, ui_token=TEST_UI_TOKEN: make(cfg, ui_token=ui_token))
    init = TestClient.__init__

    def patched(self, app, *a, **kw):
        kw.setdefault("cookies", {"airlock_ui": TEST_UI_TOKEN})
        headers = dict(kw.get("headers") or {})
        headers.setdefault("origin", "http://127.0.0.1:8800")
        kw["headers"] = headers
        init(self, app, *a, **kw)

    monkeypatch.setattr(TestClient, "__init__", patched)
