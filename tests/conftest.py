"""Tests must never touch the real ~/.airlock or ~/.ssh: the ssh config/key paths are redirected for every test."""
import pytest

from airlock import sources, sshaccess


@pytest.fixture(autouse=True)
def isolated_ssh_paths(tmp_path, monkeypatch):
    monkeypatch.setattr(sshaccess, "KEY", tmp_path / "_ssh" / "id_ed25519")
    monkeypatch.setattr(sshaccess, "CONFIG", tmp_path / "_ssh_config")
    monkeypatch.setattr(sshaccess, "USER_SSH_CONFIG", tmp_path / "_dot_ssh" / "config")

    monkeypatch.setattr(sources, "HOME", tmp_path / "_home")          # settings.json of the test, not the user
    monkeypatch.setattr(sources, "DEFAULTS", [])                      # and none of the user's default folders