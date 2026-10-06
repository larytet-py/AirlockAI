import json
import subprocess

import pytest

from airlock import awsimport as A
from airlock import config as C

RAW = json.dumps([
    {"InstanceId": "i-0123456789abcdef0", "State": {"Name": "running"}, "PrivateIpAddress": "192.0.2.10",
     "Tags": [{"Key": "Name", "Value": "alice's dev instance (build #1)"}, {"Key": "Project", "Value": "webapp"}]},
    {"InstanceId": "i-0aaa", "State": {"Name": "stopped"}, "PublicIpAddress": "3.3.3.3",
     "Tags": [{"Key": "Name", "value": "x"}, {"Key": "Owner", "Value": "ALICE"}]},
    {"InstanceId": "i-0bbb", "State": {"Name": "running"}, "PrivateIpAddress": "10.0.0.9",
     "Tags": [{"Key": "Name", "Value": "someone else's box"}]},
    {"InstanceId": "i-0ccc", "State": {"Name": "running"}},
])


def cfg(extra=None, integrations=True):
    aws = {"regions": ["us-east-1"], **(extra or {})}
    return C.Config.model_validate({"version": 1, **({"integrations": {"aws": aws}} if integrations else {})})


def test_parse_matches_user_case_insensitively_in_any_tag():
    got = A.parse(RAW, "us-east-1", "alice")
    assert [i.id for i in got] == ["i-0123456789abcdef0", "i-0aaa"]
    assert got[0].matched_on == "Name" and got[1].matched_on == "Owner"


def test_find_uses_only_read_only_describe_and_passes_user_as_one_argv(monkeypatch):
    seen = []

    def fake_run(cmd, **kw):
        seen.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, RAW, "")
    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setenv("USER_NAME", "alice")
    found = A.find_instances(cfg())
    assert len(found) == 2
    cmd = seen[0]
    assert cmd[:3] == ["aws", "ec2", "describe-instances"] and "Name=tag-value,Values=*alice*" in cmd
    assert not any(w in " ".join(cmd) for w in ("terminate", "run-instances", "modify", "create-tags", "stop-instances"))


def test_requires_user_name_and_rejects_unsafe_values(monkeypatch):
    monkeypatch.delenv("USER_NAME", raising=False)
    with pytest.raises(C.ConfigError, match="USER_NAME"):
        A.find_instances(cfg())
    for bad in ("a b", "x;rm -rf /", "$(id)", "", "a" * 70):
        with pytest.raises(C.ConfigError):
            A.find_instances(cfg(), user=bad)


def fail_with(monkeypatch, stderr):
    monkeypatch.setattr(subprocess, "run", lambda cmd, **kw: subprocess.CompletedProcess(cmd, 255, "", stderr))


def test_expired_session_tells_the_user_how_to_log_in(monkeypatch):
    fail_with(monkeypatch, "aws: [ERROR]: Your session has expired. Please reauthenticate using 'aws login'.\n")
    with pytest.raises(A.AwsAuthError) as e:
        A.find_instances(cfg(), user="alice")
    assert e.value.command == "aws login"
    assert "Log in again in a terminal with: aws login" in str(e.value) and "aws: aws:" not in str(e.value)


def test_login_command_follows_sso_and_profile(monkeypatch):
    fail_with(monkeypatch, "Error when retrieving token from sso: Token has expired and refresh failed\n")
    with pytest.raises(A.AwsAuthError) as e:
        A.find_instances(cfg({"profile": "dev"}), user="alice")
    assert e.value.command == "aws sso login --profile dev"


def test_missing_credentials_is_an_auth_error_but_other_failures_are_not(monkeypatch):
    fail_with(monkeypatch, "Unable to locate credentials. You can configure credentials by running \"aws configure\".\n")
    with pytest.raises(A.AwsAuthError):
        A.find_instances(cfg(), user="alice")
    fail_with(monkeypatch, "An error occurred (UnauthorizedOperation) when calling the DescribeInstances operation\n")
    with pytest.raises(RuntimeError) as e:
        A.find_instances(cfg(), user="alice")
    assert not isinstance(e.value, A.AwsAuthError) and "UnauthorizedOperation" in str(e.value)


def test_ui_shows_login_hint_with_retry(tmp_path, monkeypatch):
    from starlette.testclient import TestClient

    import airlock.ui as ui
    p = tmp_path / "c.yaml"
    p.write_text("version: 1\nintegrations: {aws: {regions: [us-east-1]}}\n")
    monkeypatch.setattr(A, "available", lambda: True)
    monkeypatch.setenv("USER_NAME", "alice")
    fail_with(monkeypatch, "aws: [ERROR]: Your session has expired. Please reauthenticate using 'aws login'.\n")
    page = TestClient(ui.make_app(str(p)), base_url="http://127.0.0.1:8800").get("/aws").text
    assert "needs a login" in page and "<pre" in page and ">aws login<" in page and 'href=/aws>Retry' in page


def test_no_region_is_a_clear_error(monkeypatch):
    monkeypatch.delenv("AWS_REGION", raising=False)
    monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)
    monkeypatch.setattr(A, "available", lambda: False)
    with pytest.raises(C.ConfigError, match="no AWS region"):
        A.find_instances(cfg(integrations=False), user="alice")


def test_node_naming_and_host_choice():
    c = cfg()
    i = A.parse(RAW, "us-east-1", "alice")
    assert A.node_name(i[0], set()) == "alice-s-dev-instance-build-1"
    assert A.node_name(i[0], {"alice-s-dev-instance-build-1"}).endswith("-" + "i-0123456789abcdef0"[-6:])
    assert A.host_for(i[0], c) == "192.0.2.10" and A.host_for(i[1], c) == "3.3.3.3"       # public IP wins, else private
    assert A.host_for(i[0], cfg({"host_template": "{instance_id}.example.com"})) == "i-0123456789abcdef0.example.com"
    with pytest.raises(C.ConfigError, match="no IP"):
        A.host_for(A.Instance("i-0ccc", "r", "", "running", None, None), c)


def test_spec_is_valid_config_shareable_and_not_auto_trusted(tmp_path):
    c = cfg()
    spec = A.to_spec(A.parse(RAW, "us-east-1", "alice")[0], c, set())
    p = tmp_path / "c.yaml"
    p.write_text("version: 1\n")
    C.add_node(p, spec)
    n = C.load_config(p).nodes[0]
    assert n.exec.user == "${USER_NAME}"                                        # a reference, not a literal login
    assert n.instance_id == "i-0123456789abcdef0" and n.region == "us-east-1" and not hasattr(n, "tags")
    plain = A.to_spec(A.parse(RAW, "us-east-1", "alice")[0], c, set())
    assert "tags" not in plain and plain["instance_id"] == "i-0123456789abcdef0"


def test_already_imported_instances_are_skipped(tmp_path):
    c = C.Config.model_validate({"version": 1, "nodes": [{"name": "A", "host": "h", "instance_id": "i-0aaa"}]})
    found = A.parse(RAW, "us-east-1", "alice")
    assert [i.id for i in A.new_instances(c, found)] == ["i-0123456789abcdef0"]


def test_ui_import_flow(tmp_path, monkeypatch):
    from starlette.testclient import TestClient

    import airlock.ui as ui
    p = tmp_path / "c.yaml"
    p.write_text("version: 1\nintegrations: {aws: {regions: [us-east-1]}}\n")
    monkeypatch.setattr(A, "available", lambda: True)
    monkeypatch.setenv("USER_NAME", "alice")
    monkeypatch.setattr(subprocess, "run", lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, RAW, ""))
    c = TestClient(ui.make_app(str(p)), base_url="http://127.0.0.1:8800", follow_redirects=True)
    assert "Import my AWS instances" in c.get("/").text
    page = c.get("/aws").text
    assert "i-0123456789abcdef0" in page and "i-0bbb" not in page and "someone else" not in page
    # the server re-queries AWS: an id that is not the user's cannot be added by crafting the form
    c.post("/aws/add", data={"iid": ["i-0bbb|us-east-1", "i-0aaa|us-east-1"]})
    names = {n.instance_id for n in C.load_config(p).nodes}
    assert names == {"i-0aaa"}
    assert "at least one" in c.post("/aws/add", data={}).text


def test_ui_import_disabled_without_user_name(tmp_path, monkeypatch):
    from starlette.testclient import TestClient

    import airlock.ui as ui
    p = tmp_path / "c.yaml"
    p.write_text("version: 1\n")
    monkeypatch.delenv("USER_NAME", raising=False)
    c = TestClient(ui.make_app(str(p)), base_url="http://127.0.0.1:8800")
    assert "USER_NAME is not set" in c.get("/").text


def _nodes():
    return C.Config.model_validate({"version": 1, "integrations": {"aws": {"regions": ["us-east-1", "eu-west-1"]}}, "nodes": [
        {"name": "T1", "host": "10.0.0.1", "instance_id": "i-0aaaaaaaa1", "region": "us-east-1"},
        {"name": "T2", "host": "10.0.0.2", "instance_id": "i-0aaaaaaaa2", "region": "us-east-1"},
        {"name": "T3", "host": "10.0.0.3", "instance_id": "i-0aaaaaaaa3", "region": "eu-west-1"},
        {"name": "P1", "host": "10.0.0.4", "instance_id": "i-0aaaaaaaa4"},
        {"name": "NoId", "host": "10.0.0.5"}]})


def test_control_groups_by_region_and_skips_unsafe_nodes(monkeypatch, tmp_path):
    from airlock import audit, session
    monkeypatch.setattr(audit, "HOME", tmp_path)
    monkeypatch.setattr(session, "list_sessions", lambda: [])
    monkeypatch.setattr(A, "available", lambda: True)
    calls = []
    monkeypatch.setattr(A, "_aws", lambda args, profile, timeout=60: calls.append(args) or "{}")
    c = _nodes()
    out = A.control(c, list(c.nodes), "stop")
    assert sorted(calls) == [["ec2", "stop-instances", "--instance-ids", "i-0aaaaaaaa1", "i-0aaaaaaaa2", "--region", "us-east-1"],
                             ["ec2", "stop-instances", "--instance-ids", "i-0aaaaaaaa3", "--region", "eu-west-1"],
                             ["ec2", "stop-instances", "--instance-ids", "i-0aaaaaaaa4"]]      # P1: no region known
    text = "\n".join(out)
    assert "T1: stop requested" in text and "T3: stop requested" in text
    assert "P1: stop requested" in text and "NoId: skipped, no EC2 instance id" in text


def test_control_refuses_stop_while_a_session_uses_the_node_but_allows_start(monkeypatch, tmp_path):
    from airlock import audit, session
    monkeypatch.setattr(audit, "HOME", tmp_path)
    monkeypatch.setattr(session, "sessions_using", lambda n: ["abcdef12"] if n == "T1" else [])
    monkeypatch.setattr(A, "available", lambda: True)
    calls = []
    monkeypatch.setattr(A, "_aws", lambda args, profile, timeout=60: calls.append(args) or "{}")
    c = _nodes()
    assert "T1: skipped, a session uses it" in "\n".join(A.control(c, [c.node("T1")], "reboot")) and not calls
    assert "T1: start requested" in "\n".join(A.control(c, [c.node("T1")], "start"))


def test_control_rejects_bad_action_and_empty_selection():
    with pytest.raises(C.ConfigError):
        A.control(_nodes(), [], "start")
    with pytest.raises(C.ConfigError):
        A.control(_nodes(), list(_nodes().nodes), "terminate")


def test_control_reports_a_failed_call_per_node(monkeypatch, tmp_path):
    from airlock import audit, session
    monkeypatch.setattr(audit, "HOME", tmp_path)
    monkeypatch.setattr(session, "sessions_using", lambda n: [])
    monkeypatch.setattr(A, "available", lambda: True)

    def boom(args, profile, timeout=60):
        raise RuntimeError("aws: IncorrectInstanceState")
    monkeypatch.setattr(A, "_aws", boom)
    c = _nodes()
    out = A.control(c, [c.node("T1"), c.node("T2")], "start")
    assert all("failed (aws: IncorrectInstanceState)" in ln for ln in out) and len(out) == 2


def test_control_starts_every_node_with_an_instance_id(monkeypatch, tmp_path):
    from airlock import audit, session
    monkeypatch.setattr(audit, "HOME", tmp_path)
    monkeypatch.setattr(session, "sessions_using", lambda n: [])
    monkeypatch.setattr(A, "available", lambda: True)
    calls = []
    monkeypatch.setattr(A, "_aws", lambda args, profile, timeout=60: calls.append(args) or "{}")
    c = C.Config.model_validate({"version": 1, "nodes": [
        {"name": "U", "host": "i-0123456789abcdef0"},
        {"name": "PA", "host": "10.0.0.9", "instance_id": "i-0aaaaaaaa9"}]})
    out = "\n".join(A.control(c, list(c.nodes), "start"))
    assert "U: start requested" in out and "PA: start requested" in out
    assert calls == [["ec2", "start-instances", "--instance-ids", "i-0123456789abcdef0", "i-0aaaaaaaa9"]]


def test_aws_import_page_has_no_tags_field(tmp_path, monkeypatch):
    from starlette.testclient import TestClient

    from airlock.ui import make_app
    p = tmp_path / "c.yaml"
    p.write_text("version: 1\nintegrations: {aws: {regions: [us-east-1]}}\n")
    monkeypatch.setenv("USER_NAME", "alice")
    monkeypatch.setattr(A, "available", lambda: True)
    monkeypatch.setattr(A, "_aws", lambda args, profile, timeout=60: RAW)
    page = TestClient(make_app(str(p)), base_url="http://127.0.0.1:8800").get("/aws").text
    assert "i-0123456789abcdef0" in page and "Add selected nodes" in page
    assert "Tags for the new nodes" not in page and "name=tags" not in page
