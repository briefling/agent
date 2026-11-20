"""briefling-agent against fakes on the PATH: `sbx`, `uv`, `systemctl`, `launchctl` and the bridge are small Python
scripts that log their argv (calls.jsonl) and keep a little state (state.json). The real tools are proven elsewhere:
the bridge by its own tests and the live check, sbx by the run on a real machine."""

import json
import os
import plistlib
import stat
import subprocess
import sys
import textwrap

import pytest

from briefling_agent import cli, service

FAKE = textwrap.dedent('''\
    #!{py}
    import json, os, signal, sys, time
    D = {d!r}
    tool, args = os.path.basename(sys.argv[0]), sys.argv[1:]
    with open(os.path.join(D, "calls.jsonl"), "a") as f:
        f.write(json.dumps([tool] + args) + "\\n")
    sp = os.path.join(D, "state.json")
    st = json.load(open(sp)) if os.path.exists(sp) else {{}}
    def save():
        json.dump(st, open(sp, "w"))
    if tool == "sbx":
        if args[:2] == ["ls", "-q"]:
            if st.get("sbx_down"):
                print("not signed in"); sys.exit(1)
            print("\\n".join(st.get("sandboxes", [])))
        elif args[0] == "create":
            st.setdefault("sandboxes", []).append(args[args.index("--name") + 1]); save()
        elif args[0] == "exec":
            sys.exit(0 if st.get("logged_in") else 1)
        elif args[0] == "run":
            st["logged_in"] = True; save()
        elif args[:2] == ["policy", "ls"]:  # like sbx 0.54: the resources only with --wide
            if "--wide" in args:
                print("NAME  TYPE  DECISION  RESOURCES  RULE_ID")
                for i, x in enumerate(st.get("rules", [])):
                    print(f"p{{i}}  network  allow  {{x}}  id{{i}}")
            else:
                print("default  network  allow  198 hosts")
        elif args[:3] == ["policy", "rm", "network"]:
            assert "--force" in args and "--sandbox" in args  # sbx 0.54: the sandbox is no longer positional
            res = args[args.index("--resource") + 1]
            st["rules"] = [x for x in st.get("rules", []) if x != res]; save()
        elif args[:2] == ["policy", "allow"]:
            st.setdefault("rules", []).append(args[-1]); save()
    elif tool == "uv":
        if args[:2] == ["tool", "list"]:
            if st.get("bridge"):
                print("briefling-acp-bridge v" + st["bridge"] + "\\n- briefling-acp")
        elif args[:3] == ["tool", "dir", "--bin"]:
            print(os.path.join(D, "bin"))
        elif args[:2] == ["tool", "install"]:
            st["bridge"] = args[-1].rsplit("@v", 1)[1]; save()
    elif tool == "briefling-acp":
        env = args[args.index("--env") + 1]
        if args[0].startswith("https://"):
            open(env, "w").write("BRIEFLING_CLIENT_ID=x\\n")
            print("Joined briefling as agent 'claude' (spaces: home); 1 trusted human(s) may drive it.", flush=True)
        if st.get("bridge_fails"):
            print("ERROR the agent command failed to start", flush=True); sys.exit(1)
        print("INFO connected to the hub", flush=True)
        signal.signal(signal.SIGINT, lambda *a: sys.exit(0))
        time.sleep(60)
    elif tool == "systemctl":
        if "show" in args:
            print("ActiveState=" + st.get("unit", "inactive") + "\\nMainPID=" + ("4242" if st.get("unit") == "active" else "0"))
        elif "enable" in args or "restart" in args:
            st["unit"] = "active"; save()
            if "restart" in args and os.path.exists(st.get("log", "")):
                pass
        elif "disable" in args:
            st["unit"] = "inactive"; save()
''')


@pytest.fixture
def fakes(tmp_path, monkeypatch):
    d = tmp_path / "fakes"
    (d / "bin").mkdir(parents=True)
    for tool in ("sbx", "uv", "systemctl", "launchctl"):
        p = d / "bin" / tool
        p.write_text(FAKE.format(py=sys.executable, d=str(d)))
        p.chmod(p.stat().st_mode | stat.S_IEXEC)
    os.symlink(d / "bin" / "sbx", d / "bin" / "briefling-acp")
    monkeypatch.setenv("PATH", f"{d / 'bin'}:/usr/bin:/bin")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(cli, "CONNECT_TIMEOUT_S", 10)
    # systemd: the fake "service" is started by start(), which does not run the bridge; write its log line like it would
    real_start = service.Systemd.start

    def start(self):
        err = real_start(self)
        conf = json.load(open(os.path.join(str(tmp_path / "home"), ".config/briefling-agent", self.name, "agent.json")))
        with open(conf["log"], "a") as f:
            f.write("INFO briefling_acp.bridge: connected to the hub\n")
        return err

    monkeypatch.setattr(service.Systemd, "start", start)

    class F:
        dir = d

        def calls(self, tool=None):
            p = d / "calls.jsonl"
            out = [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []
            return [c for c in out if tool is None or c[0] == tool]

        def state(self, **kw):
            p = d / "state.json"
            st = json.loads(p.read_text()) if p.exists() else {}
            st.update(kw)
            p.write_text(json.dumps(st))
            return st

    return F()


LINK = "https://briefling.example/agent.md?code=abc"


def test_refuses_without_docker_sandboxes(fakes, capsys):
    os.remove(fakes.dir / "bin" / "sbx")
    assert cli.main(["init", "claude", LINK]) == 1
    err = capsys.readouterr().err
    assert "never runs an agent outside a sandbox" in err and "brew install docker/tap/sbx" in err
    assert fakes.calls("uv") == [] and fakes.calls("briefling-acp") == []  # nothing installed nor joined


def test_says_to_sign_in_when_sbx_does_not_answer(fakes, capsys):
    fakes.state(sbx_down=True)
    assert cli.main(["init", "claude", LINK]) == 1
    assert "sbx login" in capsys.readouterr().err


def test_first_init_needs_the_link(fakes, capsys):
    assert cli.main(["init", "claude"]) == 1
    assert "invitation link" in capsys.readouterr().err


def test_init_does_every_step_once(fakes, capsys, monkeypatch):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True, raising=False)
    assert cli.main(["init", "claude", LINK]) == 0
    out = capsys.readouterr().out
    conf = json.load(open(cli.conf_path("claude")))
    port, ws = conf["port"], conf["workspace"]
    # bridge installed by uv at the pinned tag, so that it updates itself
    assert ["uv", "tool", "install", "--force", "--python", ">=3.11",
            f"git+https://github.com/briefling/acp-bridge@v{cli.BRIDGE_MIN}"] in fakes.calls("uv")
    sbx = fakes.calls("sbx")
    hist = os.path.join(cli.agent_dir("claude"), "claude-history")
    assert ["sbx", "create", "--name", "briefling-claude", "--mount", f"{hist}:/home/agent/claude-history",
            "--kit", "sbx/claude-acp:latest", "--kit", "sbx/claude-sessions:1.0.0", "claude", ws] in sbx
    assert ["sbx", "run", "--name", "briefling-claude"] in sbx  # the /login step
    assert ["sbx", "policy", "allow", "network", "--sandbox", "briefling-claude", f"localhost:{port}"] in sbx
    assert not any(c[1:3] == ["policy", "allow"] and "--sandbox" not in c for c in sbx)  # never a global rule
    # joined with the link, through the sandbox, tools on the port
    bridge = fakes.calls("briefling-acp")
    assert bridge[0][1] == LINK
    assert bridge[0][-6:] == ["--", str(fakes.dir / "bin" / "sbx"), "exec", "-i", "briefling-claude", "claude-agent-acp"]
    assert ["--mcp-port", str(port)] == bridge[0][bridge[0].index("--mcp-port"):][:2]
    assert "host.docker.internal" in bridge[0]
    assert "Joined briefling as agent 'claude'" in out and "connected to the hub" in out
    # the service runs the same command, without the link
    unit = open(os.path.join(os.environ["HOME"], ".config/systemd/user/briefling-agent-claude.service")).read()
    assert LINK not in unit and '"claude-agent-acp"' in unit and "Restart=always" in unit
    assert f'"--mcp-port" "{port}"' in unit
    assert ["systemctl", "--user", "enable", "--now", "briefling-agent-claude.service"] in fakes.calls("systemctl")
    assert os.stat(cli.agent_dir("claude")).st_mode & 0o077 == 0  # credentials folder private

    # a second init does nothing again
    n = len(fakes.calls())
    assert cli.main(["init", "claude"]) == 0
    again = fakes.calls()[n:]
    assert not any(c[1:3] == ["tool", "install"] for c in again)
    assert not any(c[0] == "sbx" and c[1] in ("create", "run") for c in again)
    assert not any(c[0] == "briefling-acp" for c in again)
    assert not any(c[1:3] == ["policy", "allow"] for c in again)
    assert json.load(open(cli.conf_path("claude")))["port"] == port  # the port stays


def test_a_link_given_again_is_not_used_without_force(fakes, capsys):
    fakes.state(logged_in=True)
    assert cli.main(["init", "claude", LINK]) == 0
    assert cli.main(["init", "claude", LINK]) == 0
    assert "Add --force" in capsys.readouterr().out
    assert len(fakes.calls("briefling-acp")) == 1
    assert cli.main(["init", "claude", LINK, "--force"]) == 0
    last = fakes.calls("briefling-acp")[-1]
    assert last[1:3] == [LINK, "--force"]


def test_login_needs_a_terminal(fakes, capsys, monkeypatch):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False, raising=False)
    assert cli.main(["init", "claude", LINK]) == 1
    assert "sbx run --name briefling-claude" in capsys.readouterr().err
    assert fakes.calls("briefling-acp") == []  # no join before the login


def test_bridge_that_does_not_connect_shows_its_log(fakes, capsys):
    fakes.state(logged_in=True, bridge_fails=True)
    assert cli.main(["init", "claude", LINK]) == 1
    err = capsys.readouterr().err
    assert "did not connect (exited)" in err and "failed to start" in err
    assert fakes.calls("systemctl") == [] or not any("enable" in c for c in fakes.calls("systemctl"))


def test_workspace_made_even_when_the_sandbox_exists(fakes):
    fakes.state(logged_in=True, sandboxes=["briefling-claude"])
    assert cli.main(["init", "claude", LINK]) == 0
    assert os.path.isdir(os.path.join(os.environ["HOME"], "briefling-agent", "claude"))
    assert not any(c[:2] == ["sbx", "create"] for c in fakes.calls())


def test_a_recent_bridge_is_kept(fakes):
    fakes.state(logged_in=True, bridge="0.3.50")
    assert cli.main(["init", "claude", LINK]) == 0
    assert not any(c[1:3] == ["tool", "install"] for c in fakes.calls("uv"))


def test_an_old_bridge_is_upgraded(fakes):
    fakes.state(logged_in=True, bridge="0.3.40")
    assert cli.main(["init", "claude", LINK]) == 0
    assert any(c[1:3] == ["tool", "install"] for c in fakes.calls("uv"))


def test_stop_status_start(fakes, capsys):
    fakes.state(logged_in=True)
    assert cli.main(["init", "claude", LINK]) == 0
    assert cli.main(["status"]) == 0
    out = capsys.readouterr().out
    assert "service    active, pid 4242" in out and "briefling-claude" in out and "127.0.0.1:" in out
    assert cli.main(["stop"]) == 0
    assert ["systemctl", "--user", "disable", "--now", "briefling-agent-claude.service"] in fakes.calls("systemctl")
    assert cli.main(["status"]) == 3
    assert cli.main(["start"]) == 0
    assert cli.main(["logs", "-n", "5"]) == 0
    assert "connected to the hub" in capsys.readouterr().out


def test_commands_without_init(fakes, capsys):
    assert cli.main(["status"]) == 1
    assert "init claude" in capsys.readouterr().err


def test_bad_name(fakes, capsys):
    assert cli.main(["init", "claude", LINK, "--name", "Bad Name"]) == 1
    assert cli.main(["init", "claude", LINK, "--port", "80"]) == 1
    assert fakes.calls() == []


def test_skills_dir_is_mounted_read_write(fakes, capsys, monkeypatch, tmp_path):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True, raising=False)
    skills = tmp_path / "agent-skills"
    assert cli.main(["init", "claude", LINK, "--skills-dir", str(skills)]) == 0, capsys.readouterr().err
    ws = json.load(open(cli.conf_path("claude")))["workspace"]
    create = next(c for c in fakes.calls("sbx") if c[1] == "create")
    # sbx's shared store off (read-only, seen by every sandbox), the folder over the agent's skills
    hist = os.path.join(cli.agent_dir("claude"), "claude-history")
    assert create == ["sbx", "create", "--name", "briefling-claude", "--mount", f"{hist}:/home/agent/claude-history",
                      "--skills", "off", "--kit", "sbx/claude-acp:latest",
                      "--kit", "sbx/claude-sessions:1.0.0", "claude", ws, f"{skills}:/home/agent/.claude/skills"]
    assert skills.is_dir() and "(its skills, read and written)" in capsys.readouterr().out
    # kept on a run again; another folder needs a new sandbox (a mount is set at creation)
    assert cli.main(["init", "claude"]) == 0
    assert json.load(open(cli.conf_path("claude")))["skills_dir"] == str(skills)
    assert cli.main(["init", "claude", "--skills-dir", str(tmp_path / "other")]) == 1
    assert "sbx rm briefling-claude" in capsys.readouterr().err
    assert sum(1 for c in fakes.calls("sbx") if c[1] == "create") == 1


def test_each_agent_has_its_own_history(fakes, monkeypatch):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True, raising=False)
    assert cli.main(["init", "claude", LINK]) == 0
    assert cli.main(["init", "claude", LINK, "--name", "other"]) == 0
    mounts = [c[c.index("--mount") + 1] for c in fakes.calls("sbx") if c[1] == "create"]
    hosts = [m.rsplit(":", 1)[0] for m in mounts]
    assert len(set(hosts)) == 2 and all(m.endswith(":/home/agent/claude-history") for m in mounts)
    for h in hosts:
        assert os.path.isdir(h) and os.stat(h).st_mode & 0o077 == 0


def test_an_old_sandbox_is_flagged(fakes, capsys, monkeypatch):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True, raising=False)
    assert cli.main(["init", "claude", LINK]) == 0
    conf = cli.load_conf("claude")
    del conf["history_dir"]  # as made by 0.1.0
    cli.save_conf(conf)
    capsys.readouterr()
    assert cli.main(["init", "claude"]) == 0
    assert "WARNING: made without a history folder of its own" in capsys.readouterr().out


def test_no_skills_dir_keeps_sbx_default(fakes, monkeypatch, tmp_path):
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True, raising=False)
    assert cli.main(["init", "claude", LINK]) == 0
    create = next(c for c in fakes.calls("sbx") if c[1] == "create")
    assert "--skills" not in create
    assert cli.main(["init", "claude", "--skills-dir", str(tmp_path / "s")]) == 1  # sandbox made without it


def test_launchd_start_waits_for_bootout_and_retries(tmp_path, monkeypatch):
    calls, answers = [], {"print": [0, 0, 1], "bootstrap": [5, 0]}

    def fake(argv):
        calls.append(argv[1])
        seq = answers.get(argv[1])
        return (seq.pop(0) if seq else 0), ("Bootstrap failed: 5: Input/output error" if argv[1] == "bootstrap" else "")
    monkeypatch.setattr(service, "_run", fake)
    monkeypatch.setattr(service.time, "sleep", lambda s: None)
    assert service.Launchd("claude", str(tmp_path)).start() is None
    assert calls == ["enable", "bootout", "print", "print", "print", "bootstrap", "bootstrap"]
    answers["bootstrap"] = [5, 5, 5]
    calls.clear()
    assert "Input/output error" in service.Launchd("claude", str(tmp_path)).start()
    assert calls.count("bootstrap") == service.BOOTSTRAP_TRIES


def test_launchd_plist(tmp_path):
    svc = service.Launchd("claude", str(tmp_path))
    argv = ["/x/briefling-acp", "--env", "/e", "--", "/opt/homebrew/bin/sbx", "exec", "-i", "briefling-claude",
            "claude-agent-acp"]
    d = plistlib.loads(svc.render(argv, "/l/bridge.log", "/opt/homebrew/bin:/usr/bin:/bin"))
    assert d["Label"] == "briefling-agent.claude" and d["ProgramArguments"] == argv
    assert d["KeepAlive"] is True and d["RunAtLoad"] is True and d["ThrottleInterval"] == 30
    assert d["StandardOutPath"] == d["StandardErrorPath"] == "/l/bridge.log"
    assert d["EnvironmentVariables"]["PATH"].startswith("/opt/homebrew/bin")
    assert svc.path == str(tmp_path / "Library/LaunchAgents/briefling-agent.claude.plist")


def test_systemd_quotes_arguments(tmp_path):
    unit = service.Systemd("claude", str(tmp_path)).render(['/a b/x', 'say "hi"', '50%'], "/l", "/usr/bin")
    assert 'ExecStart="/a b/x" "say \\"hi\\"" "50%%"' in unit


def test_runs_as_a_module():
    p = subprocess.run([sys.executable, "-m", "briefling_agent", "--version"], capture_output=True, text=True,
                       cwd=os.path.dirname(os.path.dirname(__file__)))
    assert p.returncode == 0 and p.stdout.startswith("briefling-agent ")


def test_bridge_min_is_released():
    """The pinned bridge exists: not newer than the release the hub announces (protocol/bridge-release.ts)."""
    path = os.path.join(os.path.dirname(__file__), "..", "..", "protocol", "bridge-release.ts")
    if not os.path.exists(path):
        pytest.skip("outside the briefling repo")
    import re
    released = re.search(r"version: '([\d.]+)'", open(path).read()).group(1)
    assert cli.vtuple(cli.BRIDGE_MIN) <= cli.vtuple(released)
