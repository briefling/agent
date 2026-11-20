"""CLI of briefling-agent.

    briefling-agent init claude "<invitation link>"   sandbox, login, bridge, service: everything, once
    briefling-agent start | stop | status | logs [-f]  the service afterwards
    briefling-agent ext list | add | revoke | remove   extensions (e.g. AWS access), see extensions/__init__.py

Each step of `init` says what it does before doing it, and is skipped when already done, so `init` can be run again
(after a failed step, or with --force to join again). Nothing runs without a sandbox: without Docker Sandboxes (`sbx`)
the tool stops and says how to install it.

Files, per agent (`--name`, default `claude`): ~/.config/briefling-agent/<name>/ holds agent.json (what init chose),
bridge.env (the bridge's credentials, written by the bridge itself, mode 600) and bridge.log.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
from typing import Dict, List, Optional

from . import __version__, extensions, service


# ---- network rules of a sandbox ----

def sandbox_exists(conf: Dict[str, object]) -> bool:
    sbx = str(conf.get("sbx") or "")
    return bool(sbx) and os.path.exists(sbx) and str(conf.get("sandbox")) in sandboxes(sbx)


def port_allowed(sbx: str, sandbox: str, port: int) -> bool:
    """`sbx policy ls` (0.54) prints one summary line per policy (« allow 198 hosts… »): the resources, hence
    `localhost:<port>`, only show with --wide. Matched as a whole resource (50861 is not 508610)."""
    out = run([sbx, "policy", "ls", "--wide", sandbox], check=False).stdout
    return re.search(r"(?<![\w.-])localhost:%d(?![\w.-])" % port, out) is not None


def allow_port(sbx: str, sandbox: str, port: int) -> None:
    rule = f"localhost:{port}"
    if port_allowed(sbx, sandbox, port):
        say("  already allowed.")
    else:
        run([sbx, "policy", "allow", "network", "--sandbox", sandbox, rule])
        say(f"  allowed {rule} for {sandbox}.")


def unallow_port(sbx: str, sandbox: str, port: int) -> None:
    """--force: sbx asks for a confirmation, and refuses outside a terminal without it. --sandbox, not positional
    (sbx 0.54: « the sandbox name is no longer positional »)."""
    rule = f"localhost:{port}"
    if not port_allowed(sbx, sandbox, port):
        return
    p = run([sbx, "policy", "rm", "network", "--sandbox", sandbox, "--resource", rule, "--force"], check=False)
    if port_allowed(sbx, sandbox, port):
        say(f"  the network rule {rule} is still there ({p.stdout.strip()[-300:]}): `sbx policy ls --wide "
            f"{sandbox}`, then `sbx policy rm network --sandbox {sandbox} --resource {rule} --force`.")
    else:
        say(f"  network rule {rule} removed.")

BRIDGE_REPO = "https://github.com/briefling/acp-bridge"
BRIDGE_DIST = "briefling-acp-bridge"
# Oldest bridge that serves its tools over HTTP (--mcp-port, 0.3.41) and updates itself (0.3.42). Installed at this
# tag; the bridge then installs the releases the hub announces by itself.
BRIDGE_MIN = "0.3.42"
MCP_HOST = "host.docker.internal"  # what the agent in the microVM dials; the sbx proxy sends it to the host's localhost
CONNECT_TIMEOUT_S = 120
NAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?$")

# One entry per agent kind. v1: Claude Code only (kit sbx/claude-acp, the ACP adapter over the claude workload).
AGENTS: Dict[str, Dict[str, object]] = {
    "claude": {
        "workload": "claude",
        "kits": ["sbx/claude-acp:latest", "sbx/claude-sessions:1.0.0"],
        "acp": ["claude-agent-acp"],
        "skills": "/home/agent/.claude/skills",
        # sbx/claude-sessions' host-mount@1 path. Its host folder, chosen by sbx, is ONE per kit: every sandbox of
        # the machine mounts it whole (a subfolder per sandbox is the hook's convention, not a boundary), so two
        # agents read each other's conversations and memory (seen on a real Mac). Each agent gets its own folder.
        "history": "/home/agent/claude-history",  # where --skills-dir is mounted (the agent writes its skills there)
        # /login stores the subscription's tokens on the host; the VM gets placeholders in this file.
        "logged_in": 'test -s "$HOME/.claude/.credentials.json"',
        "login_help": "Claude Code opens: type /login, finish the login in your browser, then type /exit.",
    },
}

INSTALL_SBX = """Docker Sandboxes (sbx) is not installed: briefling-agent never runs an agent outside a sandbox.
Install it, sign in, then run this command again:
  macOS (Sonoma 14+):  brew trust docker/tap && brew install docker/tap/sbx
  Ubuntu:              curl -fsSL https://get.docker.com | sudo REPO_ONLY=1 sh && sudo apt install docker-sbx
  then:                sbx login
Docs: https://docs.docker.com/ai/sandboxes/install/"""


class Fail(Exception):
    pass


def say(msg: str) -> None:
    print(msg, flush=True)


def step(what: str, why: str) -> None:
    say(f"\n» {what}\n  {why}")


def run(argv: List[str], check: bool = True, **kw) -> subprocess.CompletedProcess:
    p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, **kw)
    if check and p.returncode != 0:
        raise Fail(f"`{' '.join(argv)}` failed ({p.returncode}):\n{p.stdout.strip()[-1500:]}")
    return p


def vtuple(v: str):
    m = re.match(r"^v?(\d+)\.(\d+)\.(\d+)", v.strip())
    return tuple(int(x) for x in m.groups()) if m else None


def home() -> str:
    return os.path.expanduser("~")


def agent_dir(name: str) -> str:
    return os.path.join(home(), ".config", "briefling-agent", name)


def conf_path(name: str) -> str:
    return os.path.join(agent_dir(name), "agent.json")


def load_conf(name: str) -> Dict[str, object]:
    try:
        with open(conf_path(name)) as f:
            return json.load(f)
    except FileNotFoundError:
        raise Fail(f"no agent {name!r} here: run `briefling-agent init claude \"<invitation link>\"` first") from None


def save_conf(conf: Dict[str, object]) -> None:
    os.makedirs(agent_dir(str(conf["name"])), mode=0o700, exist_ok=True)
    tmp = conf_path(str(conf["name"])) + ".tmp"
    with open(tmp, "w") as f:
        json.dump(conf, f, indent=2)
    os.replace(tmp, conf_path(str(conf["name"])))


def the_service(name: str):
    svc = service.for_platform(sys.platform, name, home())
    if svc is None:
        raise Fail(f"unsupported system {sys.platform!r}: briefling-agent runs on macOS (launchd) and Linux (systemd)")
    return svc


# ---- Docker Sandboxes ----

def find_sbx() -> str:
    path = shutil.which("sbx")
    if not path:
        raise Fail(INSTALL_SBX)
    p = run([path, "ls", "-q"], check=False)
    if p.returncode != 0:
        raise Fail(f"sbx is installed but does not answer (`sbx ls`):\n{p.stdout.strip()[-800:]}\n"
                   "Sign in with `sbx login`, then run this command again.")
    return path


def sandboxes(sbx: str) -> List[str]:
    return [line.strip() for line in run([sbx, "ls", "-q"]).stdout.splitlines() if line.strip()]


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ---- the bridge (installed by uv or pipx, so that it can update itself) ----

def python_311() -> Optional[str]:
    for cand in ("python3.13", "python3.12", "python3.11", "python3"):
        path = shutil.which(cand)
        if path:
            p = run([path, "-c", "import sys; print(sys.version_info >= (3, 11))"], check=False)
            if p.stdout.strip() == "True":
                return path
    return None


def installed_bridge() -> Optional[Dict[str, str]]:
    """The bridge installed by `uv tool` or `pipx`: {installer, version, bin}, or None."""
    if shutil.which("uv"):
        p = run(["uv", "tool", "list"], check=False)
        m = re.search(rf"^{BRIDGE_DIST} v?(\S+)", p.stdout, re.M)
        if p.returncode == 0 and m:
            return {"installer": "uv", "version": m.group(1),
                    "bin": os.path.join(run(["uv", "tool", "dir", "--bin"]).stdout.strip(), "briefling-acp")}
    if shutil.which("pipx"):
        p = run(["pipx", "list", "--short"], check=False)
        m = re.search(rf"^{BRIDGE_DIST} (\S+)", p.stdout, re.M)
        if p.returncode == 0 and m:
            bindir = run(["pipx", "environment", "--value", "PIPX_BIN_DIR"]).stdout.strip()
            return {"installer": "pipx", "version": m.group(1), "bin": os.path.join(bindir, "briefling-acp")}
    return None


def ensure_bridge() -> str:
    have = installed_bridge()
    if have and (vtuple(have["version"]) or (0,)) >= vtuple(BRIDGE_MIN) and os.path.exists(have["bin"]):
        say(f"  ACP bridge {have['version']} already installed ({have['installer']}).")
        return have["bin"]
    spec = f"git+{BRIDGE_REPO}@v{BRIDGE_MIN}"
    if shutil.which("uv"):
        # uv fetches a Python 3.11+ itself when the system one is older (macOS ships 3.9)
        run(["uv", "tool", "install", "--force", "--python", ">=3.11", spec])
    elif shutil.which("pipx"):
        py = python_311()
        if not py:
            raise Fail("the ACP bridge needs Python 3.11 or newer, and none was found. Install uv "
                       "(https://docs.astral.sh/uv/, `brew install uv`), which brings its own Python, then retry.")
        run(["pipx", "install", "--force", "--python", py, spec])
    else:
        raise Fail("installing the ACP bridge needs uv or pipx, so that it can update itself later. Install uv "
                   "(https://docs.astral.sh/uv/, `brew install uv`) or pipx (`brew install pipx`), then retry.")
    have = installed_bridge()
    if not have or not os.path.exists(have["bin"]):
        raise Fail("the ACP bridge was installed but its command is not where uv/pipx says")
    say(f"  ACP bridge {have['version']} installed ({have['installer']}).")
    return have["bin"]


def bridge_argv(conf: Dict[str, object], link: Optional[str] = None, force: bool = False) -> List[str]:
    agent = AGENTS[str(conf["agent"])]
    argv = [str(conf["bridge"])] + ([link] if link else []) + (["--force"] if force else [])
    argv += ["--env", str(conf["env"]), "--cwd", str(conf["workspace"]),
             "--mcp-port", str(conf["port"]), "--mcp-host", MCP_HOST,
             "--", str(conf["sbx"]), "exec", "-i", str(conf["sandbox"]), *agent["acp"]]  # type: ignore[misc]
    return argv


def wait_log(log: str, offset: int, until: float, proc: Optional[subprocess.Popen] = None) -> str:
    """Waits for the bridge's « connected to the hub » in its log after `offset`: 'connected', 'exited' or 'timeout'."""
    while time.monotonic() < until:
        try:
            with open(log, errors="replace") as f:
                f.seek(offset)
                if "connected to the hub" in f.read():
                    return "connected"
        except FileNotFoundError:
            pass
        if proc is not None and proc.poll() is not None:
            return "exited"
        time.sleep(0.5)
    return "timeout"


def log_tail(log: str, offset: int = 0, n: int = 15) -> str:
    try:
        with open(log, errors="replace") as f:
            f.seek(offset)
            return "\n".join(f.read().splitlines()[-n:])
    except FileNotFoundError:
        return "(no log)"


def log_size(log: str) -> int:
    try:
        return os.path.getsize(log)
    except FileNotFoundError:
        return 0


def stop_group(proc: subprocess.Popen) -> None:
    for sig, wait in ((signal.SIGINT, 15), (signal.SIGKILL, 5)):
        if proc.poll() is not None:
            return
        try:
            os.killpg(proc.pid, sig)
        except ProcessLookupError:
            return
        try:
            proc.wait(wait)
        except subprocess.TimeoutExpired:
            pass


# ---- commands ----

def cmd_init(a: argparse.Namespace) -> int:
    name = a.name or a.agent
    if not NAME_RE.match(name):
        raise Fail(f"bad name {name!r}: lower-case letters, digits and hyphens, 40 characters at most")
    if a.port is not None and not 1024 <= a.port <= 65535:
        raise Fail(f"bad port {a.port}: 1024 to 65535")
    svc = the_service(name)
    try:
        conf = load_conf(name)
    except Fail:
        conf = {}
    if conf and conf.get("agent") != a.agent:
        raise Fail(f"agent {name!r} already exists as {conf.get('agent')!r}: pick another --name")
    agent = AGENTS[a.agent]
    adir = agent_dir(name)
    os.makedirs(adir, mode=0o700, exist_ok=True)
    env = os.path.join(adir, "bridge.env")
    if not os.path.exists(env) and not a.link:
        raise Fail('the first init needs the invitation link: briefling-agent init claude "<invitation link>"')

    step("Docker Sandboxes", "The agent only ever runs inside a microVM: no sandbox, no agent.")
    sbx = find_sbx()
    say(f"  sbx found: {sbx}")

    step("ACP bridge", "It connects the agent to briefling. Installed by uv or pipx so that it updates itself.")
    bridge = ensure_bridge()

    workspace = os.path.abspath(os.path.expanduser(a.workspace or str(conf.get("workspace") or
                                                   os.path.join(home(), "briefling-agent", name))))
    skills = os.path.abspath(os.path.expanduser(a.skills_dir)) if a.skills_dir else conf.get("skills_dir")
    if a.skills_dir and skills != conf.get("skills_dir") and sandbox_exists(conf):
        raise Fail(f"the sandbox mounts {conf.get('skills_dir') or 'sbx shared store'} as its skills: a mount is "
                   "set at creation, so "
                   f"`sbx rm {conf['sandbox']}` first (its sessions and login stay on this machine), then init again")
    conf = {**conf, "name": name, "skills_dir": skills, "agent": a.agent, "sandbox": str(conf.get("sandbox") or f"briefling-{name}"),
            "workspace": workspace, "port": int(a.port or conf.get("port") or free_port()), "sbx": sbx,
            "bridge": bridge, "env": env, "log": os.path.join(adir, "bridge.log"),
            "path": os.environ.get("PATH", "/usr/bin:/bin")}
    save_conf(conf)
    sandbox = str(conf["sandbox"])

    step(f"Sandbox {sandbox}", f"A microVM for the agent. It sees {workspace} (its working folder)"
         + (f" and {skills} (its skills, read and written)" if skills else "") + " and nothing else of this machine; "
         "its network goes through Docker's filtering proxy.")
    os.makedirs(workspace, exist_ok=True)  # also when the sandbox exists: the bridge starts its sessions there
    if sandbox in sandboxes(sbx):
        say("  already there.")
        if not conf.get("history_dir"):
            say(f"  WARNING: made without a history folder of its own, it mounts sbx's history folder shared by every "
                f"sandbox (the other agents' conversations). Move its sessions out (`sbx inspect {sandbox}` shows the "
                f"folder), `sbx rm {sandbox}`, then init again: it gets a folder of its own.")
    else:
        kits = [x for k in agent["kits"] for x in ("--kit", k)]  # type: ignore[union-attr]
        history = os.path.join(adir, "claude-history")
        os.makedirs(history, mode=0o700, exist_ok=True)
        mounts = ["--mount", f"{history}:{agent['history']}"]
        conf["history_dir"] = history
        save_conf(conf)
        if skills:
            # --skills off: no shared read-only store over the folder (sbx's default), which would refuse the
            # agent's writes and show its skills to every sandbox
            os.makedirs(str(skills), mode=0o700, exist_ok=True)
            mounts += ["--skills", "off"]
        run([sbx, "create", "--name", sandbox, *mounts, *kits, str(agent["workload"]), workspace]
            + ([f"{skills}:{agent['skills']}"] if skills else []))
        say("  created.")

    step("Agent login", "Once. The real tokens stay on this machine; the sandbox only gets placeholders.")
    if run([sbx, "exec", sandbox, "sh", "-c", str(agent["logged_in"])], check=False).returncode == 0:
        say("  already logged in.")
    else:
        if not (sys.stdin.isatty() and sys.stdout.isatty()):
            raise Fail(f"the agent is not logged in and this is not a terminal: run `sbx run --name {sandbox}` "
                       "in a terminal and log in, then run init again")
        say(f"  {agent['login_help']}")
        subprocess.run([sbx, "run", "--name", sandbox])
        if run([sbx, "exec", sandbox, "sh", "-c", str(agent["logged_in"])], check=False).returncode != 0:
            raise Fail("still not logged in: run init again and complete the login")
        say("  logged in.")

    port = int(conf["port"])  # type: ignore[arg-type]
    step(f"Network: port {port} for this sandbox only",
         f"The bridge serves briefling's tools on 127.0.0.1:{port} (a token per conversation). The sandbox may reach "
         "that one port of this machine, no other.")
    allow_port(sbx, sandbox, port)

    log = str(conf["log"])
    if a.link and (a.force or not os.path.exists(env)):
        step("Join briefling", "Redeems the invitation (once) and checks a first connection to the hub.")
        svc.stop()  # a running bridge of this agent would answer too
        offset = log_size(log)
        with open(log, "a") as out:
            proc = subprocess.Popen(bridge_argv(conf, a.link, a.force), stdin=subprocess.DEVNULL, stdout=out,
                                    stderr=subprocess.STDOUT, start_new_session=True)
        try:
            got = wait_log(log, offset, time.monotonic() + CONNECT_TIMEOUT_S, proc)
        finally:
            stop_group(proc)
        if got != "connected":
            raise Fail(f"the bridge did not connect ({got}). Its log:\n{log_tail(log, offset)}")
        joined = re.search(r"Joined briefling as agent .*", log_tail(log, offset, 200))
        say(f"  {joined.group(0) if joined else 'joined.'}")
    elif a.link:
        say(f"\n  Already joined ({env}): the link is not used. Add --force to join again with it.")

    step("Service", "Starts the bridge now and at each login, and restarts it if it stops.")
    return start(conf, svc)


def start(conf: Dict[str, object], svc) -> int:
    log = str(conf["log"])
    if log_size(log) > 10 * 1024 * 1024:  # simple rotation, one old file kept
        os.replace(log, log + ".1")
    svc.install(bridge_argv(conf), log, str(conf["path"]))
    offset = log_size(log)
    err = svc.start()
    if err:
        raise Fail(f"the service did not start: {err}")
    got = wait_log(log, offset, time.monotonic() + CONNECT_TIMEOUT_S)
    if got != "connected":
        raise Fail(f"the service started but the bridge is not connected yet ({got}). Its log:\n{log_tail(log, offset)}")
    say(f"  running, connected to the hub. Logs: briefling-agent logs{name_flag(conf)}")
    if sys.platform.startswith("linux"):
        say(f"  To start it at boot without a login: loginctl enable-linger {os.environ.get('USER', '$USER')}")
    return 0


def name_flag(conf: Dict[str, object]) -> str:
    return "" if conf["name"] == "claude" else f" --name {conf['name']}"


def cmd_start(a: argparse.Namespace) -> int:
    conf = load_conf(a.name)
    return start(conf, the_service(str(conf["name"])))


def cmd_stop(a: argparse.Namespace) -> int:
    conf = load_conf(a.name)
    err = the_service(str(conf["name"])).stop()
    if err:
        raise Fail(f"stop failed: {err}")
    say(f"stopped (the sandbox {conf['sandbox']} stays; `sbx stop {conf['sandbox']}` stops the microVM too).")
    return 0


def cmd_status(a: argparse.Namespace) -> int:
    conf = load_conf(a.name)
    state, pid = the_service(str(conf["name"])).state()
    have = installed_bridge()
    sbx = shutil.which("sbx") or str(conf["sbx"])
    there = conf["sandbox"] in sandboxes(sbx) if os.path.exists(sbx) else False
    say(f"agent      {conf['name']} ({conf['agent']})")
    say(f"service    {state}" + (f", pid {pid}" if pid else ""))
    say(f"sandbox    {conf['sandbox']}" + ("" if there else " (missing: run init again)"))
    say(f"workspace  {conf['workspace']}")
    say(f"bridge     {have['version'] + ' (' + have['installer'] + ')' if have else 'not found'}, tools on "
        f"127.0.0.1:{conf['port']}")
    lines = [ln for ln in log_tail(str(conf["log"]), 0, 400).splitlines()
             if "connected to the hub" in ln or " ERROR " in ln or " WARNING " in ln]
    if lines:
        say(f"last       {lines[-1]}")
    for line in extensions.status_lines(sys.modules[__name__], conf):
        say(line)
    return 0 if state in ("running", "active") else 3


def cmd_logs(a: argparse.Namespace) -> int:
    log = str(load_conf(a.name)["log"])
    if not os.path.exists(log):
        raise Fail(f"no log yet ({log})")
    if a.follow:
        try:
            return subprocess.run(["tail", "-n", str(a.lines), "-f", log]).returncode
        except KeyboardInterrupt:
            return 0
    say(log_tail(log, 0, a.lines))
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="briefling-agent", description="A coding agent in a Docker Sandboxes microVM, "
                                "connected to briefling.")
    p.add_argument("--version", action="version", version=f"briefling-agent {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)
    i = sub.add_parser("init", help="set up the sandbox, the login, the bridge and the service (once)")
    i.add_argument("agent", choices=sorted(AGENTS), help="the agent to run in the sandbox")
    i.add_argument("link", nargs="?", help="the invitation link from the space settings (first time)")
    i.add_argument("--name", help="this agent's local name (default: the agent, e.g. claude)")
    i.add_argument("--workspace", help="the folder the agent works in (default ~/briefling-agent/<name>)")
    i.add_argument("--port", type=int, help="local port of briefling's tools (default: a free one)")
    i.add_argument("--force", action="store_true", help="join again with a new link")
    i.add_argument("--skills-dir", help="a folder of this machine for the agent's own skills, mounted read-write "
                   "(default: sbx's shared store, read-only); set when the sandbox is created")
    for c, h in (("start", "start the service"), ("stop", "stop the service (and keep it stopped at login)"),
                 ("status", "show the service, sandbox and bridge"), ("logs", "show the bridge's log")):
        s = sub.add_parser(c, help=h)
        s.add_argument("--name", default="claude")
        if c == "logs":
            s.add_argument("-f", "--follow", action="store_true")
            s.add_argument("-n", "--lines", type=int, default=40)
    extensions.add_parsers(sub)
    a = p.parse_args(argv)
    try:
        if a.cmd == "ext":
            return extensions.main(sys.modules[__name__], a)
        return {"init": cmd_init, "start": cmd_start, "stop": cmd_stop, "status": cmd_status,
                "logs": cmd_logs}[a.cmd](a)
    except Fail as e:
        print(f"briefling-agent: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
