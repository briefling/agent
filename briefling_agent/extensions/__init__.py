"""Extensions: what an agent gets beyond the bridge, e.g. a cloud's credentials, without the tool knowing that cloud.

An extension is a manifest `<name>.json` next to this file plus a module `<name with _>.py` holding its steps. The
manifest says, in plain words, what each step does, why and its risk (printed before the step runs), the arguments it
takes, the service it runs on this machine (a host command, given one port that only the agent's sandbox may reach),
the blocks of lines it writes in the sandbox and the check that proves it works from inside the sandbox. The tool does
the generic part: service, network rule, sandbox files, check, state. Format internal for now (only embedded
extensions): it opens to others once a second extension exists.

    briefling-agent ext list
    briefling-agent ext add <extension> --name <agent> [its options]   (run again: renews what needs it, skips the rest)
    briefling-agent ext revoke <extension> --name <agent>              (cuts the access, e.g. a revoked certificate)
    briefling-agent ext remove <extension> --name <agent>              (deletes what add made)
"""

from __future__ import annotations

import argparse
import importlib
import json
import os
import shutil
import socket
import subprocess
import time
from typing import Dict, List, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
SERVICE_TIMEOUT_S = 20
CHECK_TRIES = 5


def available() -> List[str]:
    return sorted(f[:-5] for f in os.listdir(HERE) if f.endswith(".json") and not f.endswith(".template.json"))


def manifest(name: str) -> Dict[str, object]:
    with open(os.path.join(HERE, name + ".json")) as f:
        return json.load(f)


def module(name: str):
    return importlib.import_module(f"{__name__}.{name.replace('-', '_')}")


def add_parsers(sub) -> None:
    """`ext list|add|revoke|remove`, with one sub-parser per extension so that each takes its own options."""
    e = sub.add_parser("ext", help="extensions: what the agent gets beyond briefling (e.g. AWS access)")
    es = e.add_subparsers(dest="ext_cmd", required=True)
    es.add_parser("list", help="the extensions, and those of an agent").add_argument("--name", default="claude")
    for cmd, h in (("add", "set up an extension for an agent (run again to renew)"),
                   ("revoke", "cut the access an extension gives"), ("remove", "delete what add made")):
        c = es.add_parser(cmd, help=h)
        cs = c.add_subparsers(dest="ext", required=True)
        for name in available():
            m = manifest(name)
            p = cs.add_parser(name, help=str(m["summary"]))
            p.add_argument("--name", default="claude", help="the agent (as given to init)")
            if cmd != "add":
                continue
            for arg in m.get("args", []):  # type: ignore[union-attr]
                # no argparse default: a run again tells « not given » (keep what was saved) from a value
                if arg.get("flag_only"):
                    p.add_argument(arg["flag"], dest=arg["dest"], action="store_const", const=True, help=arg["help"])
                elif arg.get("multiple"):
                    p.add_argument(arg["flag"], dest=arg["dest"], action="append", help=arg["help"])
                else:
                    p.add_argument(arg["flag"], dest=arg["dest"], help=arg["help"])


def resolve_args(cli, m: Dict[str, object], a: argparse.Namespace, state: Dict[str, object]) -> None:
    """A run again keeps what the first run was given: an option left out takes its saved value, the manifest's
    default only on the first run (else a run without --prefix made a second stack and orphaned the first, and one
    without --no-cdk patched the CDK bootstrap). A `fixed` option (it names what was made, e.g. the stack) never
    changes: `ext remove` first."""
    first = not any(arg["dest"] in state for arg in m.get("args", []))  # type: ignore[union-attr]
    for arg in m.get("args", []):  # type: ignore[union-attr]
        dest, given = arg["dest"], getattr(a, arg["dest"], None)
        if given is None:
            v = arg.get("default", [] if arg.get("multiple") else (False if arg.get("flag_only") else None)) \
                if first or dest not in state else state[dest]
        else:
            v = given
            if arg.get("fixed") and not first and dest in state and state[dest] != v:
                raise cli.Fail(f"{arg['flag']} was {state[dest]!r}, it names what was made: `briefling-agent ext "
                               f"remove {a.ext} --name {a.name}` first, then add it with the new value")
        if arg.get("required") and not v:
            raise cli.Fail(f"{a.ext} needs {arg['flag']}: {arg['help']}")
        state[dest] = v


class Ctx:
    """What a step sees: the agent's conf, the extension's state (saved after each step) and helpers."""

    def __init__(self, cli, conf: Dict[str, object], ext: str) -> None:
        self.cli, self.conf, self.ext = cli, conf, ext
        self.name, self.sandbox, self.sbx = str(conf["name"]), str(conf["sandbox"]), str(conf["sbx"])
        self.state: Dict[str, object] = dict((conf.get("extensions") or {}).get(ext) or {})  # type: ignore[union-attr]
        self.dir = os.path.join(cli.agent_dir(self.name), ext)
        os.makedirs(self.dir, mode=0o700, exist_ok=True)
        self.say, self.run, self.Fail = cli.say, cli.run, cli.Fail

    def vars(self) -> Dict[str, object]:
        return {"name": self.name, "sandbox": self.sandbox, **self.state}

    def fmt(self, s: str) -> str:
        return s.format(**self.vars())

    def save(self) -> None:
        exts = dict(self.conf.get("extensions") or {})  # type: ignore[arg-type]
        exts[self.ext] = self.state
        self.conf["extensions"] = exts
        self.cli.save_conf(self.conf)

    def forget(self) -> None:
        exts = dict(self.conf.get("extensions") or {})  # type: ignore[arg-type]
        exts.pop(self.ext, None)
        self.conf["extensions"] = exts
        self.cli.save_conf(self.conf)

    def in_sandbox(self, argv: List[str], root: bool = False, stdin: Optional[str] = None,
                   check: bool = True) -> subprocess.CompletedProcess:
        cmd = [self.sbx, "exec"] + (["-i"] if stdin is not None else []) + (["-u", "root"] if root else [])
        return self.run(cmd + [self.sandbox, *argv], check=check, input=stdin)


def service_name(agent: str, ext: str) -> str:
    return f"{agent}.{ext}"


def describe(cli, what: str, why: str, risk: Optional[str] = None) -> None:
    cli.step(what, why + (f"\n  Risk: {risk}" if risk else ""))


BLOCK_SH = ('f="{path}"; mkdir -p "$(dirname "$f")"; touch "$f"; t="$(mktemp)"; '
            'awk -v b="{begin}" -v e="{end}" \'$0==b{{s=1;next}} $0==e{{s=0;next}} !s\' "$f" > "$t"; '
            'cat >> "$t"; cat "$t" > "$f"; rm -f "$t"')


def write_block(ctx: Ctx, block: Dict[str, object], lines: Optional[List[str]]) -> None:
    """Writes (or, with lines=None, removes) the extension's marked block in a sandbox file; the rest is kept."""
    begin, end = f"# >>> briefling-agent {ctx.ext}", f"# <<< briefling-agent {ctx.ext}"
    body = "" if lines is None else "\n".join([begin, *lines, end]) + "\n"
    script = BLOCK_SH.format(path=block["path"], begin=begin, end=end)
    ctx.in_sandbox(["sh", "-c", script], root=block.get("user") == "root", stdin=body)


def wait_port(port: int, until: float) -> bool:
    while time.monotonic() < until:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except OSError:
            time.sleep(0.5)
    return False


def cmd_list(cli, a: argparse.Namespace) -> int:
    try:
        have = cli.load_conf(a.name).get("extensions") or {}
    except cli.Fail:
        have = {}
    for name in available():
        st = have.get(name)
        mark = "" if st is None else (" [revoked]" if st.get("revoked") else " [added]")
        cli.say(f"{name}{mark}\n  {manifest(name)['summary']}")
    return 0


def cmd_add(cli, a: argparse.Namespace) -> int:
    m, mod = manifest(a.ext), module(a.ext)
    conf = cli.load_conf(a.name)
    for tool, how in (m.get("requires") or {}).items():  # type: ignore[union-attr]
        if not shutil.which(tool):
            raise cli.Fail(f"{a.ext} needs {tool} on this machine: {how}")
    ctx = Ctx(cli, conf, a.ext)
    if ctx.state.get("revoked"):
        raise cli.Fail(f"{a.ext} was revoked for {ctx.name}: `briefling-agent ext remove {a.ext} --name {ctx.name}` "
                       "first, then add it again (a new certificate)")
    resolve_args(cli, m, a, ctx.state)
    ctx.state["port"] = int(ctx.state.get("port") or cli.free_port())  # type: ignore[arg-type]
    ctx.save()
    sbx = cli.find_sbx()
    if ctx.sandbox not in cli.sandboxes(sbx):
        raise cli.Fail(f"no sandbox {ctx.sandbox}: run `briefling-agent init` for {ctx.name} first")

    for st in m["steps"]:  # type: ignore[union-attr]
        describe(cli, ctx.fmt(st["what"]), ctx.fmt(st["why"]), ctx.fmt(st["risk"]))
        getattr(mod, st["id"].replace("-", "_"))(ctx)
        ctx.save()

    s = m["service"]  # type: ignore[index]
    describe(cli, ctx.fmt(s["what"]), ctx.fmt(s["why"]), ctx.fmt(s["risk"]))
    svc = cli.the_service(service_name(ctx.name, a.ext))
    log = os.path.join(ctx.dir, "service.log")
    port = int(ctx.state["port"])  # type: ignore[arg-type]
    svc.install([ctx.fmt(x) for x in s["argv"]], log, str(conf["path"]))
    offset = cli.log_size(log)
    err = svc.start()
    if err:
        raise cli.Fail(f"the service did not start: {err}")
    if not wait_port(port, time.monotonic() + SERVICE_TIMEOUT_S):
        raise cli.Fail(f"nothing answers on 127.0.0.1:{port}. Its log:\n{cli.log_tail(log, offset)}")
    cli.say(f"  running on 127.0.0.1:{port}.")

    describe(cli, f"Network: port {port} for this sandbox only", "The sandbox may reach this one more port of this "
             "machine, no other.")
    cli.allow_port(sbx, ctx.sandbox, int(port))

    vm = m.get("vm") or {}
    if vm:
        describe(cli, ctx.fmt(vm["what"]), ctx.fmt(vm["why"]))  # type: ignore[index]
        need = vm.get("needs")  # type: ignore[union-attr]
        if need and ctx.in_sandbox(need["argv"], check=False).returncode != 0:
            cli.say(f"  installing {need['what']}...")
            ctx.in_sandbox(need["install"])
        for block in vm.get("blocks", []):  # type: ignore[union-attr]
            write_block(ctx, block, [ctx.fmt(x) for x in block["lines"]])
            cli.say(f"  {block['path']}: written.")

    chk = m.get("check")
    if chk:
        describe(cli, "Check from inside the sandbox", " ".join(chk["argv"][-1:]))  # type: ignore[index]
        want, got = ctx.fmt(chk["expect"]), ""  # type: ignore[index]
        for i in range(CHECK_TRIES):
            p = ctx.in_sandbox(chk["argv"], check=False)  # type: ignore[index]
            got = p.stdout.strip()
            if p.returncode == 0 and want in got:
                break
            time.sleep(2 * (i + 1))
        else:
            raise cli.Fail(f"the check failed in the sandbox (wanted {want!r}):\n{got[-1200:]}\n"
                           f"Service log:\n{cli.log_tail(log, offset)}")
        cli.say(f"  {got.splitlines()[-1]}")
    cli.say(f"\n{a.ext} ready for {ctx.name}.")
    return 0


def cmd_revoke(cli, a: argparse.Namespace) -> int:
    conf = cli.load_conf(a.name)
    ctx = Ctx(cli, conf, a.ext)
    if not ctx.state:
        raise cli.Fail(f"{a.ext} is not added for {ctx.name}")
    module(a.ext).revoke(ctx)
    ctx.state["revoked"] = True
    ctx.save()
    err = cli.the_service(service_name(ctx.name, a.ext)).stop()
    cli.say("  service stopped." if not err else f"  service: {err}")
    return 0


def cmd_remove(cli, a: argparse.Namespace) -> int:
    conf = cli.load_conf(a.name)
    ctx = Ctx(cli, conf, a.ext)
    if not ctx.state:
        raise cli.Fail(f"{a.ext} is not added for {ctx.name}")
    m = manifest(a.ext)
    svc = cli.the_service(service_name(ctx.name, a.ext))
    svc.uninstall()
    cli.say("  service removed.")
    module(a.ext).remove(ctx)
    if shutil.which(ctx.sbx) or os.path.exists(ctx.sbx):
        if ctx.sandbox in cli.sandboxes(ctx.sbx):
            for block in (m.get("vm") or {}).get("blocks", []):  # type: ignore[union-attr]
                write_block(ctx, block, None)
            cli.say("  sandbox files cleaned.")
            if ctx.state.get("port"):
                cli.unallow_port(ctx.sbx, ctx.sandbox, int(ctx.state["port"]))  # type: ignore[arg-type]
    ctx.forget()
    shutil.rmtree(ctx.dir, ignore_errors=True)
    cli.say(f"{a.ext} removed for {ctx.name}.")
    return 0


def main(cli, a: argparse.Namespace) -> int:
    return {"list": cmd_list, "add": cmd_add, "revoke": cmd_revoke, "remove": cmd_remove}[a.ext_cmd](cli, a)


def status_lines(cli, conf: Dict[str, object]) -> List[str]:
    out = []
    for ext, st in (conf.get("extensions") or {}).items():  # type: ignore[union-attr]
        state, pid = cli.the_service(service_name(str(conf["name"]), ext)).state()
        flag = " (revoked)" if st.get("revoked") else ""
        out.append(f"ext        {ext}{flag}: service {state}" + (f", pid {pid}" if pid else "") +
                   (f", 127.0.0.1:{st['port']}" if st.get("port") else ""))
    return out
