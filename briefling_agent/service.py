"""The bridge as a user service: a LaunchAgent on macOS, a systemd user unit on Linux.

Both restart the bridge when it exits (30 s apart at most, so a bridge that cannot start does not spin) and start it
when the user's session opens. Both append its output to one log file, so `logs` reads the same place on both."""

from __future__ import annotations

import os
import plistlib
import subprocess
from typing import List, Optional, Tuple

THROTTLE_S = 30


def label(name: str) -> str:
    return f"briefling-agent.{name}"


def _run(argv: List[str]) -> Tuple[int, str]:
    p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return p.returncode, p.stdout


class Launchd:
    """~/Library/LaunchAgents/<label>.plist, loaded in the user's GUI domain (starts at login)."""

    def __init__(self, name: str, home: str) -> None:
        self.name, self.label = name, label(name)
        self.path = os.path.join(home, "Library", "LaunchAgents", self.label + ".plist")
        self.domain = f"gui/{os.getuid()}"

    def render(self, argv: List[str], log: str, path_env: str) -> bytes:
        return plistlib.dumps({
            "Label": self.label,
            "ProgramArguments": argv,
            "EnvironmentVariables": {"PATH": path_env},
            "RunAtLoad": True,
            "KeepAlive": True,
            "ThrottleInterval": THROTTLE_S,
            "ProcessType": "Background",
            "StandardOutPath": log,
            "StandardErrorPath": log,
        })

    def install(self, argv: List[str], log: str, path_env: str) -> None:
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "wb") as f:
            f.write(self.render(argv, log, path_env))

    def installed(self) -> bool:
        return os.path.exists(self.path)

    def start(self) -> Optional[str]:
        _run(["launchctl", "enable", f"{self.domain}/{self.label}"])
        _run(["launchctl", "bootout", f"{self.domain}/{self.label}"])  # a loaded job must be unloaded to reload
        rc, out = _run(["launchctl", "bootstrap", self.domain, self.path])
        return None if rc == 0 else out.strip() or f"launchctl bootstrap exited {rc}"

    def stop(self) -> Optional[str]:
        # disable: a stopped agent stays stopped at the next login, like `systemctl --user disable --now`
        _run(["launchctl", "disable", f"{self.domain}/{self.label}"])
        rc, out = _run(["launchctl", "bootout", f"{self.domain}/{self.label}"])
        return None if rc == 0 or "No such process" in out or "Could not find" in out else out.strip()

    def state(self) -> Tuple[str, Optional[int]]:
        rc, out = _run(["launchctl", "print", f"{self.domain}/{self.label}"])
        if rc != 0:
            return "stopped", None
        st, pid = "loaded", None
        for line in out.splitlines():
            k, _, v = line.strip().partition(" = ")
            if k == "state":
                st = v.strip()
            elif k == "pid" and v.strip().isdigit():
                pid = int(v.strip())
        return st, pid


class Systemd:
    """~/.config/systemd/user/<unit>, enabled for the user's session (`loginctl enable-linger` for boot)."""

    def __init__(self, name: str, home: str) -> None:
        self.name, self.unit = name, f"briefling-agent-{name}.service"
        self.path = os.path.join(home, ".config", "systemd", "user", self.unit)

    @staticmethod
    def _quote(a: str) -> str:
        return '"' + a.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%") + '"'

    def render(self, argv: List[str], log: str, path_env: str) -> str:
        return "\n".join([
            "[Unit]",
            f"Description=briefling agent {self.name} (ACP bridge + Docker Sandboxes)",
            "",
            "[Service]",
            "ExecStart=" + " ".join(self._quote(a) for a in argv),
            "Environment=" + self._quote("PATH=" + path_env),
            "Restart=always",
            f"RestartSec={THROTTLE_S}",
            f"StandardOutput=append:{log}",
            f"StandardError=append:{log}",
            "",
            "[Install]",
            "WantedBy=default.target",
            "",
        ])

    def install(self, argv: List[str], log: str, path_env: str) -> None:
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w") as f:
            f.write(self.render(argv, log, path_env))
        _run(["systemctl", "--user", "daemon-reload"])

    def installed(self) -> bool:
        return os.path.exists(self.path)

    def start(self) -> Optional[str]:
        rc, out = _run(["systemctl", "--user", "enable", "--now", self.unit])
        if rc == 0:
            rc, out = _run(["systemctl", "--user", "restart", self.unit])  # pick up a rewritten unit
        return None if rc == 0 else out.strip() or f"systemctl exited {rc}"

    def stop(self) -> Optional[str]:
        rc, out = _run(["systemctl", "--user", "disable", "--now", self.unit])
        return None if rc == 0 else out.strip()

    def state(self) -> Tuple[str, Optional[int]]:
        rc, out = _run(["systemctl", "--user", "show", self.unit, "--property=ActiveState,MainPID"])
        if rc != 0:
            return "stopped", None
        vals = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
        pid = int(vals.get("MainPID", "0") or 0) or None
        return vals.get("ActiveState", "unknown"), pid


def for_platform(platform: str, name: str, home: str):
    if platform == "darwin":
        return Launchd(name, home)
    if platform.startswith("linux"):
        return Systemd(name, home)
    return None
