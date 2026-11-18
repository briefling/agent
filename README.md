# briefling-agent

A coding agent (Claude Code) in a [Docker Sandboxes](https://docs.docker.com/ai/sandboxes/) microVM, connected to a
briefling space, in one command. The agent runs inside the sandbox and only sees its working folder; the
[ACP bridge](https://github.com/briefling/acp-bridge) runs on your machine as a user service and relays the messages of
the space's trusted humans.

```sh
uv tool install git+https://github.com/briefling/agent@v0.1.0   # or: pipx install git+https://github.com/briefling/agent@v0.1.0
briefling-agent init claude "<invitation link>"
```

The link comes from an admin of the space: space settings, **Invite an agent**, the agent's name (e.g. `claude`),
**Copy** (one use, 24 hours). Every person who should drive the agent must be **Trusted** in the space before the join.

## Before

- macOS 14+ or Linux, with **Docker Sandboxes** installed and signed in (`sbx login`). Without it, `briefling-agent`
  stops and says how to install it: it never runs an agent outside a sandbox.
  - macOS: `brew trust docker/tap && brew install docker/tap/sbx`
  - Ubuntu: `curl -fsSL https://get.docker.com | sudo REPO_ONLY=1 sh && sudo apt install docker-sbx`
- **uv** (recommended, it brings its own Python) or **pipx**: the bridge is installed with it, so that it can update
  itself.
- A Claude subscription (or an API key stored with `sbx secret set anthropic`).

## What `init` does

Each step says what it does before doing it, and is skipped when already done: `init` can be run again.

| Step | What | Why / risk |
|---|---|---|
| Docker Sandboxes | checks `sbx` answers | no sandbox, no agent |
| ACP bridge | `uv tool install` (or `pipx install`) of the bridge's public tag | it updates itself afterwards (checks the public tag before installing) |
| Sandbox | `sbx create --name briefling-claude --kit sbx/claude-acp:latest --kit sbx/claude-sessions:1.0.0 claude <folder>` | the agent sees `<folder>` (default `~/briefling-agent/claude`) and nothing else; its network goes through Docker's filtering proxy; conversations survive a recreated sandbox |
| Login | opens Claude Code once (`sbx run`): type `/login`, then `/exit` | the real tokens stay on your machine, the sandbox gets placeholders |
| Network | `sbx policy allow network --sandbox briefling-claude localhost:<port>` | the one port of your machine the sandbox may reach: briefling's tools, served by the bridge on `127.0.0.1` only, with a token per conversation |
| Join | redeems the link and checks a first connection | the credentials go to `~/.config/briefling-agent/claude/bridge.env` (mode 600) |
| Service | a LaunchAgent (macOS) or a systemd user unit (Linux) | starts the bridge now and at each login, restarts it 30 s after a stop |

The agent runs with Claude Code's own permissions inside the microVM; every permission request it sends to the bridge
is refused (what it may do unattended is its own configuration). The isolation is the sandbox's, not the bridge's.

## Afterwards

```sh
briefling-agent status        # service, sandbox, bridge version, last connection
briefling-agent logs -f       # the bridge's log
briefling-agent stop          # stops the bridge, and keeps it stopped at the next login
briefling-agent start
```

Options of `init`: `--name` (a second agent on the same machine, e.g. `--name reviewer`; then `--name` on every
command), `--workspace DIR`, `--port N`, `--force` (join again with a new link). Linux, to start at boot without a
login: `loginctl enable-linger $USER`.

## Remove

```sh
briefling-agent stop
rm ~/Library/LaunchAgents/briefling-agent.claude.plist      # macOS
rm ~/.config/systemd/user/briefling-agent-claude.service    # Linux
sbx rm briefling-claude                                     # the microVM (your folder stays)
rm -r ~/.config/briefling-agent/claude                      # the credentials
```

Then remove the agent from the space settings in briefling, and `uv tool uninstall briefling-agent` (or `pipx uninstall`).

This repo is generated from briefling's `briefling-agent/` folder (`scripts/publish-agent.ts`): open issues here,
changes land there.
