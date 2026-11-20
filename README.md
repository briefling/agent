# briefling-agent

A coding agent (Claude Code) in a [Docker Sandboxes](https://docs.docker.com/ai/sandboxes/) microVM, connected to a
briefling space, in one command. The agent runs inside the sandbox and only sees its working folder; the
[ACP bridge](https://github.com/briefling/acp-bridge) runs on your machine as a user service and relays the messages of
the space's trusted humans.

```sh
uv tool install git+https://github.com/briefling/agent@v0.2.0   # or: pipx install git+https://github.com/briefling/agent@v0.2.0
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
| Sandbox | `sbx create --name briefling-claude --mount ~/.config/briefling-agent/claude/claude-history:/home/agent/claude-history --kit sbx/claude-acp:latest --kit sbx/claude-sessions:1.0.0 claude <folder>` | the agent sees `<folder>` (default `~/briefling-agent/claude`) and nothing else; its network goes through Docker's filtering proxy; conversations survive a recreated sandbox, in a folder of this agent only (without `--mount`, sbx gives every sandbox the same one: each agent would read the others' conversations) |
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
command), `--workspace DIR`, `--port N`, `--force` (join again with a new link), `--skills-dir DIR` (a folder of yours for the agent's own skills, mounted read-write at creation with `sbx create --skills off`; without it, sbx's shared store, read-only, seen by every sandbox). Linux, to start at boot without a
login: `loginctl enable-linger $USER`.

## Extensions: AWS without a stored key

```sh
briefling-agent ext list
briefling-agent ext add aws-roles-anywhere --profile <admin profile> --region us-east-1
```

An extension gives the agent something beyond briefling, through the same pattern: a service on your machine, one more
port that only the agent's sandbox may reach, a few lines written in the sandbox, and a check run from inside it. Each
step prints what it does, why and its risk; run `ext add` again to renew (it skips what is done; options left out keep the value of the first run, and `--prefix`, `--region`, `--toolkit-stack`, which name what was made, cannot change: `ext remove` first). `--name` picks the
agent, as for the other commands.

**`aws-roles-anywhere`**: the agent reads and deploys on one AWS account with [IAM Roles
Anywhere](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/introduction.html): a certificate on your machine,
1-hour credentials in the sandbox, no key in it, nothing to renew by hand for a year. Needs the AWS CLI v2 and openssl
on your machine; `--profile` is an AWS CLI profile with admin rights on the account, used here once to set it up,
never given to the agent.

| Step | What | Why / risk |
|---|---|---|
| Signing helper | AWS's `aws_signing_helper` 1.8.6, from `rolesanywhere.amazonaws.com` | trades the certificate for 1-hour credentials; refused unless its SHA-256 is the one AWS publishes |
| Certificate | a certificate authority made once per machine (`~/.config/briefling-agent/ca`), a certificate `CN=<agent>` for one year | the keys never leave your machine (mode 600); whoever reads them gets the agent's AWS access |
| AWS stack `<prefix><agent>` | trust anchor (your CA), 1-hour profile, role `-read` (`ReadOnlyAccess` without SSM / Secrets Manager values, KMS Decrypt, Lambda or ECS configuration), role `-deploy` (may only enter the CDK bootstrap roles `cdk-*`) | created with your admin profile; `--prefix` (default `briefling-agent-`) and `--tag KEY=VALUE` name and tag it |
| CDK bootstrap | adds `sts:SetSourceIdentity` next to `sts:TagSession` in the trust of the bootstrap roles (`--toolkit-stack`, default `CDKToolkit`; `--no-cdk` skips it) | Roles Anywhere carries the agent's name into every role it enters, which the bootstrap roles refuse by default. The change set is printed and refused if it does more than change roles in place (resources citing a role's ARN are only re-read). A later standard `cdk bootstrap` removes it: run `ext add` again |
| Service | `aws_signing_helper serve` on `127.0.0.1:<port>`, a LaunchAgent / systemd unit | serves the credentials like an EC2 metadata endpoint. **It has no password: any program of your machine can read the agent's 1-hour credentials on that port** |
| Network | `sbx policy allow network --sandbox <sandbox> localhost:<port>` | that sandbox only |
| Sandbox | `AWS_EC2_METADATA_SERVICE_ENDPOINT` and `AWS_REGION` in `/etc/sandbox-persistent.sh`, a `deploy` profile in `~/.aws/config` (AWS CLI v2 installed there if missing) | the agent's commands use the read role by default, `--profile deploy` (or `cdk deploy --profile deploy`) for the deploy role |
| Check | `aws sts get-caller-identity` from inside the sandbox | must answer the read role |

CloudTrail names the agent on every session of the chain: `sourceIdentity` = `CN=<agent>`, on the read role, the
deploy role and the CDK roles alike.

```sh
briefling-agent ext revoke aws-roles-anywhere    # revokes the certificate (a CRL on the trust anchor) and stops the service
briefling-agent ext remove aws-roles-anywhere    # deletes the stack, the CRL, the service, the sandbox lines and the certificate
```

After `revoke`, AWS refuses any new session at once (`Certificate revoked`); credentials already handed out end within
the hour. A revoked agent comes back only through `remove`, then `add` (a new certificate). `remove` keeps the CA
(other agents of the machine use it) and the CDK bootstrap fix; it removes the network rule.

## Remove

With extensions, remove them first (`briefling-agent ext remove <extension>`), then:

```sh
briefling-agent stop
rm ~/Library/LaunchAgents/briefling-agent.claude.plist      # macOS
rm ~/.config/systemd/user/briefling-agent-claude.service    # Linux
sbx rm briefling-claude                                     # the microVM (your folder stays)
rm -r ~/.config/briefling-agent/claude                      # the credentials and the agent's conversation history
```

Then remove the agent from the space settings in briefling, and `uv tool uninstall briefling-agent` (or `pipx uninstall`).

This repo is generated from briefling's `briefling-agent/` folder (`scripts/publish-agent.ts`): open issues here,
changes land there.
