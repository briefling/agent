"""Steps of the aws-roles-anywhere extension (manifest: aws-roles-anywhere.json).

Model: a certificate authority made on this machine signs one certificate per agent (CN = the agent's name). In the
AWS account, a trust anchor holds the CA, a profile hands out 1-hour sessions of the agent's read role, and a deploy
role is reached from the read role. `aws_signing_helper serve` (AWS's tool) turns the certificate into those sessions
and serves them like an EC2 metadata endpoint, on a port only the agent's sandbox may reach: no key ever enters the
sandbox, the worst a compromised agent keeps is one hour of its role. Roles Anywhere puts the CN as source identity
on every session, so CloudTrail names the agent, and each role entered must allow sts:SetSourceIdentity: the CDK
bootstrap roles do not by default, hence the `cdk` step.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import tempfile
import time
from typing import Dict, List, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATE = os.path.join(HERE, "aws_roles_anywhere.template.json")

# https://docs.aws.amazon.com/rolesanywhere/latest/userguide/credential-helper.html (checksums published there)
HELPER_VERSION = "1.8.6"
HELPER_URL = "https://rolesanywhere.amazonaws.com/releases/{v}/{path}/aws_signing_helper"
HELPERS: Dict[Tuple[str, str], Tuple[str, str]] = {
    ("darwin", "arm64"): ("Aarch64/MacOS/Sonoma", "56ee7a162249d0c2427e754ebcd6c9e5d672dc8b6a89623d67cfd4fd970e243c"),
    ("darwin", "x86_64"): ("X86_64/MacOS/Sonoma", "484443b80b0fccbbe33137326a30020614c634b3a2fa5456a1f39ec991f17b80"),
    ("linux", "aarch64"): ("Aarch64/Linux/Amzn2023", "b8a1800a9f483674a376170e1eabc0796a4ad3b7ac048670de9346975e9925dc"),
    ("linux", "x86_64"): ("X86_64/Linux/Amzn2023", "3553fdc515e5682541a9ebdd37031ec7f461169aa13ccbb6fbd5b7259644113d"),
}
CERT_DAYS, CA_DAYS, RENEW_BEFORE_S = 365, 1825, 30 * 24 * 3600

CA_CNF = """[ ca ]
default_ca = agents

[ agents ]
dir = {dir}
database = $dir/index.txt
new_certs_dir = $dir/certs
certificate = $dir/ca.crt
private_key = $dir/ca.key
serial = $dir/serial
crlnumber = $dir/crlnumber
default_md = sha256
default_crl_days = 365
policy = any
unique_subject = no
copy_extensions = none

[ any ]
commonName = supplied

[ req ]
distinguished_name = dn

[ dn ]

[ v3_ca ]
basicConstraints = critical,CA:true,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash

[ v3_agent ]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
"""


def platform_key() -> Tuple[str, str]:
    system = "darwin" if os.uname().sysname == "Darwin" else "linux"
    machine = platform.machine().lower()
    machine = {"amd64": "x86_64", "arm64": "arm64" if system == "darwin" else "aarch64"}.get(machine, machine)
    if system == "darwin" and machine == "aarch64":
        machine = "arm64"
    return system, machine


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def aws(ctx, *args: str, check: bool = True, output: str = "json"):
    argv = ["aws", *args, "--profile", str(ctx.state["profile"]), "--region", str(ctx.state["region"]),
            "--output", output]
    return ctx.run(argv, check=check)


def aws_json(ctx, *args: str):
    out = aws(ctx, *args).stdout.strip()
    return json.loads(out) if out else None


# ---- steps ----

def helper(ctx) -> None:
    key = platform_key()
    if key not in HELPERS:
        raise ctx.Fail(f"no aws_signing_helper for {key[0]}/{key[1]}")
    path, digest = HELPERS[key]
    bindir = os.path.join(os.path.dirname(ctx.cli.agent_dir(ctx.name)), "bin")
    dest = os.path.join(bindir, f"aws_signing_helper-{HELPER_VERSION}")
    if os.path.exists(dest) and sha256(dest) == digest:
        ctx.say(f"  {HELPER_VERSION} already here, checksum OK.")
    else:
        os.makedirs(bindir, mode=0o700, exist_ok=True)
        tmp = dest + ".part"
        ctx.run(["curl", "-fsSL", "--proto", "=https", "-o", tmp, HELPER_URL.format(v=HELPER_VERSION, path=path)])
        got = sha256(tmp)
        if got != digest:
            os.remove(tmp)
            raise ctx.Fail(f"aws_signing_helper checksum mismatch ({got}, AWS publishes {digest}): not installed")
        os.chmod(tmp, 0o755)
        os.replace(tmp, dest)
        ctx.say(f"  {HELPER_VERSION} downloaded, SHA-256 matches AWS's.")
    ctx.state["helper"] = dest


def ca_dir(ctx) -> str:
    return os.path.join(os.path.dirname(ctx.cli.agent_dir(ctx.name)), "ca")


def openssl(ctx, *args: str):
    return ctx.run(["openssl", *args])


def ensure_ca(ctx) -> str:
    d = ca_dir(ctx)
    cnf = os.path.join(d, "ca.cnf")
    if os.path.exists(os.path.join(d, "ca.crt")):
        return cnf
    os.makedirs(os.path.join(d, "certs"), mode=0o700, exist_ok=True)
    os.chmod(d, 0o700)
    with open(cnf, "w") as f:
        f.write(CA_CNF.format(dir=d))
    open(os.path.join(d, "index.txt"), "a").close()
    for f, v in (("serial", os.urandom(8).hex().upper()), ("crlnumber", "01")):
        with open(os.path.join(d, f), "w") as fh:
            fh.write(v + "\n")
    key = os.path.join(d, "ca.key")
    openssl(ctx, "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", key)
    os.chmod(key, 0o600)
    host = re.sub(r"[^A-Za-z0-9.-]", "-", platform.node() or "host")[:40]
    openssl(ctx, "req", "-new", "-x509", "-config", cnf, "-extensions", "v3_ca", "-key", key, "-sha256",
            "-days", str(CA_DAYS), "-subj", f"/O=briefling-agent/CN=briefling-agent CA {host}",
            "-out", os.path.join(d, "ca.crt"))
    ctx.say(f"  certificate authority made in {d} (key mode 600).")
    return cnf


def certificate(ctx) -> None:
    cnf = ensure_ca(ctx)
    d = ca_dir(ctx)
    key, crt = os.path.join(ctx.dir, "agent.key"), os.path.join(ctx.dir, "agent.crt")
    if os.path.exists(crt) and os.path.exists(key):
        fresh = ctx.run(["openssl", "x509", "-checkend", str(RENEW_BEFORE_S), "-noout", "-in", crt], check=False)
        same_ca = ctx.run(["openssl", "verify", "-CAfile", os.path.join(d, "ca.crt"), crt], check=False)
        if fresh.returncode == 0 and same_ca.returncode == 0:
            end = openssl(ctx, "x509", "-enddate", "-noout", "-in", crt).stdout.strip().split("=", 1)[-1]
            ctx.say(f"  certificate CN={ctx.name} valid until {end}.")
            ctx.state.update(cert=crt, key=key)
            return
    if not os.path.exists(key):
        openssl(ctx, "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", key)
        os.chmod(key, 0o600)
    csr = os.path.join(ctx.dir, "agent.csr")
    openssl(ctx, "req", "-new", "-config", cnf, "-key", key, "-subj", f"/CN={ctx.name}", "-out", csr)
    openssl(ctx, "ca", "-batch", "-config", cnf, "-extensions", "v3_agent", "-days", str(CERT_DAYS), "-notext",
            "-in", csr, "-out", crt)
    os.remove(csr)
    ctx.say(f"  certificate CN={ctx.name} issued for {CERT_DAYS} days.")
    ctx.state.update(cert=crt, key=key)


def stack_name(ctx) -> str:
    return f"{ctx.state['prefix']}{ctx.name}"


def stack(ctx) -> None:
    with open(os.path.join(ca_dir(ctx), "ca.crt")) as f:
        pem = f.read().strip()
    tags = [f"briefling-agent={ctx.name}"] + list(ctx.state.get("tags") or [])
    for t in tags:
        if not re.match(r"^[\w.:/=+@-]{1,128}=[\w.:/=+@ -]{0,256}$", t):
            raise ctx.Fail(f"bad --tag {t!r}: KEY=VALUE")
    p = aws(ctx, "cloudformation", "deploy", "--template-file", TEMPLATE, "--stack-name", stack_name(ctx),
            "--parameter-overrides", f"Prefix={ctx.state['prefix']}", f"AgentName={ctx.name}", f"CaCertificate={pem}",
            "--capabilities", "CAPABILITY_NAMED_IAM", "--no-fail-on-empty-changeset", "--tags", *tags,
            output="text")
    ctx.say("  " + (p.stdout.strip().splitlines() or ["deployed."])[-1])
    outs = aws_json(ctx, "cloudformation", "describe-stacks", "--stack-name", stack_name(ctx),
                    "--query", "Stacks[0].Outputs")
    for o in outs or []:
        ctx.state[o["OutputKey"]] = o["OutputValue"]
    for k in ("TrustAnchorArn", "ProfileArn", "ReadRoleArn", "DeployRoleArn"):
        if not ctx.state.get(k):
            raise ctx.Fail(f"the stack has no output {k}")
    ctx.say(f"  read role {ctx.state['ReadRoleArn']}")


# ---- CDK bootstrap: sts:SetSourceIdentity next to sts:TagSession, for this account only ----

SINGLE_TAG = re.compile(r"^([ \t]*)- Action: sts:TagSession[ \t]*$", re.M)


def patch_yaml(text: str) -> Tuple[str, int]:
    """The bootstrap template's same-account statements read `- Action: sts:TagSession` (one line, Principal the
    account); the trusted-accounts ones are lists under Fn::If and are left alone. A textual edit, not a YAML parse:
    CloudFormation parses the result and the change set check below refuses anything but trust changes."""
    def repl(m: "re.Match[str]") -> str:
        i = m.group(1)
        return f"{i}- Action:\n{i}    - sts:TagSession\n{i}    - sts:SetSourceIdentity"
    return SINGLE_TAG.subn(repl, text)


def patch_json(tpl: Dict[str, object]) -> int:
    n = 0
    for res in (tpl.get("Resources") or {}).values():  # type: ignore[union-attr]
        if res.get("Type") != "AWS::IAM::Role":
            continue
        doc = (res.get("Properties") or {}).get("AssumeRolePolicyDocument") or {}
        for st in doc.get("Statement") or []:
            if not isinstance(st, dict) or st.get("Principal") != {"AWS": {"Ref": "AWS::AccountId"}}:
                continue
            acts = st.get("Action")
            acts = [acts] if isinstance(acts, str) else list(acts or [])
            if "sts:TagSession" in acts and "sts:SetSourceIdentity" not in acts:
                st["Action"] = acts + ["sts:SetSourceIdentity"]
                n += 1
    return n


def patched_template(body) -> Tuple[Optional[str], str]:
    """(new template text or None when nothing to do, what was found)."""
    if isinstance(body, dict):
        n = patch_json(body)
        new, text = (json.dumps(body, indent=1) if n else None), json.dumps(body)
    else:
        new, n = patch_yaml(str(body))
        new, text = (new if n else None), str(body)
    if n:
        return new, f"{n} statement(s) to fix"
    if "sts:SetSourceIdentity" in text:
        return None, "already allows sts:SetSourceIdentity"
    return None, "no same-account sts:TagSession statement found"


def check_changes(changes: List[Dict[str, object]]) -> List[str]:
    """Refusal reasons: anything but an in-place change of IAM roles. Resources that cite a role's or the bucket's ARN
    show up as Modify too, with only `Dynamic` details (CloudFormation re-reads the ARN, unchanged since nothing is
    replaced): those pass; any other direct change, an add, a removal or a replacement does not."""
    bad = []
    for c in changes:
        rc = c.get("ResourceChange") or {}
        what = f"{rc.get('Action')} {rc.get('LogicalResourceId')} ({rc.get('ResourceType')}, replacement " \
               f"{rc.get('Replacement')})"
        if rc.get("Action") != "Modify" or rc.get("Replacement") != "False":
            bad.append(what)
        elif rc.get("ResourceType") != "AWS::IAM::Role" and any(
                d.get("Evaluation") != "Dynamic" for d in rc.get("Details") or [{}]):
            bad.append(what + ": a direct change")
    return bad


def cdk(ctx) -> None:
    if ctx.state.get("no_cdk"):
        ctx.say("  skipped (--no-cdk): cdk deploy will be refused to this agent.")
        return
    ts = str(ctx.state["toolkit_stack"])
    p = aws(ctx, "cloudformation", "get-template", "--stack-name", ts, "--query", "TemplateBody", check=False)
    if p.returncode != 0:
        if "does not exist" in p.stdout:
            ctx.say(f"  no stack {ts} in this account/region: skipped. After a `cdk bootstrap`, run this again.")
            return
        raise ctx.Fail(f"reading {ts} failed:\n{p.stdout.strip()[-800:]}")
    new, found = patched_template(json.loads(p.stdout))
    if new is None:
        if found.startswith("already"):
            ctx.say(f"  {ts} {found}.")
            return
        raise ctx.Fail(f"{ts}: {found}. Not a CDK bootstrap template this tool knows: add sts:SetSourceIdentity to "
                       "the trust of its roles by hand (next to sts:TagSession), or pass --no-cdk.")
    if len(new.encode()) > 51200:
        raise ctx.Fail(f"{ts}'s template is over CloudFormation's 51 200-byte inline limit: patch it by hand")
    ctx.say(f"  {ts}: {found}.")
    params = aws_json(ctx, "cloudformation", "describe-stacks", "--stack-name", ts, "--query", "Stacks[0].Parameters")
    with tempfile.NamedTemporaryFile("w", suffix=".template", delete=False) as f:
        f.write(new)
        tpl = f.name
    name = f"briefling-agent-source-identity-{int(time.time())}"
    try:
        aws(ctx, "cloudformation", "create-change-set", "--stack-name", ts, "--change-set-name", name,
            "--template-body", f"file://{tpl}", "--capabilities", "CAPABILITY_IAM", "CAPABILITY_NAMED_IAM",
            "--parameters", json.dumps([{"ParameterKey": x["ParameterKey"], "UsePreviousValue": True}
                                        for x in params or []]))
    finally:
        os.remove(tpl)
    aws(ctx, "cloudformation", "wait", "change-set-create-complete", "--stack-name", ts, "--change-set-name", name,
        check=False)
    cs = aws_json(ctx, "cloudformation", "describe-change-set", "--stack-name", ts, "--change-set-name", name)
    changes = cs.get("Changes") or []
    for c in changes:
        rc = c["ResourceChange"]
        direct = any(d.get("Evaluation") != "Dynamic" for d in rc.get("Details") or [{}])
        ctx.say(f"    {rc.get('Action')} {rc.get('LogicalResourceId')} ({rc.get('ResourceType')}), "
                f"replacement {rc.get('Replacement')}" + ("" if direct else ", re-read only (cites an ARN)"))
    bad = check_changes(changes) if changes else [f"change set {cs.get('Status')}: {cs.get('StatusReason')}"]
    if bad:
        aws(ctx, "cloudformation", "delete-change-set", "--stack-name", ts, "--change-set-name", name, check=False)
        raise ctx.Fail(f"{ts} left as it was: the change set holds more than trust changes:\n  " + "\n  ".join(bad))
    aws(ctx, "cloudformation", "execute-change-set", "--stack-name", ts, "--change-set-name", name)
    aws(ctx, "cloudformation", "wait", "stack-update-complete", "--stack-name", ts)
    roles = sum(1 for c in changes if c["ResourceChange"].get("ResourceType") == "AWS::IAM::Role")
    ctx.say(f"  {ts} updated ({roles} role(s), none replaced).")


# ---- revoke / remove ----

def revoke(ctx) -> None:
    cnf, crt = os.path.join(ca_dir(ctx), "ca.cnf"), str(ctx.state.get("cert") or "")
    if not os.path.exists(crt):
        raise ctx.Fail(f"no certificate for {ctx.name} here ({crt})")
    ctx.cli.step(f"Revoke the certificate CN={ctx.name}",
                 "A revocation list (CRL) on the trust anchor: AWS refuses any new session for this certificate at "
                 "once; the 1-hour credentials already handed out end within the hour.")
    p = ctx.run(["openssl", "ca", "-config", cnf, "-revoke", crt], check=False)
    if p.returncode != 0 and "Already revoked" not in p.stdout:
        raise ctx.Fail(f"openssl ca -revoke failed:\n{p.stdout[-800:]}")
    crl = os.path.join(ca_dir(ctx), "crl.pem")
    openssl(ctx, "ca", "-config", cnf, "-gencrl", "-out", crl)
    if ctx.state.get("crl_id"):
        aws(ctx, "rolesanywhere", "update-crl", "--crl-id", str(ctx.state["crl_id"]), "--crl-data", f"fileb://{crl}")
        aws(ctx, "rolesanywhere", "enable-crl", "--crl-id", str(ctx.state["crl_id"]))
    else:
        out = aws_json(ctx, "rolesanywhere", "import-crl", "--name", f"{stack_name(ctx)}-crl", "--crl-data",
                       f"fileb://{crl}", "--trust-anchor-arn", str(ctx.state["TrustAnchorArn"]), "--enabled")
        ctx.state["crl_id"] = out["crl"]["crlId"]
    ctx.say(f"  CRL {ctx.state['crl_id']} on the trust anchor: CN={ctx.name} revoked.")


def remove(ctx) -> None:
    ctx.cli.step(f"Delete the AWS stack {stack_name(ctx)}",
                 "Its trust anchor, profile and two roles. The CDK bootstrap fix stays (harmless, other agents use it).")
    if ctx.state.get("crl_id"):
        aws(ctx, "rolesanywhere", "delete-crl", "--crl-id", str(ctx.state["crl_id"]), check=False)
    if ctx.state.get("profile"):
        aws(ctx, "cloudformation", "delete-stack", "--stack-name", stack_name(ctx))
        aws(ctx, "cloudformation", "wait", "stack-delete-complete", "--stack-name", stack_name(ctx))
        ctx.say("  deleted.")
    for f in ("agent.key", "agent.crt"):
        p = os.path.join(ctx.dir, f)
        if os.path.exists(p):
            os.remove(p)
