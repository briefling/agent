"""Extensions, and aws-roles-anywhere against fakes: `sbx`, `systemctl` and `aws` log their argv; openssl is the real one
(the certificate authority and the revocation are real). The real AWS run is in the README's proof, not here."""

import json
import os
import stat
import sys
import textwrap

import pytest

from briefling_agent import cli, extensions, service
from briefling_agent.extensions import aws_roles_anywhere as ara

FAKE = textwrap.dedent('''\
    #!{py}
    import json, os, socket, sys, threading, time
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
            print("briefling-claude")
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
        elif args[0] == "exec":
            cmd = args[args.index("briefling-claude") + 1:]
            if "-i" in args:
                st.setdefault("stdin", []).append(sys.stdin.read()); save()
            if cmd[:2] == ["sh", "-c"] and cmd[2] == "command -v aws":
                sys.exit(0 if st.get("vm_aws", True) else 1)
            if cmd[0] == "bash":
                print("arn:aws:sts::ACCOUNT:assumed-role/" + st.get("role", "briefling-agent-claude-read") + "/x")
    elif tool == "aws":
        a = [x for x in args]
        if a[:2] == ["cloudformation", "describe-stacks"] and "Stacks[0].Outputs" in a:
            print(json.dumps([{{"OutputKey": k, "OutputValue": "arn:" + k}} for k in
                              ("TrustAnchorArn", "ProfileArn", "ReadRoleArn", "DeployRoleArn")]))
        elif a[:2] == ["cloudformation", "describe-stacks"]:
            print(json.dumps([{{"ParameterKey": "Qualifier", "ParameterValue": "hnb659fds"}}]))
        elif a[:2] == ["cloudformation", "get-template"]:
            if st.get("no_toolkit"):
                print("An error occurred (ValidationError): Stack with id CDKToolkit does not exist"); sys.exit(254)
            print(json.dumps(st.get("toolkit", "")))
        elif a[:2] == ["cloudformation", "create-change-set"]:
            body = open(a[a.index("--template-body") + 1][len("file://"):]).read()
            st["changeset_body"] = body; save()
        elif a[:2] == ["cloudformation", "describe-change-set"]:
            print(json.dumps({{"Status": "CREATE_COMPLETE", "Changes": st.get("changes", [])}}))
        elif a[:2] == ["rolesanywhere", "import-crl"]:
            print(json.dumps({{"crl": {{"crlId": "crl-1"}}}}))
    elif tool == "curl":
        out = args[args.index("-o") + 1]
        open(out, "wb").write(st.get("helper", "helper-bytes").encode())
    elif tool == "systemctl":
        if "show" in args:
            print("ActiveState=" + st.get("unit", "inactive") + "\\nMainPID=0")
        elif "enable" in args or "restart" in args:
            st["unit"] = "active"; save()
        elif "disable" in args:
            st["unit"] = "inactive"; save()
''')

TOOLKIT = textwrap.dedent('''\
    Resources:
      FilePublishingRole:
        Type: AWS::IAM::Role
        Properties:
          AssumeRolePolicyDocument:
            Statement:
              - Action: sts:AssumeRole
                Effect: Allow
                Principal:
                  AWS:
                    Ref: AWS::AccountId
              - Action: sts:TagSession
                Effect: Allow
                Principal:
                  AWS:
                    Ref: AWS::AccountId
              - Fn::If:
                  - HasTrustedAccounts
                  - Action:
                      - sts:TagSession
                    Effect: Allow
                    Principal:
                      AWS:
                        Ref: TrustedAccounts
                  - Ref: AWS::NoValue
    ''')

ROLE_CHANGE = {"ResourceChange": {"Action": "Modify", "LogicalResourceId": "FilePublishingRole",
                                  "ResourceType": "AWS::IAM::Role", "Replacement": "False",
                                  "Details": [{"Evaluation": "Static", "ChangeSource": "DirectModification"}]}}
# what the real change set also lists (sandbox run): a resource citing a role's ARN, only re-read
REREAD = {"ResourceChange": {"Action": "Modify", "LogicalResourceId": "StagingBucketPolicy",
                             "ResourceType": "AWS::S3::BucketPolicy", "Replacement": "False",
                             "Details": [{"Evaluation": "Dynamic", "ChangeSource": "ResourceAttribute"}]}}


@pytest.fixture
def fakes(tmp_path, monkeypatch):
    d = tmp_path / "fakes"
    (d / "bin").mkdir(parents=True)
    for tool in ("sbx", "systemctl", "aws", "curl"):
        p = d / "bin" / tool
        p.write_text(FAKE.format(py=sys.executable, d=str(d)))
        p.chmod(p.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{d / 'bin'}:/usr/bin:/bin")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(extensions, "wait_port", lambda port, until: True)
    monkeypatch.setattr(extensions, "CHECK_TRIES", 1)
    import hashlib
    key = ara.platform_key()
    monkeypatch.setitem(ara.HELPERS, key, (ara.HELPERS.get(key, ("x", ""))[0],
                                           hashlib.sha256(b"helper-bytes").hexdigest()))
    conf = {"name": "claude", "agent": "claude", "sandbox": "briefling-claude", "workspace": str(tmp_path / "ws"),
            "port": 50000, "sbx": str(d / "bin" / "sbx"), "bridge": "/bin/true", "env": "/dev/null",
            "log": str(tmp_path / "bridge.log"), "path": os.environ["PATH"]}
    cli.save_conf(conf)

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


ADD = ["ext", "add", "aws-roles-anywhere", "--profile", "admin", "--region", "us-east-1"]


def test_manifests_name_their_steps():
    assert "aws-roles-anywhere" in extensions.available()
    for name in extensions.available():
        m, mod = extensions.manifest(name), extensions.module(name)
        for st in m["steps"]:
            assert callable(getattr(mod, st["id"].replace("-", "_"))), st["id"]
            assert st["what"] and st["why"] and st["risk"]
        assert callable(mod.revoke) and callable(mod.remove)


def test_add_does_every_step(fakes, capsys):
    fakes.state(toolkit=TOOLKIT, changes=[ROLE_CHANGE, REREAD])
    assert cli.main(ADD) == 0, capsys.readouterr().err
    out = capsys.readouterr().out
    for word in ("Risk:", "SHA-256 matches", "certificate authority made", "issued for 365 days",
                 "1 role(s), none replaced", "allowed localhost:", "ready for claude"):
        assert word in out, word
    st = cli.load_conf("claude")["extensions"]["aws-roles-anywhere"]
    port = st["port"]
    # the certificate: CN = the agent, signed by the machine's CA, keys private
    p = cli.run(["openssl", "x509", "-noout", "-subject", "-in", st["cert"]])
    assert "CN" in p.stdout and "claude" in p.stdout
    assert os.stat(st["key"]).st_mode & 0o077 == 0
    ca = os.path.join(os.path.dirname(cli.agent_dir("claude")), "ca")
    assert os.stat(os.path.join(ca, "ca.key")).st_mode & 0o077 == 0
    assert cli.run(["openssl", "verify", "-CAfile", os.path.join(ca, "ca.crt"), st["cert"]]).returncode == 0
    # the stack, with the admin profile, the CA, the tag
    aws = fakes.calls("aws")
    dep = next(c for c in aws if c[1:3] == ["cloudformation", "deploy"])
    assert "--profile" in dep and dep[dep.index("--profile") + 1] == "admin"
    assert any(x.startswith("CaCertificate=-----BEGIN CERTIFICATE-----") for x in dep)
    assert "briefling-agent=claude" in dep and dep[dep.index("--stack-name") + 1] == "briefling-agent-claude"
    # the CDK fix: only the same-account TagSession gets SetSourceIdentity, then executed
    body = fakes.state()["changeset_body"]
    assert body.count("sts:SetSourceIdentity") == 1
    assert any(c[1:3] == ["cloudformation", "execute-change-set"] for c in aws)
    # the service: the helper on the port, with the certificate and the stack's ARNs
    unit = open(os.path.join(os.environ["HOME"], ".config/systemd/user",
                             "briefling-agent-claude.aws-roles-anywhere.service")).read()
    assert '"serve" "--port" "%d"' % port in unit and '"arn:TrustAnchorArn"' in unit and st["cert"] in unit
    assert "Restart=always" in unit
    # one rule, scoped; the sandbox gets the endpoint and the deploy profile, never a key
    sbx = fakes.calls("sbx")
    assert ["sbx", "policy", "allow", "network", "--sandbox", "briefling-claude", f"localhost:{port}"] in sbx
    assert not any(c[1:3] == ["policy", "allow"] and "--sandbox" not in c for c in sbx)
    written = "".join(fakes.state()["stdin"])
    assert f"AWS_EC2_METADATA_SERVICE_ENDPOINT=http://host.docker.internal:{port}/" in written
    assert "role_arn = arn:DeployRoleArn" in written and "credential_source = Ec2InstanceMetadata" in written
    assert "PRIVATE KEY" not in written and "BEGIN CERTIFICATE" not in written
    assert any(c[2:5] == ["-u", "root", "briefling-claude"] for c in sbx if c[1] == "exec" and "-i" in c) or \
        any("-u" in c and "root" in c for c in sbx)

    # run again: same port, no new certificate, nothing to patch, no second rule
    fakes.state(toolkit=body)
    n = len(fakes.calls())
    assert cli.main(ADD) == 0
    out = capsys.readouterr().out
    again = fakes.calls()[n:]
    assert "valid until" in out and "already allows sts:SetSourceIdentity" in out and "already allowed" in out
    assert not any(c[0] == "curl" for c in again)
    assert not any(c[1:3] == ["cloudformation", "create-change-set"] for c in again)
    assert cli.load_conf("claude")["extensions"]["aws-roles-anywhere"]["port"] == port


def test_a_change_set_replacing_anything_is_refused(fakes, capsys):
    replaced = {"ResourceChange": {"Action": "Modify", "LogicalResourceId": "StagingBucket",
                                   "ResourceType": "AWS::S3::Bucket", "Replacement": "True"}}
    direct = {"ResourceChange": {"Action": "Modify", "LogicalResourceId": "StagingBucket",
                                 "ResourceType": "AWS::S3::Bucket", "Replacement": "False",
                                 "Details": [{"Evaluation": "Static", "ChangeSource": "DirectModification"}]}}
    for bad in (replaced, direct):
        fakes.state(toolkit=TOOLKIT, changes=[ROLE_CHANGE, REREAD, bad])
        assert cli.main(ADD) == 1
        assert "left as it was" in capsys.readouterr().err
    aws = fakes.calls("aws")
    assert any(c[1:3] == ["cloudformation", "delete-change-set"] for c in aws)
    assert not any(c[1:3] == ["cloudformation", "execute-change-set"] for c in aws)


def test_no_toolkit_and_no_cdk(fakes, capsys):
    fakes.state(no_toolkit=True)
    assert cli.main(ADD) == 0
    assert "no stack CDKToolkit" in capsys.readouterr().out
    assert cli.main(ADD + ["--no-cdk"]) == 0
    assert "skipped (--no-cdk)" in capsys.readouterr().out


def test_a_bad_helper_is_not_installed(fakes, capsys):
    fakes.state(helper="tampered")
    assert cli.main(ADD) == 1
    assert "checksum mismatch" in capsys.readouterr().err
    assert not any(c[0] == "aws" for c in fakes.calls())  # nothing made in AWS


def test_needs_its_tools_and_args(fakes, capsys):
    assert cli.main(["ext", "add", "aws-roles-anywhere", "--region", "us-east-1"]) == 1
    assert "--profile" in capsys.readouterr().err
    os.remove(fakes.dir / "bin" / "aws")
    assert cli.main(ADD) == 1
    assert "needs aws" in capsys.readouterr().err


def test_revoke_then_remove(fakes, capsys):
    fakes.state(no_toolkit=True)
    assert cli.main(ADD) == 0
    st = cli.load_conf("claude")["extensions"]["aws-roles-anywhere"]
    assert cli.main(["ext", "revoke", "aws-roles-anywhere"]) == 0
    imp = next(c for c in fakes.calls("aws") if c[1:3] == ["rolesanywhere", "import-crl"])
    assert imp[imp.index("--trust-anchor-arn") + 1] == "arn:TrustAnchorArn" and "--enabled" in imp
    crl = imp[imp.index("--crl-data") + 1][len("fileb://"):]
    serial = cli.run(["openssl", "x509", "-noout", "-serial", "-in", st["cert"]]).stdout.strip().split("=")[1]
    assert serial in cli.run(["openssl", "crl", "-noout", "-text", "-in", crl]).stdout.replace(":", "").upper()
    assert fakes.state()["unit"] == "inactive"
    assert cli.main(["status"]) == 3 and "(revoked)" in capsys.readouterr().out
    assert cli.main(ADD) == 1 and "was revoked" in capsys.readouterr().err  # no silent comeback
    assert cli.main(["ext", "remove", "aws-roles-anywhere"]) == 0
    aws = fakes.calls("aws")
    assert any(c[1:3] == ["rolesanywhere", "delete-crl"] for c in aws)
    assert any(c[1:3] == ["cloudformation", "delete-stack"] for c in aws)
    assert "aws-roles-anywhere" not in (cli.load_conf("claude").get("extensions") or {})
    assert not os.path.exists(st["cert"])
    assert fakes.state()["rules"] == [] and "network rule localhost:%d removed" % st["port"] in capsys.readouterr().out
    assert not os.path.exists(os.path.join(os.environ["HOME"], ".config/systemd/user",
                                           "briefling-agent-claude.aws-roles-anywhere.service"))


def test_patch_yaml_keeps_trusted_accounts():
    new, n = ara.patch_yaml(TOOLKIT)
    assert n == 1
    assert "          - Action:\n              - sts:TagSession\n              - sts:SetSourceIdentity\n" \
           "            Effect: Allow" in new  # items deeper than the key, the statement's other keys untouched
    assert ara.patch_yaml(new)[1] == 0 and ara.patched_template(new)[1].startswith("already")


def test_patch_json():
    tpl = {"Resources": {"R": {"Type": "AWS::IAM::Role", "Properties": {"AssumeRolePolicyDocument": {"Statement": [
        {"Action": "sts:TagSession", "Principal": {"AWS": {"Ref": "AWS::AccountId"}}},
        {"Action": ["sts:TagSession"], "Principal": {"AWS": {"Ref": "TrustedAccounts"}}}]}}}}}
    new, found = ara.patched_template(tpl)
    st = json.loads(new)["Resources"]["R"]["Properties"]["AssumeRolePolicyDocument"]["Statement"]
    assert st[0]["Action"] == ["sts:TagSession", "sts:SetSourceIdentity"] and st[1]["Action"] == ["sts:TagSession"]
    assert ara.patched_template({"Resources": {}})[0] is None


def test_unknown_toolkit_is_refused(fakes, capsys):
    fakes.state(toolkit="Resources: {}\n")
    assert cli.main(ADD) == 1
    assert "Not a CDK bootstrap template this tool knows" in capsys.readouterr().err


def test_a_run_again_keeps_the_first_options(fakes, capsys):
    fakes.state(toolkit=TOOLKIT, changes=[ROLE_CHANGE], role="acme-claude-read")
    first = ADD + ["--prefix", "acme-", "--no-cdk", "--tag", "owner=me", "--toolkit-stack", "Boot"]
    assert cli.main(first) == 0, capsys.readouterr().err
    n = len(fakes.calls())
    assert cli.main(["ext", "add", "aws-roles-anywhere"]) == 0, capsys.readouterr().err  # nothing given again
    again = fakes.calls()[n:]
    dep = next(c for c in again if c[1:3] == ["cloudformation", "deploy"])
    assert dep[dep.index("--stack-name") + 1] == "acme-claude" and "owner=me" in dep
    assert dep[dep.index("--profile") + 1] == "admin"
    assert not any(c[1:3] == ["cloudformation", "get-template"] for c in again)  # --no-cdk kept
    assert "skipped (--no-cdk)" in capsys.readouterr().out
    st = cli.load_conf("claude")["extensions"]["aws-roles-anywhere"]
    assert (st["prefix"], st["toolkit_stack"], st["tags"], st["no_cdk"]) == ("acme-", "Boot", ["owner=me"], True)
    # what names the stack never changes on a run again: it would orphan the first one
    n = len(fakes.calls())
    for opt in (["--prefix", "other-"], ["--region", "eu-central-1"]):
        assert cli.main(["ext", "add", "aws-roles-anywhere"] + opt) == 1
        assert "ext remove" in capsys.readouterr().err
    assert not any(c[0] == "aws" for c in fakes.calls()[n:])
    # the same value given again is fine; the defaults still hold on a first run
    assert cli.main(["ext", "add", "aws-roles-anywhere", "--prefix", "acme-"]) == 0


def test_first_run_defaults(fakes, capsys):
    fakes.state(no_toolkit=True)
    assert cli.main(ADD) == 0, capsys.readouterr().err
    st = cli.load_conf("claude")["extensions"]["aws-roles-anywhere"]
    assert (st["prefix"], st["toolkit_stack"], st["tags"], st["no_cdk"]) == ("briefling-agent-", "CDKToolkit", [], False)


def test_port_allowed_is_a_whole_resource(fakes):
    fakes.state(rules=["api.anthropic.com", "localhost:508610", "localhost:50861,localhost:1"])
    assert cli.port_allowed("sbx", "briefling-claude", 50861)
    assert not cli.port_allowed("sbx", "briefling-claude", 5086)
    fakes.state(rules=["localhost:508610"])
    assert not cli.port_allowed("sbx", "briefling-claude", 50861)


def test_systemd_extension_unit_description(tmp_path):
    unit = service.Systemd("claude.aws-roles-anywhere", str(tmp_path)).render(["/x"], "/l", "/usr/bin")
    assert "Description=briefling agent claude.aws-roles-anywhere\n" in unit
