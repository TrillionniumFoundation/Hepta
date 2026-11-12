#!/usr/bin/env python3
"""Read-only consumer joins of complete selected originals; never runs supplier."""
from __future__ import annotations
import argparse, ast, hashlib, json, os, re, stat, sys, traceback
from collections import Counter
from pathlib import Path
ACTUAL = Path("/tmp/hia-full32-r4-gzip-actual-43319690424-r1")
FLAT = ACTUAL / "small/flat"
ORIGINAL_ROOT = "/home/runner/hf43305002328a1"
PUBLIC = "hia-v87-full-public/"
CHECKS = Counter()
FAILURES = []
PINS = {}
REPORT = {
    "schema": "hia.full32.r4.selected-supply-failure-independent-audit.v1",
    "scope": "Complete local selected-original bytes and original recorded predicates; not local physical recovery of the entire 3,010,752,230-byte original ZIP or 5.93GB namespace.",
    "original_run": 43305002328,
    "recovery_run": 43319690424,
    "original_artifact": {"id": 13982129929, "bytes": 3010752230,
                         "sha256": "4f5b0439a47f873e90fb6382c0232d9e3ae99b0dd05eb5b5e01132eeec4c9380"},
    "small_artifact": {"id": 13991170182, "bytes": 34570252,
                      "sha256": "7201ffb609a82d4666321960ff0a5bdb5e3db7b52d4068aadd07eda78e643f7b"},
    "supplier_executed": False, "qualification_executed": False,
    "original_statuses_reclassified": False, "full_original_zip_locally_reconstructed": False,
}
def check(group, name, condition, detail=None):
    CHECKS[group] += 1
    if condition is not True:
        FAILURES.append({"group": group, "name": name, "detail": detail})
def require(group, name, condition):
    check(group, name, bool(condition))
    if not condition:
        raise ValueError(group + ": " + name)
def record(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            "git_blob": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()}
def local(name):
    p = FLAT / name
    before = p.lstat()
    require("local", "regular-single-" + name, stat.S_ISREG(before.st_mode) and before.st_nlink == 1)
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(fd)
        raw = bytearray()
        while True:
            part = os.read(fd, 1 << 20)
            if not part: break
            raw.extend(part)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    def identity(st):
        return (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid, st.st_nlink,
                st.st_size, st.st_mtime_ns, st.st_ctime_ns)
    require("local", "stable-identity-" + name,
            identity(before) == identity(opened) == identity(after) == identity(p.lstat()))
    raw = bytes(raw)
    PINS[name] = record(raw)
    return raw
def load_json(name): return json.loads(local(name))
def main():
    index = load_json("INDEX.json")
    rows = index["originals"]
    require("index", "473-complete-selected-originals", len(rows) == 473)
    selected = {(r["scope"], r["path"]): r for r in rows}
    require("index", "unique-scope-path", len(selected) == len(rows))
    require("index", "unique-saved", len({r["saved"] for r in rows}) == len(rows))
    require("index", "exact-scope-counts", Counter(r["scope"] for r in rows) == {"OUTER": 38, "INNER": 435})
    bodies = {}
    for row in rows:
        raw = local(row["saved"])
        p = PINS[row["saved"]]
        check("selected-physical", row["path"],
              row["whole_original"] is True and row["derived"] is False
              and p["bytes"] == row["bytes"] == row["actual"]["bytes"] == row["actual"]["actual_bytes_independently_read"]
              and p["sha256"] == row["sha256"] == row["actual"]["sha256"])
        bodies[row["scope"], row["path"]] = raw
    def body(scope, name):
        return bodies[scope, name]
    def value(scope, name):
        return json.loads(body(scope, name))
    def inner(name): return value("INNER", name)
    def outer(name): return value("OUTER", PUBLIC + name)
    def relative(path):
        require("path", "fixed-original-root", path.startswith(ORIGINAL_ROOT + "/"))
        return path[len(ORIGINAL_ROOT) + 1:]
    def join(rec, scope="INNER", path=None, physical_required=True):
        key = (scope, relative(rec["path"]) if path is None else path)
        if key not in bodies:
            if physical_required: check("record", "missing:" + key[1], False)
            return False
        raw = body(*key); r = record(raw)
        check("record", key[1], r["bytes"] == rec["bytes"] and r["sha256"] == rec["sha256"]
              and ("git_blob" not in rec or rec["git_blob"] == r["git_blob"]))
        return True

    catalog = outer("ORIGINAL-CATALOG.json")
    custody = outer("CUSTODY.json")
    final = outer("FINAL.json")
    inventory = load_json("INNER-INVENTORY.json")
    observed = {x["path"]: x for x in inventory["members"]}
    cat = {x["path"]: x for x in catalog["originals"]}
    require("catalog", "unique-23967", len(cat) == len(catalog["originals"]) == 23967)
    require("catalog", "unique-observed-23967", len(observed) == len(inventory["members"]) == 23967)
    check("catalog", "one-root-one-manifest", set(cat) - set(observed) == {"."}
          and set(observed) - set(cat) == {".FULL-RETAINED-TYPED-MANIFEST.json"})
    for name in sorted(set(cat) & set(observed)):
        c, o = cat[name], observed[name]
        equal = c["kind"] == o["kind"]
        if c["kind"] == "regular":
            equal = equal and (c["bytes"], c["sha256"]) == (o["bytes"], o["sha256"])
        ident = c["identity"]
        equal = equal and stat.S_IMODE(ident[2]) == o["mode"] and ident[3] == o["uid"] and ident[4] == o["gid"]
        equal = equal and ident[7] // 1_000_000_000 == o["mtime"]
        check("catalog-recorded-metadata", name, bool(equal))
    for (scope, name), raw in bodies.items():
        if scope != "INNER": continue
        c = cat[name]; r = record(raw)
        check("catalog-to-selected-physical", name, c["kind"] == "regular" and
              c["bytes"] == r["bytes"] and c["sha256"] == r["sha256"])
    check("catalog", "original-custody-complete",
          inventory["complete"] is True and catalog["all_regular_bytes_selected"] is True
          and catalog["full_namespace_observed"] is True and catalog["unreadable_regular_paths"] == []
          and catalog["unlisted_directory_paths"] == [] and custody["all_regular_bytes_read_back"] is True
          and custody["archive_members"] == custody["original_members"] == 23967
          and custody["regular_bytes"] == sum(x.get("bytes", 0) for x in cat.values() if x["kind"] == "regular")
          and final["complete_custody"] is True and final["whole_native_delivery_qualified"] is False)
    check("catalog", "complete-catalog-pins", custody["catalog"]["sha256"] ==
          record(body("OUTER", PUBLIC+"ORIGINAL-CATALOG.json"))["sha256"])

    supply = inner("supply/SUPPLY.json")
    script = body("INNER", "control/supply_v87.py")
    plan = inner("control/supply-plan.json")
    join(supply["script"]); join(supply["configuration"])
    check("source", "actual-supplier-pin", record(script)["sha256"] ==
          "cb25fcc04be3414afce234e8842247639e6390d825198a329bb7460c089a4321")
    before = body("INNER", "supply/reports/source-before.snapshot.json")
    after = body("INNER", "supply/reports/source-after.snapshot.json")
    join(supply["source_before"]); join(supply["source_after"])
    check("source", "whole-snapshot-byte-identical", before == after)
    source = json.loads(before)
    check("source", "historical-v89-source-record",
          source["head"] == "784f088fcc5ad81c65de541d54e26d380c86293c"
          and source["tree"] == "d9e8407c70e44a3ea0152b8b4c5eb2ed3833d790"
          and source["full_physical_read"] is True and source["leaves"] == len(source["files"]) == 4076
          and supply["source"] == {k: source[k] for k in ("head", "tree")})
    steps = supply["steps"]
    require("workflow", "59-original-steps", len(steps) == 59)
    failed = []
    missing_log_bodies = []
    for ordinal, row in enumerate(steps, 1):
        stem = "%03d-%s" % (ordinal, row["label"])
        reqpath = "supply/requests/" + stem + ".json"
        retpath = "supply/logs/" + stem + ".receipt.json"
        completedpath = "supply/reports/" + stem + ".completed.json"
        req, ret, completed = inner(reqpath), inner(retpath), inner(completedpath)
        check("workflow", stem+"-exact-values", req == row["request_value"]
              and ret == row["returned"] and completed == row)
        for field in ("request", "receipt"): join(row[field])
        check("workflow", stem+"-command-closed",
              req["command"] == ret["command"] and req["cwd"] == ret["cwd"]
              and req["seconds"] == ret["workflow_seconds"] and row["observed_process_group_closed"] is True
              and ret["schema"] == "hepta.hia.external-workflow-process.v1"
              and ret["cleanup"]["complete"] is True and ret["cleanup"]["errors"] == []
              and ret["cleanup"]["full_process_tree_claimed"] is False
              and ret["cleanup"]["scope"] == "started POSIX process group only"
              and ret["selfhost_qualification_gate_modified"] is False)
        log_pins = {}
        for field in ("stdout", "stderr"):
            rec = row[field]; rel = relative(rec["path"])
            check("workflow", stem+"-"+field+"-catalog",
                  req[field] == rec["path"] and cat[rel]["bytes"] == rec["bytes"]
                  and cat[rel]["sha256"] == rec["sha256"])
            if not join(rec, physical_required=False):
                missing_log_bodies.append(rel)
            log_pins[rec["path"]] = rec["sha256"]
        check("workflow", stem+"-logs", ret["logs"] == log_pins)
        if ret["returncode"] != 0 or ret["status"] != "WORKFLOW_STEP_COMPLETED":
            failed.append({"ordinal": ordinal, "label": row["label"], "returned": ret})
        else:
            check("workflow", stem+"-natural", ret["timed_out"] is False and ret["cleanup"]["signalled"] == [])
    check("failure", "one-original-command-failed", [(x["ordinal"],x["label"]) for x in failed] == [(56,"rust195-install")])
    check("failure", "two-whole-log-bodies-not-recovered",
          sorted(missing_log_bodies) == ["supply/logs/018-qemu-data-tar.stdout", "supply/logs/021-boost-data-tar.stdout"])

    row = steps[55]; req = row["request_value"]; ret = row["returned"]
    check("failure", "056-exact-command", req["command"] ==
          ["/home/runner/.cargo/bin/rustup","toolchain","install","1.95.0","--profile","minimal"])
    check("failure", "056-failed-not-timeout", ret["returncode"] == 1 and ret["status"] == "WORKFLOW_STEP_HOLD"
          and ret["timed_out"] is False and ret["cleanup"]["signalled"] == [] and req["seconds"] == 1200
          and ret["seconds"] == 6.275462164999993)
    env = req["environment"]
    check("failure", "056-private-homes-real-HOME", env["HOME"] == "/home/runner"
          and env["CARGO_HOME"] == ORIGINAL_ROOT+"/supply/rustup195-cargo"
          and env["RUSTUP_HOME"] == ORIGINAL_ROOT+"/supply/rustup195"
          and env["RUSTUP_DIST_SERVER"] == "https://static.rust-lang.org"
          and env["RUSTUP_UPDATE_ROOT"] == "https://static.rust-lang.org/rustup"
          and "CI" not in env and "RUSTUP_CI" not in env)
    out = body("INNER","supply/logs/056-rust195-install.stdout").decode()
    err = body("INNER","supply/logs/056-rust195-install.stderr").decode()
    check("failure", "056-original-error", err.endswith(
          "error: rustup is not installed at '"+ORIGINAL_ROOT+"/supply/rustup195-cargo'\n")
          and "1.95.0-x86_64-unknown-linux-gnu installed - rustc 1.95.0" in out)
    check("failure", "later-install-validation-not-executed", not any(
          r["label"] in ("rust195-which","rust195-cargo-version","rust195-rustc-version") or
          re.fullmatch("rust195-(cargo|rustc|rust-std)-verify",r["label"]) for r in steps))
    check("failure", "supply-HOLD-no-qualification", supply["status"] == "HOLD"
          and supply["qualification_executed"] is False and "rust195_provenance" not in supply)
    version = body("INNER","supply/logs/055-rustup-version.stdout").decode()
    check("failure", "recorded-rustup-version", version == "rustup 1.29.2 (d8c92c676 2026-10-21)\n")
    rustup_sha = supply["input_bindings"].get("/home/runner/.cargo/bin/rustup")
    check("failure", "recorded-rustup-input-SHA", rustup_sha ==
          "5be191e8c70a5007074254cb74d78dbfdd25cd5a61c27de7b8e5410122ec24f4")
    check("failure", "private-rustup-binary-absent-from-observed-namespace",
          not any(p == "supply/rustup195-cargo" or p.startswith("supply/rustup195-cargo/") for p in observed))
    syntax = ast.parse(script)
    rust195 = next(n for n in ast.walk(syntax) if isinstance(n,ast.FunctionDef) and n.name=="rust195")
    calls = [n for n in ast.walk(rust195) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute)
             and n.func.attr=="step" and n.args and isinstance(n.args[0],ast.Constant) and n.args[0].value=="rust195-install"]
    check("failure", "actual-script-command-stage", len(calls)==1 and calls[0].lineno==1528
          and [x.value for x in calls[0].args[1].elts[1:]] == req["command"][1:])

    # Original full32 owner failed naturally during supply, before any qualification report.
    full_req = outer("GUARDIAN-REQUEST.json")
    full_guard = outer("qualification-guardian-originals/guardian.json")
    full_life = full_guard["lifecycle"]
    check("full-owner", "original-request-copy", full_req == outer("qualification-guardian-originals/request.json"))
    check("full-owner", "actual-request-and-inputs",
          full_guard["command"] == full_req["command"] and full_guard["cwd"] == full_req["cwd"]
          and full_guard["external_controller_seconds"] == full_req["controller_seconds"] == 10800
          and full_guard["source_identities_before"] == full_guard["source_identities_after"] == full_req["source_identities"]
          and full_guard["input_identity_preserved"] is True
          and full_guard["lifecycle_implementation_sha256"] == "36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2")
    for path,digest in full_req["source_identities"].items():
        if path.startswith(ORIGINAL_ROOT+"/"):
            rel=relative(path)
            check("full-owner", "catalog-input:"+rel, cat[rel]["sha256"]==digest)
            if ("INNER",rel) in bodies:
                check("full-owner", "actual-selected-input:"+rel, record(body("INNER",rel))["sha256"]==digest)
        else:
            check("full-owner", "recorded-runtime-input", path=="/opt/hostedtoolcache/Python/3.14.4/x64/bin/python3.14"
                  and supply["input_bindings"].get(path)==digest)
    fc=full_life["cleanup"]
    check("full-owner", "closed-natural-nonzero",
          full_life["qualification_seconds"]==10800 and full_life["cleanup_seconds"]==3
          and full_life["subreaper_enabled"] is True and full_life["returncode"]==1
          and full_life["timed_out"] is False and full_life["exit_observed_before_deadline"] is True
          and full_life["interrupted_signals"]==[] and full_life["event_overflow"] is False
          and fc["complete"] is True and fc["observed_echild"] is True and fc["leader_reaped"] is True
          and fc["remaining_direct_children"]==[] and fc["errors"]==[] and fc["deadline_exceeded"] is False
          and [e["kind"] for e in full_life["events"]]==["qualification_started","owned_child_observed","qualification_exit_observed","owned_child_reaped"]
          and full_life["events"][2]["si_status"]==full_life["events"][3]["returncode"]==1
          and full_guard["status"]=="HOLD" and full_guard["qualification"] is None
          and full_guard["whole_native_delivery_qualified"] is False)
    for field in ("stdout","stderr"):
        raw=body("INNER","guard/child."+field+".log")
        check("full-owner", "child-"+field, full_guard["logs"][ORIGINAL_ROOT+"/guard/child."+field+".log"]==record(raw)["sha256"]
              and raw==body("OUTER",PUBLIC+"qualification-guardian-originals/child."+field+".log"))

    # Root-owned APT closure is read independently of sudo's successful return.
    apt_results = {}
    owner_names = ("config.json","root-process.json","environment.json","guardian.json","child.stdout.log","child.stderr.log")
    for phase, inner_seconds, outer_seconds, ordinal in (("update",590,600,8),("install",890,900,9)):
        prefix = "supply/evidence/apt-owned-"+phase+"/"
        names = sorted(p[len(prefix):] for scope,p in bodies if scope=="INNER" and p.startswith(prefix))
        check("apt-"+phase, "exact-six-originals", names == sorted(owner_names))
        cfg = inner(prefix+"config.json"); process = inner(prefix+"root-process.json")
        environment = inner(prefix+"environment.json"); guard = inner(prefix+"guardian.json")
        life = guard["lifecycle"]; cleanup = life["cleanup"]
        command = ["/usr/bin/apt-get","update"] if phase=="update" else [
            "/usr/bin/apt-get","-o","Dir::Cache::archives="+ORIGINAL_ROOT+"/supply/apt-cache",
            "-o","APT::Keep-Downloaded-Packages=true","install","-y",
            "binutils","gcc","clang-20","libclang-rt-20-dev","strace","llvm-20","lld-20"]
        check("apt-"+phase, "original-root-owned-command",
              cfg["command"] == command and cfg["controller_seconds"] == inner_seconds
              and cfg["cwd"] == ORIGINAL_ROOT+"/supply"
              and process["uid"] == process["euid"] == 0
              and set(process)=={"uid","euid","gid","egid","pid","ppid","pgid","sid"}
              and all(type(v) is int for v in process.values()))
        check("apt-"+phase, "guardian-original-inputs",
              guard["command"] == cfg["command"] and guard["cwd"] == cfg["cwd"]
              and guard["external_controller_seconds"] == inner_seconds
              and guard["lifecycle_implementation_sha256"] == "36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2"
              and guard["lifecycle_entry"] == "supervise; distinct external schema and deadline"
              and guard["source_identities_before"] == guard["source_identities_after"] == cfg["source_identities"]
              and guard["input_identity_preserved"] is True and guard["cold_180_second_gate_modified"] is False
              and guard["qualification"] is None and guard["whole_native_delivery_qualified"] is False)
        for path, digest in cfg["source_identities"].items():
            if not path.startswith(ORIGINAL_ROOT + "/"):
                check("apt-"+phase, "external-recorded-pin:"+path,
                      path in {"/opt/hostedtoolcache/Python/3.14.4/x64/bin/python3.14", "/usr/bin/apt-get", "/usr/bin/sudo"}
                      and supply["input_bindings"].get(path) == digest)
                continue
            rel=relative(path)
            if rel.startswith("source/"):
                check("apt-"+phase, "source-pin:"+rel, source["files"][rel[7:]]["sha256"]==digest)
            else:
                check("apt-"+phase, "raw-pin:"+rel, record(body("INNER",rel))["sha256"]==digest)
        check("apt-"+phase, "actual-root-lifecycle",
              life["supervisor_pid"] == process["pid"] and life["parent_pid"] == process["ppid"]
              and life["qualification_seconds"]==inner_seconds and life["cleanup_seconds"]==3
              and life["subreaper_enabled"] is True and life["qualification_started"] is True
              and life["event_overflow"] is False and cleanup["attempted"] is True
              and cleanup["complete"] is True and cleanup["observed_echild"] is True
              and cleanup["leader_reaped"] is True and cleanup["remaining_direct_children"]==[]
              and cleanup["errors"]==[] and cleanup["deadline_exceeded"] is False)
        events=life["events"]; qpid=life["qualification_pid"]
        kinds={name:[e for e in events if e["kind"]==name and e.get("pid")==qpid] for name in
               ("qualification_started","owned_child_observed","qualification_exit_observed","owned_child_reaped")}
        require("apt-"+phase,"four-unique-leader-events",all(len(x)==1 for x in kinds.values()))
        observed_event=kinds["owned_child_observed"][0]; reaped=kinds["owned_child_reaped"][0]
        check("apt-"+phase,"natural-events",kinds["qualification_exit_observed"][0]["si_status"]==reaped["returncode"]==0
              and observed_event["ppid"]==process["pid"] and observed_event["start_ticks"]==reaped["start_ticks"]
              and all(a["monotonic_ns"]<=b["monotonic_ns"] for a,b in zip(events,events[1:]))
              and not any(e["kind"]=="owned_child_sigkill" for e in events))
        check("apt-"+phase,"natural-status",guard["status"]=="EXTERNAL_OWNED_PROCESS_COMPLETED"
              and life["status"]=="OWNED_PROCESS_COMPLETED" and life["returncode"]==0
              and life["timed_out"] is False and life["exit_observed_before_deadline"] is True
              and life["interrupted_signals"]==[] and life.get("owner_error") is None)
        logs={ORIGINAL_ROOT+"/"+prefix+n:record(body("INNER",prefix+n))["sha256"] for n in owner_names[-2:]}
        check("apt-"+phase,"complete-child-logs",guard["logs"]==logs)
        owner=supply["apt_root_owners"][phase]
        worker=inner("supply/requests/apt-"+phase+".worker.json")
        result=inner("supply/reports/apt-"+phase+".result.json"); detail=result["result"]
        check("apt-"+phase,"root-worker-request",
              worker["kind"]=="apt_owned" and worker["data"]["phase"]==phase
              and worker["data"]["external_request"]==ORIGINAL_ROOT+"/supply/requests/%03d-apt-%s.json"%(ordinal,phase)
              and worker["script_sha256"]==record(script)["sha256"]
              and worker["configuration_sha256"]==record(body("INNER","control/supply-plan.json"))["sha256"])
        check("apt-"+phase,"outer-root-group",
              owner["outer_group_closed"] is True and owner["outer_evidence"]["value"]==steps[ordinal-1]["returned"]
              and steps[ordinal-1]["request_value"]["seconds"]==outer_seconds)
        check("apt-"+phase,"result-handoff",
              result["status"]=="SUPPLY_OPERATION_COMPLETED" and result["kind"]=="apt_owned"
              and result["qualification_executed"] is False and detail["external_seconds"]==outer_seconds
              and detail["inner_seconds"]==inner_seconds and detail["cleanup_seconds"]==3
              and detail["closed"] is True and detail["natural"] is True
              and detail["evidence_handoff_complete"] is True and detail["cache_ownership_here"] is False
              and detail["cache_handoff_remains_separate_original_180_step"] is True
              and detail["guardian_exit"]==0 and owner["cache_handoff_authorized"] is True
              and owner["root_owner_closed"] is True and owner["status"]=="APT_ROOT_OWNED_COMMAND_COMPLETED")
        join(owner["root_worker_result"])
        cur=owner["current_evidence"]; orig=owner["original_root_evidence"]
        check("apt-"+phase,"raw-config-handoff",cur["config"]==orig["config"]==cfg
              and cur["root_process"]==orig["root_process"]==process
              and cur["environment_sha256"]==orig["environment_sha256"]==record(body("INNER",prefix+"environment.json"))["sha256"]
              and detail["runner_owned_evidence"]==cur and detail["original_root_evidence"]==orig
              and cur["state"]==orig["state"]==owner["owner_state"])
        attempts=detail["ownership_attempts"]
        check("apt-"+phase,"six-handoff-denominator",len(attempts)==6
              and set(cur["originals"])==set(orig["originals"])==set(owner_names))
        for name, attempt in zip(owner_names, attempts):
            old,new=orig["originals"][name],cur["originals"][name]
            join(new)
            oi,ni=old["identity"],new["identity"]
            check("apt-"+phase,"unchanged-handoff:"+name,
                  old["sha256"]==new["sha256"] and old["bytes"]==new["bytes"]
                  and old["path"]==new["path"]==ORIGINAL_ROOT+"/"+prefix+name
                  and oi[3]==0 and ni[3]==worker["data"]["uid"] and ni[4]==worker["data"]["gid"]
                  and oi[5]==ni[5]==1 and ni[2]==oi[2]|0o600
                  and all(oi[k]==ni[k] for k in (0,1,5,6,7))
                  and attempt=={"name":name,"before":oi,"after":ni,"sha256":old["sha256"],
                                "status":"OWNERSHIP_RETURNED_BYTES_UNCHANGED"})
        apt_results[phase]={"inner_seconds":inner_seconds,"outer_seconds":outer_seconds,"cleanup_seconds":3,
            "root_process":process,"qualification_pid":qpid,"events":len(events),"closed":True,"natural":True,
            "guardian_pin":record(body("INNER",prefix+"guardian.json")),
            "all_six_originals_locally_read":True}
    cache=inner("supply/reports/apt-cache-owner.result.json")
    check("apt-cache","exact-result",cache["status"]=="SUPPLY_OPERATION_COMPLETED"
          and cache["result"]==supply["apt_cache_ownership"] and cache["qualification_executed"] is False)
    check("apt-cache","original-180-seconds",steps[9]["label"]=="apt-cache-owner"
          and steps[9]["request_value"]["seconds"]==180 and steps[9]["returned"]["returncode"]==0)
    for a in cache["result"]["attempts"]:
        oi,ni=a["before"],a["after"]
        check("apt-cache","handoff:"+a["relative"],
              a["status"]=="OWNERSHIP_RETURNED_BYTES_UNCHANGED"
              and ni[3]==cache["result"]["uid"] and ni[4]==cache["result"]["gid"]
              and all(oi[k]==ni[k] for k in (0,1,2,5,6,7))
              and ("sha256_before" not in a or a["sha256_before"]==a["sha256_after"]))
    check("apt-cache","apt-supply-success-record",inner("supply/reports/apt-supply.json")==supply["apt"])

    recovery=load_json("current--recovery.json")
    check("receiver","historical-results-preserved",recovery["qualification_executed"] is False
          and recovery["project_code_executed"] is False and recovery["original_product_statuses_reclassified"] is False)
    check("receiver","expected-transport-HOLD",recovery["failed_stage"]=="FULL_ORIGINAL_AFTER"
          and recovery["error_type"]=="Refusal" and recovery["all_available_original_bodies_read"] is True
          and index["diagnostic_channel_complete"] is False)
    check("receiver","exact-two-whole-omissions",index["omitted_whole_originals"]==[
        {"bytes":136468480,"path":"supply/logs/018-qemu-data-tar.stdout","reason":"FILE_BOUND","scope":"INNER","status":"OMITTED_WHOLE_ORIGINAL"},
        {"bytes":164628480,"path":"supply/logs/021-boost-data-tar.stdout","reason":"FILE_BOUND","scope":"INNER","status":"OMITTED_WHOLE_ORIGINAL"}])
    partition=recovery["partition"]
    check("receiver","ten-reported-contiguous-ranges",len(partition["parts"])==10
          and partition["total_bytes"]==3010752230
          and partition["concatenated_sha256"]==REPORT["original_artifact"]["sha256"]
          and partition["exact_contiguous_partition"] is True)
    REPORT.update({
        "selected_originals":len(rows),"selected_original_bytes":sum(r["bytes"] for r in rows),
        "selected_scope_counts":dict(Counter(r["scope"] for r in rows)),
        "original_catalog_metadata_rows_joined":len(set(cat)&set(observed)),
        "original_catalog_kind_counts":dict(Counter(r["kind"] for r in cat.values())),
        "recorded_original_namespace_regular_bytes":custody["regular_bytes"],
        "entire_namespace_bytes_locally_read":False,
        "supply_original_status":supply["status"],"original_qualification_executed":supply["qualification_executed"],
        "original_command_population":len(steps),"failed_original_commands":failed,
        "rust195_failed_command_request":req,
        "rustup_original_binding_sha256":rustup_sha,"rustup_original_version_stdout":version,
        "rustup_binary_locally_read":False,"rustup_binary_scope":"Original supply input_binding and raw version stdout; binary not selected.",
        "rust195_stdout":out,"rust195_stderr":err,
        "rust195_next_validation_steps_executed":False,
        "rust195_toolchain_recorded_partial_files":[observed[p] for p in sorted(observed)
            if p.endswith(("/bin/cargo","/bin/rustc")) and p.startswith("supply/rustup195/")],
        "toolchain_file_scope":"Original producer/receiver inventory SHA only; no local full binary readback or promotion to accepted supply.",
        "apt":apt_results,"apt_cache_handoff_attempts":len(cache["result"]["attempts"]),
        "source_snapshot_full_bytes_equal":True,"recorded_source_head":source["head"],"recorded_source_tree":source["tree"],
        "source_files_independently_reread_here":False,
        "external_APT_tools_scope":"Python, apt-get and sudo original recorded input hashes only; their binaries were not selected and were not locally reread.",
        "original_full_owner":{"returncode":1,"timed_out":False,"closed_ECHILD":True,"seconds":10800,"cleanup_seconds":3,"qualification_report":None},
        "reader_r1_correction":"The original reader rejected three valid external APT executable paths as outside the archived operation root. r1 HOLD is preserved. r2 joins these fixed external paths to original input_bindings and explicitly does not claim physical binary readback.",
        "receiver_original_failure":{"stage":recovery["failed_stage"],"error_type":recovery["error_type"],
                                    "safe_refusal":recovery["safe_refusal"],"elapsed_ns":recovery["elapsed_ns"]},
        "omitted_whole_originals":index["omitted_whole_originals"],
        "parts_downloaded_here":0,"full_original_zip_locally_reconstructed":False,
        "pins":PINS,
    })
def entry():
    parser=argparse.ArgumentParser()
    parser.add_argument("--output",required=True)
    ns=parser.parse_args()
    started=__import__("time").monotonic_ns()
    try: main()
    except BaseException as e:
        FAILURES.append({"group":"reader","name":type(e).__name__,"detail":str(e),"traceback":traceback.format_exc()})
    REPORT.update(check_groups=dict(CHECKS),checks=sum(CHECKS.values()),failures=FAILURES,
                  status="SELECTED_ORIGINALS_AND_FAILURE_JOINS_PASS" if not FAILURES else "READER_HOLD",
                  elapsed_ns=__import__("time").monotonic_ns()-started,
                  script=record(Path(__file__).read_bytes()))
    p=Path(ns.output)
    raw=(json.dumps(REPORT,ensure_ascii=False,sort_keys=True,indent=2)+"\n").encode()
    with p.open("xb") as out:out.write(raw);out.flush();os.fsync(out.fileno())
    assert p.read_bytes()==raw
    print(json.dumps({"status":REPORT["status"],"checks":REPORT["checks"],"failures":FAILURES,
                     "report":str(p),**record(raw)},ensure_ascii=False))
    return 0 if not FAILURES else 1
if __name__=="__main__": raise SystemExit(entry())
