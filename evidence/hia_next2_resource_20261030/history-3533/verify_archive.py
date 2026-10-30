#!/usr/bin/env python3
"""Bounded same-bytes archive verification; never extract or execute archived code."""
from hashlib import sha256
from pathlib import Path, PurePosixPath
from collections import Counter
import io,json,lzma,os,re,stat,sys,tarfile,time
MAX_FILE_BYTES=16*1024*1024
MAX_TOTAL_BYTES=64*1024*1024
MAX_COMPRESSED_BYTES=16*1024*1024
MAX_MANIFEST_BYTES=1024*1024
MAX_MEMBERS=256
PAYLOADS={}
CACHE={}

def require(condition, message):
    if not condition:
        raise ValueError(message)

def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()

def pairs(items):
    value = {}
    for name, item in items:
        require(name not in value, "duplicate JSON member")
        value[name] = item
    return value

def decode(data):
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError("nonfinite JSON")))

def matches(path, identity):
    data = read_once(path)
    require(type(identity["bytes"]) is int and len(data) == identity["bytes"]
            and sha256(data).hexdigest() == identity["sha256"], "retained bytes differ: " + str(path))
    return data

def cleanup_consistency(report, body):
    """Recount the recorded finite journal. This does not execute or prove Core."""
    request, bound, cleanup = report["request"], report["cleanup_bound"], report["cleanup"]
    execution = report["runtime"]["execution"]
    require(sha256(wire(request)).hexdigest() == report["request_sha256"], "exact request hash differs")
    require(request["profile"] == report["profile"] == "raw-byte-dag-finite-heap-cleanup-v1"
            and report["status"] == "admitted_and_observed", "cleanup profile/status differs")
    maximum_formals = max(sum(p["type"] in {"readbuf", "mutbuf"} for p in f["params"])
                          for f in body["functions"])
    planned = bound["max_allocator_interactions"] + bound["max_vm_ticks"] * (1 + maximum_formals)
    require(planned == bound["action_bound"] == cleanup["reserved_actions"]
            and bound["max_borrowed_parameters"] == maximum_formals
            and planned <= request["cleanup_policy"]["max_cleanup_actions"] <= 32768
            and bound["fixed_action_limit"] == 32768, "finite journal reservation differs")
    require(bound["function"] == request["function"] and bound["arguments"] == request["arguments"]
            and bound["program_sha256"] == request["program_sha256"] == execution["program_sha256"],
            "cleanup bound/request identity differs")
    before, after, events = cleanup["before"], cleanup["after"], cleanup["events"]
    stopped = execution["status"] != "returned"
    require(wire(before) == wire(execution["resources"]) and cleanup["error"] is None
            and cleanup["status"] == ("completed" if stopped else "not_needed")
            and type(events) is list and len(events) == cleanup["actions"] <= planned,
            "cleanup lost original stop, failed or exceeded reservation")
    require(cleanup["claims"]["host_panic_oom_or_termination_cleanup_guaranteed"] is False
            and cleanup["claims"]["general_unwind_or_native_cleanup_proved"] is False
            and cleanup["claims"]["journal_reserved_before_language_execution"] is True
            and report["claims"]["native_execution_authorized"] is False
            and report["claims"]["default_production_admission_changed"] is False,
            "cleanup scope/authority changed")
    loans, owners = {}, {}
    owner_phase = False
    last_loan = last_owner = 1 << 64
    for event in events:
        if event["op"] == "end_loan":
            require(not owner_phase and type(event["loan"]) is int and 0 < event["loan"] < last_loan
                    and event["parent_kind"] in {"loan", "owner"}
                    and type(event["mutable"]) is bool and type(event["call_formal"]) is bool,
                    "loan journal order/flags differ")
            last_loan = event["loan"]; loans[last_loan] = event
        else:
            require(event["op"] == "drop_owner" and type(event["owner"]) is int
                    and 0 < event["owner"] < last_owner and type(event["bytes"]) is int
                    and event["bytes"] >= 0, "owner journal order/type differs")
            owner_phase = True; last_owner = event["owner"]; owners[last_owner] = event
    for identity, event in loans.items():
        require(event["root_owner"] in owners, "loan root was not explicitly dropped")
        if event["parent_kind"] == "owner":
            require(event["parent"] == event["root_owner"] and not event["call_formal"], "formal/root parent differs")
        else:
            parent = loans.get(event["parent"])
            require(parent is not None and event["parent"] < identity
                    and parent["root_owner"] == event["root_owner"]
                    and (not event["mutable"] or parent["mutable"]), "loan parent graph differs")
    formals = sum(e["call_formal"] for e in loans.values())
    local = len(loans) - formals
    frees = sum(e["bytes"] != 0 for e in owners.values())
    require(formals == cleanup["call_formal_loans_before"] and cleanup["call_formal_loans_after"] == 0
            and len(owners) == before["live_owners"] and local == before["live_local_loans"]
            and local == before["loans_started"] - before["loans_ended"]
            and frees == before["allocations"] - before["frees"]
            and sum(e["bytes"] for e in owners.values()) == before["live_bytes"], "complete inventory counters differ")
    expected = {**before, "live_owners":0, "live_bytes":0, "live_local_loans":0,
                "owners_dropped":before["owners_dropped"]+len(owners),
                "loans_ended":before["loans_ended"]+local, "frees":before["frees"]+frees}
    require(wire(after) == wire(expected) and cleanup["inventory_records"] == len(events)
            and cleanup["inventory_records_checked"] == (len(events) if stopped else 0)
            and (stopped or not events), "exact after ledger or normal-return scope differs")


def read_once(path):
    key=str(path)
    require(key in PAYLOADS, "archive member missing: "+key)
    if key not in CACHE:
        CACHE[key]=PAYLOADS[key]
    return CACHE[key]


def bounded_file(path, maximum):
    path=Path(path).absolute()
    require(all(not p.is_symlink() for p in (path,*path.parents)), "symlink input refused")
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        before=os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= maximum, "bounded regular input required")
        data=b""
        while True:
            block=os.read(fd,min(65536,maximum+1-len(data)))
            if not block:break
            data+=block
            require(len(data)<=maximum,"input byte limit")
        after=os.fstat(fd)
        require((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==
                (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
                and len(data)==before.st_size,"input changed during read")
        return data
    finally:os.close(fd)


def verify(base):
    started = time.monotonic_ns()
    base = PurePosixPath(base)
    run = base / "run"
    receipt = decode(read_once(run / "RECEIPT.json"))
    require(receipt["schema"] == "hepta.rust-scoped-cleanup.integrated-focused-attempt.v1"
            and receipt["status"] == "completed", "completed attempt required")
    plan = decode(matches(base / "PLAN.json", receipt["plan"]))
    matches(base / "launch.py", receipt["launcher"])
    require(plan["launcher_sha256"] == receipt["launcher"]["sha256"], "launcher plan mismatch")
    require(receipt["new_holdout"] is False and plan["new_holdout"] is False,
            "same-corpus execution cannot become new holdout")
    require(receipt["errors"] == [], "terminal errors retained")
    require(all(receipt[k] is True for k in ("source_unchanged", "tools_unchanged", "plan_unchanged", "launcher_unchanged")),
            "identity changed")
    files = receipt["retained_files"]
    for name, identity in files.items():
        path = PurePosixPath(name)
        require(not path.is_absolute() and ".." not in path.parts and str(run / path) in PAYLOADS,
                "unsafe retained path")
        matches(run / path, identity)
    actual_files = {name[len(str(run))+1:] for name in PAYLOADS if name.startswith(str(run)+"/") and name != str(run / "RECEIPT.json")}
    require(actual_files == set(files), "retained file inventory differs")
    before = decode(read_once(run / "source-before.json"))
    after = decode(read_once(run / "source-after.json"))
    require(before == after and before["head"] == plan["source_head"] and before["tree"] == plan["source_tree"]
            and before["status"] == "", "recorded exact-source binding differs")
    require(receipt["tools_before"] == receipt["tools_after"], "recorded tool identities differ")
    require([r["id"] for r in receipt["stages"]] == [s["id"] for s in plan["stages"]] == ["focused", "rust"],
            "ordered stage inventory differs")
    for stage, planned in zip(receipt["stages"], plan["stages"]):
        require(stage["argv"] == planned["argv"] and stage["returncode"] == 0
                and stage["status"] == "completed" and stage["cleanup_errors"] == []
                and stage["persistence_errors"] == [] and stage["outcome"]["passed"] is True,
                "stage did not pass completely")
        require(stage == decode(read_once(run / stage["id"] / "execution.json")),
                "outer and stage receipt differ")
        require(before == decode(read_once(run / stage["id"] / "source-after.json")),
                "stage source changed")
    focused, rust = receipt["stages"]
    rust_log = read_once(run / "rust/stdout").decode()
    require(sum(map(int, re.findall(r"test result: ok\. (\d+) passed", rust_log))) == rust["outcome"]["tests_run"],
            "Rust actual footer denominator differs")
    footers = list(re.finditer(r"(?m)^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; "
        r"(\d+) ignored; (\d+) measured; (\d+) filtered out; finished in [0-9.]+s\s*$", rust_log))
    require(len(footers) == rust["outcome"]["test_binaries"] and footers
            and all(m[1] == "ok" and all(int(m[index]) == 0 for index in (3, 4, 5, 6)) for m in footers)
            and not rust_log[footers[-1].end():].strip(), "complete Rust footer/count status differs")
    require(all(rust["outcome"][k] == 0 for k in ("failures", "filtered_out", "skipped", "measured")), "Rust exclusions changed")
    stderr = read_once(run / "focused/stderr").decode()
    methods = sorted(re.findall(r"(?m)^test\w+ \((tests\.[^\s)]+)\) \.\.\. ok$", stderr))
    require(methods == plan["focused_test_methods"] and len(methods) == focused["outcome"]["tests_run"],
            "focused actual method set differs")
    require(re.search(r"Ran " + str(len(methods)) + r" tests in [\d.]+s\n\nOK\s*$", stderr), "focused footer differs")
    raw = decode(read_once(run / "focused/raw/actual.json"))
    binary = focused["binary_after"]
    require(raw["executable_sha256"] == binary["sha256"] == rust["binary_after"]["sha256"], "binary binding differs")
    require(raw["build"]["returncode"] == 0, "actual Cargo build failed")
    require(raw["claims"]["positive_native_responses_are_actual"] is True
            and raw["claims"]["new_holdout"] is False, "raw corpus scope differs")
    responses = Counter()
    response_processes = {}
    processes = {wire(p) for p in raw["processes"]}
    for process in raw["processes"]:
        require(process["executable_sha256"] == binary["sha256"], "process binary differs")
        payload = raw["programs"][process["input_sha256"]].encode()
        require(sha256(payload).hexdigest() == process["input_sha256"], "actual process input differs")
        require(type(process["outer_wall_ns"]) is int and process["outer_wall_ns"] > 0, "process cost omitted")
        if process["returncode"] == 0:
            require(process["stderr"] == "", "successful process has diagnostics")
            response_key = (wire(decode(process["stdout"])), process["test"])
            responses[response_key] += 1
            response_processes.setdefault(response_key, []).append(process)
    for observation in raw["observations"]:
        report = observation["rust_report"]
        body = decode(raw["programs"][report["request"]["input_sha256"]])
        cleanup_consistency(report, body)
        response_key = (wire(report), observation["test"])
        require(observation["matched"] is True and responses[response_key] > 0,
                "observation lacks a distinct actual producer response")
        responses[response_key] -= 1
        process = response_processes[response_key].pop()
        request = report["request"]
        argv = process["argv_after_executable"]
        require(len(argv) == 7 and argv[0] == "--byte-dag-heap-cleanup-admit-run"
                and argv[1] == request["function"] and process["input_sha256"] == request["input_sha256"]
                and wire([decode(arg) for arg in argv[2:]]) == wire([request[key] for key in
                    ("arguments", "static_policy", "heap_policy", "cleanup_policy", "execution_policy")])
                and sha256(wire(body)).hexdigest() == request["program_sha256"],
                "actual input/argv does not bind the observation request")
        require(report["heap_bound"]["peak_bound_bytes"] == observation["python_bound"]["peak_bound_bytes"],
                "independent bound differs")
        actual, oracle = report["runtime"]["execution"], observation["python_execution"]
        require(all(wire(actual[k]) == wire(oracle[k]) for k in ("status", "steps", "resources")),
                "exact stopped runtime observation differs")
        require(wire(actual["values"]) == wire(oracle["values"]) if actual["status"] == "returned"
                else actual["error"]["code"] == oracle["error"]["code"], "values or trap code differ")
        require(actual["resources"]["peak_bytes"] <= report["heap_bound"]["peak_bound_bytes"], "observed payload exceeds bound")
    for refused in raw["refusals"]:
        require(wire(refused) in processes and refused["returncode"] == 1 and refused["stdout"] == ""
                and refused["stderr"].startswith("E_HIA_"), "refusal is not a retained actual process")
    counts = receipt["scoped_cleanup_observed_counts"]
    require(counts["runtime_statuses"] == dict(Counter(o["rust_report"]["runtime"]["execution"]["status"]
                for o in raw["observations"]))
            and counts["direct_returncodes"] == dict(Counter(str(p["returncode"]) for p in raw["processes"])),
            "status/returncode counts differ")
    for count_key, field in (("stops_with_nonzero_precleanup_payload", "live_bytes"),
                             ("stops_with_call_formal_witnesses", "call_formal_loans_before")):
        actual_count = sum(o["rust_report"]["runtime"]["execution"]["status"] != "returned" and
            (o["rust_report"]["cleanup"]["before"][field] if field == "live_bytes" else
             o["rust_report"]["cleanup"][field]) > 0 for o in raw["observations"])
        require(counts[count_key] == actual_count, "actual stopped-resource subset differs")
    require(rust["outcome"]["tests_run"] == plan["expected_rust_tests"] == 121
            and rust["outcome"]["test_binaries"] == plan["expected_rust_footers"] == 21
            and len(raw["observations"]) == plan["expected_observations"] == 260
            and len(methods) == 20, "frozen full denominator differs")
    require(receipt["retained_executable"]["sha256"] == binary["sha256"]
            and sha256(read_once(run / "hia-core-shadow-executed")).hexdigest() == binary["sha256"],
            "retained executed binary differs")
    require(receipt["cache_reused"] is True and receipt["clean_rebuild_claimed"] is False
            and receipt["cpu_performance_qualification"] is False
            and receipt["host_oom_panic_termination_cleanup_proved"] is False,
            "cache/performance/host cleanup scope changed")
    for key, field in (("actual_direct_rust_processes", "processes"),
                       ("matched_bound_and_machine_observations", "observations"),
                       ("raw_refusal_controls", "refusals"),
                       ("isolated_python_child_processes", "isolated_child_processes")):
        require(counts[key] == len(raw[field]), "actual corpus count differs: " + key)
    return {"verified": True, "source_head": before["head"], "source_tree": before["tree"],
            "retained_files_rehashed": len(files), "rust_tests": rust["outcome"]["tests_run"],
            "focused_tests": len(methods), "actual_corpus_counts": counts,
            "binary_sha256": binary["sha256"], "new_holdout": False,
            "recorded_execution_outer_wall_ns": receipt["outer_wall_ns"],
            "recorded_source_files": len(before["files"]),
            "bounded_files_read_once": len(CACHE), "bounded_bytes_read_once": sum(map(len, CACHE.values())),
            "max_file_bytes": MAX_FILE_BYTES, "max_aggregate_bytes": MAX_TOTAL_BYTES,
            "cache_reused": True, "clean_rebuild_claimed": False,
            "verification_wall_ns": time.monotonic_ns() - started,
            "scope": "offline retained-byte, count and observed-comparison consistency; does not execute or admit code, reproduce toolchain builds, or authenticate a hostile producer"}

def archive_main():
    started=time.monotonic_ns()
    require(len(sys.argv)==4,"usage: verify_archive.py ARCHIVE MANIFEST EXPECTED_MANIFEST_SHA256")
    manifest_bytes=bounded_file(sys.argv[2],MAX_MANIFEST_BYTES)
    require(sha256(manifest_bytes).hexdigest()==sys.argv[3],"external manifest pin differs")
    manifest=decode(manifest_bytes)
    raw=bounded_file(sys.argv[1],MAX_COMPRESSED_BYTES)
    require(len(raw)==manifest["archive"]["bytes"] and sha256(raw).hexdigest()==manifest["archive"]["sha256"],"compressed bytes differ")
    decoder=lzma.LZMADecompressor(format=lzma.FORMAT_XZ,memlimit=64*1024*1024)
    expanded=decoder.decompress(raw,max_length=MAX_TOTAL_BYTES+1)
    require(len(expanded)<=MAX_TOTAL_BYTES and decoder.eof and not decoder.unused_data,"XZ bound/trailing stream differs")
    require(len(expanded)%512==0,"tar block length differs")
    total=0
    with tarfile.open(fileobj=io.BytesIO(expanded),mode="r:") as archive:
        for member in archive:
            path=PurePosixPath(member.name)
            require(member.isfile() and not member.issym() and not member.islnk() and not member.pax_headers
                    and not path.is_absolute() and all(part not in {"",".","..",".git"} for part in member.name.split("/"))
                    and member.name not in PAYLOADS and member.name in manifest["members"]
                    and len(PAYLOADS)<MAX_MEMBERS and 0<=member.size<=MAX_FILE_BYTES,"unsafe or excess tar member")
            stream=archive.extractfile(member);require(stream is not None,"member stream missing")
            data=stream.read(MAX_FILE_BYTES+1);expected=manifest["members"][member.name]
            require(len(data)==member.size==expected["bytes"] and sha256(data).hexdigest()==expected["sha256"],"member bytes differ")
            PAYLOADS[member.name]=data;total+=len(data)
            require(total<=MAX_TOTAL_BYTES,"expanded member limit")
        tail=expanded[archive.offset:]
        require(len(tail)>=1024 and not any(tail),"nonzero or missing tar terminal padding")
    require(set(PAYLOADS)==set(manifest["members"]) and total==manifest["member_bytes"],"complete member inventory differs")
    result=verify("integrated3533")
    require(result["source_head"]=="3533b95c53d23de2d22c91fcc05cb601b8448eb3"
            and result["source_tree"]=="12fae5261a4478645c53e864bc262c1609d2f81d","historical execution source was relabelled")
    summary=decode(PAYLOADS["integrated3533/SUMMARY.json"])
    require(summary["source_head"]==result["source_head"] and summary["actual_counts"]==result["actual_corpus_counts"]
            and summary["source_file_count"]==result["recorded_source_files"],"summary differs from raw observations")
    dev=decode(PAYLOADS["development/SUMMARY.json"])
    require(dev["source_commit"]=="39ae13638170fad2fe3234f8e7ca989997ef69c4"
            and dev["formal_integrated_qualification"] is False and dev["full_human_agent_development_review_cost"] is None,"development scope enlarged")
    cost=sum(decode(PAYLOADS["development/"+row["id"]+"/RECEIPT.json"])["outer_wall_ns"] for row in dev["commands"])
    require(cost==dev["measured_sequential_command_outer_wall_ns"],"distinct development costs differ")
    outer=decode(PAYLOADS["integrated3533/OUTER_EXECUTION.json"])
    require(outer["returncode"]==0 and outer["status"]=="completed"
            and outer["outer_wall_ns"]==summary["cost"]["outer_process_wall_ns"],"actual outer cost differs")
    return {"verified":True,"members":len(PAYLOADS),"member_bytes":total,"compressed_bytes":len(raw),
        "archive_sha256":sha256(raw).hexdigest(),"manifest_sha256":sha256(manifest_bytes).hexdigest(),
        "source_head":result["source_head"],"recorded_source_files":result["recorded_source_files"],
        "rust_tests":result["rust_tests"],"focused_tests":result["focused_tests"],
        "actual_corpus_counts":result["actual_corpus_counts"],"development_command_cost_ns":cost,
        "verification_wall_ns":time.monotonic_ns()-started,
        "native_model_or_archived_code_executed":False,"later_head_qualified":False,
        "scope":"bounded single compressed read, external manifest pin, same-bytes XZ/tar/member and finite observed journal consistency; no extraction, native execution, producer authentication or general theorem"}


if __name__=="__main__":
    print(json.dumps(archive_main(),sort_keys=True))
