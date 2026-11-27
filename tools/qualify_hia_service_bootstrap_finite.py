"""Complete original-first bootstrap finite authority and isolated comparisons."""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import time
ROOT=Path(__file__).resolve().parents[1]
if __package__ in (None,""):
    sys.path.insert(0,str(ROOT))
from tests import hia_service_bootstrap_oracle as oracle
from tests import hia_service_bootstrap_support as support

OBSERVER=ROOT/"tests/hia_service_bootstrap_observer.py"
def _exact_nonnegative_integer(value, expected=None):
    if (type(value) is not int or value < 0
            or (expected is not None and value != expected)):
        raise ValueError("process-terminal integer identity differs")
    return value


def _terminal_late_pin(path, checkpoint_pin):
    """Hash final bytes and the checkpoint prefix in the same bounded read."""
    checkpoint_pin = support.require_pin(checkpoint_pin)
    prefix, final, size = sha256(), sha256(), 0
    with Path(path).open("rb") as stream:
        while True:
            raw = stream.read(1 << 20)
            if not raw:
                break
            if size < checkpoint_pin["bytes"]:
                prefix.update(raw[:checkpoint_pin["bytes"] - size])
            final.update(raw)
            size += len(raw)
    if (size < checkpoint_pin["bytes"]
            or prefix.hexdigest() != checkpoint_pin["sha256"]):
        raise ValueError("late channel does not preserve its checkpoint prefix")
    value = {"bytes":size, "sha256":final.hexdigest()}
    if not support.same(support.file_pin(path), value):
        raise ValueError("late channel changed while sealing its final bytes")
    return value


def _seal_process_terminal(directory, label, lane, checkpoint_raw, checkpoint,
                           start_raw, start, result_raw, result):
    """A child checkpoint is never promoted by rewriting its own report."""
    directory = Path(directory)
    seconds = 600 if lane == "original" else 1800
    pid = _exact_nonnegative_integer(start["pid"])
    if pid == 0:
        raise ValueError("a real positive owned PID is required")
    for value in (start["pgid"], result["pid"], result["pgid"],
                  checkpoint["pid"], checkpoint["pgid"]):
        _exact_nonnegative_integer(value, pid)
    for value in (start["timeout_seconds"], result["timeout_seconds"]):
        _exact_nonnegative_integer(value, seconds)
    for value in (start["cleanup_seconds"], result["cleanup_seconds"]):
        _exact_nonnegative_integer(value, 3)
    _exact_nonnegative_integer(result["returncode"], 0)
    _exact_nonnegative_integer(start["started_time_ns"])
    _exact_nonnegative_integer(result["started_time_ns"], start["started_time_ns"])
    _exact_nonnegative_integer(result["ended_time_ns"])
    if result["ended_time_ns"] < result["started_time_ns"]:
        raise ValueError("owned child terminal time precedes its start")
    if (result["timeout"] is not False or result["reaped"] is not True
            or result["cleanup_error"] is not None or result["supervisor_error"] is not None
            or result["cleanup"]["reaped"] is not True
            or result["cleanup"]["after"] != [] or result["cleanup"]["signals"] != []
            or start["command"] != result["command"]
            or checkpoint["argv"] != result["command"][3:]
            or result["command"][:3] != [checkpoint["executable"], "-I", "-B"]
            or any(value != str(ROOT) for value in
                   (start["cwd"], result["cwd"], checkpoint["cwd"]))):
        raise ValueError("process terminal seal requires an actual natural exit and empty owned group")
    checkpoint_pin = support.bytes_pin(checkpoint_raw)
    if (checkpoint["schema"] != "hepta.hia.service-bootstrap-finite-observations.v2"
            or checkpoint["status"] != ("CHECKPOINT_ORIGINAL_COMPLETE" if lane == "original"
                                        else "CHECKPOINT_CANDIDATE_COMPLETE")
            or checkpoint["lane"] != lane or checkpoint["process_terminal_required"] is not True
            or checkpoint["late_differences"] is not None
            or checkpoint["late_comparison"] != "PENDING_PROCESS_TERMINAL"
            or result["report"] != {"relative":"report.json", **checkpoint_pin}):
        raise ValueError("an explicit pending checkpoint is required before terminal sealing")
    _exact_nonnegative_integer(checkpoint["differences"], 0)
    if checkpoint["unraisables"] != []:
        raise ValueError("unraisable provider failure at checkpoint")
    checkpoint_files = checkpoint["files"]
    if type(checkpoint_files) is not dict or "late-events.jsonl" not in checkpoint_files:
        raise ValueError("checkpoint has no complete late stream")
    expected_names = set(checkpoint_files) | {"report.json"}
    actual_names = set()
    for path in directory.iterdir():
        if not path.is_file() or path.is_symlink():
            raise ValueError("finite child has a nonregular unexpected output")
        actual_names.add(path.name)
    if actual_names != expected_names:
        raise ValueError("finite child output set changed after checkpoint")
    final_files = {}
    for name, expected in checkpoint_files.items():
        if type(name) is not str or Path(name).name != name:
            raise ValueError("checkpoint file leaves its owned directory")
        support.require_pin(expected)
        if name == "late-events.jsonl":
            final_files[name] = _terminal_late_pin(directory/name, expected)
        else:
            actual = support.file_pin(directory/name)
            if not support.same(actual, expected):
                raise ValueError("nonlate checkpoint bytes changed: " + name)
            final_files[name] = actual
    start_pin, result_pin = support.bytes_pin(start_raw), support.bytes_pin(result_raw)
    late_checkpoint, late_final = checkpoint_files["late-events.jsonl"], final_files["late-events.jsonl"]
    value = {
        "schema":"hepta.hia.service-bootstrap-process-terminal.v2",
        "status":"TERMINAL_COMPLETE", "label":label, "lane":lane,
        "pid":pid, "pgid":pid, "sealer_pid":os.getpid(),
        "sealed_time_ns":time.time_ns(),
        "checkpoint_report":{"relative":"report.json", **checkpoint_pin},
        "start":{"relative":label+".start.json", **start_pin},
        "result":{"relative":label+".result.json", **result_pin},
        "natural_exit":True, "owned_group_gone":True,
        "checkpoint_files":checkpoint_files, "files":final_files,
        "late":{"relative":"late-events.jsonl", "checkpoint":late_checkpoint,
                "terminal":late_final,
                "append_bytes":late_final["bytes"]-late_checkpoint["bytes"],
                "checkpoint_prefix_preserved":True},
        "whole_native_stack_qualified":False,
    }
    if value["sealed_time_ns"] < result["ended_time_ns"]:
        raise ValueError("terminal seal precedes the actual child result")
    for name, expected in final_files.items():
        if not support.same(support.file_pin(directory/name), expected):
            raise ValueError("terminal raw stream changed before publication: " + name)
    support.exact_reread(directory/"report.json", checkpoint_raw)
    support.exact_reread(directory.parent/(label+".start.json"), start_raw)
    support.exact_reread(directory.parent/(label+".result.json"), result_raw)
    path = directory/"process-terminal.json"
    terminal_pin = support.write_json(path, value)
    terminal_raw, terminal, _ = support.capture_json(path, terminal_pin)
    return terminal, terminal_pin, (path, terminal_raw)


def _compare_terminal_late(actual_path, expected_path, actual_pin, expected_pin, output):
    """Compare every final late row only after both owned processes exited."""
    support.require_pin(actual_pin)
    support.require_pin(expected_pin)
    actual_digest, expected_digest = sha256(), sha256()
    actual_size = expected_size = count = 0
    with Path(actual_path).open("rb") as actual, Path(expected_path).open("rb") as expected:
        with Path(output).open("xb") as differences:
            ordinal = 0
            while True:
                left, right = expected.readline(), actual.readline()
                if not left and not right:
                    break
                if left:
                    if not left.endswith(b"\n"):
                        raise ValueError("original terminal late row is incomplete")
                    expected_digest.update(left)
                    expected_size += len(left)
                if right:
                    if not right.endswith(b"\n"):
                        raise ValueError("candidate terminal late row is incomplete")
                    actual_digest.update(right)
                    actual_size += len(right)
                if left != right:
                    count += 1
                    differences.write(support.canonical({
                        "ordinal":ordinal,
                        "expected":None if not left else support.parse(left),
                        "actual":None if not right else support.parse(right)})+b"\n")
                ordinal += 1
    if (not support.same({"bytes":actual_size,"sha256":actual_digest.hexdigest()}, actual_pin)
            or not support.same({"bytes":expected_size,"sha256":expected_digest.hexdigest()}, expected_pin)
            or not support.same(support.file_pin(actual_path), actual_pin)
            or not support.same(support.file_pin(expected_path), expected_pin)):
        raise ValueError("consumed terminal late bytes differ from their prior fixed identities")
    return count, support.file_pin(output)


def child(parent,label,lane,inputs,*,authority=None,authority_pin=None,manifest=None):
    directory=Path(parent)/label
    command=[sys.executable,"-I","-B",str(OBSERVER),"--lane",lane,
             "--inputs",str(inputs),"--output",str(directory)]
    if authority is not None:
        if authority_pin is None:
            raise ValueError("candidate authority must have its previously fixed identity")
        command += ["--expected",str(authority),
                    "--expected-sha256",authority_pin["sha256"],
                    "--expected-bytes",str(authority_pin["bytes"])]
    if manifest is not None:
        command += ["--manifest",str(manifest)]
    seconds=600 if lane=="original" else 1800
    receipt,checkpoint,raw=support.run_child(parent,label,command,seconds=seconds)
    if (checkpoint["lane"]!=lane or checkpoint["runtime"]!=sys.version
            or checkpoint["implementation"]!=sys.implementation.name
            or not support.same(checkpoint["source_before"],checkpoint["source_after"])
            or checkpoint["differences"]!=0 or checkpoint["late_differences"] is not None
            or checkpoint["unraisables"] or receipt["stderr"]["bytes"]!=0
            or (lane in ("original","unselected") and checkpoint["native_or_VM_entries"]!=0)
            or (lane in ("vm","native") and checkpoint["native_or_VM_entries"]<=0)):
        raise ValueError("complete bootstrap checkpoint runtime/domain/custody differs")
    support.exact_reread(directory/"report.json",raw)
    start_path=Path(parent)/(label+".start.json")
    result_path=Path(parent)/(label+".result.json")
    start_raw,start,start_pin=support.capture_json(start_path)
    result_raw,result,result_pin=support.capture_json(result_path)
    if not support.same(result,receipt) or start["command"]!=command or checkpoint["argv"]!=command[3:]:
        raise ValueError("bootstrap child command/result identity differs")
    terminal,terminal_pin,terminal_capture=_seal_process_terminal(
        directory,label,lane,raw,checkpoint,start_raw,start,result_raw,result)
    record={"label":label,"start":start_pin,"result":result_pin,
            "report":support.bytes_pin(raw),"terminal":terminal_pin,"files":terminal["files"]}
    # This in-memory view is explicitly terminal; the checkpoint report bytes
    # and their old late prefix pin remain untouched on disk.
    report={**checkpoint,"files":terminal["files"],
            "checkpoint_files":checkpoint["files"],"process_terminal":terminal_pin}
    return record,report,((start_path,start_raw),(result_path,result_raw),
                         (directory/"report.json",raw),terminal_capture)


def originals(output):
    output=Path(output)
    source_before=support.source_snapshot()
    base_cases,domain_raw=oracle.cases()
    output.mkdir(mode=0o700,parents=True,exist_ok=False)
    base={"schema":"hepta.hia.service-bootstrap-base-inputs.v1",
          "cases":base_cases,"basis_ids":list(oracle.BASIS_IDS),
          "fault_families":list(oracle.FAMILIES),"original_domain":support.bytes_pin(domain_raw)}
    base_pin=support.write_json(output/"base-inputs.json",base)
    lanes=[];captured=[];reports={}
    for label in ("basis-first","basis-second"):
        record,report,raws=child(output,label,"original",output/"base-inputs.json")
        if report["count"]!=232 or report["ordered_ids"]!=[case["id"] for case in base_cases]:
            raise ValueError("original base lane did not execute every frozen input")
        lanes.append(record);reports[label]=report;captured.extend(raws)
    for channel in ("observations.jsonl","late-events.jsonl","raw-tracebacks.jsonl"):
        if not support.identical_files(output/"basis-first"/channel,output/"basis-second"/channel,
                reports["basis-first"]["files"][channel],reports["basis-second"]["files"][channel]):
            raise ValueError("independent base original channels differ: "+channel)
    basis=[]
    for ordinal,raw,row in support.json_lines(output/"basis-first/observations.jsonl",
                                            reports["basis-first"]["files"]["observations.jsonl"]):
        if row["id"]!=base_cases[ordinal]["id"]:
            raise ValueError("original base identities changed order")
        if row["id"] in oracle.BASIS_IDS:
            basis.append(row)
    complete_cases=oracle.derive(base_cases,basis)
    complete={"schema":"hepta.hia.service-bootstrap-complete-inputs.v1",
              "cases":complete_cases,"base_domain":support.bytes_pin(domain_raw),
              "base_inputs":base_pin,"basis_observations":reports["basis-first"]["files"]["observations.jsonl"],
              "derived_only_from_original":True}
    complete_pin=support.write_json(output/"complete-inputs.json",complete)
    freeze_pin=support.write_json(output/"derived-input-freeze.json",{
        "schema":"hepta.hia.service-bootstrap-derived-input-freeze.v1",
        "complete_inputs":complete_pin,"base_inputs":base_pin,
        "basis_ids":list(oracle.BASIS_IDS),"fault_families":list(oracle.FAMILIES),
        "count":len(complete_cases),"ordered_ids":[case["id"] for case in complete_cases],
        "basis_observations":reports["basis-first"]["files"]["observations.jsonl"],
        "expected_observations_precede_any_candidate":True})
    for label in ("complete-first","complete-second"):
        record,report,raws=child(output,label,"original",output/"complete-inputs.json")
        if report["count"]!=len(complete_cases) or report["ordered_ids"]!=[case["id"] for case in complete_cases]:
            raise ValueError("complete original domain was truncated")
        lanes.append(record);reports[label]=report;captured.extend(raws)
    for channel in ("observations.jsonl","late-events.jsonl","raw-tracebacks.jsonl"):
        if not support.identical_files(output/"complete-first"/channel,output/"complete-second"/channel,
                reports["complete-first"]["files"][channel],reports["complete-second"]["files"][channel]):
            raise ValueError("independent complete original channels differ: "+channel)
    source_after=support.source_snapshot()
    if not support.same(source_before,source_after):
        raise ValueError("bootstrap originals source closure changed")
    support.exact_reread(oracle.FIXTURE/"observation-domain.json",domain_raw)
    for path,raw in captured:
        support.exact_reread(path,raw)
    authority={"schema":"hepta.hia.service-bootstrap-original-authority.v2",
               "runtime":sys.version,"implementation":sys.implementation.name,
               "source_before":source_before,"source_after":source_after,
               "base_count":232,"count":len(complete_cases),
               "ordered_ids":[case["id"] for case in complete_cases],
               "base_domain":support.bytes_pin(domain_raw),"base_inputs":base_pin,
               "complete_inputs":complete_pin,"derived_input_freeze":freeze_pin,
               "lanes":lanes,"native_or_VM_entries":0,
               "originals_equal":True,
               "late_channel_complete_and_equal":True,
               "process_terminal_complete":True,
               "checkpoint_reports_preserved":True,
               "late_comparison_scope":"NATURAL_PROCESS_EXIT",
               "raw_traceback_channels_preserved":True,
               "whole_native_stack_qualified":False}
    pin=support.write_json(output/"authority.json",authority)
    # Every consumer receives this fixed pin; no later hash is promoted to authority.
    return output/"authority.json",pin


def read_originals(authority_path, authority_pin):
    from tests.hia_service_bootstrap_observer import admit_originals
    authority_path=Path(authority_path)
    authority_raw,authority,pin=support.capture_json(authority_path,authority_pin)
    input_path=authority_path.parent/"complete-inputs.json"
    input_raw,input_value,_=support.capture_json(input_path,authority["complete_inputs"])
    before=support.source_snapshot()
    value,captured,lanes=admit_originals(authority_path,authority_pin,input_raw,before)
    support.exact_reread(authority_path,authority_raw)
    support.exact_reread(input_path,input_raw)
    if oracle.canonical(value)!=oracle.canonical(authority):
        raise ValueError("original authority parsed values changed")
    return authority,authority_raw,input_value,input_raw,captured,lanes

def current_dispatch_child(output, lane, source, *, manifest=None):
    """Keep current public controls outside the completed historical process."""
    output = Path(output)
    command = [sys.executable, "-I", "-B",
               str(ROOT / "tests/hia_bootstrap_current_dispatch.py"),
               "--lane", lane, "--output", str(output / "current-dispatch")]
    if manifest is not None:
        command += ["--manifest", str(manifest)]
    result, report, raw = support.run_child(
        output, "current-dispatch", command, seconds=60)
    if (report["schema"] != "hepta.hia.bootstrap-current-dispatch-process.v1"
            or report["status"] != "PASS_CURRENT_INIT_AND_PROGRAM_PROCESS_ONLY"
            or report["lane"] != lane or report["source_before"] != source
            or report["source_after"] != source
            or report["whole_native_stack_qualified"] is not False):
        raise ValueError("current dispatcher process does not bind its actual source")
    record = {
        "label": "current-dispatch",
        "start": support.file_pin(output / "current-dispatch.start.json"),
        "result": support.file_pin(output / "current-dispatch.result.json"),
        "report": support.bytes_pin(raw),
    }
    captures = [(output / "current-dispatch" / "report.json", raw)]
    for name in ("current-dispatch.start.json", "current-dispatch.result.json"):
        captures.append((output / name, (output / name).read_bytes()))
    return record, captures


def compare_candidate(authority_path,authority_pin,output,*,lane,manifest=None):
    if lane not in ("unselected","vm","native"):
        raise ValueError("candidate lane must explicitly name unselected, VM or Native")
    authority,authority_raw,inputs,input_raw,captured,(expected_directory,expected_report)=read_originals(
        authority_path,authority_pin)
    output=Path(output)
    output.mkdir(mode=0o700,parents=True,exist_ok=False)
    source_before=support.source_snapshot()
    if not support.same(source_before,authority["source_before"]):
        raise ValueError("candidate source differs from its original authority")
    manifest_raw=None
    if lane=="native":
        if manifest is None:
            raise ValueError("native finite comparison needs its actual manifest")
        manifest=Path(manifest)
        manifest_raw,manifest_value,manifest_pin=support.capture_json(manifest)
        image_path=manifest.parent/manifest_value["image_path"]
        if support.file_pin(image_path)["sha256"]!=manifest_value["image_sha256"]:
            raise ValueError("candidate image differs from its actual manifest")
    else:
        manifest_pin=None
    record,report,candidate_captures=child(output,"candidate",lane,
        Path(authority_path).parent/"complete-inputs.json",
        authority=authority_path,authority_pin=authority_pin,manifest=manifest)
    if (report["count"]!=authority["count"] or report["ordered_ids"]!=authority["ordered_ids"]
            or report["input"]!=authority["complete_inputs"] or report["expected_authority"]!=authority_pin):
        raise ValueError("candidate does not cover the full same original domain")
    original_pin=expected_report["files"]["observations.jsonl"]
    actual_pin=report["files"]["observations.jsonl"]
    if not support.identical_files(expected_directory/"observations.jsonl",
            output/"candidate/observations.jsonl",original_pin,actual_pin):
        raise ValueError("complete candidate bytes are not identical to sealed originals")
    late_count,late_diff_pin=_compare_terminal_late(
        output/"candidate/late-events.jsonl",expected_directory/"late-events.jsonl",
        report["files"]["late-events.jsonl"],expected_report["files"]["late-events.jsonl"],
        output/"terminal-late-differences.jsonl")
    current_record, current_captures = None, []
    if late_count == 0:
        current_record, current_captures = current_dispatch_child(
            output, lane, source_before, manifest=manifest)
    source_after=support.source_snapshot()
    if source_before!=source_after:
        raise ValueError("candidate component source changed")
    support.exact_reread(authority_path,authority_raw)
    support.exact_reread(Path(authority_path).parent/"complete-inputs.json",input_raw)
    for path,raw in (*captured,*candidate_captures,*current_captures):
        support.exact_reread(path,raw)
    if manifest_raw is not None:
        support.exact_reread(manifest,manifest_raw)
    value={"schema":"hepta.hia.service-bootstrap-finite-comparison.v2",
           "status":"PASS_FINITE_ONLY" if late_count==0 else "HOLD",
           "lane":lane,"runtime":sys.version,
           "authority":authority_pin,"originals":str(Path(authority_path).resolve()),
           "complete_inputs":authority["complete_inputs"],
           "count":authority["count"],"ordered_ids":authority["ordered_ids"],
           "candidate":record,"candidate_report":record["report"],
           "current_dispatch":current_record,
           "candidate_terminal":record["terminal"],
           "original_terminal":expected_report["process_terminal"],
           "original_observations":original_pin,"actual_observations":actual_pin,
           "full_raw_byte_equality":True,"complete_late_byte_equality":late_count==0,
           "late_comparison_scope":"BOTH_NATURAL_PROCESS_TERMINALS",
           "terminal_late_difference_count":late_count,
           "terminal_late_differences":{"relative":"terminal-late-differences.jsonl",**late_diff_pin},
           "checkpoint_reports_preserved":True,
           "raw_traceback_frames_compared_as_business_values":False,
           "raw_traceback_channels_preserved":True,
           "source_before":source_before,"source_after":source_after,
           "manifest":manifest_pin,"whole_native_stack_qualified":False}
    support.write_json(output/"report.json",value)
    if late_count:
        raise ValueError("complete process-terminal late channels differ; every raw difference retained")
    return value


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--originals-only",action="store_true")
    parser.add_argument("--originals",type=Path)
    parser.add_argument("--originals-sha256")
    parser.add_argument("--originals-bytes",type=int)
    parser.add_argument("--lane",choices=("unselected","vm","native"),default="vm")
    parser.add_argument("--manifest",type=Path)
    args=parser.parse_args()
    if args.originals_only:
        path,pin=originals(args.output)
        print(json.dumps({"authority":str(path),**pin},sort_keys=True))
        return
    if args.originals is None or args.originals_sha256 is None or args.originals_bytes is None:
        parser.error("comparison needs the previously captured complete original authority")
    compare_candidate(args.originals,{"bytes":args.originals_bytes,"sha256":args.originals_sha256},
                      args.output,lane=args.lane,manifest=args.manifest)
if __name__=="__main__":
    main()
