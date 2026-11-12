"""Audit the exact passed source83 r3 artifact, four real negative commands and bounded log. No product execution."""
from __future__ import annotations
import ast
import base64
from hashlib import sha1, sha256
import json
from pathlib import Path, PurePosixPath
import re
import zipfile

ROOT = Path(__file__).resolve().parent
STEM = "hia-numeric-source83-actions-r3-43287029044-1"
REMOTE = "/home/runner/work/_temp/" + STEM
SOURCE = REMOTE + "/source"
EXPECTED_ZIP_SHA = "20ff6d57f71d55b38571b88c6fc559141ecb4e1632d423012ff0cd122b60d2af"
CHECKS = []

def check(value, name):
    if not value:
        raise AssertionError(name)
    CHECKS.append(name)

def digest(raw):
    return {"size": len(raw), "sha256": sha256(raw).hexdigest(),
        "git_blob_sha1": sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()}

def save(name, value):
    with (ROOT / name).open("x") as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")

def content(rows):
    return [{key: row[key] for key in ("relative_path","size","sha256","git_blob_sha1","mode")} for row in rows]

def main():
    archive = ROOT / "artifact-13975032410.original.zip"
    raw_archive = archive.read_bytes()
    check(len(raw_archive) == 12968973 and sha256(raw_archive).hexdigest() == EXPECTED_ZIP_SHA,
          "provider_exact_complete_zip_size_sha256")
    with zipfile.ZipFile(archive) as z:
        infos = z.infolist()
        check(len(infos) == 1935 and len({x.filename for x in infos}) == 1935, "complete_unique_1935_zip_members")
        check(sum(x.file_size for x in infos) == 48327070, "complete_zip_expanded_bytes")
        bodies, inventory = {}, []
        for info in infos:
            path = PurePosixPath(info.filename)
            check(not path.is_absolute() and path.as_posix() == info.filename
                and all(x not in ("", ".", "..") for x in path.parts), "safe_zip_path:" + info.filename)
            raw = z.read(info)
            check(len(raw) == info.file_size, "complete_crc_checked_zip_body:" + info.filename)
            bodies[info.filename] = raw
            inventory.append(dict(path=info.filename, crc32=info.CRC, compressed_bytes=info.compress_size,
                compression=info.compress_type, external_attr=info.external_attr,
                header_offset=info.header_offset, is_directory=info.is_dir(), **digest(raw)))
    def body(name):
        return bodies[STEM + "/" + name]
    def value(name):
        return json.loads(body(name))
    def absolute_body(path):
        check(type(path) is str and (path == REMOTE or path.startswith(REMOTE + "/") or path.startswith(REMOTE + ".")),
              "original_path_in_fixed_operation:" + str(path))
        return bodies[path[len("/home/runner/work/_temp/"):]]
    bound_pins = 0
    def bind(pin):
        nonlocal bound_pins
        raw = absolute_body(pin["path"])
        check(digest(raw) == {k:pin[k] for k in ("size","sha256","git_blob_sha1")},
              "actual_raw_pin:" + pin["path"])
        bound_pins += 1
        return raw
    request = value("REQUEST.json")
    frozen = json.loads((ROOT.parent.parent / "core-numeric-source83-on-v89-r3/REQUEST.json").read_bytes())
    policy = json.loads((ROOT.parent.parent / "core-numeric-source83-actions-r3/POLICY.json").read_bytes())
    context = value("RUN-CONTEXT.json")
    preparation = value("PREPARATION.json")
    check(context["GITHUB_RUN_ID"] == "43287029044" and context["GITHUB_RUN_ATTEMPT"] == "1"
          and context["GITHUB_SHA"] == "c7cf72d26a38d68fdafdf4e515e35645d29e49f1"
          and context["GITHUB_EVENT_NAME"] == "create"
          and context["GITHUB_REF_NAME"] == policy["execution_branch"]
          and context["NUMERIC_SOURCE83_WORKFLOW_SHA"] == context["GITHUB_SHA"], "actual_unique_run_context")
    check(preparation["context"] == request["remote_execution_context"] == context
          and preparation["status"] == "NEW_SOURCE_REQUEST_PREPARED_NOT_EXECUTED"
          and preparation.get("error") is None
          and preparation["runtime_version"] == [3,14,4], "actual_preparation_and_runtime31404")
    for name in policy["unchanged_request_fields"]:
        check(request[name] == frozen[name], "protected_request_field:" + name)
    check(request["source_root"] == SOURCE and request["evidence_root"] == REMOTE + "/actual-source"
          and request["revision"] == "github-actions-cpython31404-source83-r3", "fresh_request_paths_revision")
    bind(preparation["new_request"])
    check(request["runtime"] == preparation["runtime"], "runtime_observed_identity_consistency")
    for pin in request["control_inputs"]:
        raw = bind(pin)
        name = Path(pin["path"]).name
        expected = (ROOT.parent.parent / "core-numeric-source83-on-v89-r3/control" / name).read_bytes()
        if name == "worker.py":
            for row in policy["worker_metadata_substitutions"]:
                check(expected.count(row["old_text"].encode()) == 1, "worker_single_metadata_marker")
                expected = expected.replace(row["old_text"].encode(), row["new_text"].encode(), 1)
        check(raw == expected, "actual_control_exact:" + name)
    bind(request["process_owner"])
    check(request["process_owner"]["sha256"] == "36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2",
          "original_process_owner_bytes")
    life_raw = body("actual-source/lifecycle.json")
    life = json.loads(life_raw)
    wrapper = value("actual-source/wrapper.json")
    owner_raw = body("actual-source/lifecycle.json.request.json")
    owner_request = json.loads(owner_raw)
    check(wrapper["receipt_sha256"] == sha256(life_raw).hexdigest()
          and {k:v for k,v in wrapper.items() if k not in ("receipt_sha256","supervisor_returncode")} == life,
          "wrapper_complete_original_receipt_projection")
    check(life["request_sha256"] == sha256(owner_raw).hexdigest()
          and owner_request["command"] == [request["runtime"]["path"],"-I","-S","-B",REMOTE+"/control/worker.py"]
          and owner_request["cwd"] == REMOTE
          and owner_request["stdout_path"] == REMOTE+"/actual-source/child.stdout.log"
          and owner_request["stderr_path"] == REMOTE+"/actual-source/child.stderr.log"
          and owner_request["receipt_path"] == REMOTE+"/actual-source/lifecycle.json"
          and owner_request["implementation_sha256"] == life["implementation_sha256"] == request["process_owner"]["sha256"]
          and owner_request["qualification_seconds"] == life["qualification_seconds"] == 180
          and owner_request["cleanup_seconds"] == life["cleanup_seconds"] == 3
          and owner_request["deadline_ns"]-owner_request["started_ns"] == 180000000000,
          "raw_owner_command_paths_implementation_and_180plus3")
    cleanup = life["cleanup"]
    check(life["status"] == "OWNED_PROCESS_COMPLETED" and type(life["returncode"]) is int and life["returncode"] == 0 and wrapper["supervisor_returncode"] == 0
          and life["timed_out"] is False and life["exit_observed_before_deadline"] is True
          and life["qualification_started"] is True and life["subreaper_enabled"] is True
          and life["interrupted_signals"] == [] and life["event_overflow"] is False
          and life.get("owner_error") is None
          and cleanup["attempted"] is True and cleanup["complete"] is True
          and cleanup["observed_echild"] is True and cleanup["leader_reaped"] is True
          and cleanup["deadline_exceeded"] is False and cleanup["remaining_direct_children"] == []
          and cleanup["errors"] == [], "actual_natural_zero_closed_ECHILD_no_timeout")
    check([x["kind"] for x in life["events"]] == ["qualification_started","owned_child_observed",
          "qualification_exit_observed","owned_child_reaped"], "four_natural_owner_events_no_kill")
    final = value("actual-source/FINAL.json")
    check(final["status"] == "SOURCE_INTEGRATION_PASS" and final["closed_owner_confirmed"] is True
          and final["child_originals_read"] is True, "successful_final_requires_closed_custody")
    bind(final["request"])
    for pin in final["actual_originals"]:
        bind(pin)
    actual_paths = {REMOTE + name[len(STEM):] for name in bodies
                    if name.startswith(STEM + "/actual-source/") and not name.endswith("/FINAL.json")}
    check({x["path"] for x in final["actual_originals"]} == actual_paths
          and len(final["actual_originals"]) == len(actual_paths), "complete_closed_original_pin_set")
    worker = value("actual-source/evidence/report.json")
    tests = value("actual-source/evidence/source-tests.json")
    check(worker["status"] == "SOURCE_INTEGRATION_PASS" and tests["status"] == "SOURCE_CHILD_PASS" and len(worker["commands"]) == 71
          and 0 < worker["seconds"] < 180
          and worker["source_preserved_after_derivation"] is True, "actual_worker_success_and_preservation")
    check(worker["base_commit"] == policy["base_commit"] and worker["base_tree"] == policy["base_tree"]
          and worker["runtime"] == request["runtime"] and worker["generator_count"] == 62,
          "worker_source_and_runtime_binding")
    expected_specs = [("generator-"+format(i+1,"02d")+"-"+name,"module",["tools.generate_hia_"+name])
                      for i,name in enumerate(request["generator_names"])]
    expected_specs += [(prefix+str(i+1),"script",[name,*args])
                      for prefix in ("derive-","idempotence-")
                      for i,(name,args) in enumerate(request["derivations"])]
    expected_specs.append(("source-tests","tests",[]))
    command_rows = []
    for index,(row,(label,op,args)) in enumerate(zip(worker["commands"],expected_specs,strict=True)):
        report_name = "source-tests.json" if op == "tests" else label + ".report.json"
        check(row["label"] == label and row["command"] == [request["runtime"]["path"],"-I","-S","-B",
              REMOTE+"/control/child.py",op,*args], "exact_child_command:" + label)
        for key,suffix in (("stdout",".stdout.log"),("stderr",".stderr.log"),("report",None)):
            expected_path = REMOTE+"/actual-source/evidence/"+(report_name if suffix is None else label+suffix)
            check(row[key]["path"] == expected_path,"fixed_command_original_path:"+label+":"+key)
            bind(row[key])
        child = value("actual-source/evidence/"+report_name)
        check(child["runtime_identity"] == request["runtime"] and child["operation"] == op,
              "child_runtime_operation:"+label)
        if index < 70:
            check(row["returncode"] == 0 and child["status"] == "SOURCE_CHILD_PASS"
                  and child.get("error") is None and child["native_or_compiler_or_process_attempts"] == [],
                  "successful_source_command:" + label)
        else:
            check(row["returncode"] == 0 and child == tests and child["status"] == "SOURCE_CHILD_PASS", "actual_source_tests_pass")
        command_rows.append({"label":label,"returncode":row["returncode"],"status":child["status"],
             "seconds":child["seconds"],"report":row["report"]})
    ids = request["expected_ids"]
    check(tests["expected_ids"] == tests["loaded_ids"] == tests["executed_ids"] == ids
          and len(ids) == len(set(ids)) == tests["tests_run"] == 83, "all83_original_ids_loaded_executed")
    check(all(tests[key] == [] for key in ("failures", "errors", "loader_errors", "skipped",
          "expectedFailures", "unexpectedSuccesses", "native_or_compiler_or_process_attempts", "forbidden_attempts", "negative_permission_refusals"))
          and tests["forbidden_attempt_count"] == 0, "all83_zero_anomalies_and_no_forbidden_attempts")
    spec = request["source_child_process_policy"]
    check(spec == policy["source_child_process_policy"] == tests["source_child_process_policy"]
          == worker["source_child_process_policy"] == final["source_child_process_policy"]
          and spec["timeout_seconds"] == 10 and spec["expected_processes"] == 4,
          "one_fixed_original_four_negative_command_policy")
    check(tests["allowed_negative_processes"] == worker["allowed_negative_processes"]
          == final["allowed_negative_processes"] == 4
          and tests["zero_process_scope_claimed"] is worker["zero_process_scope_claimed"]
          is final["zero_process_scope_claimed"] is False, "complete_explicit_four_process_accounting")
    for row in worker["commands"]:
        child = json.loads(bind(row["report"]))
        check(child["allowed_negative_processes"] == (4 if row["label"] == "source-tests" else 0)
              and child["source_child_process_policy"] == spec
              and child["forbidden_attempts"] == [] and child["forbidden_attempt_count"] == 0
              and child["negative_permission_refusals"] == [] and child["zero_process_scope_claimed"] is False,
              "each_child_exact_process_scope:" + row["label"])
        if row["label"] != "source-tests":
            check(child["allowed_negative_process_records"] == [], "non_test_no_negative_process_record")
    negative = tests["allowed_negative_process_records"]
    check(len(negative) == 4 and [r["case"] for r in negative] == spec["cases"]
          and [r["index"] for r in negative] == [1, 2, 3, 4]
          and len({r["cwd"] for r in negative}) == 4, "four_original_ordered_distinct_negative_commands")
    last_end = None
    negative_originals = []
    for index, row in enumerate(negative, 1):
        case = spec["cases"][index - 1]
        cwd = row["cwd"]
        check(PurePosixPath(cwd).parent.as_posix() == row["temporary_parent"] == "/tmp"
              and PurePosixPath(cwd).as_posix() == cwd and ".." not in PurePosixPath(cwd).parts,
              "fixed_private_negative_temporary_path")
        argv = [request["runtime"]["path"], "-I", "-S", "-B", SOURCE + "/" + spec["script"],
                "component", "--owner", case["owner"], "--cold-report", cwd + "/cold.json",
                "--output", cwd + "/report.json", "--evidence-dir", cwd + "/evidence"]
        env = dict(spec["environment"])
        if case["development"]:
            env[spec["prefixes"][case["owner"]] + "_DEVELOPMENT_MANIFEST"] = "/old/development"
        check(row["command"] == argv and row["environment"] == env and row["timeout_seconds"] == 10
              and row["test_id"] == spec["target_test_id"] and type(row["pid"]) is int and row["pid"] > 0,
              "actual_negative_command_env_test_runtime_timeout")
        check(row["status"] == "NEGATIVE_ADMISSION_RETURNED_AND_CLOSED"
              and all(row[k] is True for k in ("popen_permission_consumed", "process_started", "original_run_called",
                 "original_run_returned", "original_process_context_closed", "output_absent", "evidence_absent"))
              and type(row["returncode"]) is int and row["returncode"] != 0
              and row["returncode_after_original_run"] == row["returncode"]
              and row.get("error") is None and not row.get("preservation_errors"), "real_negative_refusal_and_closed_original_context")
        check(row["runtime_before"] == row["runtime_after"] == request["runtime"]
              and row["directory_before"] == row["directory_after"]
              and row["directory_before"]["mode"] == 0o700 and row["directory_before"]["uid"] == 1001
              and row["cold_before"] == row["cold_after"] and row["cold_before"]["path"] == cwd + "/cold.json"
              and row["cold_before"]["size"] == 2 and row["cold_before"]["sha256"] == sha256(b"{}").hexdigest()
              and row["cold_before"]["uid"] == 1001 and row["cold_before"]["nlink"] == 1
              and row["cold_before"]["mode"] & 0o022 == 0, "held_input_runtime_directory_before_after")
        check(row["binding_sources_before"] == row["binding_sources_after"]
              and [r["path"] for r in row["binding_sources_before"]] == [SOURCE + "/" + n for n in spec["binding_sources"]],
              "four_frozen_negative_binding_sources")
        for pin in row["binding_sources_before"]: bind(pin)
        stem = REMOTE + "/actual-source/evidence/negative-admission-" + str(index)
        for field, suffix in (("input_original", ".input.bin"), ("stdout", ".stdout.bin"),
                              ("stderr", ".stderr.bin"), ("request_original", ".request.json"),
                              ("receipt_original", ".receipt.json")):
            check(row[field]["path"] == stem + suffix, "one_exact_negative_original_path")
            bind(row[field]); negative_originals.append(row[field])
        check(bind(row["input_original"]) == b"{}"
              and (b"development selection" if case["development"] else b"nested_report") in bind(row["stderr"]),
              "actual_original_negative_input_and_error_bytes")
        receipt = json.loads(bind(row["receipt_original"]))
        check(receipt == {k:v for k,v in row.items() if k != "receipt_original"}, "exact_negative_terminal_receipt")
        original = json.loads(bind(row["request_original"]))
        keys = ("schema", "index", "case", "test_id", "command", "cwd", "environment", "timeout_seconds",
                "runtime_before", "binding_sources_before", "temporary_parent", "directory_before", "cold_before", "input_original", "started_monotonic_ns")
        check(original == {k: row[k] for k in keys}, "exact_negative_original_request")
        check(type(row["started_monotonic_ns"]) is int and type(row["ended_monotonic_ns"]) is int
              and row["started_monotonic_ns"] <= row["ended_monotonic_ns"]
              and (last_end is None or row["started_monotonic_ns"] >= last_end), "ordered_negative_actual_timestamps")
        last_end = row["ended_monotonic_ns"]
    postprocess = json.loads(bodies[STEM + ".postprocess.json"])
    check(postprocess["status"] == "SOURCE83_SOURCE_VALIDATION_PASS"
          and postprocess["owner"]["closed"] is True and postprocess["owner"]["natural"] is True
          and postprocess["owner"]["returncode"] == postprocess["owner"]["supervisor_returncode"] == 0
          and postprocess["source_method_count"] == 83 and postprocess["command_count"] == 71
          and postprocess["allowed_negative_processes"] == 4 and postprocess["forbidden_attempts"] == 0
          and postprocess["negative_commands"]["complete_originals"] == negative_originals,
          "independent_remote_finalizer_full_twenty_original_join")
    snapshots = {name:value("actual-source/evidence/"+name) for name in (
        "source-before.json","source-after-generators.json","source-derived.json","source-after.json")}
    prepared = value("SOURCE-PHYSICAL-PINS.json")
    check(snapshots["source-before.json"] == prepared and content(prepared) == request["source_files"]
          and len(prepared) == 1658, "1658_before_source_exact_preparation")
    check(content(snapshots["source-after-generators.json"]) == content(prepared),
          "all62_generated_sources_byte_mode_idempotent")
    before_map={x["relative_path"]:x for x in content(prepared)}
    derived_map={x["relative_path"]:x for x in content(snapshots["source-derived.json"])}
    check(before_map.keys()==derived_map.keys(),"no_source_addition_or_deletion")
    changed=[name for name in before_map if before_map[name]!=derived_map[name]]
    check(changed == worker["actual_derived_changes"]
          and set(changed) == set(request["allowed_derived_changes"]), "exact_actual_two_derived_changes")
    check(content(snapshots["source-derived.json"]) == content(snapshots["source-after.json"])
          == worker["final_source_content"],"after_derivation_idempotence_and_tests_preserved")
    source_paths = {name for name in bodies if name.startswith(STEM+"/source/")}
    check(len(source_paths) == 1658,"all1658_actual_source_bodies_present")
    for row in snapshots["source-after.json"]:
        check(row["path"] == SOURCE+"/"+row["relative_path"],"source_fixed_absolute_path")
        bind(row)
    for name in changed:
        check(body("source/"+name) == body("actual-source/evidence/derived-"+Path(name).name),
              "complete_captured_derived_raw:"+name)
    worker_originals=value("actual-source/evidence/ORIGINALS.json")
    evidence_paths={REMOTE+name[len(STEM):] for name in bodies if name.startswith(STEM+"/actual-source/evidence/")
                    and not name.endswith("/ORIGINALS.json")}
    check(len(worker_originals)==len({x["path"] for x in worker_originals})
          and {x["path"] for x in worker_originals}==evidence_paths,"complete_worker_originals_inventory")
    for pin in worker_originals: bind(pin)
    log=(ROOT/"job-131423025805.original.log").read_bytes()
    check(len(log)==706477 and sha256(log).hexdigest()=="b782233bb258c79d29e40a20f2085ec99b4b44188e81039584efe1f1f0243683",
          "complete_original_job_log")
    marker_lines=[]
    for line in log.decode().splitlines():
        match=re.match(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z (HIA_SOURCE83_[A-Z_]+) (.*)$",line)
        if match: marker_lines.append((match.group(1),match.group(2)))
    check(marker_lines[0][0]=="HIA_SOURCE83_MANIFEST" and marker_lines[-1][0]=="HIA_SOURCE83_END",
          "small_channel_unique_ordered_manifest_and_end")
    manifest=json.loads(marker_lines[0][1]); end=json.loads(marker_lines[-1][1])
    check(manifest==json.loads(bodies[STEM+".small.manifest.json"]),"original_manifest_full_wire_values")
    check(manifest["raw_cap"]==524288 and manifest["stdout_cap"]==1048576
          and len(manifest["fixed_targets"])==34 and manifest["context"]==context
          and manifest["owner"]["closed"] is True and manifest["owner"]["natural"] is True,
          "small_manifest_limits_context_and_successful_closed_owner")
    check([x["index"] for x in manifest["fixed_targets"]]==list(range(34)),"exact34_target_indices")
    selected=[x for x in manifest["fixed_targets"] if x["status"]=="SELECTED_COMPLETE"]
    cursor=1;frame_count=0;raw_count=0
    for row in selected:
        tag,encoded=marker_lines[cursor];cursor+=1
        header=json.loads(encoded)
        check(tag=="HIA_SOURCE83_FILE" and header=={"index":row["index"],"actual":row["actual"]},
              "small_file_header:"+str(row["index"]))
        data=bytearray()
        while marker_lines[cursor][0]=="HIA_SOURCE83_CHUNK":
            chunk=json.loads(marker_lines[cursor][1]);cursor+=1
            raw=base64.b64decode(chunk["base64"],validate=True)
            check(chunk["index"]==row["index"] and chunk["offset"]==len(data)
                  and len(raw)==chunk["size"] and 0<len(raw)<=8192
                  and sha256(raw).hexdigest()==chunk["sha256"],"small_chunk_exact_offset_size_hash")
            data.extend(raw);frame_count+=1
        tag,encoded=marker_lines[cursor];cursor+=1
        finish=json.loads(encoded)
        check(tag=="HIA_SOURCE83_FILE_END" and finish=={"index":row["index"],"size":len(data),
              "sha256":sha256(data).hexdigest()} and digest(bytes(data))=={
                  k:row["actual"][k] for k in ("size","sha256","git_blob_sha1")}, "small_complete_file:"+str(row["index"]))
        check(bytes(data)==absolute_body(row["path"]),"small_raw_matches_exact_zip:"+str(row["index"]))
        raw_count+=len(data)
    check(cursor==len(marker_lines)-1 and len(selected)==27 and frame_count==69 and raw_count==445674,
          "complete_27_files_70frames_445674bytes")
    prefix=b"".join((tag+" "+raw+"\n").encode() for tag,raw in marker_lines[:-1])
    check(len(prefix)==end["prefix_bytes"]==645530 and sha256(prefix).hexdigest()==end["prefix_sha256"],
          "complete_small_channel_prefix")
    result_raw=bind(end["result"]); result=json.loads(result_raw)
    check(result["frames"]==69 and result["selected_files"]==27 and result["raw_bytes"]==445674
          and result["prefix_sha256"]==end["prefix_sha256"],"actual_small_RESULT_full_body")
    output=prefix+(marker_lines[-1][0]+" "+marker_lines[-1][1]+"\n").encode()
    check(output==bodies[STEM+".small.stdout.log"] and len(output)<=1048576,
          "complete_small_stdout_bytes_match_zip")
    derived_dir = ROOT / "derived-originals"
    derived_dir.mkdir()
    for name in changed:
        output = derived_dir / Path(name).name
        output.open("xb").write(body("source/" + name))
    save("DERIVED-ORIGINALS.json", [{"source_path": name, "local_path": str(derived_dir / Path(name).name),
         **digest(body("source/" + name))} for name in changed])
    non_source=[row for row in inventory if not row["path"].startswith(STEM+"/source/")]
    save("ZIP-MANIFEST.json",{"artifact_id":13975032410,"archive":digest(raw_archive),
        "members":inventory,"files":len(inventory),"expanded_bytes":sum(x["size"] for x in inventory)})
    save("AUDIT.json",{"schema":"hepta.hia.numeric-source83-r3-actual-custody-audit.v1",
        "status":"CUSTODY_COMPLETE_ACTUAL_SOURCE83_PASS","checks":CHECKS,
        "check_count":len(CHECKS),"bound_raw_pin_joins":bound_pins,
        "actual_run":43287029044,"actual_job":131423025805,
        "artifact_id":13975032410,"artifact":digest(raw_archive),
        "all_zip_members_read":len(inventory),"expanded_bytes":sum(x["size"] for x in inventory),
        "source_body_count":1658,"non_source_original_count":len(non_source),
        "non_source_original_bytes":sum(x["size"] for x in non_source),
        "qualification_result":"SOURCE83_PASS","owner_status":life["status"],
        "owner_returncode":life["returncode"],"supervisor_returncode":wrapper["supervisor_returncode"],
        "worker_seconds":worker["seconds"],"timed_out":False,"closed_ECHILD":True,
        "commands":command_rows,"source_ids":ids,"source_tests_failures":tests["failures"],
        "source_tests_errors":tests["errors"],"blocked_subprocess_attempts":tests["native_or_compiler_or_process_attempts"],
        "changed_documents":changed,"small_channel":{"files":27,"frames":69,"raw_bytes":445674},
        "no_product_or_source_reexecution":True,"source_validation_pass_claimed":True,
        "pure_derived_candidate_published":False,"native_cold_installed_claimed":False,"allowed_negative_commands":4,"negative_originals":negative_originals})
    print(json.dumps({"status":"CUSTODY_COMPLETE_ACTUAL_SOURCE83_PASS",
        "checks":len(CHECKS),"raw_pin_joins":bound_pins,"zip_members":len(inventory),
        "non_source_originals":len(non_source),"non_source_bytes":sum(x["size"] for x in non_source),
        "source_ids":len(ids),"failures":0,"errors":0,"worker_seconds":worker["seconds"]},sort_keys=True))

if __name__=="__main__":
    main()
