"""Independently join the two provider-sealed ZIP artifacts and original controls.

No network, project import, executable loading, or product execution.
"""
import binascii
import hashlib
import json
import os
from pathlib import Path
import stat
import time
import traceback
import zipfile

ROOT = Path(__file__).resolve().parent / "full-zip-two-parts-r1"
OUT = ROOT / "actual-local-readback-r1"
PARTS = [(0, 314572800, "95d2d3471e8d6772419c50636328845f1208bd0536b19c1b4f232d6099cf2651"),
         (314572800, 284854451, "c86b2d665ddbc6cc27b709bd53e06d4c658b73f9574c05bce8f829631aa6ef01")]
SEALED = [(13921918024, 314648599, "4be52f18e29956996c88674e638f96fd24dcc137cd72fc771bd15e8d754244ba"),
          (13922162652, 284930266, "f41a9aa57ed55bc040856655fab14c4d80c663d6e9bd243be27c3f18654c29c7")]
ORIGINAL_SIZE = 599427251
ORIGINAL_SHA = "40e81308484173d36153f6a3014293a78705aa28e8f8f7718dcdd3d87c03f580"
A = "969b5ab2c6aa267a778ae35478dde24098b99050"
B = "75d8de12f462bbeab29364577d3575c30fc12626"
POLICY_SHA = "840fa84af6254d1685064ce5e4b1d4561a5377bfca10fcee5778b27a555616b1"
OWNER_SHA = "36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2"
OLD_ROOT = "/home/runner/work/_temp/hia-970-full-original-two-parts-r1"
PREFIX = "experiments/hia_970_ci_original_custody_20261112/full-zip-two-parts-r1/"
CONTROLS = ['context.json', 'setup.json', 'guard/request.json', 'guard/guardian.json',
            'guard/child.stdout.log', 'guard/child.stderr.log', 'supervisor.stdout.log',
            'supervisor.stderr.log', 'recovery.json', 'recovery-terminal.json',
            'api/artifact-13911977275.metadata.original.json']
CHUNK = 1024 * 1024

def sha(b):
    return hashlib.sha256(b).hexdigest()

def record(b):
    return {"bytes": len(b), "sha256": sha(b)}

def ident(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns)

def file_sha(p, size, expected_sha):
    assert not any(q.is_symlink() for q in (p, *p.parents))
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as f:
        before = os.fstat(f.fileno())
        assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size == size
        h = hashlib.sha256()
        count = 0
        for b in iter(lambda: f.read(CHUNK), b""):
            h.update(b)
            count += len(b)
        assert count == size and h.hexdigest() == expected_sha
        assert ident(before) == ident(os.fstat(f.fileno())) == ident(p.lstat())
    return {"path": str(p), "bytes": count, "sha256": h.hexdigest(), "identity": list(ident(before))}

def put(p, b):
    with p.open("xb") as f:
        f.write(b)
        f.flush()
        os.fsync(f.fileno())
    assert p.read_bytes() == b
    return {"path": str(p), **record(b)}

def main():
    OUT.mkdir(mode=0o700, exist_ok=False)
    report = {"schema": "hia.970-two-artifact-independent-local-reconstruction.v1",
              "status": "HOLD", "errors": [], "provider_artifacts": [],
              "original_product_execution": False, "full_5400_executed": False,
              "historical_custody_statuses_reclassified": False}
    started = time.monotonic_ns()
    try:
        policy_raw = (ROOT / "control/policy.json").read_bytes()
        assert sha(policy_raw) == POLICY_SHA
        policy = json.loads(policy_raw)
        fixed = {"slice.bin", "PART.json", "FINAL.json"} | {"controls/" + n.replace("/", "--") for n in CONTROLS}
        final_raw = None
        common_controls = None
        whole = hashlib.sha256()
        total = 0
        output_path = OUT / "artifact-13911977275.original.zip"
        fd = os.open(output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        with os.fdopen(fd, "wb") as output:
            for number, ((artifact_id, size, digest), (offset, length, part_sha)) in enumerate(zip(SEALED, PARTS)):
                path = ROOT / ("part-%02d.artifact.original.zip" % number)
                before = file_sha(path, size, digest)
                report["provider_artifacts"].append({"artifact_id": artifact_id, **before})
                with zipfile.ZipFile(path) as z:
                    infos = z.infolist()
                    assert len(infos) == 14 and {i.filename for i in infos} == fixed
                    assert sum(i.file_size for i in infos) <= 320 * CHUNK
                    assert all(not i.is_dir() and not i.flag_bits & 1 and i.compress_type in (0, 8)
                               and stat.S_IFMT(i.external_attr >> 16) in (0, stat.S_IFREG) for i in infos)
                    small = {n: z.read(n) for n in fixed - {"slice.bin"}}
                    if number == 0:
                        final_raw = small["FINAL.json"]
                        common_controls = {n: small["controls/" + n.replace("/", "--")] for n in CONTROLS}
                        for name, data in small.items():
                            put(OUT / ("part00-" + name.replace("/", "--")), data)
                    else:
                        assert small["FINAL.json"] == final_raw
                        assert all(small["controls/" + n.replace("/", "--")] == common_controls[n] for n in CONTROLS)
                        put(OUT / "part01-PART.json", small["PART.json"])
                    final = json.loads(small["FINAL.json"])
                    part = json.loads(small["PART.json"])
                    assert final["schema"] == "hia.actions.970-full-original-two-parts-final.v1"
                    assert final["status"] == part["status"] == "TWO_SEALED_CONTIGUOUS_PARTS_VERIFIED_NOT_QUALIFICATION"
                    assert final["complete_local_two_part_readback"] is True and final["closed_echild"] is True
                    assert final["source_inputs_preserved"] is True and final["errors"] == final["missing_originals"] == []
                    assert final["artifact"] == part["artifact"] == policy["artifact"]
                    assert final["new_product_execution"] is final["old_runs_replayed"] is False
                    assert final["full_5400_retained_suite_executed"] is final["historical_results_reclassified"] is False
                    assert final["expected_parts"] == policy["parts"]
                    assert part["schema"] == "hia.970-original-zip-part.v1"
                    assert part["run_id"] == 43171286581 and part["run_attempt"] == 1
                    assert part["control_commit"] == A and part["workflow_commit"] == B and part["policy_sha256"] == POLICY_SHA
                    assert part["expected"] == policy["parts"][number]
                    observed = final["parts"][number]
                    assert observed == part["observed"] and observed["kind"] == "SEALED_ORIGINAL_RANGE"
                    assert {k: observed[k] for k in policy["parts"][number]} == policy["parts"][number]
                    for key in ("source", "retained"):
                        assert observed[key]["bytes"] == length and observed[key]["sha256"] == part_sha
                        assert observed[key]["identity"][5] == 1 and observed[key]["identity"][6] == length
                    expected_copy = final["captured_controls"]
                    assert [x["name"] for x in expected_copy] == CONTROLS
                    for entry in expected_copy:
                        data = common_controls[entry["name"]]
                        for item in [entry["original"], *entry["copies"]]:
                            assert item["bytes"] == len(data) and item["sha256"] == sha(data)
                            assert item["identity"][5] == 1 and item["identity"][6] == len(data)
                    h = hashlib.sha256()
                    crc = 0
                    count = 0
                    assert total == offset and z.getinfo("slice.bin").file_size == length
                    with z.open("slice.bin") as incoming:
                        for chunk in iter(lambda: incoming.read(CHUNK), b""):
                            count += len(chunk)
                            assert count <= length
                            h.update(chunk)
                            whole.update(chunk)
                            crc = binascii.crc32(chunk, crc)
                            output.write(chunk)
                    assert count == length and h.hexdigest() == part_sha
                    assert crc & 0xffffffff == z.getinfo("slice.bin").CRC
                    total += count
                    report.setdefault("parts", []).append({"ordinal": number, "offset": offset,
                        "bytes": count, "sha256": h.hexdigest(), "crc32": crc & 0xffffffff})
                assert file_sha(path, size, digest) == before
            assert total == ORIGINAL_SIZE and whole.hexdigest() == ORIGINAL_SHA
            output.flush()
            os.fsync(output.fileno())
        context = json.loads(common_controls["context.json"])
        setup = json.loads(common_controls["setup.json"])
        request = json.loads(common_controls["guard/request.json"])
        guard = json.loads(common_controls["guard/guardian.json"])
        worker = json.loads(common_controls["recovery-terminal.json"])
        assert context == final["context"] == setup["context"]
        assert context["actual_control_checkout"] == A and context["actual_workflow_commit"] == B
        assert context["run_id"] == 43171286581 and context["run_attempt"] == 1
        assert context["event"] == "create" and context["event_ref_type"] == "branch"
        assert context["event_ref"] == policy["trigger_branch"] and context["policy_sha256"] == POLICY_SHA
        assert context["original_product_commit"] == policy["source"]["head"]
        assert context["original_product_tree"] == policy["source"]["tree"]
        assert context["root"] == OLD_ROOT and context["qualification_executed"] is False
        command = [context["python"]["resolved"], "-I", "-S", "-B", OLD_ROOT + "/control/worker.py",
                   "--root", OLD_ROOT, "--policy-sha256", POLICY_SHA]
        assert setup["command"] == request["command"] == guard["command"] == command
        assert request["schema"] == "hia-external-guardian-request.v1" and request["controller_seconds"] == 900
        assert setup["controller_seconds"] == 900 and setup["cleanup_seconds"] == 3
        assert request["cwd"] == guard["cwd"] == OLD_ROOT
        assert sha(common_controls["guard/request.json"]) == setup["guardian_config_sha256"]
        assert setup["source_identities"] == request["source_identities"] == guard["source_identities_before"] == guard["source_identities_after"]
        assert guard["schema"] == "hepta.hia.external-qualification-guardian.v1"
        assert guard["lifecycle_implementation_sha256"] == OWNER_SHA
        assert guard["status"] == "EXTERNAL_OWNED_PROCESS_COMPLETED" and guard["input_identity_preserved"] is True
        assert guard["external_controller_seconds"] == 900 and guard["qualification"] is None
        assert guard["whole_native_delivery_qualified"] is guard["cold_180_second_gate_modified"] is False
        life = guard["lifecycle"]
        assert life["schema"] == "hepta.hia.external-qualification-guardian.v1.lifecycle"
        assert life["status"] == "OWNED_PROCESS_COMPLETED" and life["returncode"] == 0
        assert life["qualification_seconds"] == 900 and life["cleanup_seconds"] == 3
        assert life["qualification_started"] is life["exit_observed_before_deadline"] is life["subreaper_enabled"] is True
        assert life["timed_out"] is life["event_overflow"] is False and life["interrupted_signals"] == []
        assert life.get("owner_error") is None
        clean = life["cleanup"]
        assert all(clean[k] is True for k in ("attempted", "complete", "observed_echild", "leader_reaped"))
        assert clean["deadline_exceeded"] is False and clean["remaining_direct_children"] == clean["errors"] == []
        events = life["events"]
        assert [e["kind"] for e in events] == ["qualification_started", "owned_child_observed", "qualification_exit_observed", "owned_child_reaped"]
        assert events[2]["si_code"] == 1 and events[2]["si_status"] == events[3]["returncode"] == 0
        assert guard["logs"] == {OLD_ROOT + "/guard/" + n: sha(common_controls["guard/" + n]) for n in ("child.stdout.log", "child.stderr.log")}
        for key, name in (("setup", "setup.json"), ("guardian", "guard/guardian.json"), ("worker", "recovery-terminal.json")):
            assert all(final[key][k] == v for k, v in record(common_controls[name]).items())
        assert worker["status"] == "TWO_SEALED_PARTS_PENDING_NATURAL_GUARDIAN"
        assert worker["policy_sha256"] == POLICY_SHA and worker["artifact"] == policy["artifact"]
        assert worker["source"] == policy["source"]
        assert len(worker["API_attempts"]) == 2 and len(worker["GET_attempts"]) == 1
        assert worker["GET_attempts"][0]["bytes"] == ORIGINAL_SIZE and worker["GET_attempts"][0]["sha256"] == ORIGINAL_SHA
        assert all(v["sha256"] == setup["source_identities"][p] for p, v in final["source_inputs_final"].items())
        assert set(final["source_inputs_final"]) == set(setup["source_identities"])
        report["original"] = file_sha(output_path, ORIGINAL_SIZE, ORIGINAL_SHA)
        report["final_original"] = record(final_raw)
        report["guardian_original"] = record(common_controls["guard/guardian.json"])
        report["owner_seconds"] = (events[2]["monotonic_ns"] - events[0]["monotonic_ns"]) / 1e9
        report["actual_runner"] = context["runner"]
        report["status"] = "TWO_PARTS_FULL_RECONSTRUCTION_AND_NATURAL_OWNER_VERIFIED_NOT_QUALIFICATION"
    except BaseException as error:
        report["errors"].append({"type": type(error).__name__, "message": str(error), "traceback": traceback.format_exc()})
    report["elapsed_ns"] = time.monotonic_ns() - started
    report["reader_sha256"] = sha(Path(__file__).read_bytes())
    result = put(OUT / "RECONSTRUCTION.json", (json.dumps(report, sort_keys=True, indent=2) + "\n").encode())
    print(json.dumps({"status": report["status"], "original": report.get("original"), "report": result}))
    return 1 if report["errors"] else 0

if __name__ == "__main__":
    raise SystemExit(main())
