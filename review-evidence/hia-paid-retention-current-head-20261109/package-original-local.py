"""Package one retained local attempt by reading bytes only; never run the producer."""
import argparse
from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path
import tarfile

p = argparse.ArgumentParser()
p.add_argument("--original", type=Path, required=True)
p.add_argument("--expected", type=Path, required=True)
p.add_argument("--output", type=Path, required=True)
a = p.parse_args()
a.output.mkdir(parents=True, exist_ok=False)
expected = json.loads(a.expected.read_bytes())
original = a.original
paths = sorted(original.rglob("*"))
assert not any(x.is_symlink() for x in paths)
files = [x for x in paths if x.is_file()]
assert len(files) == 164
contents = {str(x.relative_to(original)): x.read_bytes() for x in files}
receipt_path = "hia-paid-retention/evidence/RESULT.json"
receipt = json.loads(contents[receipt_path])
execution = json.loads(contents["EXECUTION.json"])
identity = {"commit":expected["head"],"tree":expected["tree"],"status":""}
assert receipt["status"] == "PASS" and receipt["source_commit"] == expected["head"]
assert receipt["source_before"] == receipt["source_after"] == identity
assert execution["source_before"] == execution["source_after"] == identity
assert execution["status"] == "PASS_CURRENT_HEAD_12_TESTS" and execution["exit_code"] == 0
assert execution["hosted_ci_result"] is False and execution["old_task_replayed"] is False
assert receipt["source"] == expected["source"]
assert receipt["registered_wall_budget_ns"] == execution["expected_cell_budget_ns"] == 2000000000
assert receipt["planned_tests"] == receipt["tests_run"] == 12
assert receipt["expected_test_ids"] == receipt["loaded_test_ids"] == expected["expected_test_ids"]
assert sorted(receipt["executed_test_ids"]) == expected["expected_test_ids"]
assert len(set(receipt["executed_test_ids"])) == 12
for key in ["failures","errors","skipped","expected_failures","unexpected_successes","loader_errors"]:
    assert receipt[key] == [], key
assert receipt["old_job_replayed"] is False and receipt["ndu_status"] == "NOT_RUN"
assert receipt["original_source_unchanged"] is True and execution["source_unchanged"] is True
assert contents["hia-paid-retention/evidence/source.patch"] == b""
for name, value in expected["source"].items():
    b = contents["hia-paid-retention/evidence/source/" + name]
    assert len(b) == value["bytes"] and sha256(b).hexdigest() == value["sha256"]
workflow_path = "hia-paid-retention/evidence/source/.github/workflows/hia-paid-observation-retention.yml"
workflow = contents[workflow_path].decode()
assert "          include-hidden-files: true\n" in workflow
block, inside = [], False
for line in workflow.splitlines():
    if line == "        run: |":
        inside = True
        continue
    if inside:
        if line and not line.startswith("          "):
            break
        block.append(line[10:] if line else "")
assert ("\n".join(block) + "\n").encode() == contents["workflow-step.sh"]
for key in ["stdout","stderr"]:
    b = contents["workflow-step." + key]
    assert execution[key] == {"bytes":len(b),"sha256":sha256(b).hexdigest()}
assert execution["step_sha256"] == sha256(contents["workflow-step.sh"]).hexdigest()
assert contents["workflow-step.stdout"] == contents["hia-paid-retention/tests.log"]
assert len(receipt["retained_fixtures"]) == execution["retained_fixture_directories"] == 10
for fixture in receipt["retained_fixtures"]:
    assert fixture["test"] in expected["expected_test_ids"]
    prefix = "hia-paid-retention/evidence/fixtures/" + Path(fixture["directory"]).name + "/"
    assert any(name.startswith(prefix) for name in contents)
index = {"schema":"hepta.hia.original-file-index.v1","original_files":len(contents),
         "original_bytes":sum(map(len,contents.values())),
         "files":[{"path":"original/"+name,"bytes":len(b),"sha256":sha256(b).hexdigest()}
                  for name,b in contents.items()]}
index_bytes = (json.dumps(index,sort_keys=True,indent=2)+"\n").encode()
archive_path = a.output / "original-attempt.tar.xz"
with tarfile.open(archive_path,"w:xz") as t:
    for name,b in [("FILE_INDEX.json",index_bytes)] + [("original/"+n,b) for n,b in contents.items()]:
        info = tarfile.TarInfo(name)
        info.size, info.mode, info.mtime = len(b), 0o644, 0
        t.addfile(info,BytesIO(b))
seen = {}
with tarfile.open(archive_path,"r:xz") as t:
    for member in t:
        assert member.isfile()
        b = t.extractfile(member).read()
        if member.name == "FILE_INDEX.json":
            assert b == index_bytes
        else:
            assert member.name.startswith("original/")
            original_name = member.name[len("original/"):]
            assert b == contents[original_name]
            seen[member.name] = {"bytes":len(b),"sha256":sha256(b).hexdigest()}
assert len(seen) == len(contents)
for row in index["files"]:
    assert seen[row["path"]] == {k:row[k] for k in ["bytes","sha256"]}
archive_bytes = archive_path.read_bytes()
archive = {"schema":"hepta.hia.paid-retention-local-archive.v1",
           "path":archive_path.name,"bytes":len(archive_bytes),"sha256":sha256(archive_bytes).hexdigest(),
           "indexed_original_files":len(contents),"indexed_original_bytes":index["original_bytes"],
           "file_index_sha256":sha256(index_bytes).hexdigest(),"all_indexed_bytes_re_read_equal":True}
audit = {"schema":"hepta.hia.paid-retention-local-byte-audit.v1","status":"PASS",
         "head":expected["head"],"tree":expected["tree"],"hosted_ci_result":False,
         "executed_test_ids":receipt["executed_test_ids"],"tests_run":12,
         "skipped":0,"failures":0,"errors":0,"retained_fixture_directories":10,
         "registered_wall_budget_ns":2000000000,"clean_before_and_after":True,
         "source_snapshots_match":True,"hidden_workflow_snapshot_present":True,
         "published_workflow_run_block_equals_executed_step":True,
         "suite_wall_ns":receipt["wall_ns"],
         "suite_parent_cpu_ns":receipt["parent_cpu_ns"],"suite_child_cpu_ns":receipt["child_cpu_ns"],
         "execution_started_utc":execution["started_utc"],"execution_completed_utc":execution["completed_utc"],
         "root_outer_elapsed_seconds":execution["outer_elapsed_seconds"],
         "archive":archive,"producer_imported_or_executed_by_packager":False,
         "old_task_replayed":False,"ndu_status":"NOT_RUN",
         "full_billed_cost_known":False,"independent_timing_attestation_claim":False}
for name,b in {"EXECUTION.json":contents["EXECUTION.json"],"QUALIFICATION.json":contents[receipt_path],
               "workflow-step.sh":contents["workflow-step.sh"],"workflow-step.stdout":contents["workflow-step.stdout"],
               "workflow-step.stderr":contents["workflow-step.stderr"],"FILE_INDEX.json":index_bytes,
               "expected.json":a.expected.read_bytes()}.items():
    (a.output/name).write_bytes(b)
for name,value in [("ARCHIVE.json",archive),("BYTE_AUDIT.json",audit)]:
    (a.output/name).write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
(a.output/"package-original-local.py").write_bytes(Path(__file__).read_bytes())
print(json.dumps(archive,sort_keys=True))
print(json.dumps({k:v for k,v in audit.items() if k not in ["archive","executed_test_ids"]},sort_keys=True))
