"""Capture frozen-source proofs and independent summaries for one downloaded run."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

import source_git_audit
import zip_git_audit
from report_audit import review_reports
from supplemental_audit import review_supplemental


def save(path, value):
    with path.open("x") as stream:
        stream.write(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n")


def identity(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--repo", type=Path, required=True)
parser.add_argument("--raw", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
parser.add_argument("--job-log", type=Path, required=True)
parser.add_argument("--observations", type=Path, required=True)
args = parser.parse_args()
members = {path.relative_to(args.raw).as_posix(): path.read_bytes()
           for path in args.raw.rglob("*") if path.is_file()}
inventory = json.loads((args.output / "zip-inventory.json").read_bytes())
full = json.loads(members["artifacts/candidate/release-validation.json"])
assert full["source_git_commit"] == source_git_audit.COMMIT
source_summary = source_git_audit.prepare(args.repo, full["source_snapshot"], args.output)
zip_summary = zip_git_audit.capture(args.repo, inventory, args.output / "zip-source-tree-proof.json")
save(args.output / "capture-source-audit.json", {"source_snapshot": source_summary, "zip_classification": zip_summary})

helpers = ("performance_audit.py", "report_audit.py", "supplemental_audit.py", "verify_bundle.py",
           "source_git_audit.py", "zip_git_audit.py", "select_originals.py", "capture_archive.py", "build_sidecars.py", "seal_bundle.py")
for name in helpers:
    raw = (Path(__file__).parent / name).read_bytes()
    with (args.output / name).open("xb") as stream:
        stream.write(raw)
with (args.output / ".gitattributes").open("xb") as stream:
    stream.write(b"* -text\n*.log -diff\n*.b64* -diff\n")

job = args.job_log.read_bytes()
with (args.output / "job-121976747689.log").open("xb") as stream:
    stream.write(job)
for path in sorted(args.observations.glob("*.json")):
    output = args.output / "provider-observations" / path.name
    output.parent.mkdir(exist_ok=True)
    with output.open("xb") as stream:
        stream.write(path.read_bytes())

copy_paths = ["artifacts/workflow-source.json", "artifacts/candidate/release-validation.json",
    "artifacts/candidate/unit_and_integration.log", "artifacts/candidate/sandbox.json",
    "artifacts/candidate/task_io_composition.json",
    "artifacts/candidate/llvm_native.json", "artifacts/candidate/llvm_owned.json",
    "artifacts/candidate/cpp_composed_llvm.json", "artifacts/candidate/cpp_owned_llvm.json",
    "artifacts/hia-unified/qualification.json",
    "artifacts/hia-unified/unit_regression.stderr.log", "artifacts/hia-unified/performance.json",
    "artifacts/hia-unified/performance-artifacts/artifact-retention.json"]
copy_paths.extend(row["log"] for row in full["gates"] if row["status"] != "passed")
copies = []
for name in sorted(set(copy_paths)):
    if name not in members:
        continue
    raw = members[name]
    target = "originals/" + name
    output = args.output / target
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("xb") as stream:
        stream.write(raw)
    copies.append({"path": target, "archive_member": name, **identity(raw)})
save(args.output / "original-copies.json", copies)
save(args.output / "original-identities.json", {
    "source_commit": source_git_audit.COMMIT, "run_id": 40439677114, "job_id": 121976747689,
    "job_log": {**identity(job), "lines": len(job.decode().splitlines()),
                "capture_scope": "complete provider-decoded job log, encoded as UTF-8 without content editing"},
    "files": {name: identity(raw) for name, raw in sorted(members.items())}})
sidecars = {path.relative_to(args.output).as_posix(): path.read_bytes()
            for path in args.output.rglob("*") if path.is_file()}
review = review_reports(members, sidecars, inventory["members"])
save(args.output / "review.json", review)
supplemental = review_supplemental(members, sidecars)
save(args.output / "supplemental-review.json", supplemental)
print(json.dumps({"source": source_summary, "classification": zip_summary,
    "source_full": review["full_source"], "hia": review["hia"],
    "namespace": supplemental["namespace"], "known_qualification_limitations": supplemental["known_qualification_limitations"],
    "performance": {name: {key: row.get(key) for key in ("phase", "status", "observed_raw_samples")}
                    for name, row in review["performance"].items()}}, indent=2, sort_keys=True))
