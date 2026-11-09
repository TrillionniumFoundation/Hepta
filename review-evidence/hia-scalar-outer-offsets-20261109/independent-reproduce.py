"""Offline independent mutations of the original scalar control campaign."""
import argparse
from hashlib import sha256
import io
import json
from pathlib import Path
import subprocess
import tempfile
from types import ModuleType, SimpleNamespace
from unittest.mock import patch
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--ref", required=True)
    parser.add_argument("--expect", choices=("accept", "reject"), required=True)
    args = parser.parse_args()
    source = subprocess.check_output(["git", "show", args.ref + ":tools/measure_hia_scalar_controller_controls.py"], cwd=args.repository)
    study = ModuleType("independent_scalar_outer_review")
    study.__file__ = str(args.repository / "tools/measure_hia_scalar_controller_controls.py")
    exec(compile(source, study.__file__, "exec"), study.__dict__)
    path = args.repository / "review-evidence/hia-ndu-scalar-controls-20261108-23d1/original-campaign.zip"
    raw = path.read_bytes()
    assert sha256(raw).hexdigest() == "d9025d10bacdd5e8558625c26fce40130effc87e05fe962a2387bfd4680add6d"
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        assert archive.testzip() is None
        originals = {name.removeprefix("campaign/"): archive.read(name) for name in archive.namelist()
                     if name.startswith("campaign/") and not name.endswith("/")}
    observations = []
    for case in ("understated_outer", "summary_cell_offset_float", "successful_count_float", "completed_pairs_float"):
        files = dict(originals)
        summary = study.decode(files["SUMMARY.json"])
        if case == "understated_outer":
            cost = summary["measurement"]
            cost["outer_wall_ns_to_summary_preparation"] = cost["all_attempted_call_wall_ns"]
            cost["admission_capture_export_audit_wall_ns"] = 0
        elif case == "summary_cell_offset_float":
            summary["cells"][0]["end_offset_ns"] = float(summary["cells"][0]["end_offset_ns"])
        elif case == "successful_count_float":
            summary["successful_native_calls"] = float(summary["successful_native_calls"])
        else:
            summary["completed_pairs"] = float(summary["completed_pairs"])
        files["SUMMARY.json"] = study.wire(summary)
        row = {"case": case, "checker_sha256": sha256(source).hexdigest()}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original_read, original_iterdir = study.read_bytes, Path.iterdir

            def read(path):
                path = Path(path)
                return files[str(path.relative_to(root))] if path.is_relative_to(root) else original_read(path)

            def iterdir(path):
                return iter(root / name for name in files if name.startswith("objects/")) if path == root / "objects" else original_iterdir(path)

            with patch.object(study, "read_bytes", read), patch.object(Path, "iterdir", iterdir):
                try:
                    result = study.verify(SimpleNamespace(directory=root, expected_plan_sha256=sha256(files["PLAN.json"]).hexdigest(), output=None))
                    row.update(accepted=True, verification=result["verification"],
                               successful_native_calls=result["successful_native_calls"], completed_pairs=result["completed_pairs"])
                except ValueError as error:
                    row.update(accepted=False, error=str(error))
        observations.append(row)
    print(json.dumps({"schema": "hepta.hia.scalar.outer-independent-review.v1", "ref": args.ref,
                      "expect": args.expect, "archive_sha256": sha256(raw).hexdigest(),
                      "native_processes_started": 0, "observations": observations}, indent=2))
    assert all(row["accepted"] is (args.expect == "accept") for row in observations)


if __name__ == "__main__":
    main()
