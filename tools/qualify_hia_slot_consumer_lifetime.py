"""Capture a separate Slot consumer/terminal lifetime contract through GDB.

The original strict observer and its result remain unchanged. This tool neither
changes production code nor sets GC thresholds or requests additional collection.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import shutil
import sys

HERE = Path(__file__).resolve().parents[1]
PROFILE = HERE / "tests/fixtures/hia_slot_external_lifetime_cpython3144.json"
PROBE = HERE / "tests/hia_slot_external_lifetime_probe.py"
GROUPS = ("original248", "derived7574")
DIAGNOSTIC_ORDINALS = (573, 818, 857, 862, 1843, 2953, 3026, 3029,
                       3032, 3568, 3621, 3624, 4058, 4207, 5606)
LAYOUTS = {"external-state-layout.json", "external-heap-types-layout.json",
           "frozen-row-owner-layout.json", "frozen-traceback-layout.json",
           "inline-layout.json", "frame-layout.json"}


def read(path):
    return json.loads(Path(path).read_text())


def pin(path):
    path = Path(path).resolve(strict=True)
    raw = path.read_bytes()
    return {"path": str(path), "bytes": len(raw), "sha256": sha256(raw).hexdigest()}


def write(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def validate_profile(profile, python, gdb):
    value = read(profile)
    if (value.get("schema") != "hepta.slot.external-lifetime-layout.v1"
            or set(value.get("layouts", {})) != LAYOUTS):
        raise ValueError("unsupported external lifetime layout contract")
    if pin(python)["sha256"] != value["python"]["sha256"]:
        raise ValueError("Python executable differs from the independently checked layout")
    if pin(gdb)["sha256"] != value["gdb"]["sha256"]:
        raise ValueError("GDB executable differs from the recorded capture tool")
    return value


def capture(root, baseline, evidence, profile, gdb):
    root, baseline = root.resolve(strict=True), baseline.resolve(strict=True)
    gdb = gdb.resolve(strict=True)
    originals = {g: read(baseline / (g + "-original-1") / "command.json")
                 for g in GROUPS}
    python = Path(originals[GROUPS[0]]["argv"][0])
    layout = validate_profile(profile, python, gdb)
    commands = {}
    for backend in ("original", "native"):
        for group in GROUPS:
            label = group + ("-original-1" if backend == "original" else "-native")
            command = read(baseline / label / "command.json")
            if Path(command["cwd"]).resolve() != root or Path(command["argv"][0]) != python:
                raise ValueError("baseline source root or Python executable differs")
            if any("\n" in key + value or "\r" in key + value or "\0" in key + value
                   for key, value in command["environment"].items()):
                raise ValueError("baseline environment cannot be represented exactly by GDB")
            commands[group, backend] = (label, command)
    evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    layout_dir = evidence / "layout"
    layout_dir.mkdir()
    for name, value in layout["layouts"].items():
        write(layout_dir / name, value)
    shutil.copyfile(PROBE, evidence / "probe.py")
    labels = {g: {b: g + "-" + b for b in ("original", "native")} for g in GROUPS}
    write(evidence / "labels.json", labels)
    write(evidence / "capture-inputs.json", {
        "schema": "hepta.slot.external-lifetime-capture.v1",
        "root": str(root), "baseline": str(baseline), "probe": pin(PROBE),
        "profile": pin(profile), "python": pin(python), "gdb": pin(gdb),
        "driver": pin(__file__), "labels": labels,
        "original_strict_report": pin(baseline / "independent-readback/report.json"),
    })
    sys.path.insert(0, str(root))
    from tests.hia_slot_operations_qualification_support import run_owned

    # Both complete original groups finish before either complete native group.
    for backend in ("original", "native"):
        for group in GROUPS:
            source_label, command = commands[group, backend]
            base = baseline / source_label / "observation"
            folder = evidence / labels[group][backend]
            folder.mkdir()
            argv = list(command["argv"])
            argv[argv.index("--output") + 1] = str(folder / "observation")
            config = {
                "layout_base": str(layout_dir),
                "frame_layout": str(layout_dir / "frame-layout.json"),
                "ordered_ids": read(base / "planned.json")["ordered_ids"],
                "diagnostic_ordinals": list(DIAGNOSTIC_ORDINALS) if group == "derived7574" else [],
                "expected_environment": command["environment"],
                "records": str(folder / "external-records.jsonl"),
                "report": str(folder / "external-report.json"),
            }
            write(folder / "config.json", config)
            wrapper = folder / "gdb.py"
            wrapper.write_text(
                "from pathlib import Path\nconfig_file=" + repr(str(folder / "config.json"))
                + "\nexec(compile(Path(" + repr(str(evidence / "probe.py")) + ").read_text(),"
                + repr(str(evidence / "probe.py")) + ",'exec'))\n")
            result = run_owned(
                [str(gdb), "-q", "-nx", "-batch", "-x", str(wrapper), "--args", *argv],
                cwd=root, directory=folder / "owned", timeout_seconds=2400,
                environment=command["environment"])
            write(folder / "process.json", result)
            probe_report = read(folder / "external-report.json")
            print(json.dumps({"group": group, "backend": backend,
                "status": probe_report["status"], "cases": probe_report["cases"],
                "natural_exit": probe_report["natural_inferior_exit_code"]}), flush=True)
            if (result["exit_code"] != 0 or result["timed_out"]
                    or probe_report["status"] != "RECORDED"):
                raise ValueError("external capture incomplete; retain this failure, do not retry for green")
    return labels


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--profile", type=Path, default=PROFILE)
    parser.add_argument("--gdb", type=Path, default=Path("/usr/bin/gdb"))
    options = parser.parse_args()
    labels = capture(options.root, options.baseline, options.evidence, options.profile, options.gdb)
    from read_hia_slot_consumer_lifetime import readback
    report = readback(options.root, options.baseline, options.evidence, options.profile, labels, PROBE)
    write(options.evidence / "independent-lifetime-readback.json", report)
    print(json.dumps({"semantic_gate": report["semantic_gate"],
                      "original_strict_status": report["original_strict_status"],
                      "seal_comparison_status": report["seal_comparison_status"]}, sort_keys=True))
    return 0 if report["semantic_gate"]["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
