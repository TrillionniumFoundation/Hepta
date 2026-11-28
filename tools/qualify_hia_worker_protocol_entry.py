"""Run every retained native Worker CLI case for an explicit options protocol."""
from pathlib import Path
import argparse
import json
import sys
import traceback
from tools.hia_worker_entry_protocol_fixture import prepare, ORIGINAL

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__, add_help=False)
    parser.add_argument("--protocol", choices=("01", "02", "03"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args, rest = parser.parse_known_args()
    if any(x == "--case" or x.startswith("--case=") for x in rest):
        raise ValueError("the explicit protocol gate requires every original CLI case")
    output = args.output.resolve()
    if output.exists():
        raise ValueError("Worker protocol qualification requires a fresh output")
    sidecar = output.with_name(output.name + ".protocol-preparation.json")
    if sidecar.exists():
        raise ValueError("Worker protocol preparation already exists")
    prepared = prepare(ROOT, args.protocol)
    record = prepared.evidence()
    record["component_gate_passed"] = False
    sidecar.parent.mkdir(parents=True, exist_ok=True)
    sidecar.write_text(json.dumps(record, sort_keys=True, indent=2) + "\n")
    saved = list(sys.argv)
    try:
        sys.argv = [str(ROOT / ORIGINAL), "--output", str(output), *rest]
        namespace = {"__name__": "__main__", "__file__": str(ROOT / ORIGINAL),
                     "__package__": None}
        exec(compile(prepared.source, str(ROOT / ORIGINAL), "exec"), namespace)
        result = namespace["record"]
        if (result.get("passed") is not True or not result["cases"]
                or result["case_count"] != len(result["cases"])
                or any(row["passed"] is not True for row in result["cases"])):
            raise ValueError("the complete original CLI gate did not pass")
        prepared.verify()
        record.update(component_gate_passed=True, original_cases=result["case_count"])
    except BaseException:
        record["error"] = traceback.format_exc()
        raise
    finally:
        sys.argv = saved
        try:
            prepared.verify()
        except BaseException:
            record["component_gate_passed"] = False
            record["terminal_input_error"] = traceback.format_exc()
            raise
        finally:
            sidecar.write_text(json.dumps(record, sort_keys=True, indent=2) + "\n")


if __name__ == "__main__":
    main()
