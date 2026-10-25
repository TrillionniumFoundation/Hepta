"""Run safe rejection checks; execute only explicitly valid neighbouring cases.

Run from a checkout with PYTHONPATH=. to inspect that checkout's compiler.
Invalid candidates are never built into or run as native C executables.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from hepta.backend import compile_rust
from hepta.c_backend import compile_c
from hepta.pipeline import analyze, compiler_hash, resource_ir_analysis


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    cases = json.loads(Path(__file__).with_name("cases.json").read_text())
    rows = []
    for group, sources in cases.items():
        for name, source in sources.items():
            frontend = analyze(source, native=False, crate_type="bin")
            resource = resource_ir_analysis(frontend)
            c = analyze(source, native=False, backend="c", crate_type="bin")
            rust = analyze(source, native=True, crate_type="bin")
            row = {"name": name, "category": group, "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
                   "frontend": frontend.report, "resource": resource, "c": c.report,
                   "c_emitted": c.c is not None, "rust": rust.report,
                   "invalid_native_execution_attempted": False, "valid_executions": []}
            if group == "accepted":
                with tempfile.TemporaryDirectory(prefix="hepta-order-safe-") as td:
                    for backend, analysis in (("c", c), ("rust", rust)):
                        if not analysis.report["ok"]:
                            continue
                        output = Path(td) / backend
                        built = (compile_c(analysis.c, output=output, crate_type="bin", sanitize=True) if backend == "c" else
                                 compile_rust(analysis.rust, output=output, crate_type="bin"))
                        if not built["ok"]:
                            raise RuntimeError(json.dumps(built))
                        executed = subprocess.run([str(output)], capture_output=True, text=True, timeout=10)
                        row["valid_executions"].append({"backend": backend, "build": built,
                                                        "returncode": executed.returncode,
                                                        "stdout": executed.stdout, "stderr": executed.stderr})
            rows.append(row)
    report = {"schema": "hepta.resource-order-audit.v1", "compiler_sha256": compiler_hash(),
              "rows": rows, "invalid_c_acceptances": sum(row["category"] == "rejected" and row["c_emitted"] for row in rows),
              "invalid_native_execution_attempted": False,
              "scope": "Frontend/IR/C-emission comparisons and native Rust rejection; only valid neighbouring programs are executed"}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps({"invalid_c_acceptances": report["invalid_c_acceptances"], "output": str(args.output)}))


if __name__ == "__main__":
    main()
