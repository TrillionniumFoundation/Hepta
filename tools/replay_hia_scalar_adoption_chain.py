#!/usr/bin/env python3
"""Rehash one selected capped-add packet and replay its 52 saved SMT queries.

This reads no private service database and loads no native image. A replay is a
new solver observation of the saved queries, not a new native adoption run.
"""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import time

SPECIFICATION_OBLIGATIONS = (
    ("unsigned_input_domain_nonvacuous", "sat"),
    ("core_always_returns_and_preserves_caller_bytes", "unsat"),
    ("core_equals_unbounded_sum_capped_at_limit", "unsat"),
)
MACHINE_OBLIGATIONS = (
    ("caller_contract_nonvacuous", "sat"),
    ("machine_memory_access_bounds", "unsat"),
    ("sysv_stack_alignment_and_preservation", "unsat"),
    ("all_inputs_reach_a_terminal_model_outcome", "unsat"),
    ("core_to_final_image_return_abort_and_caller_bytes", "unsat"),
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--expected-manifest-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    source = args.input.resolve(strict=True)
    result = {"schema": "hepta.hia.scalar-adoption-chain-replay.v1", "status": "started",
        "replayer_sha256": sha256(Path(__file__).read_bytes()).hexdigest(),
        "files_verified": 0, "queries": [], "fresh_native_execution": False,
        "kernel_checked_isa_proof": False}
    started = time.monotonic_ns()
    with args.output.open("x") as stream:
        try:
            import z3
            require(z3.get_version_string() == "4.15.4", "pinned Z3 version is required")
            result["solver_version"] = z3.get_version_string()
            data = (source / "original-files.json").read_bytes()
            require(sha256(data).hexdigest() == args.expected_manifest_sha256, "selected manifest differs")
            result["original_manifest_sha256"] = args.expected_manifest_sha256
            manifest = json.loads(data)
            require(type(manifest) is list and 1 <= len(manifest) <= 2048, "manifest inventory bound")
            names = [row["path"] for row in manifest]
            require(len(names) == len(set(names)), "duplicate manifest member")
            for row in manifest:
                requested = source / row["path"]
                path = requested.resolve(strict=True)
                require(not requested.is_symlink() and path.is_relative_to(source)
                        and path.is_file() and path.stat().st_size <= 16 * 1024**2, "artifact path or size")
                content = path.read_bytes()
                require(len(content) == row["bytes"] and sha256(content).hexdigest() == row["sha256"],
                        "retained artifact bytes differ: " + row["path"])
                result["files_verified"] += 1
            report_bytes = (source / "report.json").read_bytes()
            report = json.loads(report_bytes)
            result["source_report_sha256"] = sha256(report_bytes).hexdigest()
            require(report["status"] == "passed" and report["source"]["worktree_status"] == "",
                    "a complete unchanged clean-source run is required")
            require(report["types"] == ["u8", "u32", "u64", "usize"]
                    and [row["type"] for row in report["families"]] == report["types"], "four-type inventory differs")
            result["source"] = report["source"]
            for family in report["families"]:
                require(family["status"] == "passed", "incomplete family")
                root = source / family["type"]
                spec = json.loads((root / "specification/specification.json").read_bytes())
                require(spec == family["specification"] and spec["core_sha256"] == family["candidate"]["sha256"],
                        "specification and selected Core differ")
                require(tuple((q["name"], q["expected"]) for q in spec["obligations"]) == SPECIFICATION_OBLIGATIONS,
                        "mathematical specification obligation inventory differs")
                queries = [(root / "specification" / q["query_file"], q) for q in spec["obligations"]]
                for mode in ("canonical", "planned"):
                    proof = json.loads((root / (mode + "-machine-evidence.json")).read_bytes())
                    require(proof["artifact_binding"]["candidate_core_sha256"] == family["candidate"]["sha256"]
                            and proof["validation"]["complete"] and proof["validation"]["ok"], "machine proof differs")
                    require(tuple((q["name"], q["expected"]) for q in proof["validation"]["obligations"]) == MACHINE_OBLIGATIONS,
                            "independent machine obligation inventory differs")
                    queries.extend((root / (mode + "-" + q["query_file"]), q)
                                   for q in proof["validation"]["obligations"])
                require(len(queries) == 13, "per-type query inventory differs")
                for path, obligation in queries:
                    require(path.resolve(strict=True).is_relative_to(source)
                            and str(path.relative_to(source)) in names, "unmanifested query")
                    query = path.read_bytes()
                    require(sha256(query).hexdigest() == obligation["query_sha256"], "query identity differs")
                    solver = z3.Solver(ctx=z3.Context())
                    solver.set(timeout=15000)
                    solver.from_string(query.decode())
                    actual = str(solver.check())
                    result["queries"].append({"path": str(path.relative_to(source)),
                        "query_sha256": obligation["query_sha256"], "expected": obligation["expected"], "result": actual})
                    require(actual == obligation["expected"], "replayed query did not match its expected result")
            require(len(result["queries"]) == 52, "complete query inventory differs")
            result["status"] = "passed"
            return 0
        except BaseException as exc:
            result.update(status="failed", error_type=type(exc).__name__, error=str(exc))
            raise
        finally:
            result["elapsed_ns"] = str(time.monotonic_ns() - started)
            json.dump(result, stream, indent=2, sort_keys=True)
            stream.write("\n")
            print(json.dumps({"status": result["status"], "files": result["files_verified"],
                              "queries": len(result["queries"]), "output": str(args.output)}))


if __name__ == "__main__":
    raise SystemExit(main())
