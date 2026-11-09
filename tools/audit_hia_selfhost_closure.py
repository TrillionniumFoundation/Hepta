"""Inventory the actual selfhosting boundary; never promote a subset to whole HIA.

This is a static source audit, not execution evidence or a formal correctness
proof. It includes every live Python package file, not archived source copies.
"""
from __future__ import annotations

import argparse
import ast
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from hepta.hia_opcodes import WIDTHS
from tools.hia_selfhost_contract import validate_contract

COMPONENTS = (
    ("assembly_frontend", ("hepta/hia_agent_assembly.py",), "partial",
     "HIA scanner/parser implements the declared fixed assembly grammar only; arbitrary names and full syntax remain open."),
    ("core_verifier_and_resources", ("hepta/hia_program.py", "hepta/hia_capability_flow.py", "hepta/hia_program_composite.py"), "partial",
     "Native fixed-profile checks exist; composite elaboration, returned resources and general result signatures remain open."),
    ("execution_and_standard_library", ("hepta/hia_program_runtime.py", "hepta/runtime_io.py", "hepta/runtime_task_tree.py"), "open",
     "Core reference interpreter, general runtime/task/I/O and production library are not rewritten as HIA."),
    ("native_backend_and_linker", ("hepta/hia_program_native.py", "hepta/hia_program_aarch64.py", "hepta/hia_program_llvm.py"), "partial",
     "HIA writes bounded Linux x86-64 flat/ELF images; general linking, multiple exports and other native targets remain Python/external tools."),
    ("modules_packages_build", ("hepta/modules.py", "hepta/packages.py", "hepta/pipeline.py"), "open",
     "Module graphs, package locks, build orchestration and the complete frontend pipeline remain Python."),
    ("agent_tools_and_persistence", ("hepta/hia_agent_worker.py", "hepta/hia_agent_service.py", "hepta/hia_agent_store.py"), "open",
     "The real Agent worker/service, durable tools and protocol orchestration remain Python."),
    ("optimizer_and_proof_tools", ("hepta/hia_ndu_optimizer.py", "hepta/hia_translation_validation.py", "hepta/hia_scalar_proof_contract.py"), "open",
     "Planning/optimization/translation validation and proof construction are not rewritten; finite proof scopes do not establish whole compiler refinement."),
    ("cli_and_release", ("hepta/cli.py", "hepta/__main__.py", "tools/hia_release.py"), "open",
     "The CLI, installation/materialization/release tools and clean-machine executable entry are not a complete HIA-only toolchain."),
)


def audit(root=ROOT):
    root = Path(root)
    contract = validate_contract(root)
    records = []
    for path in sorted((root / "hepta").rglob("*.py")):
        data = path.read_bytes()
        tree = ast.parse(data, filename=str(path))
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(n.name for n in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.add("." * node.level + (node.module or ""))
        records.append({"path": path.relative_to(root).as_posix(), "implementation_language": "Python",
            "bytes": len(data), "lines": len(data.splitlines()), "sha256": sha256(data).hexdigest(),
            "functions": sum(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) for n in ast.walk(tree)),
            "imports": sorted(imports)})
    paths = {row["path"] for row in records}
    components = []
    for name, authority, status, boundary in COMPONENTS:
        for relative in authority:
            if not (root / relative).is_file():
                raise ValueError("missing live implementation authority: " + relative)
        components.append({"component": name, "status": status, "current_authorities": list(authority),
                           "boundary": boundary, "whole_component_rewritten_in_hia": False})
    scalar_support = next(r["items"] for r in contract["support"] if r["area"] == "scalar_types")
    source = (root / "examples/hia_bootstrap/selfhost.hiaasm").read_bytes()
    return {"schema": "hepta.hia.whole-selfhost-static-audit.v1",
        "profile": contract["profile"], "live_python_package": records,
        "totals": {"python_files": len(records), "python_lines": sum(r["lines"] for r in records),
                   "python_bytes": sum(r["bytes"] for r in records),
                   "component_statuses": dict(Counter(r["status"] for r in components))},
        "compiler_source": {"path": "examples/hia_bootstrap/selfhost.hiaasm", "sha256": sha256(source).hexdigest(),
                            "bytes": len(source), "functions": sum(line.startswith(b"fn ") for line in source.splitlines())},
        "general_core_integer_types_not_in_native_selfhost": sorted(set(WIDTHS) - set(scalar_support)),
        "components": components,
        "authorities_in_live_package": sorted(paths.intersection(p for _, a, _, _ in COMPONENTS for p in a)),
        "whole_stack_rewritten_in_hia": False,
        "evidence_kind": "static inventory and explicit implementation boundary, not execution evidence",
        "limits": ["AST imports do not enumerate dynamic imports or prove dependency closure",
                   "line counts do not measure semantic completion",
                   "a byte fixed point proves only the declared compiler subset's observed self-reproduction",
                   "external OS, ABI, allocator and linker dependencies must stay explicit",
                   "historical or adjacent-branch CI does not qualify changed source bytes"],
        "closure_gates": ["full language/Core conformance with independent negative controls",
                          "HIA implementations replace the live Python authorities rather than call through to them",
                          "arbitrary identifiers, module graph, linking and a real standalone CLI",
                          "source-only B0/B1/B2/B3 and modified-source fixed points for the full toolchain",
                          "fresh current-source regression, cross-target and resource failure qualification",
                          "clean-machine installation and real project build without a Python compiler dependency"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = audit()
    with args.output.open("x") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps({"output": str(args.output), "profile": report["profile"],
                      "totals": report["totals"], "whole_stack_rewritten_in_hia": False}, sort_keys=True))


if __name__ == "__main__":
    main()
