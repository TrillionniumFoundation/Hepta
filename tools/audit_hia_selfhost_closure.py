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
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from hepta.hia_opcodes import WIDTHS
from tools.hia_selfhost_contract import validate_contract

COMPONENTS = (
    ("assembly_frontend", ("hepta/hia_agent_assembly.py", "hepta/lexer.py", "hepta/hia_source_lexer_native.py", "hepta/hia_source_types_native.py", "hepta/hia_source_names_native.py", "hepta/hia_source_clauses_native.py", "hepta/hia_source_expressions_native.py", "hepta/hia_source_frontend_native.py", "hepta/parser.py", "hepta/hia_json_preflight.py", "hepta/hia_json_preflight_native.py", "hepta/hia_json_decode.py", "hepta/hia_json_decode_native.py", "hepta/hia_json_canonical_native.py", "hepta/hia_core_json_frontend_native.py"), "partial",
     "HIA scanner/parser supports general ASCII module/function/SSA/formal/block identifiers and arbitrary entry declaration order in the bounded assembly profile. Explicitly selected HIA source components handle high-level token grammar, UTF-8 positions, diagnostics, arbitrary-size integer magnitudes and exact decimal-to-binary64 conversion. Native type, qualified-name, declaration-parameter, effects/resources and complete existing expression grammars preserve exact prefix consumption, diagnostic priority, generic token splits and the remaining caller nesting budget. One frontend bundle binds all component manifests and compiler/lexer identities, and refuses conflicting or broken selections without fallback. Python object construction, arena/image custody, declaration/statement grammar, semantic type checking and the default reference remain. Explicitly selected HIA JSON decoding/canonicalization are integrated into existing inputs. A separate HIA primitive v8 JSON Core representation frontend emits assembly for real native semantic compilation; host drivers still handle manifests, allocation, files and child receipts. Foreign-object bridging and caller-owned serialization remain Python. Explicit scalar-export JSON representation requires operator ELF selection; general module graphs, composites/full frontend grammar and whole-runtime replacement remain open."),
    ("core_verifier_and_resources", ("hepta/checker.py", "hepta/hia_effects.py", "hepta/native/effect_closure.hiaasm", "hepta/hia_program.py", "hepta/hia_capability_flow.py", "hepta/hia_program_composite.py"), "partial",
     "The default source checker delegates effect closure, worker-forbidden masks and resource conflicts to a single HIA program; the previous Python fixed-point and conflict algorithm is removed. Linux x86-64 normally runs native code, with Python/direct-emitter/GNU-ld bootstrap; other hosts or out-of-native-profile graphs execute the same HIA source in the VM, never retrying native failures. General semantic checking, composite elaboration and general result signatures remain open; bounded scalar/owner/parameter-bound loan tuples require current-source qualification."),
    ("execution_and_standard_library", ("hepta/hia_program_runtime.py", "hepta/runtime_io.py", "hepta/runtime_task_tree.py", "hepta/hia_sha256_native.py", "hepta/hia_sha256_stream_native.py"), "open",
     "One-shot and incremental SHA-256 state/padding/compression algorithms are implemented in HIA and can be explicitly selected for Core content digests, with bounded chunks rather than an 8-MiB total-input limit; host code-custody hashing remains. A HIA-emitted syscall-only observer executes ordinary flat-ABI qualification calls in fresh sealed native children; the host supervisor and independent generation/shared/trap loader remain. Core reference interpretation, general production runtime/task/I/O and the complete production library remain open."),
    ("native_backend_and_linker", ("hepta/hia_program_native.py", "hepta/hia_program_aarch64.py", "hepta/hia_program_llvm.py", "examples/hia_bootstrap/elf_linker.hiaasm", "tools/build_hia_elf_linker.py", "tools/link_hia_elf.py"), "partial",
     "HIA writes bounded Linux x86-64 flat/ELF images, including multiple exact-name scalar C exports and allocator relocations. An explicitly selected HIA linker writes loadable ELF64 ET_DYN from up to sixteen canonical selfhost ET_REL objects and 128 scalar exports, including closed calloc/free PLT/GOT/relocations. Its syscall-only standalone entry executes without Python or GNU ld; host build/custody and libc allocator/dynamic loader remain dependencies. General external symbols/module/link graphs, arbitrary ELF input, resource-bearing public ABI and other targets remain open."),
    ("modules_packages_build", ("hepta/modules.py", "hepta/packages.py", "hepta/pipeline.py"), "open",
     "Module graphs, package locks, build orchestration and the complete frontend pipeline remain Python."),
    ("agent_tools_and_persistence", ("hepta/hia_agent_worker.py", "hepta/hia_agent_service.py", "hepta/hia_agent_store.py"), "open",
     "The real Agent worker/service, durable tools and protocol orchestration remain Python."),
    ("optimizer_and_proof_tools", ("hepta/hia_ndu_optimizer.py", "hepta/hia_translation_validation.py", "hepta/hia_scalar_proof_contract.py"), "open",
     "Planning/optimization/translation validation and proof construction are not rewritten; finite proof scopes do not establish whole compiler refinement."),
    ("cli_and_release", ("hepta/cli.py", "hepta/__main__.py", "tools/hia_release.py"), "open",
     "Bounded Linux syscall-only stdin/stdout entries exist for assembly and the two-stage JSON Core-to-machine pipeline. The HIA ELF packer writes headers, patches calls and copies pinned frontend/compiler images; runtime parsing/verification/codegen need no Python driver. Explicit native CLI builds still use a host filesystem/custody driver. Full production command surface, installation/materialization/release and whole clean-machine toolchain remain open."),
)


def tracked_tree_inventory(root):
    """Account for every tracked path without treating research as live runtime.

    This is a file-identity inventory, not semantic or execution qualification.
    Symlinks hash their target spelling and never read an external target.
    """
    root = Path(root).resolve(strict=True)
    def git(*args):
        return subprocess.check_output(['git', '-C', str(root), *args])
    if Path(os.fsdecode(git('rev-parse', '--show-toplevel')).strip()).resolve() != root:
        raise ValueError('inventory requires the exact checkout root')
    names = sorted(os.fsdecode(p) for p in git('ls-files', '-z').split(b'\0') if p)
    roles = {'hepta': 'live_compiler_package', 'tools': 'host_authoring_build_qualification',
             'rust': 'native_rust_bridges', 'formal': 'formal_support', 'tests': 'tests',
             '.github': 'ci_workflows', 'docs': 'documentation', 'examples': 'examples',
             'experiments': 'research_experiments', 'benchmarks': 'benchmarks',
             'evidence': 'retained_evidence', 'artifacts': 'retained_evidence',
             'reports': 'retained_evidence', 'review-evidence': 'retained_evidence'}
    languages = {'.py': 'Python', '.rs': 'Rust', '.c': 'C', '.h': 'C-header',
                 '.cpp': 'C++', '.hpp': 'C++-header', '.lean': 'Lean', '.sh': 'shell',
                 '.hiaasm': 'HIA-assembly', '.hepta': 'Hepta-source', '.ll': 'LLVM-IR',
                 '.S': 'assembly', '.s': 'assembly'}
    rows, groups, live_non_python = [], {}, []
    for name in names:
        path = root / name
        kind = 'symlink-target' if path.is_symlink() else 'file'
        data = os.fsencode(os.readlink(path)) if kind == 'symlink-target' else path.read_bytes()
        role = roles.get(name.split('/')[0], 'root_build_or_other')
        language = languages.get(path.suffix, 'other')
        row = {'path': name, 'kind': kind, 'bytes': len(data),
               'sha256': sha256(data).hexdigest(), 'role': role, 'language': language}
        rows.append(row)
        key = role + ':' + language
        group = groups.setdefault(key, {'role': role, 'language': language, 'files': 0, 'bytes': 0})
        group['files'] += 1
        group['bytes'] += len(data)
        if (role in {'live_compiler_package', 'host_authoring_build_qualification',
                      'native_rust_bridges', 'formal_support'}
                and language not in {'Python', 'other'} and kind == 'file'):
            live_non_python.append({**row, 'lines': len(data.splitlines()),
                                    'rewritten_in_hia': language == 'HIA-assembly'})
    identity = json.dumps(rows, sort_keys=True, separators=(',', ':')).encode()
    head = subprocess.run(['git', '-C', str(root), 'rev-parse', '--verify', '--quiet', 'HEAD'],
                          capture_output=True, check=False)
    return {'git_head_at_capture': os.fsdecode(head.stdout).strip() if head.returncode == 0 else None,
            'working_tree_dirty_at_capture': bool(git('status', '--porcelain', '--untracked-files=all')),
            'capture_is_checkout_state_not_commit_qualification': True,
            'untracked_paths_included': False,
            'tracked_paths': len(rows), 'tracked_bytes': sum(r['bytes'] for r in rows),
            'file_identity_manifest_sha256': sha256(identity).hexdigest(),
            'file_identity_manifest': rows,
            'role_language_totals': sorted(groups.values(), key=lambda r: (r['role'], r['language'])),
            'live_non_python_support_sources': live_non_python,
            'all_tracked_paths_accounted_for': sum(r['files'] for r in groups.values()) == len(rows),
            'research_is_not_live_runtime': True, 'file_inventory_is_semantic_audit': False,
            'file_inventory_is_execution_evidence': False}


def audit(root=ROOT):
    root = Path(root)
    contract = validate_contract(root)
    def python_inventory(directory):
        records = []
        for path in sorted((root / directory).rglob("*.py")):
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
        return records
    records = python_inventory("hepta")
    # Host-side authoring/build/qualification tools are not HIA replacements.
    # Keep them distinct from the production package, not absent from the audit.
    tools = python_inventory("tools")
    hia_package = []
    for path in sorted((root / "hepta").rglob("*.hiaasm")):
        data = path.read_bytes()
        hia_package.append({"path": path.relative_to(root).as_posix(),
            "implementation_language": "HIA-assembly", "bytes": len(data),
            "lines": len(data.splitlines()), "sha256": sha256(data).hexdigest()})
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
        "tracked_tree": tracked_tree_inventory(root),
        "profile": contract["profile"], "live_python_package": records,
        "live_python_tools": tools, "packaged_hia_sources": hia_package,
        "inventory_scope": {"ast_and_hash_roots": ["hepta/", "tools/"],
            "tools_are_not_all_production_runtime": True,
            "unlisted_roots_qualified": False,
            "excluded_roles": ["tests", "historical artifacts/evidence/reports",
                               "experiments", "examples", "benchmarks", "formal-support scripts"]},
        "totals": {"python_files": len(records), "python_lines": sum(r["lines"] for r in records),
                   "python_bytes": sum(r["bytes"] for r in records),
                   "python_tool_files": len(tools), "python_tool_lines": sum(r["lines"] for r in tools),
                   "python_tool_bytes": sum(r["bytes"] for r in tools),
                   "package_and_tool_python_files": len(records) + len(tools),
                   "packaged_hia_files": len(hia_package),
                   "packaged_hia_bytes": sum(r["bytes"] for r in hia_package),
                   "component_statuses": dict(Counter(r["status"] for r in components))},
        "compiler_source": {"path": "examples/hia_bootstrap/selfhost.hiaasm", "sha256": sha256(source).hexdigest(),
                            "bytes": len(source), "functions": sum(line.startswith(b"fn ") for line in source.splitlines())},
        "general_core_integer_types_not_in_native_selfhost": sorted(set(WIDTHS) - set(scalar_support)),
        "components": components,
        "authorities_in_live_package": sorted(paths.intersection(p for _, a, _, _ in COMPONENTS for p in a)),
        "whole_stack_rewritten_in_hia": False,
        "legacy_retirement": {
            "status": "BLOCKED_BY_OPEN_IMPLEMENTATION_AND_QUALIFICATION_GATES",
            "eligible_now": False,
            "final_distribution_requires_no_legacy_production_implementation": True,
            "optional_native_backends_are_not_retirement": True,
            "git_history_and_nonshipped_review_evidence_are_not_live_providers": True,
            "required_before_removal": [
                "complete HIA implementation of every live authority",
                "default native routes with no legacy fallback",
                "whole-toolchain source-only and changed-source bootstrap",
                "fresh complete regressions and all applicable platform gates",
                "clean-machine install and real project builds without legacy toolchain"]},
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
