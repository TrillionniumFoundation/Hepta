#!/usr/bin/env python3
"""Independent finite acceptance comparison against the pre-catalog #399 Core.

This runs the pinned original checker text from Git in a separate module and
the current checker on identical primitive-Core fixtures and deterministic
mutations. It is regression evidence, not a proof of verifier equivalence.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from hepta.hia_program import verify_program

BASELINE = "e0ab595468d67bcf95485eacd22cea8ff332520c"
MUTATION_SITE_LIMIT = 64
PRIMITIVE_SCHEMAS = {f"hepta.hia.program.v{n}" for n in range(1, 9)}


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _original():
    package = "hepta._catalog_baseline_399"
    parent = ModuleType(package)
    parent.__path__ = []
    sys.modules[package] = parent
    identities = {}
    # Pin the primitive checker's actual relative dependencies too. Composite
    # inputs are excluded; they would require a different dependency closure.
    for filename in ("hia_schema.py", "hia_json_preflight.py", "hia_program.py"):
        path = "hepta/" + filename
        text = subprocess.run(["git", "--no-replace-objects", "show", BASELINE + ":" + path],
                              cwd=ROOT, capture_output=True, check=True, timeout=20).stdout
        name = package + "." + filename.removesuffix(".py")
        specification = importlib.util.spec_from_loader(name, loader=None)
        module = importlib.util.module_from_spec(specification)
        sys.modules[name] = module
        exec(compile(text, "git:" + BASELINE + ":" + path, "exec"), module.__dict__)
        identities[path] = sha256(text).hexdigest()
    return module.verify_program, identities


def _seeds():
    from tests.test_hia_program import arithmetic, resource_program, joined_loan_program
    from tests.test_hia_bulk_memory import bulk_program
    from tests.test_hia_call_expansion import loop_resources, loan_call, checked_loop_resources
    from tests.test_hia_returned_loans import (loan_program, multiple_shared, swapped_mutable,
                                             fallible_return_program, negative_programs)

    seeds = [resource_program(), joined_loan_program(), bulk_program(), loop_resources(),
             loan_call(), checked_loop_resources(), swapped_mutable(), fallible_return_program()]
    for typ in ("i8", "u8", "i32", "u32", "isize", "usize"):
        for op in ("int.add.checked", "int.sub.wrap", "int.mul.checked", "int.div.checked",
                   "int.rem.checked", "int.shl.checked", "int.shr.checked"):
            seeds.append(arithmetic(op, typ))
    seeds += [loan_program(mode, construction) for mode in ("read", "mut")
              for construction in ("forward", "child", "cfg", "recursive")]
    seeds += [multiple_shared(construction) for construction in ("forward", "child")]
    negative = negative_programs()
    seeds += list(negative.values()) if type(negative) is dict else [row[1] for row in negative]
    files = []
    for directory in ("formal", "examples", "tests/fixtures"):
        for path in sorted((ROOT / directory).rglob("*.json")):
            try:
                document = json.loads(path.read_bytes())
            except (ValueError, OSError):
                continue
            if type(document) is dict and document.get("schema") in PRIMITIVE_SCHEMAS:
                seeds.append(document)
                files.append(path.relative_to(ROOT).as_posix())
    return [seed for seed in seeds if seed.get("schema") in PRIMITIVE_SCHEMAS], files


def _cases(seed):
    yield seed
    for version in range(1, 9):
        changed = deepcopy(seed)
        changed["schema"] = f"hepta.hia.program.v{version}"
        yield changed
    sites = 0
    for fi, function in enumerate(seed["functions"]):
        for effect in function["effects"]:
            changed = deepcopy(seed)
            changed["functions"][fi]["effects"].remove(effect)
            yield changed
        if "return_loans" in function:
            changed = deepcopy(seed)
            changed["functions"][fi]["return_loans"] = [None] * len(function["returns"])
            yield changed
        for bi, block in enumerate(function["blocks"]):
            for oi, instruction in enumerate(block["ops"]):
                sites += 1
                if sites > MUTATION_SITE_LIMIT:
                    continue
                for field, value in (("args", []), ("out", []),
                                     ("attrs", {**instruction["attrs"], "unreviewed": True})):
                    changed = deepcopy(seed)
                    changed["functions"][fi]["blocks"][bi]["ops"][oi][field] = value
                    yield changed
                if instruction["out"]:
                    for typ in ("bool", "unit", "i8", "u32", "buffer", "readbuf", "mutbuf", "chain"):
                        changed = deepcopy(seed)
                        changed["functions"][fi]["blocks"][bi]["ops"][oi]["out"][0]["type"] = typ
                        yield changed
                if instruction["op"] in {"owner.drop", "owner.move", "loan.end"}:
                    changed = deepcopy(seed)
                    changed["functions"][fi]["blocks"][bi]["ops"].pop(oi)
                    yield changed


def qualify():
    original, baseline_source = _original()
    seeds, fixture_files = _seeds()
    inputs = tuple(dict.fromkeys((
        "tools/qualify_hia_catalog_compatibility.py", "hepta/hia_program.py", "hepta/hia_opcodes.py",
        "hepta/hia_schema.py", "hepta/hia_json_preflight.py", "tests/test_hia_program.py",
        "tests/test_hia_bulk_memory.py", "tests/test_hia_call_expansion.py",
        "tests/test_hia_returned_loans.py", *fixture_files)))
    identities = {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in inputs}
    seen, mismatches = set(), []
    observations = sha256()
    accepted = rejected = 0
    def outcome(check, document):
        try:
            checked = check(document)
            return {"accepted": True, "core_sha256": checked.sha256}
        except ValueError as error:
            return {"accepted": False, "error_code": getattr(error, "code", type(error).__name__)}
    for seed in seeds:
        for case in _cases(seed):
            digest = sha256(wire(case)).hexdigest()
            if digest in seen:
                continue
            seen.add(digest)
            if len(seen) % 1000 == 0:
                print(json.dumps({"event": "catalog_comparison_progress", "cases": len(seen)}),
                      file=sys.stderr, flush=True)
            before, after = outcome(original, case), outcome(verify_program, case)
            observations.update(wire({"input_sha256": digest, "before": before, "after": after}) + b"\n")
            if before["accepted"]:
                accepted += 1
            else:
                rejected += 1
            # Diagnostics may select another equally valid first refusal. The
            # compatibility contract here is admission and accepted Core bytes.
            if (before["accepted"] != after["accepted"]
                    or before.get("core_sha256") != after.get("core_sha256")):
                mismatches.append({"input_sha256": digest, "before": before, "after": after, "core": case})
    unchanged = all(sha256((ROOT / name).read_bytes()).hexdigest() == digest
                    for name, digest in identities.items())
    return {"schema": "hepta.hia.catalog-compatibility.v1", "ok": not mismatches and unchanged,
            "baseline_commit": BASELINE, "baseline_source_identity": baseline_source,
            "source_identity": identities, "source_unchanged": unchanged,
            "seed_count": len(seeds), "distinct_cases": len(seen),
            "seed_documents_sha256": sha256(wire(seeds)).hexdigest(),
            "mutation_site_limit_per_seed": MUTATION_SITE_LIMIT,
            "baseline_accepted": accepted, "baseline_rejected": rejected,
            "observation_stream_sha256": observations.hexdigest(), "mismatches": mismatches,
            "claims": {"finite_acceptance_and_canonical_bytes_compared": True,
                       "verifier_semantic_equivalence_proved": False,
                       "whole_language_soundness_proved": False,
                       "diagnostic_first_error_identical": False},
            "limitations": ["Original checker, primitive schema and JSON preflight are loaded from the pinned baseline Git objects.",
                            "Only primitive schemas are compared; all seeds run, with mutations at the first 64 instruction sites per seed.",
                            "Finite fixtures and mutations do not exhaust all Core programs or resource states.",
                            "This compares admission, not interpreter, backend, ABI or machine execution."]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    report = qualify()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({key: report[key] for key in ("ok", "seed_count", "distinct_cases",
                                                   "baseline_accepted", "baseline_rejected")}))
    return 0 if report["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
