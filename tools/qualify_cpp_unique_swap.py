"""Native lifetime and admission evidence for captured unique_ptr member swap.

The project is an authored integration fixture, not a new upstream C++ library.
The independent oracle follows allocation identities through C++ owner slots.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.c_migrate import MigrationRejected
from hepta.cpp_unique_reset import lower_unique_reset_project
from tools.qualify_cpp_unique_reset import qualify, bindings
from tools.qualify_cpp_unique_reuse import cases as reuse_cases
from tools.validate_cpp_composed import _word
from tools.validate_cpp_owned import _identity

EXAMPLE = ROOT / "examples/cpp/unique_swap_migration"
FIELDS = ("left", "right", "value", "index", "reject", "early", "refuse_at")


def oracle(raw, *, weight):
    left, right, value, index, reject, early, refuse_at = raw
    events = []
    allocations = attempts = refusals = 0

    def free(owner):
        if owner is not None:
            events.append((2, *owner))

    def allocate(size):
        nonlocal allocations, attempts, refusals
        if size == 0:
            return None, False
        attempts += 1
        if attempts == refuse_at:
            refusals += 1
            events.append((3, attempts, size))
            return None, True
        allocations += 1
        owner = (allocations, size)
        events.append((1, *owner))
        return owner, False

    if left > 4096 or right > 4096:
        expected, family = 4001, "capacity_guard"
    else:
        source, failed = allocate(left)
        if failed:
            expected, family = 1001, "allocation_refusal_1"
        else:
            destination, failed = allocate(right)
            if failed:
                free(source)
                expected, family = 1001, "allocation_refusal_" + str(attempts)
            else:
                source, destination = destination, source
                if reject == 1:
                    free(destination); free(source)
                    expected, family = 1007, "throw_after_swap"
                elif early == 1:
                    free(destination); free(source)
                    expected, family = 2001, "early_after_swap"
                else:
                    free(destination)
                    destination, source = source, None
                    source, destination = destination, source
                    destination, source = source, destination
                    if reject == 2:
                        expected, family = 1008, "throw_after_empty_swap"
                    elif early == 4:
                        expected, family = 2005, "adopt_empty_after_swap"
                    elif early == 2:
                        expected, family = 2002, "reset_after_swap"
                    elif early == 3:
                        expected, family = 2004, "nullptr_after_swap"
                    elif index >= right:
                        expected, family = 2003, "range_after_swap"
                    else:
                        expected, family = value * weight + left + right, "value_after_swap"
                    free(destination)
    trace = 14695981039346656037
    for event in events:
        for part in event:
            trace = _word(trace, part)
    return dict(zip(FIELDS, raw), expected=expected, allocated=allocations, refusals=refusals,
                trace=trace, family=family, events=[list(e) for e in events])


def cases(weight):
    # Reuse only input selection; expected values and event traces are recomputed.
    raw = {tuple(row[k] for k in FIELDS) for row in reuse_cases(weight)}
    for left, right in ((0, 3), (3, 0), (3, 5), (257, 513), (4096, 4096)):
        for index in (max(right - 1, 0), right, right + 1):
            for reject in (0, 1, 2):
                for early in (0, 1, 2, 3, 4):
                    for refuse in (0, 1, 2):
                        raw.add((left, right, 255, index, reject, early, refuse))
    first = (3, 5, 7, 0, 1, 0, 0)
    return [oracle(row, weight=weight) for row in [first, *sorted(raw - {first})]]


REFUSALS = (
    ("stale_length_after_swap", "        if (index < right) { source[index] = value; }",
     "        if (index < left) { source[index] = value; }", "E_CPP_RESET_BOUNDS", 1),
    ("read_empty_after_transfer", "        destination.reset(source.release());\n        source.swap(destination);",
     "        destination.reset(source.release());\n        if (index < right) { source[index] = value; }\n        source.swap(destination);", "E_CPP_RESET_OWNER", 1),
    ("continuing_branch_swap", "        destination.swap(source);",
     "        if (reject == 2) { destination.swap(source); }\n        destination.swap(source);", "E_CPP_RESET_JOIN", 1),
    ("retained_alias", "        source.swap(source);",
     "        auto& alias = source;\n        source.swap(alias);", "E_CPP_COMPOSED_TYPE", 1),
    ("free_function_swap", "        destination.swap(source);",
     "        std::swap(destination, source);", "E_CPP_RESET_STATEMENT", 1),
    ("raw_pointer_escape", "        destination.reset(source.release());",
     "        auto* raw = source.release();\n        destination.reset(raw);", "E_CPP_COMPOSED_TYPE", 1),
)


def qualify_refusals(directory, *, clangxx):
    output = Path(directory).resolve(); output.mkdir(parents=True, exist_ok=False)
    frozen = bindings(reusable_released_owners=True, owner_swaps=True)
    report = {"schema": "hepta.cpp-unique-swap-source-refusals.v1", "ok": False,
              "source_bindings": frozen, "controls": [], "human_engineering_seconds": None}
    start = time.monotonic_ns()
    try:
        controls = [("unchanged_v1_boundary", None, None, "E_CPP_RESET_SWAP_PROFILE", 1, False, False),
                    ("unchanged_v2_boundary", None, None, "E_CPP_RESET_SWAP_PROFILE", 1, True, False)]
        controls += [(*row, True, True) for row in REFUSALS]
        for name, old, new, code, count, reusable, swaps in controls:
            project = output / name; shutil.copytree(EXAMPLE, project)
            source = project / "component.cpp"
            if old is not None:
                text = source.read_text()
                if text.count(old) < count:
                    raise ValueError("mutation target missing: " + name)
                source.write_text(text.replace(old, new, count))
            row = {"name": name, "source": _identity(source), "expected_code": code,
                   "fresh_clang_capture": True, "rejected": False}
            report["controls"].append(row); then = time.monotonic_ns()
            try:
                lower_unique_reset_project(project / "compile_commands.json", clangxx=clangxx,
                    reusable_released_owners=reusable, owner_swaps=swaps)
            except MigrationRejected as error:
                row.update(rejected=True, code=error.code, diagnostic=str(error),
                           wall_ns=time.monotonic_ns() - then)
                if error.code != code:
                    raise ValueError("unexpected refusal boundary: " + name)
            else:
                raise ValueError("unsupported source admitted: " + name)
        if bindings(reusable_released_owners=True, owner_swaps=True) != frozen:
            raise ValueError("source drift")
        report["ok"] = True
    except Exception as error:
        report["error"] = {"kind": type(error).__name__, "message": str(error)}
    report["wall_ns"] = time.monotonic_ns() - start
    (output / "qualification.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workdir", required=True)
    parser.add_argument("--clangxx", required=True)
    parser.add_argument("--clang", required=True)
    parser.add_argument("--cc", default="gcc")
    parser.add_argument("--source-refusals-only", action="store_true")
    args = parser.parse_args()
    result = (qualify_refusals(args.workdir, clangxx=args.clangxx) if args.source_refusals_only else
              qualify(args.workdir, clangxx=args.clangxx, clang=args.clang, cc=args.cc,
                      reusable_released_owners=True, owner_swaps=True))
    print(json.dumps({"ok": result["ok"], "error": result.get("error"),
                      "variants": [{k: row.get(k) for k in ("name", "case_count", "expected", "costs")}
                                   for row in result.get("variants", [])],
                      "controls": result.get("controls", []), "costs": result.get("costs")}))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
