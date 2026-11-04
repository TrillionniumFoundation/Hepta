"""Native lifecycle qualification for repeated closed unique_ptr adoption.

Both variants are authored project fixtures using the actual C++ standard
library. They are not a claim of a new upstream library migration. The separate
GSL qualification owns that evidence. This oracle follows allocation identities,
not generated Hepta source or Core instructions.
"""
from __future__ import annotations

import argparse
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
import random
import shutil
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from hepta.c_migrate import MigrationRejected
from hepta.cpp_unique_reset import lower_unique_reset_project, REUSABLE_PROFILE
from tools.validate_cpp_composed import _word
from tools.validate_cpp_owned import _identity
from tools.qualify_cpp_unique_reset import qualify, bindings

EXAMPLE = ROOT / "examples/cpp/unique_reuse_migration"


def oracle(raw, *, weight):
    left, right, value, index, reject, early, refuse_at = raw
    events = []
    allocations = attempts = refusals = 0

    def release(owner):
        if owner is not None:
            events.append((2, *owner))

    def allocate(size):
        nonlocal allocations, attempts, refusals
        if not size:
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
                release(source)
                expected, family = 1001, "allocation_refusal_" + str(attempts)
            elif reject == 1:
                release(destination); release(source)
                expected, family = 1007, "throw_before_reuse"
            elif early == 1:
                release(destination); release(source)
                expected, family = 2001, "early_before_reuse"
            else:
                # Delete only the old destination. Two subsequent adoptions
                # move the same allocation back and forth without any delete.
                release(destination)
                destination, source = source, None
                source, destination = destination, None
                destination, source = source, None
                if reject == 2:
                    expected, family = 1008, "throw_after_reuse"
                elif early == 4:
                    expected, family = 2005, "empty_source_adoption"
                elif early == 2:
                    expected, family = 2002, "reset_after_reuse"
                elif early == 3:
                    expected, family = 2004, "nullptr_after_reuse"
                elif index >= left:
                    expected, family = 2003, "range_after_reuse"
                else:
                    expected, family = value * weight + left + right, "value_after_reuse"
                release(destination)
    trace = 14695981039346656037
    for event in events:
        for part in event:
            trace = _word(trace, part)
    return dict(zip(("left", "right", "value", "index", "reject", "early", "refuse_at"), raw),
                expected=expected, allocated=allocations, refusals=refusals,
                trace=trace, family=family, events=[list(e) for e in events])


def cases(weight):
    raw = [(3, 5, 7, 0, 1, 0, 0)]
    for left, right in ((0, 0), (0, 3), (3, 0), (1, 1), (3, 5), (257, 513), (4096, 4096)):
        for value in (0, 255):
            for index in sorted({0, max(left - 1, 0), left, left + 1}):
                for reject in (0, 1, 2):
                    for early in (0, 1, 2, 3, 4):
                        for refuse in (0, 1, 2):
                            raw.append((left, right, value, index, reject, early, refuse))
    for left, right in ((4097, 0), (0, 4097), (2**64 - 1, 1), (1, 2**64 - 1)):
        for refuse in (0, 1, 2):
            raw.append((left, right, 255, 2**64 - 1, 2, 4, refuse))
    rng = random.Random(0xC105ED04)
    for _ in range(128):
        left, right = rng.randrange(4097), rng.randrange(4097)
        raw.append((left, right, rng.randrange(256), rng.randrange(left + 2),
                    rng.randrange(3), rng.randrange(5), rng.randrange(4)))
    return [oracle(row, weight=weight) for row in raw]


REFUSALS = (
    ("raw_pointer_escape", "        source.reset(destination.release());",
     "        auto* escaped = destination.release();\n        source.reset(escaped);", "E_CPP_COMPOSED_TYPE"),
    ("read_empty_source", "        source.reset(destination.release());",
     "        if (index < left) { source[index] = value; }\n        source.reset(destination.release());", "E_CPP_RESET_OWNER"),
    ("read_empty_destination", "        destination.reset(source.release());\n        source.reset(source.release());",
     "        if (index < left) { destination[index] = value; }\n        destination.reset(source.release());\n        source.reset(source.release());", "E_CPP_RESET_OWNER"),
    ("stale_length_after_adoption", "        destination.reset(source.release());\n        source.reset(destination.release());",
     "        source.reset(destination.release());", "E_CPP_RESET_BOUNDS"),
    ("get_self_adoption", "        source.reset(source.release());",
     "        source.reset(source.get());", "E_CPP_RESET_CALL"),
    ("continuing_branch_change", "        source.reset(destination.release());",
     "        if (reject == 2) { source.reset(destination.release()); }\n        source.reset(destination.release());", "E_CPP_RESET_JOIN"),
)


def qualify_refusals(directory, *, clangxx):
    directory = Path(directory).resolve()
    directory.mkdir(parents=True, exist_ok=False)
    frozen = bindings(reusable_released_owners=True)
    report = {"schema": "hepta.cpp-unique-reuse-source-refusals.v1", "ok": False,
              "source_bindings": frozen, "controls": [], "human_engineering_seconds": None}
    started = time.monotonic_ns()
    try:
        # The former default profile must continue refusing this new source.
        controls = [("unchanged_v1_refusal", None, None, "E_CPP_RESET_OWNER", False)]
        controls += [(*row, True) for row in REFUSALS]
        for name, original, replacement, expected_code, reusable in controls:
            project = directory / name
            shutil.copytree(EXAMPLE, project)
            source = project / "component.cpp"
            if original is not None:
                text = source.read_text()
                if text.count(original) != 1:
                    raise ValueError("ambiguous source mutation: " + name)
                source.write_text(text.replace(original, replacement))
            row = {"name": name, "source": _identity(source),
                   "expected_code": expected_code, "fresh_clang_capture": True, "rejected": False}
            report["controls"].append(row)
            before = time.monotonic_ns()
            try:
                lower_unique_reset_project(project / "compile_commands.json", clangxx=clangxx,
                                           reusable_released_owners=reusable)
            except MigrationRejected as error:
                row.update(rejected=True, code=error.code, diagnostic=str(error),
                           wall_ns=time.monotonic_ns() - before)
                if error.code != expected_code:
                    raise ValueError("source rejected at unexpected boundary: " + name)
            else:
                raise ValueError("invalid source admitted: " + name)
        if bindings(reusable_released_owners=True) != frozen:
            raise ValueError("qualification sources changed")
        report["ok"] = True
    except Exception as error:
        report["error"] = {"kind": type(error).__name__, "message": str(error)}
    report["wall_ns"] = time.monotonic_ns() - started
    (directory / "qualification.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workdir", required=True)
    parser.add_argument("--clangxx", required=True)
    parser.add_argument("--clang", required=True)
    parser.add_argument("--cc", default="gcc")
    parser.add_argument("--source-refusals-only", action="store_true")
    args = parser.parse_args()
    if args.source_refusals_only:
        result = qualify_refusals(args.workdir, clangxx=args.clangxx)
    else:
        result = qualify(args.workdir, clangxx=args.clangxx, clang=args.clang, cc=args.cc,
                         reusable_released_owners=True)
    print(json.dumps({"ok": result["ok"], "error": result.get("error"),
                      "variants": [{k: v.get(k) for k in ("name", "case_count", "expected", "costs")}
                                   for v in result.get("variants", [])],
                      "controls": result.get("controls", []), "costs": result.get("costs")},
                     sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
