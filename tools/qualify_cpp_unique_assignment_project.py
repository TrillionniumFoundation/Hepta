"""Actual cross-TU unique-array replacement, self move and failure qualification."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import random
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from hepta.cpp_unique_project import lower_unique_assignment_matrix
from hepta.hia_program_llvm import build_program_native
from hepta.hia_program_source import lower_source
from tools.evidence_checks import require
from tools.qualify_cpp_unique_project import _qualify, command, HARNESS, WRAP_FLAGS
from tools.validate_cpp_composed import _word

EXAMPLE = ROOT / "examples/cpp/unique_assignment_project_migration"


def oracle(raw, variant):
    """Independent value/allocation model including overwritten owner identity.

    The first pair is the source; the second pair already owns reversed-size
    buffers. Constructor unwind is reverse order. Successful member assignment
    releases the old destination in forward order. Self moves emit no events.
    """
    left, right, value, index, reject, early, refuse_at = raw
    weight, mask = {"three_weight": (3, 37), "five_weight": (5, 11)}[variant]
    events, attempts, allocated, refusals = [], 0, 0, 0

    def release(owners):
        for identity, size in owners:
            events.append((2, identity, size))

    def construct(sizes, rejection):
        nonlocal attempts, allocated, refusals
        owners = []
        for field, size in enumerate(sizes, 1):
            if size:
                attempts += 1
                if attempts == refuse_at:
                    refusals += 1
                    events.append((3, attempts, size))
                    release(reversed(owners))
                    return None, 1001, "allocation_refusal_" + str(attempts)
                allocated += 1
                owners.append((allocated, size))
                events.append((1, allocated, size))
            if rejection == field:
                release(reversed(owners))
                return None, 1002, "leaf_constructor_rejection_" + str(field)
        if rejection == 3:
            release(reversed(owners))
            return None, 1003, "composite_constructor_rejection"
        return owners, None, None

    source, expected, family = construct((left, right), reject)
    if expected is None and early == 1:
        release(reversed(source))
        expected, family = 2001, "early_before_replacement"
    elif expected is None:
        destination, expected, family = construct((right, left), 0)
        if expected is not None:
            release(reversed(source))
        else:
            release(destination)
            if early == 2:
                expected, family = 2002, "early_after_replacement_and_self_move"
            elif index >= min(left, right):
                expected, family = 2003, "range_error_after_replacement"
            else:
                first = value ^ 91 if index == 0 else value
                expected = (first * weight + (value ^ mask) + left + right) % 2**64
                family = "replacement_self_move_cross_unit_success"
            release(reversed(source))
    trace = 14695981039346656037
    for event in events:
        for part in event:
            trace = _word(trace, part)
    return dict(zip(("left", "right", "value", "index", "reject", "early", "refuse_at"), raw),
                expected=expected, allocated=allocated, refusals=refusals, trace=trace,
                family=family, events=[list(event) for event in events])


def cases(variant):
    raw = [(3, 5, 7, 0, 0, 0, 0)]
    for left, right in ((0, 0), (0, 3), (3, 0), (1, 1), (3, 5), (257, 513)):
        for value in (0, 255):
            for index in sorted({0, max(min(left, right) - 1, 0), min(left, right)}):
                for reject in range(4):
                    for refusal in range(5):
                        raw.append((left, right, value, index, reject, 0, refusal))
                for early in (1, 2):
                    for refusal in range(5):
                        raw.append((left, right, value, index, 0, early, refusal))
    rng = random.Random(0xA5516E04)
    for _ in range(128):
        left, right = rng.randrange(1025), rng.randrange(1025)
        raw.append((left, right, rng.randrange(256), rng.randrange(min(left, right) + 2),
                    rng.randrange(4), rng.randrange(3), rng.randrange(5)))
    return [oracle(row, variant) for row in raw]


def source_bindings():
    paths = [Path(__file__), ROOT / "tools/qualify_cpp_unique_project.py",
             ROOT / "tools/validate_cpp_composed.py", ROOT / "tools/validate_cpp_owned.py",
             ROOT / "tools/evidence_checks.py", ROOT / "examples/cpp/composed_migration/harness.c",
             *[ROOT / "hepta" / name for name in (
                 "cpp_unique_assignment.py", "cpp_unique_project.py", "cpp_unique_capture.py",
                 "cpp_composed_project.py", "cpp_composed_migrate.py", "cpp_owned_migrate.py")],
             *EXAMPLE.iterdir()]
    return {str(path.relative_to(ROOT)): sha256(path.read_bytes()).hexdigest()
            for path in paths if path.is_file()}


def assignment_order_control(*, name, target, source, clang, cc):
    """Execute a resource-safe but observably wrong cleanup-order mutation."""
    before = ("    HeptaLeaf_drop(move destination.resource0);\n"
              "    HeptaLeaf_drop(move destination.resource1);")
    after = ("    HeptaLeaf_drop(move destination.resource1);\n"
             "    HeptaLeaf_drop(move destination.resource0);")
    require(source.count(before) == 1, "Expected exact two-field assignment helper for order control")
    changed = source.replace(before, after)
    path = target / "wrong-assignment-order.hepta"
    path.write_text(changed)
    program = lower_source(changed, path=str(path))
    obj, binary = target / "wrong-assignment-order.o", target / "wrong-assignment-order"
    record = {"scope": "deliberately_mutated_qualification_fixture", "commands": [],
              "resource_check_passed": True, "detected": False,
              "source_sha256": sha256(changed.encode()).hexdigest()}
    record["build"] = build_program_native(program.as_dict(), obj, clang=clang, kind="object")
    command(record["commands"], None, [cc, "-std=c11", "-O2", "-fno-lto", *WRAP_FLAGS,
                                        "-I" + str(target), str(HARNESS / "harness.c"), str(obj), "-o", str(binary)])
    observation = command(record, "execution", [str(binary)], expected_code=3)
    result = json.loads(observation["stdout"])
    require(result.get("ok") is False and result.get("failure") == "lifecycle"
            and result.get("case") == 0 and result.get("live") == 0,
            "Independent lifecycle oracle did not detect assignment cleanup-order mutation")
    record["detected"] = True
    record["artifact_sha256"] = sha256(binary.read_bytes()).hexdigest()
    return {name + "_wrong_assignment_cleanup_order": record}


def qualify(directory, *, clangxx="clang++", clang="clang", cc="gcc"):
    return _qualify(directory, clangxx=clangxx, clang=clang, cc=cc, example=EXAMPLE,
                    translate_matrix=lower_unique_assignment_matrix, vectors_for_variant=cases,
                    bindings_for_run=source_bindings,
                    schema="hepta.cpp-unique-assignment-project-native-qualification.v1",
                    extra_claims={"profile_supports_complete_owner_move_assignment": True,
                                  "profile_requires_inert_self_move": True,
                                  "profile_requires_forward_assignment_cleanup": True,
                                  "reset_release_or_pointer_adoption_supported": False},
                    extra_native_controls=assignment_order_control)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workdir", required=True)
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--clangxx", default="clang++")
    parser.add_argument("--cc", default="gcc")
    args = parser.parse_args()
    report = qualify(args.workdir, clang=args.clang, clangxx=args.clangxx, cc=args.cc)
    print(json.dumps({"ok": report["ok"], "error": report.get("error"), "variants": [
        {key: row.get(key) for key in ("name", "case_count", "expected")} for row in report["variants"]]}))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
