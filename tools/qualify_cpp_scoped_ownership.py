"""Execute real C++ lexical ownership migration and its cleanup boundaries.

The C++ reference is compiled separately. The three generated implementations
contain only translated Hepta (Rust, C, direct LLVM) and observation harnesses.
Finite observations do not prove general C++ equivalence or performance parity.
"""
from __future__ import annotations

import argparse
from collections import Counter
from contextlib import contextmanager
import json
from pathlib import Path
import random
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from hepta.cpp_composed_migrate import migrate_cpp_composed
from hepta.llvm_owned_pipeline import build_llvm_owned_source
from hepta.object_symbols import inspect_object_symbols
from hepta.pipeline import compiler_hash
from tools.evidence_checks import require, strict_equal
from tools.validate_cpp_composed import (_build, _word, case_sources, observation_oracle,
                                        reference_source, EXAMPLE as HARNESS)
from tools.validate_cpp_owned import CPP_FLAGS, WRAP_FLAGS, _canonical, _identity, _process, _run, _sha

EXAMPLE = ROOT / "examples/cpp/scoped_ownership_migration"


class _Fault(Exception):
    pass


def oracle(raw):
    """Independent chronological allocation model, unrelated to the lowerer."""
    left, right, value, index, reject, early, refuse_at = raw
    events = []
    allocated = attempts = refusals = 0

    def release(owner):
        for ident, size in reversed(owner):
            events.append((2, ident, size))

    @contextmanager
    def owner(a, b, rejection):
        nonlocal allocated, attempts, refusals
        held = []
        try:
            for field, size in enumerate((a, b), 1):
                if size:
                    attempts += 1
                    if attempts == refuse_at:
                        refusals += 1
                        events.append((3, attempts, size))
                        raise _Fault(1001)
                    allocated += 1
                    held.append((allocated, size))
                    events.append((1, allocated, size))
                if rejection == field:
                    raise _Fault(1002)
            if rejection == 3:
                raise _Fault(1003)
            yield
        finally:
            release(held)

    def score(a, b, v, i):
        return ((v ^ 91 if i == 0 else v) * 3 + (v ^ 37) + a + b) % 2**64

    def execute():
        with owner(left, right, 0):
            if early == 1:
                with owner(right, left, reject):
                    if index >= min(right, left):
                        return 3003, "branch_range_return"
                    if value == 255:
                        return score(right, left, value ^ 19, index), "branch_value_return"
            with owner(left + 1, right + 2, reject):
                if early == 2:
                    if index >= min(left + 1, right + 2):
                        return 4003, "moved_block_range_return"
                    return score(left + 1, right + 2, value ^ 17, index), "moved_block_value_return"
                with owner(1, 2, 0):
                    if early == 3:
                        return score(1, 2, 7, 0), "nested_early_return"
            if index >= min(left, right):
                return 2003, "outer_range_after_scoped_cleanup"
            return score(left, right, value, index), "outer_success_after_scoped_cleanup"

    try:
        expected, family = execute()
    except _Fault as error:
        expected = error.args[0]
        family = "allocation_refusal" if expected == 1001 else "constructor_rejection"
    trace = 14695981039346656037
    for event in events:
        for part in event:
            trace = _word(trace, part)
    return dict(zip(("left", "right", "value", "index", "reject", "early", "refuse_at"), raw),
                expected=expected, allocated=allocated, refusals=refusals, trace=trace,
                family=family, events=[list(event) for event in events])


def cases():
    # First case has eight allocations, a completed conditional owner, a moved
    # block owner, and an inner scope ending before the enclosing owner.
    vectors = [(3, 5, 7, 0, 0, 1, 0)]
    for left, right in ((0, 0), (0, 3), (3, 0), (1, 1), (3, 5)):
        for value in (0, 255):
            for index in sorted({0, max(min(left, right) - 1, 0), min(left, right) + 2}):
                for early in range(4):
                    for reject in range(4):
                        vectors.append((left, right, value, index, reject, early, 0))
                    for refusal in range(1, 9):
                        vectors.append((left, right, value, index, 0, early, refusal))
    rng = random.Random(0x5C0FED)
    vectors += [(rng.randrange(33), rng.randrange(33), rng.randrange(256),
                 rng.randrange(35), rng.randrange(4), rng.randrange(4), rng.randrange(9))
                for _ in range(64)]
    return [oracle(row) for row in vectors]


def _command(container, key, argv, code=0):
    row = _run(argv)
    # Keep failed compiler/linker/native observations before checking status.
    if key is None:
        container.append(row)
    else:
        container[key] = row
    _process(row, code)
    return row


def qualify(directory, *, clangxx="clang++", clang="clang", rustc=None, cc="gcc"):
    work = Path(directory).absolute()
    if work.exists() or work.is_symlink():
        raise ValueError("A new qualification directory is required")
    work.mkdir(parents=True)
    start_hash = compiler_hash()
    report = {"schema": "hepta.cpp-scoped-ownership-qualification.v1", "ok": False,
              "status": "started", "compiler_sha256": start_hash, "routes": {},
              "negative_controls": {}, "performance": {"status": "not_measured"},
              "claims": {"actual_cpp_implementation_migrated": True,
                         "original_cpp_objects_in_targets": False,
                         "foreign_cpp_calls": 0, "whole_cpp_raii_supported": False,
                         "source_equivalence_proved": False,
                         "general_performance_advantage_proved": False}}
    try:
        source = work / "original.cpp"
        source.write_bytes((EXAMPLE / "scoped.cpp").read_bytes())
        entry, migrated = work / "consumer.hepta", work / "migrated.hepta"
        entry.write_bytes((EXAMPLE / "consumer.hepta").read_bytes())
        report["migration"] = migrate_cpp_composed(source, migrated, clangxx=clangxx)
        require(report["migration"]["ok"], "Actual scoped source translation rejected")
        report["sources"] = {p.name: _identity(p) for p in (source, entry, migrated)}
        vectors = cases(); expected = observation_oracle(vectors)
        report.update(case_count=len(vectors), families=dict(Counter(v["family"] for v in vectors)),
                      cases_sha256=_sha(_canonical(vectors)), expected=expected)
        header, _ = case_sources(vectors)
        (work / "cases.h").write_text(header)
        (work / "cases.json").write_text(json.dumps(vectors, indent=2) + "\n")
        (work / "reference.cpp").write_text(reference_source("pair"))
        cpp, linker = shutil.which(clangxx), shutil.which("g++")
        require(cpp and linker, "Native C++ reference tools required")
        reference = {"commands": [], "sources": {
            "original": _identity(source), "wrapper": _identity(work / "reference.cpp"),
            "harness": _identity(HARNESS / "harness.c")}}
        report["routes"]["cpp_reference"] = reference
        for argv in ([cpp, *CPP_FLAGS, "-c", str(work / "reference.cpp"), "-o", str(work / "original.o")],
                     [cpp, *CPP_FLAGS, "-x", "c++", "-I" + str(work), "-c", str(HARNESS / "harness.c"), "-o", str(work / "harness.o")],
                     [linker, *CPP_FLAGS, str(work / "original.o"), str(work / "harness.o"), "-o", str(work / "original-native")]):
            _command(reference["commands"], None, argv)
        _command(reference, "execution", [str(work / "original-native")])
        require(strict_equal(json.loads(reference["execution"]["stdout"]), expected), "C++ differs from independent oracle")
        for backend in ("rust", "c"):
            row = {}; report["routes"][backend] = row
            _build(entry, work / backend, backend, vectors, row, rustc=rustc, cc=cc)
            require(strict_equal(json.loads(row["execution"]["stdout"]), expected), backend + " differs from independent oracle")
            require(row["foreign_cpp_link_inputs"] == [], "Original C++ may not enter translated target")
        obj, binary = work / "direct.o", work / "direct-native"
        llvm = {"foreign_cpp_link_inputs": []}; report["routes"]["llvm"] = llvm
        llvm["build"] = build_llvm_owned_source(entry, obj, clang=clang, rustc=rustc, kind="object")
        require(llvm["build"]["ok"], "Direct LLVM generation failed: " + json.dumps(llvm["build"]))
        symbols = inspect_object_symbols(obj.read_bytes(), "ELF64", 62)
        require(symbols["defined"] == frozenset({"composed_case"})
                and symbols["undefined"] <= frozenset({"malloc", "calloc", "free", "memset", "abort"}),
                "Unexpected direct-object implementation or foreign dependency")
        llvm["symbols"] = {k: sorted(v) for k, v in symbols.items()}
        argv = [cc, "-std=c11", "-O2", "-fno-lto", *WRAP_FLAGS, "-I" + str(work),
                str(HARNESS / "harness.c"), str(obj), "-o", str(binary)]
        _command(llvm, "link", argv); llvm["artifact"] = _identity(binary)
        _command(llvm, "execution", [str(binary)])
        require(strict_equal(json.loads(llvm["execution"]["stdout"]), expected), "LLVM differs from independent oracle")
        for mutation in ("leak", "destruction_order"):
            row = {}; report["negative_controls"][mutation] = row
            _build(entry, work / mutation, "c", vectors, row, rustc=rustc, cc=cc, mutation=mutation)
            observed = json.loads(row["execution"]["stdout"])
            require(observed["ok"] is False and observed["failure"] == "lifecycle" and observed["case"] == 0,
                    "Actual native lifetime mutation not detected")
            if mutation == "leak":
                require(observed["freed"] == 0 and observed["live"] == 8, "Leak control lost its denominator")
            else:
                require(observed["freed"] == 8 and observed["live"] == 0
                        and observed["trace"] != observed["expected_trace"], "Order error mistaken for leak")
        report["source_unchanged"] = (compiler_hash() == start_hash and
            report["sources"] == {p.name: _identity(p) for p in (source, entry, migrated)})
        require(report["source_unchanged"], "Compiler changed during qualification")
        report.update(ok=True, status="scoped_native_ownership_qualified")
    except Exception as error:
        report.update(status="failed", error={"kind": type(error).__name__, "message": str(error)})
    (work / "qualification.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workdir", required=True)
    parser.add_argument("--clangxx", default="clang++")
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--rustc")
    parser.add_argument("--cc", default="gcc")
    args = parser.parse_args()
    report = qualify(args.workdir, clangxx=args.clangxx, clang=args.clang, rustc=args.rustc, cc=args.cc)
    print(json.dumps({k: report.get(k) for k in ("ok", "status", "case_count", "expected", "error")}))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
