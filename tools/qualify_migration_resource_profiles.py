"""Two upstream components: conditional GSL cleanup and SQLite fixed codec.

All native observations are retained. SQLite input slices are byte-for-byte
complete functions from pinned real amalgamations, not replacement algorithms.
GSL callbacks and scalar harnesses are explicitly authored integration code.
"""
from __future__ import annotations

import argparse
import copy
from hashlib import sha256
import json
from pathlib import Path
import random
import resource
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.c_migrate import migrate_c_project
from hepta.cpp_gsl_final_action import capture_and_lower, MigrationError
from hepta.hia_program_llvm import build_program_native, emit_program_llvm
from hepta.hia_program_source import lower_source
from hepta.pipeline import analyze, compiler_hash
from tools.qualify_cpp_gsl_final_action import build_original, cases as gsl_cases

SQLITE = ROOT / "tests/fixtures/sqlite_fixed_codec"
GSL = ROOT / "examples/cpp/gsl_branching_callbacks"
PORTABLE_FLAGS = ["-DSQLITE_BYTEORDER=0", "-DGCC_VERSION=0", "-DMSVC_VERSION=0"]

SQLITE_CLIENT = r'''
// Authored scalar ABI harness around the two automatically imported functions.
pub export "C" fn migrated_get(packed: u32) -> u32 effects {alloc, block, panic, write} {
    let mut bytes = buffer(4);
    bytes[0] = (packed >> 24) as u8;
    bytes[1] = (packed >> 16) as u8;
    bytes[2] = (packed >> 8) as u8;
    bytes[3] = packed as u8;
    let answer = c_sqlite3Get4byte(read bytes);
    drop(move bytes);
    return answer;
}
pub export "C" fn migrated_put(value: u32) -> u64 effects {alloc, block, panic, write} {
    let mut bytes = buffer(6);
    bytes[4] = 165;
    bytes[5] = 90;
    c_sqlite3Put4byte(mut bytes, value);
    let answer = ((bytes[0] as u64) << 40) | ((bytes[1] as u64) << 32)
        | ((bytes[2] as u64) << 24) | ((bytes[3] as u64) << 16)
        | ((bytes[4] as u64) << 8) | (bytes[5] as u64);
    drop(move bytes);
    return answer;
}
'''

SQLITE_REFERENCE = r'''
#include <stdint.h>
extern unsigned int sqlite3Get4byte(const unsigned char *);
extern void sqlite3Put4byte(unsigned char *, unsigned int);
uint32_t original_get(uint32_t packed) {
    unsigned char p[6] = {165, packed >> 24, packed >> 16, packed >> 8, packed, 90};
    return sqlite3Get4byte(p + 1);
}
uint64_t original_put(uint32_t value) {
    unsigned char p[8] = {17, 0, 0, 0, 0, 165, 90, 31};
    sqlite3Put4byte(p + 1, value);
    if (p[0] != 17 || p[7] != 31) return UINT64_MAX;
    return ((uint64_t)p[1] << 40) | ((uint64_t)p[2] << 32)
        | ((uint64_t)p[3] << 24) | ((uint64_t)p[4] << 16)
        | ((uint64_t)p[5] << 8) | p[6];
}
'''

SQLITE_HARNESS = r'''
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#ifndef GET
#define GET original_get
#define PUT original_put
#endif
extern uint32_t GET(uint32_t);
extern uint64_t PUT(uint32_t);
int main(void) {
    uint32_t input;
    unsigned count = 0;
    while (scanf("%" SCNu32, &input) == 1) {
        printf("%" PRIu32 " %" PRIu64 "\n", GET(input), PUT(input));
        ++count;
    }
    return count ? 0 : 2;
}
'''


def require(value, message):
    if not value:
        raise RuntimeError(message)


def digest(path):
    result = sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def tool_identity(name):
    executable = shutil.which(str(name))
    require(executable is not None, "Missing native compiler: " + str(name))
    path = Path(executable).resolve()
    version = subprocess.run([str(path), "--version"], capture_output=True,
                             text=True, timeout=10)
    require(version.returncode == 0, "Could not identify native compiler")
    return {"path": str(path), "sha256": digest(path),
            "version": version.stdout, "version_stderr": version.stderr}


def write(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n")


def command(log, argv, *, stdin=None, accepted=(0,)):
    start = time.perf_counter_ns()
    proc = subprocess.run(list(map(str, argv)), input=stdin, capture_output=True,
                          text=True, timeout=60)
    row = {"argv": list(map(str, argv)), "returncode": proc.returncode,
           "stdout": proc.stdout, "stderr": proc.stderr,
           "elapsed_ns": time.perf_counter_ns() - start}
    log.append(row)
    require(proc.returncode in accepted, "Native command failed: " + proc.stderr[:2000])
    return proc


def compile_hepta(source, directory, *, clang, label="migrated"):
    path = directory / (label + ".hepta")
    path.write_text(source)
    checked = analyze(source, path=str(path), backend="c", native=False)
    write(directory / (label + ".check.json"), checked.report)
    require(checked.report["ok"], "Hepta source rejected: " + json.dumps(checked.report["diagnostics"]))
    core = lower_source(source, path=str(path))
    write(directory / (label + ".core.json"), core.as_dict())
    (directory / (label + ".ll")).write_text(emit_program_llvm(core).text)
    obj = directory / (label + ".o")
    build = build_program_native(core.as_dict(), obj, clang=clang, kind="object")
    write(directory / (label + ".build.json"), build)
    return obj, build


def migrate_sqlite(project, output, *, clang, contracts=None, flags=None):
    flags = PORTABLE_FLAGS if flags is None else flags
    database = project / "compile_commands.json"
    database.write_text(json.dumps([{"directory": str(project), "file": str(project / "adapter.c"),
        "arguments": [clang, "-std=c11", "-O2", *flags, "-c", str(project / "adapter.c"), "-o", "adapter.o"]}]))
    contract = json.loads((SQLITE / "contracts.json").read_text()) if contracts is None else contracts
    return migrate_c_project(database, output, contracts=contract, clang=clang, verify_native=False)


def sqlite_inputs():
    values = {0, 1, 0x7fffffff, 0x80000000, 0xffffffff, 0x01020304, 0xfefdfcfb}
    for byte in range(256):
        for shift in (0, 8, 16, 24):
            values.add(byte << shift)
            values.add(0xffffffff ^ (byte << shift))
    rng = random.Random(0x5317532)
    values.update(rng.getrandbits(32) for _ in range(512))
    return sorted(values)


def observations(log, binary, input_text, path):
    observed = command(log, [binary], stdin=input_text).stdout
    path.write_text(observed)
    return [tuple(map(int, row.split())) for row in observed.splitlines()]


def qualify_sqlite(output, *, clang, cc):
    start = time.perf_counter_ns()
    report = {"schema": "hepta.sqlite-fixed-codec.qualification.v1", "versions": {}, "negative_controls": {}}
    values = sqlite_inputs()
    expected = [(v, (v << 16) | 0xa55a) for v in values]
    input_text = "".join(str(v) + "\n" for v in values)
    (output / "inputs.txt").write_text(input_text)
    write(output / "expected.json", expected)
    provenance = json.loads((SQLITE / "UPSTREAM.json").read_text())
    for upstream in provenance["versions"]:
        version = upstream["version"]
        directory = output / version; directory.mkdir()
        project = directory / "project"; shutil.copytree(SQLITE / version, project)
        require(digest(project / "codec.inc") == upstream["source_slice_sha256"], "SQLite source identity differs")
        migration_begin = time.perf_counter_ns()
        migration = migrate_sqlite(project, directory / "bundle", clang=clang)
        write(directory / "migration.json", migration)
        require(migration["ok"], "SQLite import rejected: " + json.dumps(migration["diagnostics"]))
        source = (directory / "bundle/source.hepta").read_text() + SQLITE_CLIENT
        obj, build = compile_hepta(source, directory, clang=clang)
        migration_ns = time.perf_counter_ns() - migration_begin
        (directory / "reference.c").write_text(SQLITE_REFERENCE)
        (directory / "harness.c").write_text(SQLITE_HARNESS)
        log = []
        original_obj = directory / "original.o"
        command(log, [cc, "-std=c11", "-O2", "-fno-lto", *PORTABLE_FLAGS,
                      "-c", project / "adapter.c", "-o", original_obj])
        original = directory / "original"
        command(log, [cc, "-std=c11", "-O2", directory / "reference.c", directory / "harness.c", original_obj, "-o", original])
        migrated = directory / "migrated"
        command(log, [cc, "-std=c11", "-O2", "-DGET=migrated_get", "-DPUT=migrated_put",
                      directory / "harness.c", obj, "-o", migrated])
        before = observations(log, original, input_text, directory / "original.stdout")
        after = observations(log, migrated, input_text, directory / "migrated.stdout")
        require(before == expected and after == expected, "SQLite native result or write boundary differs from independent byte oracle")
        write(directory / "commands.json", log)
        report["versions"][version] = {"upstream": upstream, "inputs": len(values),
            "native_function_observations": 2 * len(values), "oracle_equal": True,
            "selected_candidate_functions": 2, "automatically_converted_functions": len(migration["functions"]),
            "candidate_function_fraction": [len(migration["functions"]), 2],
            "whole_sqlite_conversion_fraction": None,
            "promoted_signed_shift_proofs": [proof for f in migration["functions"] for proof in f.get("proven_nonnegative_shifts", [])],
            "source_migration_and_native_build_ns": migration_ns,
            "retained_original_cpp_or_c_link_objects": [],
            "foreign_runtime": ["libc allocator/free/abort used by authored buffer harness"],
            "build": build, "migration_report": str(directory / "migration.json")}
    # New independent captures must reject invalid contracts, not normalize them.
    project = output / "3.53.2/project"
    base_contract = json.loads((SQLITE / "contracts.json").read_text())
    for length in (0, -1, 65_537, True):
        contract = copy.deepcopy(base_contract)
        contract["functions"]["sqlite3Get4byte"]["slices"]["p"]["length"] = length
        name = "invalid_fixed_length_" + str(length)
        rejected = migrate_sqlite(project, output / name, clang=clang, contracts=contract)
        require(not rejected["ok"], name + " was accepted")
        report["negative_controls"][name] = {"rejected": True, "diagnostics": rejected["diagnostics"]}
    for name, alteration in {
        "signed_shift_overflow": lambda s: s.replace("(p[1]<<16)", "(p[1]<<24)"),
        "signed_shift_width": lambda s: s.replace("(p[1]<<16)", "(p[1]<<32)"),
    }.items():
        variant = output / (name + "-source"); shutil.copytree(SQLITE / "3.53.2", variant)
        path = variant / "codec.inc"; old = path.read_text(); new = alteration(old)
        require(old != new, "Negative source alteration missed its target")
        path.write_text(new)
        rejected = migrate_sqlite(variant, output / name, clang=clang)
        require(not rejected["ok"], name + " was accepted")
        report["negative_controls"][name] = {"rejected": True, "diagnostics": rejected["diagnostics"]}
    short = output / "short-safe-buffer"; short.mkdir()
    source = (output / "3.53.2/bundle/source.hepta").read_text() + SQLITE_CLIENT.replace("buffer(4)", "buffer(3)")
    # Isolate the contract check: do not write a fourth byte before the call.
    source = source.replace("    bytes[3] = packed as u8;\n", "")
    short_obj, _ = compile_hepta(source, short, clang=clang)
    log = []
    short_binary = short / "short"
    command(log, [cc, "-std=c11", "-O2", "-DGET=migrated_get", "-DPUT=migrated_put",
                  output / "3.53.2/harness.c", short_obj, "-o", short_binary])
    failed = command(log, [short_binary], stdin="1\n", accepted=(-6, 134))
    write(short / "commands.json", log)
    report["negative_controls"]["safe_core_short_buffer"] = {"terminated_before_read": True, "returncode": failed.returncode}
    # Type correctness does not establish semantics: independently falsify one.
    wrong = output / "wrong-but-typed"; wrong.mkdir()
    source = (output / "3.53.2/migrated.hepta").read_text()
    require("(16 as i32)" in source, "Expected proven source shift was not found")
    source = source.replace("(16 as i32)", "(15 as i32)", 1)
    wrong_obj, _ = compile_hepta(source, wrong, clang=clang)
    log = []; wrong_binary = wrong / "wrong"
    command(log, [cc, "-std=c11", "-O2", "-DGET=migrated_get", "-DPUT=migrated_put",
                  output / "3.53.2/harness.c", wrong_obj, "-o", wrong_binary])
    bad = observations(log, wrong_binary, input_text, wrong / "wrong.stdout")
    mismatches = [i for i, (a, b) in enumerate(zip(bad, expected)) if a != b]
    require(mismatches, "Wrong-but-typed codec escaped the oracle")
    write(wrong / "commands.json", log)
    first = mismatches[0]
    report["negative_controls"]["wrong_but_typed_shift"] = {"detected": True,
        "mismatches": len(mismatches), "first_input": values[first], "actual": bad[first], "expected": expected[first]}
    report.update(ok=True, qualification_ns=time.perf_counter_ns()-start,
        scope={"selected_functions": ["sqlite3Get4byte", "sqlite3Put4byte"],
               "qualified_configuration": PORTABLE_FLAGS,
               "other_original_preprocessor_branches": "preserved_in_source_but_not_migrated_or_qualified",
               "source_contract": "one live initialized four-byte allocation; mutable caller has exclusive access",
               "raw_pointer_validity_inferred": False,
               "raw_c_abi_bridge_execution_qualified": False,
               "whole_sqlite_migrated": False,
               "source_equivalence_formally_proved": False,
               "runtime_performance_advantage_claimed": False})
    write(output / "report.json", report)
    return report


def callback_oracle(seed, tag, mode, profile):
    trace, calls = seed, 0
    tags = [] if mode == 7 else ([9, tag] if mode == 5 else [tag])
    for value in tags:
        if profile == "budget_release":
            if value <= trace:
                trace -= value; calls += 1
            else:
                calls += 2
        elif value % 2 == 0 or trace == 0:
            trace = (trace + value) % (1 << 64); calls += 1
        else:
            other = trace ^ value
            trace = other if other > trace else (trace * 37 + value) % (1 << 64)
            calls += 1
    status = {1: 2001, 2: 2002, 3: 2003, 4: 1004, 5: 2005, 6: 1006, 7: 1007}.get(mode, 0)
    return trace, calls, status


def qualify_gsl(output, *, clang, cc, cxx):
    rows = gsl_cases()
    report = {"schema": "hepta.gsl-branching-callback.qualification.v1", "profiles": {}, "negative_controls": {}}
    for profile in ("budget_release", "masked_release"):
        profile_dir = output / profile; profile_dir.mkdir()
        examples = profile_dir / "source"
        shutil.copytree(ROOT / "examples/cpp/gsl_final_action", examples)
        shutil.copyfile(GSL / (profile + ".cpp"), examples / "callback.cpp")
        input_text = "".join("%d %d %d\n" % row for row in rows)
        expected = [callback_oracle(*row, profile) for row in rows]
        (profile_dir / "inputs.txt").write_text(input_text); write(profile_dir / "expected.json", expected)
        versions = {}
        for version in ("3.1.0", "4.0.0"):
            directory = profile_dir / version; directory.mkdir()
            begin = time.perf_counter_ns()
            migration = capture_and_lower(ROOT, version, directory, clang=clang, examples=examples)
            obj, build = compile_hepta(migration["source"], directory, clang=clang)
            migration_ns = time.perf_counter_ns() - begin
            log = []; original = build_original(ROOT, version, directory, log, cxx=cxx, cc=cc, examples=examples)
            migrated = directory / "migrated"
            command(log, [cc, "-std=c11", "-O2", "-DCASE_FUNCTION=migrated_case", examples / "harness.c", obj, "-o", migrated])
            before = observations(log, original, input_text, directory / "original.stdout")
            after = observations(log, migrated, input_text, directory / "migrated.stdout")
            require(before == expected and after == expected, "GSL callback lifecycle differs from independent oracle")
            write(directory / "commands.json", log)
            versions[version] = {"cases": len(rows), "oracle_equal": True,
                "statistics": migration["report"]["statistics"],
                "migration_and_native_build_ns": migration_ns,
                "upstream": migration["report"]["upstream"], "build": build,
                "retained_original_cpp_link_objects": [],
                "authored_integration_client_bytes": (examples / "client.hepta").stat().st_size,
                "authored_callback_bytes": (examples / "callback.cpp").stat().st_size}
        report["profiles"][profile] = versions
    for name, replacement in {
        "static_local": ("const unsigned long long before", "static const unsigned long long before"),
        "unknown_loop": ("const unsigned long long before", "while (false) {}\n    const unsigned long long before"),
        "pointer_rebind_in_else": ("state->trace = before;", "state = nullptr;"),
        "early_callback_return": ("state->calls = state->calls + 1ULL;", "return;"),
    }.items():
        examples = output / (name + "-source")
        shutil.copytree(output / "budget_release/source", examples)
        path = examples / "callback.cpp"; old = path.read_text(); new = old.replace(*replacement)
        require(old != new, "Missing negative callback mutation")
        path.write_text(new)
        try:
            capture_and_lower(ROOT, "4.0.0", output / name, clang=clang, examples=examples)
        except (MigrationError, ValueError) as error:
            report["negative_controls"][name] = {"rejected": True, "reason": str(error)}
        else:
            raise RuntimeError("Unsupported callback accepted: " + name)
    report.update(ok=True, scope={"upstream_libraries": ["Microsoft GSL"],
        "new_authored_callback_profiles": 2, "whole_gsl_migrated": False,
        "general_cpp_exceptions_automatically_migrated": False,
        "cross_translation_unit_reference_execution": True,
        "integration_client_automatically_migrated": False,
        "asynchronous_callbacks_or_escaping_capture_supported": False,
        "real_allocator_or_file_descriptor_callback_supported": False})
    write(output / "report.json", report)
    return report


def qualify(output, *, clang, cc="gcc", cxx="g++"):
    output = Path(output).resolve()
    require(not output.exists(), "Qualification requires a fresh evidence directory")
    output.mkdir(parents=True)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    before, start = compiler_hash(), time.perf_counter_ns()
    tools = {"clang": tool_identity(clang), "cc": tool_identity(cc), "cxx": tool_identity(cxx)}
    clang, cc, cxx = (tools[name]["path"] for name in ("clang", "cc", "cxx"))
    revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                              capture_output=True, text=True, check=True).stdout.strip()
    tracked = subprocess.run(["git", "diff", "--name-only", "HEAD"], cwd=ROOT,
                             capture_output=True, text=True, check=True).stdout.splitlines()
    sources = [Path(__file__), *SQLITE.rglob("*"), *GSL.iterdir()]
    bindings = {str(p.relative_to(ROOT)): digest(p) for p in sources if p.is_file()}
    report = {"schema": "hepta.two-upstream-migration.qualification.v1", "ok": False,
        "compiler_sha256": before, "source_bindings": bindings,
        "source_revision": revision, "tracked_changes_at_start": tracked,
        "native_toolchains": tools,
        "human_engineering_seconds": None, "human_engineering_status": "not_measured",
        "agent_token_cost": None, "claim_whole_libraries_migrated": False,
        "claim_general_c_cpp_migration": False, "claim_performance_parity": False}
    try:
        for name in ("sqlite", "gsl"):
            (output / name).mkdir()
        report["sqlite"] = qualify_sqlite(output / "sqlite", clang=clang, cc=cc)
        report["gsl"] = qualify_gsl(output / "gsl", clang=clang, cc=cc, cxx=cxx)
        require(compiler_hash() == before, "Compiler implementation changed during qualification")
        require(all(digest(tool["path"]) == tool["sha256"] for tool in tools.values()),
                "Native compiler changed during qualification")
        require(all(digest(ROOT / p) == d for p, d in bindings.items()), "Source changed during qualification")
        report["ok"] = True
    except Exception as error:
        report["error"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        report["qualification_ns"] = time.perf_counter_ns() - start
        write(output / "report.json", report)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clang", required=True)
    parser.add_argument("--cc", default="gcc")
    parser.add_argument("--cxx", default="g++")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = qualify(args.output, clang=args.clang, cc=args.cc, cxx=args.cxx)
    print(json.dumps({"ok": report["ok"], "report": str(args.output / "report.json")}, indent=2))
