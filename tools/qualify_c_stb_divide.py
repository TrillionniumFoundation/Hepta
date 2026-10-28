"""Execute a complete frozen stb_divide component through existing migration.

Every enabled library declaration is translated. The full upstream header,
including disabled self-test/platform branches, is retained unchanged. A native
C executable computes original results and calls the independent generated
library through its actual scalar ABI. No original object enters that target.
The portable route uses Rust; the additional HIA LLVM route is explicit and
currently restricted to its supported native Linux x86-64 host.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from hepta.backend import compile_rust, emit_rust
from hepta.c_migrate import migrate_c_project
from hepta.c_project import captured_source_argument, invoke, verify_capture
from hepta.checker import check
from hepta.clang_capture import run_bounded
from hepta.hia_program import execute_program, verify_program
from hepta.hia_program_runtime import HIAProgramTrap
from hepta.hia_program_source import lower_source
from hepta.parser import parse
from tools.validate_native_host import (COMPILER_PROBE, check_compiler_version,
    compiler_probe_command, msvc_version, parse_compiler_probe)

FIXTURE = ROOT / "tests/fixtures/c_migration/stb_divide"
UPSTREAM_COMMIT = "003501f6d7a8668ce8b6d875e34dd97ad0d5d5b5"
SOURCE_SHA256 = "46358dedcc0f49324a602f796b13f24e00fa0e512046354ee69511997401af6c"
FUNCTIONS = ("stb_div_trunc", "stb_div_floor", "stb_div_eucl",
             "stb_mod_trunc", "stb_mod_floor", "stb_mod_eucl")
VARIANTS = {"generic": [], "truncating": ["-DC_INTEGER_DIVISION_TRUNCATES"]}
MIN, MAX = -(1 << 31), (1 << 31) - 1
SEED = 20261028


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def source_identity():
    def git(*args):
        return subprocess.run(["git", *args], cwd=ROOT, text=True, capture_output=True, check=True).stdout.strip()
    return {"commit": git("rev-parse", "HEAD"), "tree": git("rev-parse", "HEAD^{tree}"),
            "status": git("status", "--porcelain", "--", "hepta", "tools", "tests", ".github/workflows"),
            "status_scope": "implementation_tests_and_workflows; generated artifacts outside these paths excluded",
            "implementation_files": {str(path.relative_to(ROOT)): sha(path)
                for folder in (ROOT / "hepta", ROOT / "tools") for path in sorted(folder.glob("*.py"))},
            "fixture_files": {str(path.relative_to(FIXTURE)): sha(path)
                              for path in sorted(FIXTURE.rglob("*")) if path.is_file()}}


def verify_upstream():
    metadata = json.loads((FIXTURE / "UPSTREAM.json").read_text())
    if metadata["commit"] != UPSTREAM_COMMIT or metadata["source_modifications"]:
        raise ValueError("Frozen unmodified upstream identity changed")
    expected = {
        "stb_divide.h": "6a51e3f2e3b328df25bf9c9a866268782889d08c",
        "LICENSE": "a77ae91f3ec0abb0028c9d9bd8d34d880b454d38",
        "UPSTREAM_README.md": "b474d06d686940893a892ba5004f4a316dd6b72f",
        "UPSTREAM_CONTRIBUTING.md": "0b24bebeae206b572c5b06b52cafe6eece46c167",
    }
    if {row["local_path"]: row["git_blob"] for row in metadata["files"]} != expected:
        raise ValueError("Frozen complete source/license inventory changed")
    for row in metadata["files"]:
        data = (FIXTURE / row["local_path"]).read_bytes()
        blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        if (blob != row["git_blob"] or len(data) != row["bytes"]
                or hashlib.sha256(data).hexdigest() != row["sha256"]):
            raise ValueError("Upstream file differs: " + row["local_path"])
    if sha(FIXTURE / "stb_divide.h") != SOURCE_SHA256:
        raise ValueError("Complete original header changed")
    return metadata


def corpus():
    """Unique finite defined-domain inputs, independent of native results."""
    seen = set()
    edges = [MIN, MIN + 1, MIN + 2, -(1 << 30), -65537, -65536, -1025, -129,
             -65, -64, -33, -17, -7, -3, -2, -1, 0, 1, 2, 3, 7, 17, 33,
             64, 65, 129, 1025, 65536, 65537, 1 << 30, MAX - 2, MAX - 1, MAX]
    rng = random.Random(SEED)
    categories = [("small_grid", ((a, b) for a in range(-64, 65) for b in range(-64, 65))),
                  ("int32_edges", ((a, b) for a in edges for b in edges)),
                  ("seeded_full_width", ((rng.randint(MIN, MAX), rng.randint(MIN, MAX)) for _ in range(4096)))]
    for category, pairs in categories:
        for a, b in pairs:
            if b == 0 or (a, b) == (MIN, -1) or (a, b) in seen:
                continue
            seen.add((a, b))
            magnitude = abs(a) // abs(b)
            trunc = -magnitude if (a < 0) != (b < 0) else magnitude
            floor = a // b
            remainder = a % abs(b)
            euclidean = (a - remainder) // b
            values = [trunc, floor, euclidean, a - trunc * b, a % b, remainder]
            if any(not MIN <= value <= MAX for value in values):
                raise AssertionError("Oracle escaped the defined 32-bit domain")
            yield {"category": category, "a": a, "b": b, "expected": values}


ALLOCATION_PROBE = r'''
struct StbAllocationProbe;
static STB_ALLOC: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static STB_ATTEMPTS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static STB_FREE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static STB_LIVE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
unsafe impl std::alloc::GlobalAlloc for StbAllocationProbe {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        use core::sync::atomic::Ordering::SeqCst;
        STB_ATTEMPTS.fetch_add(1,SeqCst);
        let p = std::alloc::System.alloc(layout);
        if !p.is_null() { STB_ALLOC.fetch_add(1,SeqCst); STB_LIVE.fetch_add(1,SeqCst); }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, layout: std::alloc::Layout) {
        use core::sync::atomic::Ordering::SeqCst;
        std::alloc::System.dealloc(p,layout);
        STB_FREE.fetch_add(1,SeqCst); STB_LIVE.fetch_sub(1,SeqCst);
    }
}
#[global_allocator] static STB_ALLOCATOR: StbAllocationProbe = StbAllocationProbe;
#[no_mangle] pub extern "C" fn stb_migration_resource_count(which:i32)->u64 {
    use core::sync::atomic::Ordering::SeqCst;
    match which { 0=>STB_ATTEMPTS.load(SeqCst), 1=>STB_ALLOC.load(SeqCst), 2=>STB_FREE.load(SeqCst), _=>STB_LIVE.load(SeqCst) }
}
'''


HARNESS = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#ifdef _WIN32
#include <windows.h>
typedef HMODULE Library;
static Library open_library(const char *path) { return LoadLibraryA(path); }
#else
#include <dlfcn.h>
#include <sys/resource.h>
typedef void *Library;
static Library open_library(const char *path) { return dlopen(path,RTLD_NOW|RTLD_LOCAL); }
#endif
#define STB_DIVIDE_IMPLEMENTATION
#include "stb_divide.h"
_Static_assert(sizeof(int)==4 && INT_MIN==(-2147483647-1) && INT_MAX==2147483647,"int32 ABI required");
_Static_assert(sizeof(unsigned long long)==8,"counter ABI required");
typedef int (*Function)(int,int);
typedef unsigned long long (*Counter)(int);
static const char *names[6]={"stb_div_trunc","stb_div_floor","stb_div_eucl","stb_mod_trunc","stb_mod_floor","stb_mod_eucl"};
static Function originals[6]={stb_div_trunc,stb_div_floor,stb_div_eucl,stb_mod_trunc,stb_mod_floor,stb_mod_eucl};
static int symbol(Library lib,const char *name,void *destination,size_t size) {
#ifdef _WIN32
    FARPROC pointer=GetProcAddress(lib,name);
#else
    void *pointer=dlsym(lib,name);
#endif
    if(!pointer || size!=sizeof(pointer)) return 0;
    memcpy(destination,&pointer,size); return 1;
}
int main(int argc,char **argv) {
    Library lib; Function functions[6]; Counter count=NULL;
    int i,a,b,expected[6],original[6],actual[6],read_count;
    unsigned long long before[4]={0,0,0,0},after[4]={0,0,0,0},cases=0;
    FILE *input,*output;
    if(argc<3)return 10;
#ifndef _WIN32
    {struct rlimit limit={0,0}; if(setrlimit(RLIMIT_CORE,&limit)!=0)return 19;}
#else
    SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX);
#endif
    lib=open_library(argv[1]); if(!lib)return 11;
    for(i=0;i<6;i++)if(!symbol(lib,names[i],&functions[i],sizeof(functions[i])))return 12;
    if(strcmp(argv[2],"--trap")==0) {
        int result,index;
        if(argc!=6)return 13;
        index=atoi(argv[3]); if(index<0||index>=6)return 14;
        a=(int)strtol(argv[4],NULL,10);b=(int)strtol(argv[5],NULL,10);
        puts("ENTERED_SAFE_TARGET");fflush(stdout);
        result=functions[index](a,b);
        printf("UNEXPECTED_RETURN %d\n",result);return 99;
    }
    if(argc!=4)return 15;
    (void)symbol(lib,"stb_migration_resource_count",&count,sizeof(count));
    if(count)for(i=0;i<4;i++)before[i]=count(i);
    input=fopen(argv[2],"r");output=fopen(argv[3],"w");if(!input||!output)return 16;
    while((read_count=fscanf(input,"%d%d%d%d%d%d%d%d",&a,&b,&expected[0],&expected[1],&expected[2],&expected[3],&expected[4],&expected[5]))==8) {
        if(b==0 || (a==INT_MIN && b==-1))return 17;
        for(i=0;i<6;i++){original[i]=originals[i](a,b);actual[i]=functions[i](a,b);}
        fprintf(output,"%d\t%d",a,b);
        for(i=0;i<6;i++)fprintf(output,"\t%d",expected[i]);
        for(i=0;i<6;i++)fprintf(output,"\t%d",original[i]);
        for(i=0;i<6;i++)fprintf(output,"\t%d",actual[i]);
        fputc('\n',output);cases++;
        for(i=0;i<6;i++)if(original[i]!=expected[i]||actual[i]!=expected[i]) {
            fprintf(stderr,"functional mismatch case %llu function %s expected %d original %d target %d\n",cases,names[i],expected[i],original[i],actual[i]);
            fclose(input);fclose(output);return 2;
        }
        if(count)for(i=0;i<4;i++)if(count(i)!=before[i])return 3;
    }
    if(read_count!=EOF)return 18;
    fclose(input);fclose(output);
    if(count)for(i=0;i<4;i++)after[i]=count(i);
    printf("{\"cases\":%llu,\"native_function_observations\":%llu,\"allocation_probe\":%s",cases,cases*12,count?"true":"false");
    if(count)printf(",\"resource_before\":[%llu,%llu,%llu,%llu],\"resource_after\":[%llu,%llu,%llu,%llu]}",before[0],before[1],before[2],before[3],after[0],after[1],after[2],after[3]);
    else printf(",\"resource_before\":null,\"resource_after\":null}");
    putchar('\n');
    return 0;
}
'''


def command(argv, cwd, processes, *, expected=0):
    argv = list(map(str, argv))
    started = time.monotonic()
    process = run_bounded(argv, cwd=cwd, timeout=120, stdin_limit=0,
                          stdout_limit=128_000, stderr_limit=256_000)
    row = {"argv": argv, "cwd": str(cwd), "returncode": process.returncode,
           "stdout": process.stdout, "stderr": process.stderr,
           "seconds": time.monotonic() - started}
    processes.append(row)
    if expected is not None and process.returncode != expected:
        raise RuntimeError("Native command failed: " + json.dumps(row))
    return row


def capture_fixture(work, flags):
    work.mkdir()
    for path in FIXTURE.iterdir():
        if path.is_file():
            shutil.copyfile(path, work / path.name)
    database = work / "compile_commands.json"
    write(database, [{"directory": str(work), "file": "implementation.c",
        "arguments": ["clang", "-std=c11", "-O2", *flags, "-c", "implementation.c", "-o", "implementation.o"]}])
    return database


def compiler_identity(selected, family, work, processes, host):
    compiler = shutil.which(selected)
    if compiler is None:
        raise ValueError("Required original compiler unavailable: " + selected)
    compiler = str(Path(compiler).resolve())
    driver = "msvc" if family == "msvc" else "gnu"
    probe = work / ("identity-" + family + ".c")
    probe.write_text(COMPILER_PROBE, encoding="utf-8")
    result = command(compiler_probe_command(compiler, driver, probe), work, processes)
    identity = parse_compiler_probe(result["stdout"])
    if identity["family"] != family or (identity["system"], identity["machine"]) != host:
        raise ValueError("Actual compiler identity does not match requested host/family")
    version = (msvc_version(identity) if family == "msvc" else
               command([compiler, "--version"], work, processes)["stdout"].strip())
    check_compiler_version(identity, version)
    return {"path": compiler, "family": family, "sha256": sha(compiler),
            "version": version, "macro_probe": identity}


def harness_command(compiler, source, output, flags, system):
    if compiler["family"] == "msvc":
        return [compiler["path"], "/nologo", "/std:c11", "/O2", "/MD",
                *["/D" + flag[2:] for flag in flags], "/Tc" + str(source),
                "/Fo" + str(output.with_suffix(".obj")), "/Fe" + str(output), "/link", "/INCREMENTAL:NO"]
    return [compiler["path"], "-std=c11", "-O2", *flags, str(source), "-o", str(output),
            *(["-ldl"] if system == "Linux" else [])]


def replay_rows(path, cases):
    count = 0
    with path.open() as stream:
        for row, expected in zip(stream, cases, strict=True):
            values = [int(part) for part in row.split()]
            if values != [expected["a"], expected["b"], *expected["expected"], *expected["expected"], *expected["expected"]]:
                raise ValueError("Retained native observation differs from independent oracle")
            count += 1
    return count


def qualify(output, *, clang, rustc, cc, cc_family, additional_cc=None, hia_native=False, audit_original_ub=False,
            expected_system=None, expected_machine=None):
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    machine = {"amd64": "x86_64", "arm64": "aarch64"}.get(platform.machine().lower(), platform.machine().lower())
    host = (platform.system(), machine)
    report = {"schema": "hepta.c-stb-divide-qualification.v1", "ok": False,
        "status": "failed", "processes": [], "variants": [],
        "host": {"system": host[0], "machine": host[1]}, "source_before": source_identity(),
        "claims": {"complete_c_component_in_declared_variants": False,
            "source_equivalence_proved": False, "cpp_migration": False,
            "all_stb_libraries_migrated": False, "unlisted_configurations_qualified": False,
            "original_implementation_linked_into_target": False,
            "performance_or_migration_cost_improvement_proved": False,
            "cross_host_results_inferred": False, "resource_owning_upstream_translated": False}}
    try:
        if ((expected_system and host[0] != expected_system)
                or (expected_machine and host[1] != expected_machine)):
            raise ValueError("Execution host differs from requested host")
        if hia_native and host != ("Linux", "x86_64"):
            raise ValueError("This additional HIA LLVM collector requires actual Linux x86-64")
        if audit_original_ub and host[0] != "Linux":
            raise ValueError("The additional original-C UBSan audit is qualified on Linux only")
        report["upstream"] = verify_upstream()
        report["scope"] = {"unchanged_header_bytes": 14507, "unchanged_header_lines": 433,
            "public_functions_per_variant": 6, "active_project_declarations_per_variant": 12,
            "declared_variants": VARIANTS, "upstream_body_edits": 0,
            "authored_adapter_bytes": (FIXTURE / "implementation.c").stat().st_size,
            "caller_pointer_or_resource_annotations": 0,
            "manual_contract": "32-bit C int, denominator nonzero and (INT_MIN,-1) excluded from all original-C calls",
            "manual_review_hours": None, "agent_tokens": None,
            "disabled_source": ["built-in STB_DIVIDE_TEST harness", "STB_DIVIDE_TEST_FLOOR simulation", "C_INTEGER_DIVISION_FLOORS path", "C++ extern-C declaration wrapper"],
            "disabled_source_policy": "complete bytes retained; not counted as active translated declarations"}
        compilers = [compiler_identity(cc, cc_family, output, report["processes"], host)]
        if additional_cc:
            compilers.append(compiler_identity(additional_cc[0], additional_cc[1], output, report["processes"], host))
        if len({row["family"] for row in compilers}) != len(compilers):
            raise ValueError("Additional compiler must be an independent family")
        report["original_compilers"] = compilers
        cases = list(corpus())
        with (output / "cases.jsonl").open("x") as stream:
            for row in cases:
                stream.write(json.dumps(row, separators=(",", ":")) + "\n")
        (output / "inputs.txt").write_text("".join(" ".join(map(str, [row["a"], row["b"], *row["expected"]])) + "\n" for row in cases))
        report["corpus"] = {"unique_inputs": len(cases), "categories": dict(Counter(row["category"] for row in cases)),
            "input_sha256": sha(output / "cases.jsonl"), "seed": SEED,
            "oracle": "Python unbounded integers; explicit truncating/floor/Euclidean quotient-remainder definitions"}
        suffix = {"Windows": ".dll", "Darwin": ".dylib", "Linux": ".so"}[host[0]]
        for name, flags in VARIANTS.items():
            work = output / name
            database = capture_fixture(work, flags)
            item = {"name": name, "flags": flags, "executions": [], "traps": []}
            report["variants"].append(item)
            migration = migrate_c_project(database, work / "translated", clang=clang)
            write(work / "migration.json", migration)
            item["migration"] = migration
            if (not migration["ok"] or not migration["declaration_inventory_complete"]
                    or migration["coverage"]["active_project_declarations"] != 12
                    or migration["coverage"]["status_counts"] != {"function_converted": 6, "prototype_resolved": 6}
                    or set(row["name"] for row in migration["functions"]) != set(FUNCTIONS)):
                raise ValueError("Whole component migration failed or its declaration denominator changed")
            if any(row["return"] != "i32" or [p["type"] for p in row["params"]] != ["i32", "i32"]
                   or any(p["pointer"] for p in row["params"]) for row in migration["functions"]):
                raise ValueError("The six original scalar signatures were not preserved")
            for filename, identity in migration["artifacts"].items():
                artifact = work / "translated" / filename
                if sha(artifact) != identity["sha256"] or artifact.stat().st_size != identity["bytes"]:
                    raise ValueError("Published migration artifact differs from byte manifest: " + filename)
            config = migration["build"]["configurations"][0]
            ast = invoke([migration["build"]["compiler"]["path"], *config["frontend_arguments"],
                "-Werror", "-fsyntax-only", "-Xclang", "-ast-dump=json", captured_source_argument(config)], work)
            (work / "raw-clang-ast.json").write_text(ast, encoding="utf-8", newline="\n")
            preprocessed = invoke([migration["build"]["compiler"]["path"], *config["frontend_arguments"],
                                  "-E", "-P", captured_source_argument(config)], work)
            (work / "preprocessed.c").write_text(preprocessed, encoding="utf-8", newline="\n")
            tree = json.loads(ast)
            definitions = [node for node in tree["inner"] if node.get("kind") == "FunctionDecl"
                           and any(child.get("kind") == "CompoundStmt" for child in node.get("inner", []))]
            if {node.get("name") for node in definitions} != set(FUNCTIONS):
                raise ValueError("Raw Clang AST body inventory differs from translated function inventory")
            def walk(node):
                yield node
                for child in node.get("inner", []):
                    if isinstance(child, dict):
                        yield from walk(child)
            node_counts = Counter(part.get("kind", "unknown") for node in definitions for part in walk(node))
            item["ast"] = {"sha256": sha(work / "raw-clang-ast.json"), "bytes": len(ast.encode()),
                "top_level_nodes": len(tree["inner"]), "active_function_definition_nodes": len(definitions),
                "active_definition_node_counts": dict(node_counts),
                "preprocessed_sha256": sha(work / "preprocessed.c"),
                "preprocessed_bytes": len(preprocessed.encode()), "preprocessed_lines": len(preprocessed.splitlines()),
                "full_header_source_bytes_are_not_active_ast_coverage": True}
            target = work / ("translated" + suffix)
            rust_source = (work / "translated/generated.rs").read_text() + ALLOCATION_PROBE
            (work / "instrumented-generated.rs").write_text(rust_source)
            item["rust_build"] = compile_rust(rust_source, rustc=rustc, crate_type="cdylib", output=target)
            if not item["rust_build"]["ok"]:
                raise ValueError("Generated Rust native target failed")
            source = (work / "translated/source.hepta").read_text()
            hia_source = source + "\n".join(f'export "C" fn {fn}(a:i32,b:i32)->i32 effects {{panic,write}} {{return c_{fn}(a,b);}}' for fn in FUNCTIONS)
            (work / "program.hepta").write_text(hia_source + "\n")
            program = lower_source(hia_source)
            (work / "program.hia.json").write_bytes(program.canonical_bytes)
            item["hia"] = {"sha256": program.sha256, "native_requested": hia_native,
                           "native_executed": False, "public_scalar_signature_preserved": True,
                           "native_allocator_counters_observed": False}
            # The interpreter is deliberately a separately stated subset, not
            # relabeled as every native input/configuration observation.
            interpreted_cases = [row for row in cases if row["category"] == "int32_edges"
                and row["a"] in {MIN, MIN + 1, MAX}
                and row["b"] in {MIN, MIN + 1, -7, -2, -1, 1, 2, 7, MAX}] + cases[:16] + cases[-16:]
            interpreted_count = 0
            with (work / "interpreter.jsonl").open("x") as stream:
                for row in interpreted_cases:
                    for fn, expected in zip(FUNCTIONS, row["expected"]):
                        actual = execute_program(program, fn, [row["a"], row["b"]], max_heap_bytes=0)
                        if actual["result"] != expected or any(actual["resources"].values()):
                            raise ValueError("Standalone interpreter differs or consumes resources")
                        stream.write(json.dumps({"function": fn, "input": [row["a"], row["b"]], "expected": expected, "actual": actual}, separators=(",", ":")) + "\n")
                        interpreted_count += 1
            item["hia"]["interpreter_function_observations"] = interpreted_count
            item["hia"]["interpreter_unique_inputs"] = len(interpreted_cases)
            targets = [("rust", target)]
            if hia_native:
                from hepta.hia_program_llvm import build_program_native, emit_program_llvm
                llvm = emit_program_llvm(program)
                (work / "program.ll").write_text(llvm.text)
                hia_target = work / "hia.so"
                item["hia"]["build"] = build_program_native(program, hia_target, clang=clang)
                if not item["hia"]["build"]["ok"]:
                    raise ValueError("Direct HIA LLVM build failed")
                targets.append(("hia_llvm", hia_target))
            harness = work / "harness.c"
            harness.write_text(HARNESS, encoding="utf-8")
            executables = []
            for compiler in compilers:
                executable = work / ("original-caller-" + compiler["family"] + (".exe" if host[0] == "Windows" else ""))
                command(harness_command(compiler, harness, executable, flags, host[0]), work, report["processes"])
                executables.append(executable)
                for route, library in targets:
                    observations = work / (compiler["family"] + "-" + route + ".tsv")
                    observed = command([executable, library, output / "inputs.txt", observations], work, report["processes"])
                    summary = json.loads(observed["stdout"])
                    if (summary["cases"] != len(cases) or summary["native_function_observations"] != len(cases) * 12
                            or summary["allocation_probe"] != (route == "rust")
                            or summary["resource_before"] != summary["resource_after"]
                            or replay_rows(observations, cases) != len(cases)):
                        raise ValueError("Actual native execution denominator/resource log differs")
                    item["executions"].append({"original_compiler_family": compiler["family"],
                        "generated_route": route, "summary": summary, "caller_sha256": sha(executable),
                        "target_sha256": sha(library), "observations_sha256": sha(observations)})
                    if route == "hia_llvm":
                        item["hia"]["native_executed"] = True
            if audit_original_ub:
                sanitizer_compiler = next((row for row in compilers if row["family"] == "gcc"), None)
                if sanitizer_compiler is None:
                    raise ValueError("Original-C UBSan audit requires actual GCC")
                sanitized = work / "original-caller-gcc-ubsan"
                argv = harness_command(sanitizer_compiler, harness, sanitized, flags, host[0])
                command([*argv, "-fsanitize=undefined", "-fno-sanitize-recover=undefined"], work, report["processes"])
                observations = work / "gcc-ubsan-rust.tsv"
                observed = command([sanitized, target, output / "inputs.txt", observations], work, report["processes"])
                summary = json.loads(observed["stdout"])
                if summary["cases"] != len(cases) or replay_rows(observations, cases) != len(cases):
                    raise ValueError("Original-C UBSan corpus differs")
                item["original_c_ubsan_audit"] = {"passed": True, "summary": summary,
                    "caller_sha256": sha(sanitized), "observations_sha256": sha(observations),
                    "scope": "observed original-C executions only; not absence of UB over all int32 inputs"}
            for route, library in targets:
                for index, fn in enumerate(FUNCTIONS):
                    for label, a, b in (("zero_divisor", 7, 0), ("unrepresentable_quotient", MIN, -1)):
                        trapped = command([executables[0], library, "--trap", index, a, b], work, report["processes"], expected=None)
                        accepted_codes = {3, 0xC0000409, -1073740791} if host[0] == "Windows" else {-6}
                        if trapped["returncode"] not in accepted_codes or trapped["stdout"].strip() != "ENTERED_SAFE_TARGET":
                            raise ValueError("Unsafe input did not enter and abort in the safe target")
                        item["traps"].append({"route": route, "function": fn, "input": [a, b],
                            "case": label, "exit_code": trapped["returncode"], "original_c_called": False})
            for fn in FUNCTIONS:
                for arguments in ([7, 0], [MIN, -1]):
                    try:
                        execute_program(program, fn, arguments, max_heap_bytes=0)
                    except HIAProgramTrap as exc:
                        if any(exc.report["resources"].values()):
                            raise ValueError("Scalar trap unexpectedly consumed resources")
                    else:
                        raise ValueError("Standalone HIA did not trap invalid division")
            verify_capture(migration["build"])
        if (len({item["ast"]["preprocessed_sha256"] for item in report["variants"]}) != 2
                or len({item["hia"]["sha256"] for item in report["variants"]}) != 2):
            raise ValueError("The two declared macro builds must produce distinct captured implementations")
        # A resource-legal, actually compiled wrong implementation must fail
        # the same native oracle. Source verification alone cannot admit it.
        wrong_source = "\n".join(f'export "C" fn {fn}(a:i32,b:i32)->i32 effects {{}} {{return 0;}}' for fn in FUNCTIONS)
        wrong_program = parse(wrong_source)
        wrong_checked = check(wrong_program)
        if not wrong_checked.ok:
            raise ValueError("Wrong-code control must first be source/resource legal")
        wrong_hia = lower_source(wrong_source)
        verify_program(wrong_hia)
        (output / "wrong.hepta").write_text(wrong_source + "\n")
        (output / "wrong.hia.json").write_bytes(wrong_hia.canonical_bytes)
        wrong_path = output / ("wrong" + suffix)
        wrong_rust = emit_rust(wrong_program, wrong_checked, crate_type="cdylib") + ALLOCATION_PROBE
        (output / "wrong.rs").write_text(wrong_rust)
        report["wrong_build"] = compile_rust(wrong_rust, rustc=rustc, crate_type="cdylib", output=wrong_path)
        if not report["wrong_build"]["ok"]:
            raise ValueError("Wrong-code native build failed before functional rejection")
        wrong = command([executables[0], wrong_path, output / "inputs.txt", output / "wrong.tsv"], output, report["processes"], expected=2)
        if "functional mismatch" not in wrong["stderr"]:
            raise ValueError("Wrong-code control did not reach the actual functional oracle")
        report["wrong_code_control"] = {"source_and_hia_resource_legal": True, "actual_native_executed": True,
            "rejected_by_functional_oracle": True, "exit_code": wrong["returncode"], "target_sha256": sha(wrong_path)}
        report["refusal_controls"] = []
        for label, addition, expected in [
            ("extra_global", "int unsupported_global;\n", "E_C_TOPLEVEL"),
            ("uninitialized_path", "int unsupported_path(int c){int x;if(c)x=1;return x;}\n", "E_C_UNINITIALIZED"),
            ("extra_pointer_return", "int *unsupported_pointer(int *p){return p;}\n", "E_C_TYPE")]:
            work = output / ("reject-" + label)
            database = capture_fixture(work, [])
            with (work / "implementation.c").open("a") as stream:
                stream.write(addition)
            rejected = migrate_c_project(database, work / "translated", clang=clang)
            write(work / "migration.json", rejected)
            if (rejected["ok"] or (work / "translated").exists()
                    or expected not in [row["code"] for row in rejected["diagnostics"]]
                    or not rejected["declaration_inventory_complete"]
                    or rejected["coverage"]["active_project_declarations"] != 13):
                raise ValueError("Extra unsupported declaration escaped whole-bundle rejection")
            report["refusal_controls"].append({"name": label, "expected": expected,
                "active_project_declarations": 13, "whole_bundle_rejected": True, "published_partial_bundle": False})
        # The dual-use header is not automatically a qualified C++ migration.
        # Keep a real refusal from the existing C++ entry with the whole header.
        from hepta.cpp_project_migrate import lower_cpp_project
        work = output / "cpp-entry-refusal"
        database = capture_fixture(work, [])
        (work / "implementation.cpp").write_bytes((work / "implementation.c").read_bytes())
        write(database, [{"directory": str(work), "file": "implementation.cpp",
                         "arguments": ["clang++", "-std=c++20", "-O2", "-c", "implementation.cpp"]}])
        try:
            lower_cpp_project(database, clangxx=clang)
        except ValueError as exc:
            if getattr(exc, "code", None) != "E_CPP_PROJECT_PROFILE":
                raise
            report["cpp_entry_refusal"] = {"rejected": True, "code": exc.code,
                "message": str(exc), "upstream_header_sha256": sha(work / "stb_divide.h"),
                "declaration_inventory_complete": False, "cpp_migration_claimed": False}
        else:
            raise ValueError("Unqualified C++ no-noexcept source unexpectedly entered the explicit C++ profile")
        report["totals"] = {
            "distinct_inputs": len(cases), "input_configuration_pairs": len(cases) * len(VARIANTS),
            "original_target_pair_executions": sum(row["summary"]["cases"] for item in report["variants"] for row in item["executions"]),
            "native_function_observations": sum(row["summary"]["native_function_observations"] for item in report["variants"] for row in item["executions"]),
            "additional_ubsan_native_function_observations": sum(item.get("original_c_ubsan_audit", {}).get("summary", {}).get("native_function_observations", 0) for item in report["variants"]),
            "interpreter_function_observations": sum(item["hia"]["interpreter_function_observations"] for item in report["variants"]),
            "native_target_only_trap_processes": sum(len(item["traps"]) for item in report["variants"]),
            "ordinary_native_routes_include_repeated_original_and_target_calls": True}
        report["resource_scope"] = {
            "upstream_component": "borrow-free scalar arithmetic; no upstream owning resources or allocator failure API",
            "rust_native_counters": ["allocation_attempts", "successful_allocations", "frees", "live_allocations"],
            "native_counter_comparison": "unchanged around each six-function input group; only rows with allocation_probe=true",
            "hia_interpreter": "zero heap budget; resource event counters must all remain zero on returns and traps",
            "hia_native": "functional and trap observations; allocator counters not measured"}
        report["claims"]["complete_c_component_in_declared_variants"] = True
        report["checks"] = {"complete_unchanged_upstream": True,
            "all_active_declarations_accounted": True, "independent_functional_oracle": True,
            "distinct_macro_implementations_really_executed": True,
            "native_original_and_generated_abi_calls": True, "separate_scalar_resource_observations": True,
            "unsafe_inputs_never_sent_to_original_c": True, "actual_wrong_code_rejected": True,
            "unsupported_declarations_reject_whole_bundle": True}
        report.update(ok=True, status="passed_for_actual_host_and_declared_component_variants")
    except Exception as exc:
        report["error"] = {"type": type(exc).__name__, "message": str(exc)}
    finally:
        report["source_after"] = source_identity()
        report["source_unchanged_during_run"] = report["source_before"] == report["source_after"]
        if not report["source_unchanged_during_run"]:
            report.update(ok=False, status="failed_source_changed")
        report["seconds"] = time.monotonic() - started
        report["artifacts"] = [{"path": str(path.relative_to(output)), "bytes": path.stat().st_size, "sha256": sha(path)}
                               for path in sorted(output.rglob("*")) if path.is_file()]
        write(output / "qualification.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--clang", default="clang")
    parser.add_argument("--rustc", required=True)
    parser.add_argument("--cc", default="gcc")
    parser.add_argument("--cc-family", choices=("gcc", "clang", "msvc"), default="gcc")
    parser.add_argument("--additional-cc")
    parser.add_argument("--additional-cc-family", choices=("gcc", "clang", "msvc"))
    parser.add_argument("--hia-native", action="store_true")
    parser.add_argument("--audit-original-ub", action="store_true")
    parser.add_argument("--expected-system")
    parser.add_argument("--expected-machine")
    args = parser.parse_args()
    if bool(args.additional_cc) != bool(args.additional_cc_family):
        parser.error("Additional compiler path and actual family are required together")
    report = qualify(args.output_directory, clang=args.clang, rustc=args.rustc, cc=args.cc,
        cc_family=args.cc_family,
        additional_cc=(args.additional_cc, args.additional_cc_family) if args.additional_cc else None,
        hia_native=args.hia_native, audit_original_ub=args.audit_original_ub,
        expected_system=args.expected_system, expected_machine=args.expected_machine)
    print(json.dumps({"ok": report["ok"], "status": report["status"], "seconds": report["seconds"],
                      "report": str(args.output_directory / "qualification.json"), "error": report.get("error")}, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
