#!/usr/bin/env python3
"""Independent native observations for raw stores composed with Copy ADTs.

Reuses the Unit gate's native execution/receipt harness; expected values and
source generators below are independent of production lowering.
"""
from pathlib import Path
import random
import sys
import hashlib
import json
import os
import platform
import shutil
import signal
import subprocess
import tempfile
from qualify_c_unit_oracle import digest, parse, check, emit_c, emit_rust, compile_c, compile_rust
import qualify_c_unit_oracle as harness

ROOT = Path(__file__).resolve().parents[1]
SEED = 610707
RANDOM_CASES = 64


def fixtures():
    # Expected values come only from Python integers and explicit call-order
    # accounting, never from generated C, Rust, or the language interpreter.
    cases = {}
    declarations = """
        struct Cell<T>{value:T,done:Unit}
        enum Event<T>{Value(T),Empty(Unit)}
        fn unit()->Unit effects {} {}
        fn mark(n:mut i64,digit:i64)->Unit effects {write,panic} {n=n*10+digit;}
        fn pointer(p:raw mut Result<Event<Cell<f64>>,Unit>,n:mut i64)->raw mut Result<Event<Cell<f64>>,Unit> effects {write,panic} {mark(mut n,1);return p;}
        fn index(n:mut i64)->usize effects {write,panic} {mark(mut n,2);return 0;}
        fn values(x:i64)->[Result<Event<Cell<f64>>,Unit>;2] effects {} {return [Result::Ok(Event::Value(Cell{value:x as f64,done:unit()})),Result::Err(unit())];}
        fn payload(n:mut i64,i:mut usize,x:i64)->Result<Event<Cell<f64>>,Unit> effects {write,panic} {
            mark(mut n,3);i=1;return values(x)[0];
        }
    """
    rng=random.Random(SEED)
    for mode in ('calls','index_snapshot'):
        f=harness.Fixture(declarations)
        f.lines[1]='fn main()->Unit effects {write,panic,io,unsafe,alloc,block} {'
        for j in range(32):
            x=rng.randint(-100000,100000)
            f.add('if true {let mut n:i64=0;let mut i:usize=0;let mut a:[Result<Event<Cell<f64>>,Unit>;2]=[Result::Err(unit()),Result::Err(unit())];')
            offset='index(mut n)' if mode=='calls' else 'i'
            f.add(f'unsafe {{store(pointer(ptr_mut(mut a),mut n),{offset},payload(mut n,mut i,{x}));}}')
            f.observe('n',123 if mode=='calls' else 13)
            f.observe('i',1)
            f.add('match a[0] {Result::Ok(e)=>{match e {Event::Value(c)=>{let u=c.done;')
            f.observe('c.value as i64',x)
            f.add('},Event::Empty(_)=>{assert(false);}}},Result::Err(_)=>{assert(false);}}')
            f.add('match a[1] {Result::Err(u)=>{let v=u;},Result::Ok(_)=>{assert(false);}}}')
        cases[mode]=f.finish()
    # C helper storage is aligned and both pointer choices remain in bounds.
    imports='''
        extern "C" fn destination()->raw mut i64 effects {ffi};
        extern "C" fn offset()->usize effects {ffi};
        extern "C" fn payload()->i64 effects {ffi};
        extern "C" fn finish()->Unit effects {ffi};
    '''
    for failure in ('none','pointer','index','value'):
        args=['destination()','offset()','payload()']
        declaration=''
        if failure!='none':
            pos=('pointer','index','value').index(failure)
            typ=('raw mut i64','usize','i64')[pos]
            declaration=f'fn fail()->{typ} effects {{ffi,unsafe,panic}} {{unsafe {{let v={args[pos]};assert(false);return v;}}}}'
            args[pos]='fail()'
        source=imports+declaration+'fn main()->Unit effects {ffi,unsafe,panic,write} {unsafe {store('+','.join(args)+');finish();}}'
        expected='PIVA:42:0\n' if failure=='none' else 'PIV'[:('pointer','index','value').index(failure)+1]
        cases['operand_'+failure]={'source':source,'expected_stdout':expected,'observations':1,'must_trap':failure!='none','helper':True}
    return cases


HELPER = r'''
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
static int64_t cells[2] = {0,0};
static size_t selected;
static void event(char c) { putchar(c); fflush(stdout); }
int64_t *destination(void) { event('P'); return cells + selected; }
size_t offset(void) { event('I'); return 0; }
int64_t payload(void) { event('V'); selected=1; return 42; }
void finish(void) { event('A'); printf(":%lld:%lld\n",(long long)cells[0],(long long)cells[1]); }
'''


def main():
    require_rust = os.environ.get("HEPTA_ENUM_REQUIRE_RUST") == "1"
    directory = Path(tempfile.mkdtemp(prefix="hepta-store-adt-oracle-", dir="/tmp"))
    inputs = sorted((ROOT / "hepta").glob("*.py")) + [Path(__file__).resolve(), ROOT / "toolchain-lock.json", ROOT / "tools/qualify_c_unit_oracle.py"]
    hashes = {str(p.relative_to(ROOT)): digest(p.read_bytes()) for p in inputs}
    result = {"schema": 1, "seed": SEED, "seeded_case_count": RANDOM_CASES,
              "scope": "ordinary raw stores with temporary Copy ADTs, Unit and numeric casts; shared Python parser/checker, not interpreter independence",
              "python": sys.version, "host": platform.platform(), "evidence_directory": str(directory),
              "rust_required": require_rust, "rust_executed": False,
              "input_sha256": hashes, "fixtures": [], "complete_pass": False}

    def save():
        (directory / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")

    try:
        save()
        cc = shutil.which("gcc")
        if not cc:
            raise RuntimeError("Native GCC is required")
        result["gcc_version"] = subprocess.run([cc, "--version"], capture_output=True, text=True, check=True, timeout=10).stdout
        result["gcc_sha256"] = digest(Path(cc).read_bytes())
        compiler = None
        if require_rust:
            requested = os.environ.get("RUSTC") or "rustc"
            compiler = shutil.which(requested)
            if not compiler:
                raise RuntimeError("HEPTA_ENUM_REQUIRE_RUST=1 but native Rust is unavailable: " + requested)
            version = subprocess.run([compiler, "--version"], capture_output=True, text=True, check=True, timeout=10).stdout.strip()
            result["rustc_version"] = version
            result["rustc_sha256"] = digest(Path(compiler).read_bytes())
            locked = next(entry["package"].split("-")[1] for entry in json.loads((ROOT / "toolchain-lock.json").read_text()) if entry["package"].startswith("rustc-"))
            if len(version.split()) < 2 or version.split()[0] != "rustc" or version.split()[1] != locked:
                raise RuntimeError(f"Required Rust version {locked}, got {version}")
        for name, case in fixtures().items():
            source, expected = case["source"], case["expected_stdout"]
            folder = directory / name
            folder.mkdir()
            helper=folder / "helper.c"
            helper.write_text(HELPER)
            links=[str(helper)] if case.get("helper") else []
            (folder / "program.hepta").write_text(source)
            (folder / "expected.stdout").write_text(expected)
            fixture = {"name": name, "hepta_sha256": digest(source.encode()),
                       "observations": case["observations"], "must_trap": case.get("must_trap", False), "expected_stdout": expected, "expected_stdout_sha256": digest(expected.encode()), "runs": []}
            result["fixtures"].append(fixture)
            save()
            program = parse(source)
            checked = check(program)
            if not checked.ok:
                raise RuntimeError(f"{name}: frontend rejected: {[d.to_dict() for d in checked.diagnostics]}")
            generated = {"c": emit_c(program, checked)}
            if require_rust:
                generated["rust"] = emit_rust(program, checked, crate_type="bin")
            fixture["generated_sha256"] = {k: digest(v.encode()) for k, v in generated.items()}
            for language, text in generated.items():
                (folder / ("program.c" if language == "c" else "program.rs")).write_text(text)
                for optimize in (False, True):
                    label = f"{language}-O{3 if optimize else 0}"
                    output = folder / label
                    run = {"language": language, "optimization": "O3" if optimize else "O0"}
                    fixture["runs"].append(run)
                    save()
                    if language == "c":
                        report = compile_c(text, cc=cc, output=output, optimize=optimize, sanitize=True, link_args=links)
                    else:
                        obj=folder / "helper.o"
                        if links:
                            subprocess.run([cc,"-c",str(helper),"-o",str(obj)],check=True,capture_output=True,timeout=30)
                        report = compile_rust(text, rustc=compiler, crate_type="bin", output=output, optimize=optimize, link_args=[str(obj)] if links else [])
                    run["compilation"] = {k: v for k, v in report.items() if k != "artifact"}
                    save()
                    if not report.get("ok"):
                        raise RuntimeError(f"{name}: {language} compilation failed")
                    required = {"-O3" if optimize else "-O0", "-fsanitize=undefined", "-fno-sanitize-recover=all"}
                    if language == "c" and not required.issubset(report["flags"]):
                        raise RuntimeError("Required optimization/nonrecovering UBSan flags missing")
                    if language == "rust" and f"opt-level={3 if optimize else 0}" not in report["flags"]:
                        raise RuntimeError("Required Rust optimization flag missing")
                    run["artifact_sha256"] = digest(output.read_bytes())
                    completed = subprocess.run([str(output)], capture_output=True, timeout=20)
                    if language == "rust":
                        result["rust_executed"] = True
                    (folder / f"{label}.stdout").write_bytes(completed.stdout)
                    (folder / f"{label}.stderr").write_bytes(completed.stderr)
                    run.update(returncode=completed.returncode,
                               stdout=completed.stdout.decode(errors="replace"),
                               stderr=completed.stderr.decode(errors="replace"))
                    save()
                    if case.get("must_trap"):
                        if completed.returncode != -signal.SIGABRT or completed.stdout != expected.encode():
                            raise RuntimeError(f"{name}: {label} failed mandatory operand failure boundary")
                        if language == "c" and completed.stderr:
                            raise RuntimeError(f"{name}: {label} unexpected sanitizer diagnostic")
                    else:
                        actual = (completed.returncode, completed.stdout, completed.stderr)
                        if actual != (0, expected.encode(), b""):
                            raise RuntimeError(f"{name}: {label} failed independently computed native observations")
                        # Exercise the same exact-output comparator with a
                        # deliberately false expectation, for every native run.
                        wrong = expected.encode() + b"999999\n"
                        run["wrong_output_negative_control_rejected"] = actual != (0, wrong, b"")
                        if not run["wrong_output_negative_control_rejected"]:
                            raise RuntimeError("Wrong-output negative control was accepted")
                    if language == "c" and optimize and not case.get("must_trap"):
                        wrong_source = text.replace("return 0;", 'puts("wrong-control"); return 0;')
                        if wrong_source == text:
                            raise RuntimeError("Missing binary main for native wrong-output control")
                        wrong_exe = folder / "wrong-output-control"
                        wrong_report = compile_c(wrong_source, cc=cc, output=wrong_exe, optimize=True, sanitize=True, link_args=links)
                        run["compiled_wrong_output_control"] = {"source_sha256": digest(wrong_source.encode()), "compilation": wrong_report}
                        if not wrong_report.get("ok"):
                            raise RuntimeError("Native wrong-output control did not compile")
                        wrong_run = subprocess.run([str(wrong_exe)], capture_output=True, timeout=20)
                        run["compiled_wrong_output_control"].update(returncode=wrong_run.returncode, stdout=wrong_run.stdout.decode(), stderr=wrong_run.stderr.decode())
                        if wrong_run.returncode != 0 or wrong_run.stderr or wrong_run.stdout == expected.encode():
                            raise RuntimeError("Native wrong-output control failed to be rejected")
        if any(digest((ROOT / name).read_bytes()) != value for name, value in hashes.items()):
            raise RuntimeError("Inputs changed during qualification; rerun against a stable tree")
        result["complete_pass"] = True
    except Exception as error:
        result["error"] = str(error)
    save()
    print(json.dumps(result, sort_keys=True))
    return 0 if result["complete_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
