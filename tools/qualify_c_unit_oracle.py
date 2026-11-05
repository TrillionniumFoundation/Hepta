#!/usr/bin/env python3
"""Independent bounded Unit observations, with native C/Rust evidence.

Python determines every expected observation; only parsing/checking and native
compilation plumbing are shared. C O0/O3 with nonrecovering UBSan is mandatory.
HEPTA_ENUM_REQUIRE_RUST=1 additionally requires actual pinned Rust O0/O3.
No recursion, generic functions, resource payloads, or runtime installation.
"""
from pathlib import Path
import hashlib
import json
import os
import platform
import shutil
import signal
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from hepta.parser import parse
from hepta.checker import check
from hepta.c_backend import emit_c, compile_c
from hepta.backend import emit_rust, compile_rust

SEED = 7051105
RANDOM_CASES = 0
EFFECTS = "{write,panic,io,block,alloc}"


class Fixture:
    def __init__(self, declarations=""):
        self.lines = [declarations, f"fn main()->Unit effects {EFFECTS} {{"]
        self.expected = []

    def add(self, source):
        self.lines.append(source)

    def observe(self, expression, expected):
        self.add(f"print_i64(({expression}) as i64);")
        self.expected.append(int(expected))

    def result(self, expression, ok, value, payload="v"):
        good, bad = ("Ok", "Err") if ok else ("Err", "Ok")
        self.add(f"match {expression} {{Result::{bad}(_)=>{{assert(false);}},Result::{good}({payload})=>{{")
        self.observe(payload, value)
        self.add("}}")

    def finish(self):
        return {"source": "\n".join([*self.lines, "}"]),
                "expected_stdout": "".join(f"{n}\n" for n in self.expected),
                "observations": len(self.expected)}


def fixtures():
    cases = {}
    declarations = """
        fn unit()->Unit effects {} {}
        fn mark(n:mut i64, digit:i64)->Unit effects {write,panic} {n=n*10+digit;}
        fn forward(n:mut i64)->Unit effects {write,panic} {return mark(mut n,7);}
    """
    f = Fixture(declarations)
    f.add("let mut n:i64=0;let mut a:Unit=mark(mut n,1);let b=a;a=mark(mut n,2);let c=forward(mut n);a=b;let d=c;")
    f.observe("n", 127)
    f.add("let e=assert(true);let g=unit();let h=print_i64(131);")
    f.expected.append(131)
    cases["locals_assignments_unit_return"] = f.finish()

    f = Fixture(declarations + """
        fn fill(xs:mut [Unit])->Unit effects {write,panic} {for i in 0..len(xs) {xs[i]=unit();}}
        fn size(xs:read [Unit])->usize effects {} {return len(xs);}
    """)
    f.add("let mut n:i64=0;let mut a:[Unit;3]=[mark(mut n,1),mark(mut n,2),mark(mut n,3)];let saved=a;")
    f.observe("n",123)
    f.add("a[1]=mark(mut n,4);let v=a[2];let mut nested:[[Unit;3];2]=[saved,a];nested[1][0]=unit();fill(mut a);")
    f.observe("n",1234)
    f.observe("size(read a)",3)
    f.observe("len(nested)",2)
    f.add("let b=nested[0];")
    f.observe("size(read b)",3)
    cases["arrays_slices_nested_copy"] = f.finish()

    f = Fixture(declarations + """
        struct Plain{token:Unit,value:i64}
        struct Pair<T>{left:T,right:T,stamp:i64}
        fn copy(x:read Plain)->Plain effects {} {return x;}
        fn change(x:mut Plain)->Unit effects {write} {x.token=unit();x.value=181;}
    """)
    f.add("let mut n:i64=0;let mut p=Plain{token:mark(mut n,1),value:173};let saved=copy(read p);change(mut p);")
    f.observe("saved.value",173)
    f.observe("p.value",181)
    f.add("let q=Pair::<Unit>{right:mark(mut n,2),stamp:191,left:mark(mut n,3)};let z=q.left;")
    f.observe("n",123)
    f.observe("q.stamp",191)
    cases["records_generic_and_source_order"] = f.finish()

    f = Fixture(declarations + """
        enum Event{Quiet,One(Unit),Pair(Unit,i64)}
        enum Generic<T>{Empty,Value(T)}
        struct Box<T>{value:T}
    """)
    f.add("let mut n:i64=0;let mut e=Event::Pair(mark(mut n,1),211);let saved=e;e=Event::One(mark(mut n,2));")
    f.add("match saved {Event::Quiet=>{assert(false);},Event::One(_)=>{assert(false);},Event::Pair(u,v)=>{let copy=u;")
    f.observe("v",211)
    f.add("}}match e {Event::Quiet=>{assert(false);},Event::Pair(_,_)=>{assert(false);},Event::One(u)=>{let copy=u;print_i64(223);}}")
    f.expected.append(223)
    f.add("let g=Generic::<Box<[Unit;2]>>::Value(Box{value:[mark(mut n,3),mark(mut n,4)]});")
    f.add("match g {Generic::Empty=>{assert(false);},Generic::Value(b)=>{let u=b.value[1];print_i64(227);}}")
    f.expected.append(227)
    f.observe("n",1234)
    cases["enum_unit_and_nested_payloads"] = f.finish()

    f = Fixture(declarations)
    f.add("let mut n:i64=0;let mut a:Result<Unit,i64>=Result::Ok(mark(mut n,1));let saved=a;a=Result::Err(233);")
    f.add("match saved {Result::Err(_)=>{assert(false);},Result::Ok(u)=>{let v=u;print_i64(239);}}")
    f.expected.append(239)
    f.result("a",False,233)
    f.add("let b:Result<i64,Unit>=Result::Err(mark(mut n,2));match b {Result::Ok(_)=>{assert(false);},Result::Err(u)=>{let v=u;print_i64(241);}}")
    f.expected.append(241)
    f.add("let c:Result<Unit,Unit>=Result::Ok(mark(mut n,3));let d:Result<Result<Unit,Unit>,Unit>=Result::Ok(c);")
    f.add("match d {Result::Err(_)=>{assert(false);},Result::Ok(r)=>{match r {Result::Err(_)=>{assert(false);},Result::Ok(u)=>{let v=u;print_i64(251);}}}}")
    f.expected.append(251)
    f.observe("n",123)
    cases["result_unit_both_variants_nested"] = f.finish()

    # Each operation must trap before the unreachable observation. Keep stdout
    # empty: abort does not promise flushing a hosted stdio buffer.
    for name, action in [
        ("array_read", "let v=a[invalid()];"),
        ("array_write", "a[invalid()]=unit();"),
        ("slice_read", "read_bad(read a);"),
        ("slice_write", "write_bad(mut a);")
    ]:
        f = Fixture(declarations + """
            fn invalid()->usize effects {} {return 2;}
            fn read_bad(xs:read [Unit])->Unit effects {panic} {let v=xs[2];}
            fn write_bad(xs:mut [Unit])->Unit effects {write,panic} {xs[2]=unit();}
        """)
        f.add("let mut a:[Unit;2]=[unit(),unit()];" + action + "print_i64(999);")
        case = f.finish()
        case["must_trap"] = True
        cases["bounds_" + name] = case
    return cases


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    require_rust = os.environ.get("HEPTA_ENUM_REQUIRE_RUST") == "1"
    directory = Path(tempfile.mkdtemp(prefix="hepta-unit-oracle-", dir="/tmp"))
    inputs = sorted((ROOT / "hepta").glob("*.py")) + [Path(__file__).resolve(), ROOT / "toolchain-lock.json"]
    hashes = {str(p.relative_to(ROOT)): digest(p.read_bytes()) for p in inputs}
    result = {"schema": 1, "seed": SEED, "random_cases_per_type": RANDOM_CASES,
              "scope": "bounded Unit locals, arrays, nominal payloads, side effects and bounds; shared Python parser/checker",
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
                        report = compile_c(text, cc=cc, output=output, optimize=optimize, sanitize=True)
                    else:
                        report = compile_rust(text, rustc=compiler, crate_type="bin", output=output, optimize=optimize)
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
                        if completed.returncode != -signal.SIGABRT or completed.stdout != b"":
                            raise RuntimeError(f"{name}: {label} failed mandatory bounds trap")
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
