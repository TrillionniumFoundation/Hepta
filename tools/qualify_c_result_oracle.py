#!/usr/bin/env python3
"""Independent bounded Result observations, with native C/Rust evidence.

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
import random
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from hepta.parser import parse
from hepta.checker import check
from hepta.c_backend import emit_c, compile_c
from hepta.backend import emit_rust, compile_rust

SEED = 7031105
RANDOM_CASES = 24
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
    rng = random.Random(SEED)
    for typ, low, high in [("i8", -110, 110), ("u32", 0, 1000000), ("i64", -10**12, 10**12)]:
        f = Fixture(f"""
            fn choose(x:{typ}, fail:bool)->Result<{typ},i16> effects {{panic}} {{
                if fail {{return Result::Err(-719);}}return Result::Ok(x);
            }}
        """)
        for i in range(RANDOM_CASES):
            value = rng.randint(low, high)
            fail = bool(rng.randrange(2))
            f.add(f"let mut r{i}=choose({value},{str(fail).lower()});let saved{i}=r{i};"
                  f"r{i}=Result::Err(-733);")
            f.result(f"saved{i}", not fail, -719 if fail else value)
            f.result(f"r{i}", False, -733)
        cases[f"seeded_branches_{typ}"] = f.finish()

    f = Fixture()
    f.add("""
        let a:Result<bool,f64>=Result::Ok(true);
        let b:Result<bool,f64>=Result::Err(-3.125);
        let c:Result<u64,f32>=Result::Ok(18446744073709551615);
        let d:Result<u64,f32>=Result::Err(6.25);
        match a {Result::Err(_)=>{assert(false);},Result::Ok(v)=>{if v {print_i64(1);}else{assert(false);}}}
        match b {Result::Ok(_)=>{assert(false);},Result::Err(v)=>{if v == -3.125 {print_i64(2);}else{assert(false);}}}
        match c {Result::Err(_)=>{assert(false);},Result::Ok(v)=>{if v == 18446744073709551615 {print_i64(3);}else{assert(false);}}}
        match d {Result::Ok(_)=>{assert(false);},Result::Err(v)=>{if v == 6.25 {print_i64(4);}else{assert(false);}}}
    """)
    f.expected.extend([1, 2, 3, 4])
    cases["scalar_payload_permutations"] = f.finish()

    f = Fixture("""
        struct Box<T>{value:T}
        enum Event<T>{Quiet,Payload(T)}
        struct Pair<A,B>{left:A,right:B}
    """)
    for i, (outer, inner) in enumerate([(True, True), (True, False), (False, True)]):
        expression = ("Result::Ok(Result::Ok(Box{value:[-809,811]}))" if inner else "Result::Ok(Result::Err(821))") if outer else "Result::Err(false)"
        f.add(f"let n{i}:Result<Result<Box<[i16;2]>,u32>,bool>={expression};")
        if outer:
            f.add(f"match n{i} {{Result::Err(_)=>{{assert(false);}},Result::Ok(r)=>{{")
            if inner:
                f.add("match r {Result::Err(_)=>{assert(false);},Result::Ok(b)=>{")
                f.observe("b.value[0]", -809)
                f.observe("b.value[1]", 811)
                f.add("}}")
            else:
                f.result("r", False, 821)
            f.add("}}")
        else:
            f.add(f"match n{i} {{Result::Ok(_)=>{{assert(false);}},Result::Err(b)=>{{if b {{assert(false);}}else{{print_i64(0);}}}}}}")
            f.expected.append(0)
    f.add("""
        let mut p=Pair::<Result<i32,u8>,Result<Event<Box<i32>>,i16>>{
            right:Result::Ok(Event::Payload(Box{value:-829})),left:Result::Err(211)};
        let saved=Result::<Pair<Result<i32,u8>,Result<Event<Box<i32>>,i16>>,u8>::Ok(p);
        p.left=Result::Ok(839);p.right=Result::Err(-853);
        match saved {Result::Err(_)=>{assert(false);},Result::Ok(q)=>{
    """)
    f.result("q.left", False, 211)
    f.add("match q.right {Result::Err(_)=>{assert(false);},Result::Ok(e)=>{match e {Event::Quiet=>{assert(false);},Event::Payload(b)=>{")
    f.observe("b.value", -829)
    f.add("}}}}}}")
    f.result("p.left", True, 839)
    f.result("p.right", False, -853)
    cases["nested_result_struct_enum"] = f.finish()

    f = Fixture("""
        fn copy(x:read Result<[i32;2],i16>)->Result<[i32;2],i16> effects {} {return x;}
        fn update(xs:mut [Result<[i32;2],i16>])->Unit effects {write,panic} {
            for i in 0..len(xs) {xs[i]=Result::Err(-877);}
        }
        fn show(xs:read [Result<[i32;2],i16>])->Unit effects {write,panic,io,block,alloc} {
            for i in 0..len(xs) {match xs[i] {
                Result::Ok(v)=>{print_i64(v[0] as i64);print_i64(v[1] as i64);},
                Result::Err(e)=>{print_i64(e as i64);}
            }}
        }
    """)
    f.add("""
        let mut xs:[Result<[i32;2],i16>;3]=[Result::Ok([881,-883]),Result::Err(-887),Result::Ok([-907,911])];
        let saved=xs;let one=copy(read xs[2]);update(mut xs);show(read saved);show(read xs);
        match one {Result::Err(_)=>{assert(false);},Result::Ok(v)=>{
    """)
    f.expected.extend([881, -883, -887, -907, 911, -877, -877, -877])
    f.observe("v[0]", -907)
    f.observe("v[1]", 911)
    f.add("}}")
    cases["read_mut_slice_copy"] = f.finish()

    f = Fixture("""
        struct Pair<A,B>{saved:A,stamp:B}
        fn reset(r:mut Result<[i32;2],i16>)->i32 effects {write,panic} {r=Result::Err(-929);return 937;}
        fn next(n:mut i32)->i32 effects {write,panic} {n=n+1;return n;}
    """)
    f.add("""
        let mut r:Result<[i32;2],i16>=Result::Ok([941,-947]);
        let p=Pair::<Result<[i32;2],i16>,i32>{saved:r,stamp:reset(mut r)};
        match p.saved {Result::Err(_)=>{assert(false);},Result::Ok(v)=>{
    """)
    f.observe("v[0]", 941)
    f.observe("v[1]", -947)
    f.add("}}")
    f.result("r", False, -929)
    f.observe("p.stamp", 937)
    f.add("""
        r=Result::Ok([953,-967]);
        let q=Pair::<Result<[i32;2],i16>,i32>{stamp:reset(mut r),saved:r};
        let mut n:i32=971;
        let a:Result<[i32;3],u8>=Result::Ok([n,next(mut n),next(mut n)]);
        let b:Result<u8,[i32;3]>=Result::Err([n,next(mut n),next(mut n)]);
    """)
    f.result("q.saved", False, -929)
    for name, variant, start in [("a", "Ok", 971), ("b", "Err", 973)]:
        other = "Err" if variant == "Ok" else "Ok"
        f.add(f"match {name} {{Result::{other}(_)=>{{assert(false);}},Result::{variant}(v)=>{{")
        for i in range(3):
            f.observe(f"v[{i}]", start + i)
        f.add("}}")
    f.observe("n", 975)
    cases["constructor_order_and_array_snapshots"] = f.finish()
    return cases


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    require_rust = os.environ.get("HEPTA_ENUM_REQUIRE_RUST") == "1"
    directory = Path(tempfile.mkdtemp(prefix="hepta-result-oracle-", dir="/tmp"))
    inputs = sorted((ROOT / "hepta").glob("*.py")) + [Path(__file__).resolve(), ROOT / "toolchain-lock.json"]
    hashes = {str(p.relative_to(ROOT)): digest(p.read_bytes()) for p in inputs}
    result = {"schema": 1, "seed": SEED, "random_cases_per_type": RANDOM_CASES,
              "scope": "bounded concrete Copy Result payloads; shared Python parser/checker",
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
                       "observations": case["observations"], "expected_stdout_sha256": digest(expected.encode()), "runs": []}
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
                    if (completed.returncode, completed.stdout, completed.stderr) != (0, expected.encode(), b""):
                        raise RuntimeError(f"{name}: {label} failed independently computed native observations")
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
