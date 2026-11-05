#!/usr/bin/env python3
"""Independent deterministic generic-enum oracle, requiring native C O0/O3 + UBSan.

Run from any directory. HEPTA_ENUM_REQUIRE_RUST=1 additionally requires native
Rust O0/O3; without it, no Rust execution is claimed. Expected values are
constructed in Python, independently of either backend. No third-party packages.
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

SEED = 702419
RANDOM_CASES = 40


def fixtures():
    cases = {}
    cases["nested_permutations"] = r"""
    enum Slot<T> { Absent, Present(T) }
    enum Pair<A,B> { Absent, Present(A,B) }
    enum Wrap<T> { Value(Pair<Slot<T>,[T;2]>), Empty }
    fn main()->Unit effects {write,panic} {
        let a=Pair::<Slot<i32>,Slot<bool>>::Present(Slot::Present(-93),Slot::Present(true));
        let b=Pair::<Slot<bool>,Slot<i32>>::Present(Slot::Present(false),Slot::Present(101));
        match a {Pair::Present(x,y)=>{match x {Slot::Present(n)=>{assert(n==-93);},Slot::Absent=>{assert(false);}}match y {Slot::Present(n)=>{assert(n);},Slot::Absent=>{assert(false);}}},Pair::Absent=>{assert(false);}}
        match b {Pair::Present(x,y)=>{match x {Slot::Present(n)=>{assert(!n);},Slot::Absent=>{assert(false);}}match y {Slot::Present(n)=>{assert(n==101);},Slot::Absent=>{assert(false);}}},Pair::Absent=>{assert(false);}}
        let mut w=Wrap::<i16>::Value(Pair::Present(Slot::Present(109),[113,127]));let copy=w;w=Wrap::Empty;
        match copy {Wrap::Value(p)=>{match p {Pair::Present(s,arr)=>{assert(arr[0]==113);assert(arr[1]==127);match s {Slot::Present(n)=>{assert(n==109);},Slot::Absent=>{assert(false);}}},Pair::Absent=>{assert(false);}}},Wrap::Empty=>{assert(false);}}
        let nested=Slot::<Slot<Slot<u8>>>::Present(Slot::Present(Slot::Present(251)));
        match nested {Slot::Present(outer)=>{match outer {Slot::Present(inner)=>{match inner {Slot::Present(byte)=>{assert(byte==251);},Slot::Absent=>{assert(false);}}},Slot::Absent=>{assert(false);}}},Slot::Absent=>{assert(false);}}
    }
    """
    cases["snapshot_and_slice"] = r"""
    enum Slot<T> { Absent, Present(T) }
    enum Pair<A,B> { Empty, Values(A,B) }
    fn reset(x:mut Slot<[i32;2]>)->i32 effects {write} {x=Slot::Absent;return 137;}
    fn update(xs:mut [Slot<i32>])->Unit effects {write,panic} {for i in 0..len(xs) {match xs[i] {Slot::Absent=>{xs[i]=Slot::Present(7);},Slot::Present(v)=>{xs[i]=Slot::Present(v+3);}}}}
    fn readout(x:read Slot<i32>)->i32 effects {panic} {match x {Slot::Absent=>{return -1;},Slot::Present(v)=>{return v;}}}
    fn main()->Unit effects {write,panic} {
        let mut x=Slot::<[i32;2]>::Present([131,139]);let pair=Pair::<Slot<[i32;2]>,i32>::Values(x,reset(mut x));
        match pair {Pair::Values(first,n)=>{assert(n==137);match first {Slot::Present(arr)=>{assert(arr[0]==131);assert(arr[1]==139);},Slot::Absent=>{assert(false);}}},Pair::Empty=>{assert(false);}}
        let mut xs:[Slot<i32>;3]=[Slot::Absent,Slot::Present(149),Slot::Present(-151)];let before=xs;update(mut xs);
        assert(readout(read xs[0])==7);assert(readout(read xs[1])==152);assert(readout(read xs[2])==-148);assert(readout(read before[0])==-1);assert(readout(read before[1])==149);
    }
    """
    rng = random.Random(SEED)
    for typ, lower, upper in [("i16", -30000, 30000), ("u32", 0, 1000000), ("i64", -100000000, 100000000)]:
        lines = ["enum Choice<T> { Empty, Scalar(T), Vector([T;3],T) }", "fn main()->Unit effects {write,panic} {", f"let mut value=Choice::<{typ}>::Empty;"]
        for i in range(RANDOM_CASES):
            tag = rng.randrange(3)
            values = [rng.randint(lower, upper) for _ in range(4)]
            a,b,c,d = values
            expr = [f"Choice::<{typ}>::Empty", f"Choice::<{typ}>::Scalar({a})", f"Choice::<{typ}>::Vector([{a},{b},{c}],{d})"][tag]
            lines.extend([f"value={expr};let saved{i}=value;value=Choice::Empty;", f"match saved{i} {{Choice::Empty=>{{assert({str(tag==0).lower()});}},Choice::Scalar(n)=>{{assert({str(tag==1).lower()});assert(n=={a});}},Choice::Vector(arr,n)=>{{assert({str(tag==2).lower()});assert(arr[0]=={a});assert(arr[1]=={b});assert(arr[2]=={c});assert(n=={d});}}}}"])
        lines.append("}")
        cases[f"seeded_{typ}"] = "\n".join(lines)
    return cases


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    require_rust = os.environ.get("HEPTA_ENUM_REQUIRE_RUST") == "1"
    inputs = sorted((ROOT / "hepta").glob("*.py")) + [Path(__file__).resolve(), ROOT / "toolchain-lock.json"]
    hashes = {str(p.relative_to(ROOT)): digest(p.read_bytes()) for p in inputs}
    result = {"schema": 1, "seed": SEED, "random_cases": RANDOM_CASES,
              "python": sys.version, "host": platform.platform(),
              "rust_required": require_rust, "rust_executed": False,
              "input_sha256": hashes, "fixtures": [], "complete_pass": False}
    try:
        if not shutil.which("gcc"):
            raise RuntimeError("Native GCC is required")
        result["gcc_version"] = subprocess.run([shutil.which("gcc"), "--version"], capture_output=True, text=True, check=True, timeout=10).stdout
        result["gcc_sha256"] = digest(Path(shutil.which("gcc")).read_bytes())
        compiler = None
        if require_rust:
            compiler = os.environ.get("RUSTC") or shutil.which("rustc")
            if not compiler:
                raise RuntimeError("HEPTA_ENUM_REQUIRE_RUST=1 but native Rust is unavailable")
            version = subprocess.run([compiler, "--version"], capture_output=True, text=True, check=True, timeout=10).stdout.strip()
            result["rustc_version"] = version
            result["rustc_sha256"] = digest(Path(shutil.which(compiler) or compiler).read_bytes())
            locked = next(entry["package"].split("-")[1] for entry in json.loads((ROOT / "toolchain-lock.json").read_text()) if entry["package"].startswith("rustc-"))
            if version.split()[1] != locked:
                raise RuntimeError(f"Required Rust version {locked}, got {version}")
        with tempfile.TemporaryDirectory(prefix="hepta-generic-oracle-") as temp:
            for name, source in fixtures().items():
                fixture = {"name": name, "hepta_sha256": digest(source.encode()), "runs": []}
                result["fixtures"].append(fixture)
                program = parse(source)
                checked = check(program)
                if not checked.ok:
                    raise RuntimeError([d.to_dict() for d in checked.diagnostics])
                generated = {"c": emit_c(program, checked)}
                if require_rust:
                    generated["rust"] = emit_rust(program, checked, crate_type="bin")
                fixture["generated_sha256"] = {k: digest(v.encode()) for k, v in generated.items()}
                for language, text in generated.items():
                    for optimize in (False, True):
                        output = Path(temp) / f"{name}-{language}-{int(optimize)}"
                        if language == "c":
                            report = compile_c(text, output=output, optimize=optimize, sanitize=True)
                        else:
                            report = compile_rust(text, rustc=compiler, crate_type="bin",
                                                  output=output, optimize=optimize)
                        run = {"language": language, "optimization": "O3" if optimize else "O0",
                               "compilation": {k: v for k, v in report.items() if k != "artifact"}}
                        fixture["runs"].append(run)
                        if not report.get("ok"):
                            raise RuntimeError(f"{name}: {language} compilation failed")
                        if language == "c" and not {"-fsanitize=undefined", "-fno-sanitize-recover=all"}.issubset(report["flags"]):
                            raise RuntimeError("Required nonrecovering UBSan flags missing")
                        if language == "rust":
                            result["rust_executed"] = True
                        run["artifact_sha256"] = digest(output.read_bytes())
                        completed = subprocess.run([str(output)], capture_output=True, timeout=20)
                        run.update(returncode=completed.returncode,
                                   stdout=completed.stdout.decode(errors="replace"),
                                   stderr=completed.stderr.decode(errors="replace"))
                        if (completed.returncode, completed.stdout, completed.stderr) != (0, b"", b""):
                            raise RuntimeError(f"{name}: {language} failed independent expected assertions")
        if any(digest((ROOT / name).read_bytes()) != value for name, value in hashes.items()):
            raise RuntimeError("Inputs changed during qualification")
        result["complete_pass"] = True
    except Exception as error:
        result["error"] = str(error)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["complete_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
