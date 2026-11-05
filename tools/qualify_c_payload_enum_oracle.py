#!/usr/bin/env python3
"""Independent deterministic payload-enum oracle, requiring native C O0/O3 + UBSan.

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

SEED = 472901
RANDOM_CASES = 120


def fixtures():
    cases={}
    cases['order_snapshot_nested']='''
    enum Leaf { Empty, One(i64), Pair(i64,i64) }
    struct Record { a: [Leaf;2], n:i64 }
    enum Boxed { None, Record(Record,[i64;2],Leaf) }
    fn step(n:mut i64)->i64 effects {write,panic} {n=n+1;return n;}
    fn replace(n:mut Leaf)->i64 effects {write} {n=Leaf::Empty;return 42;}
    fn main()->Unit effects {write,panic} {
    let mut n:i64=0;
    let p=Leaf::Pair(step(mut n),step(mut n));
    match p {Leaf::Pair(a,b)=>{assert(a==1);assert(b==2);},Leaf::One(_)=>{assert(false);},Leaf::Empty=>{assert(false);}}
    let mut source=Leaf::One(77);
    let ordered=Leaf::Pair(5,replace(mut source));
    match ordered {Leaf::Pair(_,b)=>{assert(b==42);},Leaf::One(_)=>{assert(false);},Leaf::Empty=>{assert(false);}}
    source=Leaf::One(91);
    match source {Leaf::One(x)=>{source=Leaf::Pair(3,4);assert(x==91);},Leaf::Empty=>{assert(false);},Leaf::Pair(_,_)=>{assert(false);}}
    let mut record=Record {a:[p,source],n:8};
    let boxed=Boxed::Record(record,[12,13],source);
    record.n=99;record.a[0]=Leaf::Empty;
    match boxed {Boxed::None=>{assert(false);},Boxed::Record(r,arr,leaf)=>{
    assert(r.n==8);assert(arr[0]==12);assert(arr[1]==13);
    match r.a[0] {Leaf::Pair(x,y)=>{assert(x==1);assert(y==2);},Leaf::Empty=>{assert(false);},Leaf::One(_)=>{assert(false);}}
    match leaf {Leaf::Pair(x,y)=>{assert(x==3);assert(y==4);},Leaf::Empty=>{assert(false);},Leaf::One(_)=>{assert(false);}}
    }}
    }
    '''
    cases['argument_snapshot_borrowed']='''
    enum E { A(i64), B(i64,i64), Empty }
    enum W { Values(E,i64), Empty }
    fn reset(e:mut E)->i64 effects {write} {e=E::Empty;return 7;}
    fn inspect(e:read E)->i64 effects {panic} {match e {E::A(x)=>{return x;},E::B(a,b)=>{return a+b;},E::Empty=>{return 0;}}}
    fn make()->E effects {} {return E::B(12,13);}
    fn main()->Unit effects {write,panic} {
    let mut e=E::A(99);let w=W::Values(e,reset(mut e));assert(inspect(read e)==0);
    match w {W::Values(first,_)=>{assert(inspect(read first)==99);},W::Empty=>{assert(false);}}
    e=make();match e {E::B(a,b)=>{reset(mut e);assert(a==12);assert(b==13);},E::A(_)=>{assert(false);},E::Empty=>{assert(false);}}
    assert(inspect(read e)==0);
    }
    '''
    rng=random.Random(SEED)
    lines=['enum E { Empty, Small(i64), Wide([i64;3],i64) }','fn main()->Unit effects {write,panic} {','let mut e=E::Empty;']
    for i in range(RANDOM_CASES):
        tag=rng.randrange(3); vals=[rng.randrange(-10000,10001) for _ in range(4)]
        expr=['E::Empty',f'E::Small({vals[0]})',f'E::Wide([{vals[0]},{vals[1]},{vals[2]}],{vals[3]})'][tag]
        lines+=['e='+expr+';',f'let copy{i}=e;','e=E::Empty;',f'match copy{i} {{E::Empty=>{{assert({str(tag==0).lower()});}},E::Small(x)=>{{assert({str(tag==1).lower()});assert(x=={vals[0]});}},E::Wide(a,b)=>{{assert({str(tag==2).lower()});assert(a[0]=={vals[0]});assert(a[1]=={vals[1]});assert(a[2]=={vals[2]});assert(b=={vals[3]});}}}}']
    lines+=['}'];cases['seeded_120']= '\n'.join(lines)
    return cases


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    require_rust = os.environ.get("HEPTA_ENUM_REQUIRE_RUST") == "1"
    inputs = sorted((ROOT / "hepta").glob("*.py")) + [Path(__file__).resolve()]
    hashes = {str(p.relative_to(ROOT)): digest(p.read_bytes()) for p in inputs}
    result = {"schema": 1, "seed": SEED, "random_cases": RANDOM_CASES,
              "python": sys.version, "host": platform.platform(),
              "rust_required": require_rust, "rust_executed": False,
              "input_sha256": hashes, "fixtures": [], "complete_pass": False}
    try:
        if not shutil.which("gcc"):
            raise RuntimeError("Native GCC is required")
        compiler = None
        if require_rust:
            compiler = os.environ.get("RUSTC") or shutil.which("rustc")
            if not compiler:
                raise RuntimeError("HEPTA_ENUM_REQUIRE_RUST=1 but native Rust is unavailable")
        with tempfile.TemporaryDirectory(prefix="hepta-payload-oracle-") as temp:
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
