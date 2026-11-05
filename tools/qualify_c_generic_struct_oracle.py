#!/usr/bin/env python3
"""Bounded concrete Copy-generic struct oracle with retained native evidence.

Expected observations are authored/computed in Python, not read from a backend.
The parser/checker are shared: this is not an independent semantic frontend.
Native C O0/O3 with nonrecovering UBSan is mandatory. Set the existing contract
HEPTA_ENUM_REQUIRE_RUST=1 to additionally require pinned native Rust O0/O3.
No installs, recursive programs, or generic functions are used. Every run keeps
its source, generated programs, native artifacts, and result.json under /tmp.
"""
from itertools import permutations
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

SEED = 11052026
RANDOM_CASES = 32
EFFECTS = "{write,panic,io,block,alloc}"


class Fixture:
    """Record actual expressions and independent expected native observations."""
    def __init__(self, declarations=""):
        self.lines = [declarations, f"fn main()->Unit effects {EFFECTS} {{"]
        self.expected = []

    def add(self, source):
        self.lines.append(source)

    def observe(self, expression, expected):
        if isinstance(expected, bool):
            self.add(f"assert({expression}=={str(expected).lower()});"
                     f"if {expression} {{print_i64(1);}} else {{print_i64(0);}}")
        else:
            self.add(f"assert({expression}=={expected});print_i64(({expression}) as i64);")
        self.expected.append(int(expected))

    def finish(self):
        return {"source": "\n".join([*self.lines, "}"]),
                "expected_stdout": "".join(f"{value}\n" for value in self.expected),
                "observations": len(self.expected)}


def fixtures():
    cases = {}
    f = Fixture("""
        struct Pair<A,B>{left:A,right:B}
        struct Cell<T>{value:T}
        fn make()->Pair<u16,bool> effects {} {return Pair{right:true,left:65003};}
        fn pick(x:Pair<i16,u32>)->i16 effects {} {return x.left;}
    """)
    f.add("""
        let a=Pair::<i16,u32>{right:900007,left:-19001};
        let b:Pair<u32,i16>=Pair{left:800011,right:-18013};
        let c=Pair::<bool,[u8;3]>{right:[251,241,239],left:false};
        let d=Pair::<[i16;2],bool>{left:[-17011,16007],right:true};
        let e=Cell::<Cell<Pair<u16,bool>>>{value:Cell{value:make()}};
        let wide=Pair::<i64,u64>{right:18446744073709551615,left:-5000000003};
        let float=Pair::<f32,f64>{right:3.5,left:-2.25};
        assert(wide.right==18446744073709551615);assert(float.left==-2.25);assert(float.right==3.5);
    """)
    for expression, value in [("pick(a)", -19001), ("a.right", 900007),
                              ("b.left", 800011), ("b.right", -18013),
                              ("c.left", False), ("c.right[0]", 251),
                              ("c.right[1]", 241), ("c.right[2]", 239),
                              ("d.left[0]", -17011), ("d.left[1]", 16007),
                              ("d.right", True), ("e.value.value.left", 65003),
                              ("e.value.value.right", True), ("wide.left", -5000000003)]:
        f.observe(expression, value)
    cases["specialization_permutations"] = f.finish()

    f = Fixture("""
        struct Cell<T>{value:T}
        enum Option<T>{Absent,Present(T)}
        struct Packet<T>{history:[Cell<T>;2],current:Option<Cell<T>>}
        enum Event<T>{Idle,Data(Packet<T>)}
    """)
    f.add("""
        let mut packet=Packet::<i32>{current:Option::Present(Cell{value:-22003}),
            history:[Cell{value:23003},Cell{value:-24001}]};
        let event=Event::<i32>::Data(packet);let saved=packet;
        packet.history[0].value=25013;packet.current=Option::Absent;
    """)
    f.observe("saved.history[0].value", 23003)
    f.observe("saved.history[1].value", -24001)
    f.observe("packet.history[0].value", 25013)
    f.add("match event {Event::Idle=>{assert(false);},Event::Data(p)=>{")
    f.observe("p.history[0].value", 23003)
    f.add("match p.current {Option::Absent=>{assert(false);},Option::Present(cell)=>{")
    f.observe("cell.value", -22003)
    f.add("}}}}")
    f.add("""
        let bools=Cell::<[Option<Cell<bool>>;2]>{value:[Option::Present(Cell{value:true}),Option::Absent]};
        match bools.value[0] {Option::Absent=>{assert(false);},Option::Present(cell)=>{
    """)
    f.observe("cell.value", True)
    f.add("}} match bools.value[1] {Option::Present(_)=>{assert(false);},Option::Absent=>{}}")
    f.add("""
        let matrix=Packet::<[i16;2]>{history:[Cell{value:[-301,307]},Cell{value:[311,-313]}],
            current:Option::Present(Cell{value:[317,-331]})};
    """)
    f.observe("matrix.history[0].value[0]", -301)
    f.observe("matrix.history[1].value[1]", -313)
    f.add("match matrix.current {Option::Absent=>{assert(false);},Option::Present(cell)=>{")
    f.observe("cell.value[0]", 317)
    f.observe("cell.value[1]", -331)
    f.add("}}")
    cases["nested_struct_enum_arrays"] = f.finish()

    f = Fixture("""
        struct Cell<T>{value:T,stamp:u16}
        struct Row<T>{cells:[Cell<T>;4]}
        fn bump(cell:mut Cell<i32>)->Unit effects {write,panic} {
            cell.value=cell.value+9;cell.stamp=cell.stamp+1;
        }
        fn update(cells:mut [Cell<i32>])->Unit effects {write,panic} {
            for i in 0..len(cells) {bump(mut cells[i]);}
        }
        fn readsum(cells:read [Cell<i32>])->i32 effects {write,panic} {
            let mut total:i32=0;for i in 0..len(cells) {total=total+cells[i].value;}return total;
        }
        fn copy(cell:read Cell<i32>)->Cell<i32> effects {} {return cell;}
    """)
    initial = [-401, 409, -419, 421]
    stamps = [5, 13, 29, 37]
    cells = ",".join(f"Cell{{value:{value},stamp:{stamp}}}" for value, stamp in zip(initial, stamps))
    f.add(f"let mut row=Row::<i32>{{cells:[{cells}]}};let before=row;let one=copy(read row.cells[2]);")
    f.observe("readsum(read row.cells)", sum(initial))
    f.add("update(mut row.cells);")
    for i, (value, stamp) in enumerate(zip(initial, stamps)):
        f.observe(f"row.cells[{i}].value", value + 9)
        f.observe(f"row.cells[{i}].stamp", stamp + 1)
        f.observe(f"before.cells[{i}].value", value)
        f.observe(f"before.cells[{i}].stamp", stamp)
    f.observe("readsum(read row.cells)", sum(initial) + 4 * 9)
    f.observe("readsum(read before.cells)", sum(initial))
    f.observe("one.value", initial[2])
    f.observe("one.stamp", stamps[2])
    cases["read_mut_slices_and_snapshots"] = f.finish()

    f = Fixture("""
        struct Triple<T>{first:T,second:T,third:T}
        struct Cell<T>{value:T}
        struct Snapshot<A,B>{saved:A,marker:B}
        fn next(n:mut i32)->i32 effects {write,panic} {n=n+1;return n;}
        fn reset(cell:mut Cell<[i32;2]>)->i32 effects {write} {cell.value=[503,509];return 521;}
    """)
    count = 1009
    f.add(f"let mut n:i32={count};")
    # All source-field orders, each with a plain value before later mutations.
    for index, order in enumerate(permutations(("first", "second", "third"))):
        values = {order[0]: count, order[1]: count + 1, order[2]: count + 2}
        f.add(f"let t{index}=Triple::<i32>{{{order[0]}:n,{order[1]}:next(mut n),{order[2]}:next(mut n)}};")
        count += 2
        for field in ("first", "second", "third"):
            f.observe(f"t{index}.{field}", values[field])
        f.observe("n", count)
    f.add("""
        let mut cell=Cell::<[i32;2]>{value:[487,491]};
        let before=Snapshot::<Cell<[i32;2]>,i32>{saved:cell,marker:reset(mut cell)};
    """)
    for expression, value in [("before.saved.value[0]", 487), ("before.saved.value[1]", 491),
                              ("before.marker", 521), ("cell.value[0]", 503), ("cell.value[1]", 509)]:
        f.observe(expression, value)
    f.add("""
        cell.value=[523,541];
        let after=Snapshot::<Cell<[i32;2]>,i32>{marker:reset(mut cell),saved:cell};
        cell.value=[557,563];
        let array=Snapshot::<[i32;2],i32>{saved:cell.value,marker:reset(mut cell)};
        cell.value[0]=547;
    """)
    for expression, value in [("after.saved.value[0]", 503), ("after.saved.value[1]", 509),
                              ("after.marker", 521), ("array.saved[0]", 557),
                              ("array.saved[1]", 563), ("cell.value[0]", 547)]:
        f.observe(expression, value)
    cases["constructor_source_order"] = f.finish()

    rng = random.Random(SEED)
    for typ, lower, upper in [("i8", -100, 100), ("u32", 0, 1000000), ("i64", -10**12, 10**12)]:
        f = Fixture("""
            struct Cell<T>{value:T}
            struct Pair<A,B>{first:A,second:B}
            struct Row<T>{cells:[Cell<T>;3],marked:bool}
        """)
        for i in range(RANDOM_CASES):
            values = [rng.randint(lower, upper) for _ in range(3)]
            replacement = rng.randint(lower, upper)
            mark = bool(rng.randrange(2))
            target = rng.randrange(3)
            cells = ",".join(f"Cell{{value:{value}}}" for value in values)
            f.add(f"let mut row{i}=Row::<{typ}>{{marked:{str(mark).lower()},cells:[{cells}]}};"
                  f"let saved{i}=row{i};let pair{i}=Pair::<Row<{typ}>,Cell<bool>>{{second:Cell{{value:{str(not mark).lower()}}},first:row{i}}};"
                  f"row{i}.cells[{target}].value={replacement};row{i}.marked={str(not mark).lower()};")
            for j, value in enumerate(values):
                f.observe(f"saved{i}.cells[{j}].value", value)
                f.observe(f"pair{i}.first.cells[{j}].value", value)
                f.observe(f"row{i}.cells[{j}].value", replacement if j == target else value)
            f.observe(f"saved{i}.marked", mark)
            f.observe(f"row{i}.marked", not mark)
            f.observe(f"pair{i}.second.value", not mark)
        cases[f"seeded_snapshots_{typ}"] = f.finish()
    return cases


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    require_rust = os.environ.get("HEPTA_ENUM_REQUIRE_RUST") == "1"
    directory = Path(tempfile.mkdtemp(prefix="hepta-generic-struct-oracle-", dir="/tmp"))
    inputs = sorted((ROOT / "hepta").glob("*.py")) + [Path(__file__).resolve(), ROOT / "toolchain-lock.json"]
    hashes = {str(p.relative_to(ROOT)): digest(p.read_bytes()) for p in inputs}
    result = {"schema": 1, "seed": SEED, "random_cases_per_type": RANDOM_CASES,
              "scope": "bounded concrete Copy-generic structs; shared Python parser/checker",
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
