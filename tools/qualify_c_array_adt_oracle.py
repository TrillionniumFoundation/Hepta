#!/usr/bin/env python3
"""Independent Python observations for temporary arrays and concrete Copy ADTs.

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
SEED = 583706
RANDOM_CASES = 64


def fixtures():
    cases = {}
    f=harness.Fixture('''
        struct Cell<T>{value:T,done:Unit} enum Event<T>{Value(T),Empty(Unit)}
        fn unit()->Unit effects {} {}
        fn values(n:i64)->[Result<Event<Cell<f64>>,Unit>;2] effects {} {
            return [Result::Ok(Event::Value(Cell{value:n as f64,done:unit()})),Result::Err(unit())];
        }
    ''')
    rng=random.Random(SEED)
    for index in range(64):
        value=rng.randint(-100000,100000)
        f.add(f'match values({value})[0] {{Result::Ok(e)=>{{match e {{Event::Value(c)=>{{let u=c.done;')
        f.observe('c.value as i32',value)
        f.add('},Event::Empty(_)=>{assert(false);}}},Result::Err(_)=>{assert(false);}}')
        f.add(f'match values({value})[1] {{Result::Err(u)=>{{let v=u;')
        f.observe(f'len(values({value}))',2)
        f.add('},Result::Ok(_)=>{assert(false);}}')
    cases['seeded_result_enum_unit_values']=f.finish()

    f=harness.Fixture('''
        struct Grid<T>{rows:[[T;2];2],done:Unit}
        fn unit()->Unit effects {} {}
        fn grid(x:i64)->Grid<f32> effects {panic} {return Grid{rows:[[x as f32,(-x) as f32],[3.75 as f32,-8.75 as f32]],done:unit()};}
    ''')
    for value in [-65536,-32769,-255,-1,0,1,255,32769,65536]:
        f.observe(f'grid({value}).rows[0][0] as i64',value)
        f.observe(f'grid({value}).rows[0][1] as i64',-value)
        f.observe(f'grid({value}).rows[1][0] as i8',3)
        f.observe(f'grid({value}).rows[1][1] as u8',0)
        f.observe(f'len(grid({value}).rows[0])',2)
    cases['nested_records_numeric_read_and_length']=f.finish()

    f=harness.Fixture('''
        struct Cell<T>{value:T,done:Unit}
        fn tick(n:mut i64)->Unit effects {write,panic} {n=n+1;}
        fn values(n:mut i64)->[Cell<i64>;2] effects {write,panic} {
            return [Cell{done:tick(mut n),value:n},Cell{done:tick(mut n),value:n}];
        }
        fn units(n:mut i64)->[Unit;2] effects {write,panic} {return [tick(mut n),tick(mut n)];}
        fn position(n:read i64)->usize effects {panic} {return (n % 2) as usize;}
    ''')
    f.add('let mut n:i64=0;')
    expected=0
    for _ in range(32):
        f.observe('values(mut n)[position(read n)].value',expected+1)
        expected+=2
        f.observe('n',expected)
        f.observe('len(units(mut n))',2)
        expected+=2
        f.add(f'let u{expected}=units(mut n)[1];')
        expected+=2
        f.observe('n',expected)
        f.add('assert(true || len(units(mut n))==0);assert(!(false && len(values(mut n))==0));')
        f.observe('n',expected)
    cases['effect_order_unit_rvalues_and_short_circuit']=f.finish()

    for name,index in [('length','2'),('huge','18446744073709551615')]:
        f=harness.Fixture('''fn unit()->Unit effects {} {} fn values()->[Unit;2] effects {} {return [unit(),unit()];}'''+f'fn index()->usize effects {{}} {{return {index};}}')
        f.add('let u=values()[index()];print_i64(999);')
        case=f.finish();case['must_trap']=True;cases['unit_bounds_'+name]=case
    return cases


def main():
    require_rust = os.environ.get("HEPTA_ENUM_REQUIRE_RUST") == "1"
    directory = Path(tempfile.mkdtemp(prefix="hepta-array-adt-oracle-", dir="/tmp"))
    inputs = sorted((ROOT / "hepta").glob("*.py")) + [Path(__file__).resolve(), ROOT / "toolchain-lock.json", ROOT / "tools/qualify_c_unit_oracle.py"]
    hashes = {str(p.relative_to(ROOT)): digest(p.read_bytes()) for p in inputs}
    result = {"schema": 1, "seed": SEED, "random_cases_per_type": RANDOM_CASES,
              "scope": "bounded temporary Copy arrays with Unit, generic ADTs and numeric casts; shared Python parser/checker",
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
                    if language == "c" and optimize and not case.get("must_trap"):
                        wrong_source = text.replace("return 0;", 'puts("wrong-control"); return 0;')
                        if wrong_source == text:
                            raise RuntimeError("Missing binary main for native wrong-output control")
                        wrong_exe = folder / "wrong-output-control"
                        wrong_report = compile_c(wrong_source, cc=cc, output=wrong_exe, optimize=True, sanitize=True)
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
