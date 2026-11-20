"""Build the explicit HIA cold-transport R3 candidate from complete captured bytes.

No default observer selection or release promotion occurs. A successful build
is still BUILT_NOT_QUALIFIED; explicit development authorization is required by
the runtime selector even when the compiler came from a complete cold report.
"""
from __future__ import annotations
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import sysconfig

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from tools.hia_cold_native_transport_bridge import SOURCE_INPUTS, SELECTOR, DEVELOPMENT, SCHEMA
from tools.hia_cold_native_transport_evidence import (Captures, canonical, data_pin,
    regular_bytes, run_owned, successful_exit, write_json, parse)


def current_python_library():
    """Locate the declared shared library without loading or admitting it.

    A relocated interpreter can retain its old build-time LIBDIR, so preserve
    the library beside the resolved running executable as the first candidate.
    Distribution interpreters can instead use an explicit multiarch LIBDIR.
    The builder still captures and pins the selected file's complete bytes.
    """
    name = sysconfig.get_config_var("LDLIBRARY")
    if (type(name) is not str or not name or name in {".", ".."}
            or "/" in name or "\\" in name or "\0" in name):
        raise ValueError("current runtime did not declare one shared Python library")
    prefix_candidate = Path(sys.executable).resolve(strict=True).parent.parent / "lib" / name
    if prefix_candidate.is_file():
        return prefix_candidate.resolve(strict=True)
    libdir = sysconfig.get_config_var("LIBDIR")
    if (type(libdir) is not str or not libdir or "\0" in libdir
            or not Path(libdir).is_absolute()):
        raise ValueError("current runtime did not declare an absolute Python library directory")
    configured_candidate = Path(libdir) / name
    if configured_candidate.is_file():
        return configured_candidate.resolve(strict=True)
    raise ValueError("declared Python shared library is missing: "
                     + str(prefix_candidate) + "; " + str(configured_candidate))


def _compile_child(directory, compiler):
    if SELECTOR in os.environ or DEVELOPMENT in os.environ:
        raise ValueError("policy compiler child cannot select the policy it is building")
    from tools.qualify_hia_selfhost import compile_stage
    directory = Path(directory)
    directory.mkdir(mode=0o700)
    source = regular_bytes(ROOT / "examples/hia_bootstrap/cold_native_transport.hepta")
    image, receipt = compile_stage(directory, "cold-native-transport", Path(compiler), source)
    from tools.build_hia_source_build import _check_pack_output
    full = regular_bytes(directory / "cold-native-transport.output.bin")
    packed = _check_pack_output(receipt, full, artifact=regular_bytes(compiler), source=source)
    if packed != regular_bytes(image):
        raise ValueError("complete native compiler output differs from published policy")


def build(output, compiler, compiler_sha256, python_library, *, cc, cold_report=None, development=False):
    if development == (cold_report is not None):
        raise ValueError("choose exactly one real current cold report or explicit development")
    if sys.implementation.name != "cpython" or sys.version_info[:2] != (3, 14):
        raise ValueError("R3 hosted bridge requires the explicit CPython 3.14 runtime")
    capture = Captures()
    output, compiler = Path(output).resolve(), Path(compiler).resolve(strict=True)
    compiler_raw = capture.raw(compiler)
    if data_pin(compiler_raw)["sha256"] != compiler_sha256:
        raise ValueError("actual compiler differs from the explicitly supplied source binding")
    inputs = {name: capture.raw(ROOT / name) for name in sorted(SOURCE_INPUTS)}
    runtime = Path(sys.executable).resolve(strict=True)
    runtime_raw = capture.raw(runtime)
    subprocess_path = Path(subprocess.__file__).resolve(strict=True)
    subprocess_raw = capture.raw(subprocess_path)
    python_library = Path(python_library).resolve(strict=True)
    library_raw = capture.raw(python_library)
    include = Path(sysconfig.get_paths()["include"]).resolve(strict=True)
    headers = {str(path): data_pin(capture.raw(path))
               for path in sorted(include.rglob("*.h"))}
    if str(include / "Python.h") not in headers or not headers:
        raise ValueError("actual CPython include tree is incomplete")
    suffix = sysconfig.get_config_var("EXT_SUFFIX")
    if type(suffix) is not str or "/" in suffix or not suffix.endswith(".so"):
        raise ValueError("noncanonical runtime extension suffix")
    cc_path = Path(shutil.which(str(cc)) or str(cc)).resolve(strict=True)
    cc_raw = capture.raw(cc_path)
    cold_raw, sources = None, None
    if cold_report is not None:
        from tools.build_hia_json_preflight import admit_cold_build
        cold_raw = capture.raw(cold_report)
        sources = admit_cold_build(compiler_raw, cold_raw)
        if any(sources.get(name) != data_pin(raw)["sha256"] for name, raw in inputs.items()):
            raise ValueError("cold source manifest does not bind every transport input")
    output.mkdir(mode=0o700)
    write_json(output / "before.json", {"inputs": {name: data_pin(raw) for name, raw in inputs.items()},
               "consumed": capture.pins(), "compiler": data_pin(compiler_raw),
               "cold_source": sources, "qualification": False})
    environment = dict(os.environ)
    for key in (SELECTOR, DEVELOPMENT):
        environment.pop(key, None)
    python = [str(runtime), "-I", "-S", "-B"]
    compile_command = [*python, str(ROOT / "tools/build_hia_cold_native_transport.py"),
                       "--internal-compile", str(output / "policy"), str(compiler)]
    commands = []
    commands.append(run_owned(compile_command, cwd=ROOT, directory=output / "compile-owned",
                               timeout_seconds=600, environment=environment))
    if not successful_exit(commands[-1]):
        raise ValueError("policy build child did not complete; compile_stage retains its original internal 20-second invocation cap")
    policy_path = output / "policy/cold-native-transport.image.bin"
    policy_raw = capture.raw(policy_path)
    receipt = capture.json(output / "policy/cold-native-transport.receipt.json")
    full = capture.raw(output / "policy/cold-native-transport.output.bin")
    from tools.build_hia_source_build import _check_pack_output
    if _check_pack_output(receipt, full, artifact=compiler_raw,
                         source=inputs["examples/hia_bootstrap/cold_native_transport.hepta"]) != policy_raw:
        raise ValueError("parent complete compile receipt differs")
    core = str(ROOT / "tools/hia_cold_native_transport.c")
    pybridge = str(ROOT / "tools/hia_cold_native_transport_python.c")
    common = [str(cc_path), "-std=c11", "-O2", "-fno-strict-aliasing",
              "-Werror=implicit-function-declaration", "-I" + str(include),
              "-I" + str(ROOT / "tools"), "-pthread", "-Wl,-z,noexecstack",
              "-Wl,-z,relro", "-Wl,-z,now"]
    extension = output / ("_hia_cold_native_transport" + suffix)
    probe = output / "cold-native-transport-probe"
    controls = output / "cold-native-transport-handoff-controls"
    compile_sets = [
        ("extension", [*common, "-fPIC", "-shared", core, pybridge, "-o", str(extension)]),
        ("probe", [*common, core, str(ROOT / "tools/hia_cold_native_transport_driver.c"),
                   "-o", str(probe)]),
        ("handoff-controls", [*common, core, str(ROOT / "tools/hia_cold_native_transport_handoff_controls.c"),
                              str(python_library), "-Wl,-rpath," + str(python_library.parent),
                              "-ldl", "-lm", "-o", str(controls)]),
    ]
    for label, command in compile_sets:
        commands.append(run_owned(command, cwd=ROOT, directory=output / (label + "-owned"),
                                  timeout_seconds=20, environment=environment))
        if not successful_exit(commands[-1]):
            raise ValueError("actual native mechanical build failed: " + label)
    extension_raw, probe_raw, controls_raw = map(capture.raw, (extension, probe, controls))
    if sources is not None:
        from tools.build_hia_json_preflight import current_sources
        if current_sources() != sources:
            raise ValueError("cold source set changed during build")
    capture.unchanged()
    manifest = {
        "schema": SCHEMA, "status": "BUILT_NOT_QUALIFIED_EXPLICIT_DEVELOPMENT",
        "whole_native": False, "source_root": str(ROOT),
        "inputs": {name: data_pin(raw) for name, raw in inputs.items()},
        "runtime": {"path": str(runtime), "version": sys.version, "pin": data_pin(runtime_raw),
                    "subprocess_path": str(subprocess_path), "subprocess_pin": data_pin(subprocess_raw)},
        "policy": {"path": str(policy_path), "pin": data_pin(policy_raw)},
        "extension": {"path": str(extension), "pin": data_pin(extension_raw)},
        "probe": {"path": str(probe), "pin": data_pin(probe_raw)},
        "handoff_controls": {"path": str(controls), "pin": data_pin(controls_raw)},
        "compiler": {"path": str(compiler), "pin": data_pin(compiler_raw)},
        "build_tool": {"path": str(cc_path), "pin": data_pin(cc_raw)},
        "python_library": {"path": str(python_library), "pin": data_pin(library_raw)},
        "python_headers": headers, "cold_source": sources,
        "cold_report": None if cold_raw is None else {"path": str(Path(cold_report).resolve()), "pin": data_pin(cold_raw)},
        "scope": "DEVELOPMENT_COMPILER" if development else "MATCHING_SOURCE_COLD_COMPILER",
    }
    write_json(output / "manifest.json", manifest)
    write_json(output / "build.json", {
        "schema": "hepta.cold-native-transport.build.r3", "status": "BUILT_NOT_QUALIFIED",
        "manifest": data_pin(regular_bytes(output / "manifest.json")),
        "commands": commands, "native_compile_receipt": receipt,
        "consumed": capture.pins(), "source_stable": True,
        "whole_native": False, "qualification_complete": False,
    })
    capture.unchanged()
    return output / "manifest.json"


def main():
    if len(sys.argv) == 4 and sys.argv[1] == "--internal-compile":
        _compile_child(sys.argv[2], sys.argv[3])
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--compiler", type=Path, required=True)
    parser.add_argument("--compiler-sha256", required=True)
    parser.add_argument("--python-library", type=Path, required=True)
    parser.add_argument("--cc", required=True)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument("--cold-report", type=Path)
    choice.add_argument("--development", action="store_true")
    args = parser.parse_args()
    print(build(args.output, args.compiler, args.compiler_sha256, args.python_library,
                cc=args.cc, cold_report=args.cold_report, development=args.development))


if __name__ == "__main__":
    main()
