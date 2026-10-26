"""Finite native differential qualification for source-replayed HIA scalar SSA.

One module, two boundaries: compare_oracle_with_native checks finite behavior
only; qualify_scalar_source additionally compiles through the existing Hepta
Rust-reference/Resource-IR/HIA/LLVM publisher, then replays the exact source.
Neither is a proof of whole-language soundness or arbitrary C ABI behavior.
"""
from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import sys
import tempfile

_IDENT = re.compile(r"[A-Za-z_][A-Za-z_0-9]*\Z")
_TYPES = {"i32": (-2**31, 2**31 - 1), "u32": (0, 2**32 - 1)}
_MAX_CASES = 256
_MAX_BYTES = 8 * 1024 * 1024

# No repository import or source parsing occurs in the native child. Only the
# already published shared object, an exact exported symbol and integer args.
_WORKER = r'''
import ctypes, json, resource, sys
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
lib, symbol, word, packed = sys.argv[1:]
args = json.loads(packed)
c = ctypes.c_int32 if word == "i32" else ctypes.c_uint32
f = getattr(ctypes.CDLL(lib), symbol)
f.argtypes = [c] * len(args)
f.restype = c
print(json.dumps({"value": int(f(*args))}, separators=(",", ":")), flush=True)
'''


class HIADifferentialRejected(ValueError):
    """Invalid corpus, corrupted source/artifact, or actual native divergence."""


def _reject(message: str) -> None:
    raise HIADifferentialRejected("E_HIA_DIFFERENTIAL: " + message)


def _canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _corpus(cases, return_words):
    if (type(cases) is not dict or type(return_words) is not tuple
            or not 1 <= len(cases) <= 32 or len(return_words) != len(cases)):
        _reject("corpus must cover every native exported function")
    words = {}
    for item in return_words:
        if (type(item) is not tuple or len(item) != 2
                or type(item[0]) is not str or _IDENT.fullmatch(item[0]) is None
                or item[0] in words or item[1] not in _TYPES):
            _reject("invalid or duplicated native ABI function inventory")
        words[item[0]] = item[1]
    if set(cases) != set(words):
        _reject("missing or unreviewed native export case coverage")
    total = 0
    for fn, inputs in cases.items():
        if type(inputs) is not list or not inputs:
            _reject("each export requires a nonempty list of test vectors")
        word = words[fn]
        low, high = _TYPES[word]
        for args in inputs:
            if (type(args) is not list or len(args) > 16
                    or any(type(x) is not int or not low <= x <= high for x in args)):
                _reject("case arguments violate exact i32/u32 ABI range")
            total += 1
            if total > _MAX_CASES:
                _reject("finite corpus exceeds 256 cases")
    if len(_canonical(cases)) > 64_000:
        _reject("finite corpus exceeds byte budget")
    return words, total


def _observe_native(library: Path, function: str, word: str, args: list[int], *, timeout: float):
    if (platform.system() != "Linux" or not 0 < timeout <= 10
            or type(function) is not str or _IDENT.fullmatch(function) is None
            or word not in _TYPES):
        _reject("bounded Linux x86-64 scalar host required")
    try:
        with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
            proc = subprocess.run([sys.executable, "-I", "-c", _WORKER, str(library),
                                   function, word, json.dumps(args, separators=(",", ":"))],
                                  stdout=out, stderr=err, check=False, timeout=timeout)
            out.seek(0)
            err.seek(0)
            child_stdout = out.read(4097)
            child_stderr = err.read(4097)
    except (subprocess.TimeoutExpired, OSError) as exc:
        raise HIADifferentialRejected("E_HIA_DIFFERENTIAL: native child unavailable or timed out") from exc
    if len(child_stdout) > 4096 or len(child_stderr) > 4096:
        _reject("native subprocess exceeded output budget")
    if proc.returncode == -signal.SIGABRT:
        return ("trap", None)
    if proc.returncode != 0:
        _reject("native child exited with unexpected error/signal " + str(proc.returncode))
    try:
        value = json.loads(child_stdout)
    except (ValueError, UnicodeError) as exc:
        raise HIADifferentialRejected("E_HIA_DIFFERENTIAL: invalid native child output") from exc
    low, high = _TYPES[word]
    if (type(value) is not dict or set(value) != {"value"}
            or type(value["value"]) is not int or not low <= value["value"] <= high):
        _reject("native child returned invalid scalar observation")
    return ("value", value["value"])


def compare_oracle_with_native(oracle, library: str | Path, cases: dict, *,
                               max_steps: int = 20000, timeout: float = 3.0) -> dict:
    """Compare all exports; trap/budget/crash are deliberately distinct.

    This helper is NOT source binding. Use qualify_scalar_source for that.
    """
    from .hia_oracle import HIAOracleBudgetExceeded, HIAOracleRejected, HIAOracleTrap

    if (type(max_steps) is not int or not 1 <= max_steps <= 1_000_000
            or type(timeout) not in (float, int) or not 0 < timeout <= 10):
        _reject("invalid execution limits")
    words, total = _corpus(cases, getattr(oracle, "return_words", None))
    binary = Path(library)
    if (binary.is_symlink() or not binary.is_file() or
            not 0 < binary.stat().st_size <= _MAX_BYTES):
        _reject("native artifact must be bounded regular file")
    original = binary.read_bytes()
    artifact_sha = sha256(original).hexdigest()
    matches = traps = 0
    # Iterate canonically so receipt and first failure do not depend on map order.
    for function in sorted(cases):
        for index, args in enumerate(cases[function]):
            if binary.read_bytes() != original:
                _reject("native artifact changed during differential execution")
            try:
                expected = ("value", oracle.run(function, args, max_steps=max_steps))
            except HIAOracleTrap:
                expected = ("trap", None)
            except (HIAOracleBudgetExceeded, HIAOracleRejected) as exc:
                raise HIADifferentialRejected(
                    "E_HIA_DIFFERENTIAL: oracle failed or exhausted budget, never native trap") from exc
            observed = _observe_native(binary, function, words[function], args, timeout=timeout)
            if observed != expected:
                _reject(f"native mismatch at {function} case {index}: expected {expected}, observed {observed}")
            matches += 1
            traps += observed[0] == "trap"
    if binary.read_bytes() != original:
        _reject("native artifact changed after differential execution")
    if matches != total:
        _reject("complete finite denominator not executed")
    return {
        "schema": "hepta.hia.scalar-native-differential.v0",
        "status": "finite_native_observations_match_oracle_not_proved",
        "cases_sha256": sha256(_canonical(cases)).hexdigest(),
        "artifact_sha256": artifact_sha,
        "function_count": len(words), "cases_executed": matches,
        "defined_traps_observed": traps,
        "claims": {"finite_native_oracle_match": True,
                   "checked_hepta_source_replayed": False,
                   "backend_refinement_proved": False,
                   "whole_language_soundness_proved": False,
                   "physical_target_qualified": False},
    }


def qualify_scalar_source(source: str | Path, cases: dict, *, rustc=None,
                          clang="clang", locked=False, max_steps=20000) -> dict:
    """Actual Hepta source -> pinned Rust -> HIA/SSA -> LLVM -> child oracle.

    Separate source replay prevents a modified file with unchanged export names
    or rehashed data-only core from qualifying the published binary.
    """
    from .pipeline import analyze_project
    from .hsir import lower_checked_program
    from .cfg import lower_hsir_cfg
    from .ssa import lower_cfg_scalar_ssa
    from .ssa_verify import verify_scalar_ssa
    from .native_resource_gate import qualify_native_resource_source
    from .hia_core import seal_hia_scalar_core
    from .hia_oracle import prepare_scalar_oracle
    from .llvm_ssa_pipeline import build_llvm_ssa_source

    if platform.system() != "Linux":
        _reject("source qualification currently requires Linux host")
    with tempfile.TemporaryDirectory(prefix="hia-native-diff-") as directory:
        shared = Path(directory) / "source.so"
        compiled = build_llvm_ssa_source(source, shared, rustc=rustc,
                                         clang=clang, locked=locked)
        if compiled.get("ok") is not True:
            _reject("source LLVM qualification failed: " + str(compiled.get("diagnostics", []))[:600])
        analyzed = analyze_project(Path(source), backend="rust", native=False,
                                   crate_type="rlib", locked=locked)
        if (analyzed.report.get("ok") is not True or analyzed.program is None
                or analyzed.checked is None or analyzed.project is None
                or not analyzed.project.unchanged()):
            _reject("current source could not be independently replayed")
        h = lower_checked_program(analyzed.program, analyzed.checked)
        cfg = lower_hsir_cfg(h)
        ssa = lower_cfg_scalar_ssa(cfg)
        verified = verify_scalar_ssa(ssa, cfg)
        project_sha = analyzed.project.identity
        gate = qualify_native_resource_source(
            analyzed.program, analyzed.checked,
            canonical_hsir_sha256=h.as_dict()["source_semantic_sha256"],
            project_sha256=project_sha)
        core = seal_hia_scalar_core(h, cfg, ssa, verified, gate,
                                    project_sha256=project_sha)
        oracle = prepare_scalar_oracle(core, analyzed.program, analyzed.checked,
                                       project_sha256=project_sha)
        record = compiled.get("identities", {})
        native = compiled.get("native_backend", {})
        if (record.get("hia_scalar_core_sha256") != core.sha256
                or record.get("canonical_ssa_sha256") != ssa.sha256
                or record.get("resource_ir_sha256") != gate["resource_ir_sha256"]
                or compiled.get("resource_verification", {}).get("project_sha256") != project_sha
                or native.get("artifact_sha256") != sha256(shared.read_bytes()).hexdigest()):
            _reject("HIA source/project, Resource IR or native artifact identity drift")
        result = compare_oracle_with_native(oracle, shared, cases, max_steps=max_steps)
        if not analyzed.project.unchanged():
            _reject("source graph changed while differential corpus ran")
        result["source_project_sha256"] = project_sha
        result["hia_core_sha256"] = core.sha256
        result["ssa_sha256"] = ssa.sha256
        result["compiler_sha256"] = record.get("compiler_sha256")
        result["claims"]["checked_hepta_source_replayed"] = True
        return result
