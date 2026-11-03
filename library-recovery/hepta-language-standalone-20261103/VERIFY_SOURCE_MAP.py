#!/usr/bin/env python3
"""Code-only historical source replay; never a Hepta release or safety gate PASS.

Run from any directory. A clean staged package is built for each source generation.
Default exit=2 if a test is skipped or a known missing frontend remains unresolved.
Use --research-only only to inspect passing *scoped* tests, never to qualify release.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "source"

BLOBS = {
    "hsir.py": "054e3ebdf36a7515a4fd4535cb45f292cb73facf",
    "test_hsir.py": "a987dd9fbce16dc0161cced9fed63f486482d087",
    "c2hepta.py": "3e1813f844ac5f1a5e89a37cd01ca9b4fde82e36",
    "test_c2hepta.py": "3f61cef5faeb94253a16599336663928ce97b8de",
    "Hepta_cpp2hepta.py": "d0940d18956b1f0940057cc60b527122f1b9c037",
    "Hepta_test_cpp2hepta.py": "d8799feb9dd4072e1a4a2169c578abccbf8215ba",
    "Hepta_P6_llvm_scalar_backend.py": "a9304c64f3b53fca5174580dcd34fcdb3df9d668",
    "Hepta_P6_llvm_scalar_tests.py": "7e34453508312a2d5ae07cdf3730d83aa7b2ed03",
    "Hepta_P6_llvm_backend_cross.py": "f2291ce7a33c9bb041e80c21b96bcdd598b7fccb",
    "Hepta_P6_llvm_cross_tests.py": "7345321b4affac0b45d057c4dc791ea3f05f4b47",
    "Hepta_abi_host_probe.py": "70e7c584e0dbf4f22f6c302135c9f852ffd93265",
    "Hepta_test_abi_host_probe.py": "b2771567e4db3b4c97a3fdca35d0705131ed2925",
    "Hepta_cpp_bridge_source.py": "3c370f38082aad2120034de96ff535cc39752b52",
    "Hepta_cpp_bridge_tests.py": "21fa93fde38500a0f36838563b035e2c97ecb5a5",
    "Hepta_test_llvm_scalar_phi.py": "df68945aae792d826fe9001536abed62e83f2842",
    "Hepta_verify_llvm_subset_host.py": "9dd362467cc8381fb72b818c0e9c1257a32f0a64",
}

COMMON = {
    "c2hepta.py": "hepta/c2hepta.py",
    "Hepta_cpp_bridge_source.py": "hepta/cpp_bridge.py",
    "Hepta_abi_host_probe.py": "tools/abi_host_probe.py",
    "Hepta_test_abi_host_probe.py": "tests/test_abi_host_probe.py",
    "Hepta_cpp_bridge_tests.py": "tests/test_cpp_bridge.py",
}

SCALAR = {
    "Hepta_P6_llvm_scalar_backend.py": "hepta/llvm_scalar_backend.py",
    "Hepta_P6_llvm_scalar_tests.py": "tests/test_llvm_scalar_backend.py",
}

CROSS = {
    "Hepta_P6_llvm_backend_cross.py": "hepta/llvm_scalar_backend.py",
    "Hepta_P6_llvm_scalar_tests.py": "tests/test_llvm_scalar_backend.py",
    "Hepta_test_llvm_scalar_phi.py": "tests/test_llvm_scalar_phi.py",
    "Hepta_P6_llvm_cross_tests.py": "tests/test_llvm_scalar_targets.py",
}


def verify_bytes() -> None:
    actual = {p.name for p in SOURCE.iterdir() if p.is_file()}
    if actual != set(BLOBS):
        raise RuntimeError(f"Source inventory incomplete/extra: missing={sorted(set(BLOBS)-actual)}, extra={sorted(actual-set(BLOBS))}")
    for name, expected in BLOBS.items():
        data = (SOURCE / name).read_bytes()
        blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        if blob != expected:
            raise RuntimeError(f"Git blob identity mismatch: {name}")
    print(f"SOURCE_IDENTITIES: {len(BLOBS)}/{len(BLOBS)} exact, original bytes", flush=True)


def stage(tmp: Path, mapping: dict[str, str]) -> None:
    for package in ("hepta", "tools", "tests"):
        p = tmp / package
        p.mkdir()
        (p / "__init__.py").write_bytes(b"")
    for source_name, target in mapping.items():
        dest = tmp / target
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(SOURCE / source_name, dest)


def replay(name: str, mapping: dict[str, str], modules: tuple[str, ...]) -> tuple[int, int, int, int]:
    with tempfile.TemporaryDirectory(prefix="hepta-historical-scoped-") as tmp_s:
        tmp = Path(tmp_s)
        stage(tmp, mapping)
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", OPENBLAS_NUM_THREADS="1", OMP_NUM_THREADS="1")
        proc = subprocess.run(
            [sys.executable, "-m", "unittest", "-v", *modules],
            cwd=tmp, env=env, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, timeout=120, check=False,
        )
        # Preserve the exact original unittest text, including skips and failures.
        print(f"\n== {name} ==\n{proc.stdout}", flush=True)
        match = re.search(r"(?m)^Ran (\d+) tests? in", proc.stdout)
        skipped = re.search(r"(?m)^OK \(skipped=(\d+)\)$", proc.stdout)
        total = int(match.group(1)) if match else 0
        nskip = int(skipped.group(1)) if skipped else 0
        status = "SCOPED_PASS_WITH_SKIP" if proc.returncode == 0 and nskip else (
            "SCOPED_PASS" if proc.returncode == 0 else "FAIL")
        print(f"RESULT {name}: {status}; tests={total}; skipped={nskip}; subprocess_exit={proc.returncode}", flush=True)
        return proc.returncode, total, nskip, 1 if not match else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--research-only", action="store_true", help="exit 0 if only the named scoped tests pass; NEVER a production qualification")
    args = parser.parse_args()
    try:
        verify_bytes()
        results = [
            replay("host-c-abi-and-cpp-l0", COMMON, ("tests.test_abi_host_probe", "tests.test_cpp_bridge")),
            replay("older-scalar-backend", SCALAR, ("tests.test_llvm_scalar_backend",)),
            replay("separate-cross-phi-backend", CROSS, (
                "tests.test_llvm_scalar_backend", "tests.test_llvm_scalar_phi", "tests.test_llvm_scalar_targets")),
        ]
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"REPLAY_REFUSED: {type(exc).__name__}: {exc}", flush=True)
        return 2
    if any(rc or missing or total == 0 for rc, total, _, missing in results):
        print("VERDICT=FAIL (scoped tests not all executed cleanly); PRODUCTION_ACTIVATION=false", flush=True)
        return 2
    skipped = sum(nskip for _, _, nskip, _ in results)
    print(f"TOTAL_COLLECTION={sum(total for _, total, _, _ in results)}; SKIPPED={skipped}", flush=True)
    print("UNRUN_FRONTEND_TESTS=2 historical modules (requires full Hepta parser/AST)", flush=True)
    print("RELEASE_GATES=OPEN; PRODUCTION_ACTIVATION=false; PROOF_OF_SAFETY=false", flush=True)
    if args.research_only:
        print("RESEARCH_SCOPED_VERDICT=PASS_WITH_LIMITATIONS; NEVER A RELEASE PASS", flush=True)
        return 0
    print("STRICT_VERDICT=DENY_ALL (expected nonzero: missing frontend and/or skipped native checks)", flush=True)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
