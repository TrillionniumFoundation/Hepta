"""Finite acyclic native Rust/C context comparisons; no optional compilers."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta.ast import HeptaError
from hepta.backend import compile_rust, find_rustc, toolchain_info
from hepta.c_backend import compile_c
from hepta.lock_diff import compare_locks
from hepta.modules import load_project
from hepta.packages import load_package, package_snapshot, verify_lock, write_lock
from hepta.pipeline import analyze_project

ROOT = Path(__file__).resolve().parents[1]
RECEIPTS = []
CLI_RECEIPTS = []


def sha(data):
    return hashlib.sha256(data).hexdigest()


class VersionedPackageContextNativeTests(unittest.TestCase):
    def setUp(self):
        self.rustc = find_rustc()
        toolchain_info(self.rustc)  # Missing/wrong Rust is an error, never a skip.
        self.temporary = tempfile.TemporaryDirectory(prefix="hepta-context-native-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.serial = 0

    def put(self, path, contents):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8")

    def manifest(self, path, name, version="1.0.0", kind="lib", dependencies=None):
        text = (f'[package]\nname={json.dumps(name)}\nversion={json.dumps(version)}\n'
                f'kind={json.dumps(kind)}\n[dependencies]\n')
        for alias, spec in (dependencies or {}).items():
            text += alias + "={" + ", ".join(k + "=" + json.dumps(v) for k, v in spec.items()) + "}\n"
        self.put(path / "hepta.toml", text)

    def graph(self, *, reverse=False, backtrack=False, fixed=False):
        app, bridge = self.root / "app", self.root / "bridge"
        paths = ["src/low", "src/high"]
        if reverse:
            paths.reverse()
        def choice(paths, bound="<3.0.0"):
            return {"package": "vendor", "version": ">=1.0.0, " + bound, "candidates": paths}
        for directory, version, answer in (("low", "1.0.0", 24), ("high", "2.0.0", 42)):
            pkg = app / "src" / directory
            self.manifest(pkg, "vendor", version)
            self.put(pkg / "src/helper.hepta", f"pub fn value()->i32 effects {{}} {{ return {answer}; }}\n")
            self.put(pkg / "src/lib.hepta", "import helper;\npub fn answer()->i32 effects {} { return helper::value(); }\n")
        self.manifest(bridge, "bridge", dependencies={"pick": choice(
            ["../app/" + path for path in paths], "<2.0.0" if backtrack else "<3.0.0")})
        self.put(bridge / "src/lib.hepta", "import pick;\npub fn answer()->i32 effects {} { return pick::answer(); }\n")
        dependencies = {"first": choice(paths), "second": choice(paths[::-1]), "bridge": {"path": "../bridge"}}
        if fixed:
            dependencies["fixed"] = {"path": "src/high/../high"}
        self.manifest(app, "app", kind="bin", dependencies=dependencies)
        self.put(app / "src/helper.hepta", "pub fn value()->i32 effects {} { return 7; }\n")
        source = "import first;\nimport second;\nimport bridge;\n"
        check = "assert(first::answer()==second::answer()); assert(first::answer()==bridge::answer()); "
        if fixed:
            source += "import fixed;\n"
            check += "assert(first::answer()==fixed::answer()); "
        source += "fn main()->i32 effects {panic} { " + check + "return first::answer(); }\n"
        self.put(app / "src/main.hepta", source)
        return app

    def selection(self, app, selected, *, fixed=False):
        package = load_package(app)
        picked = package.dependencies["first"]
        self.assertEqual(picked.root, app / "src" / selected)
        self.assertIs(picked, package.dependencies["second"])
        self.assertIs(picked, package.dependencies["bridge"].dependencies["pick"])
        if fixed:
            self.assertIs(picked, package.dependencies["fixed"])
        nodes = package_snapshot(package)["packages"]
        self.assertEqual(set(nodes), {".", "../bridge", "src/" + selected})
        expected = {"first": "src/" + selected, "second": "src/" + selected, "bridge": "../bridge"}
        if fixed:
            expected["fixed"] = "src/" + selected
        self.assertEqual(nodes["."]["dependencies"], expected)
        self.assertEqual(nodes["../bridge"]["dependencies"], {"pick": "src/" + selected})

    def parity(self, app, selected, expected, *, locked=True, fixed=False, local=False):
        self.selection(app, selected, fixed=fixed)
        lock = (app / "Hepta.lock").read_bytes()
        observed = []
        for backend in ("c", "rust"):
            result = analyze_project(app, backend=backend, native=False, crate_type="bin", locked=locked)
            self.assertTrue(result.report["ok"], result.report)
            self.assertEqual(result.report["diagnostics"], [])
            self.assertTrue(result.project.unchanged())
            self.assertEqual(len(result.project.modules), 6 if local else 4)
            self.assertEqual(sum(m["path"] == str(app / "src" / selected / "src/lib.hepta")
                                 for m in result.project.modules), 1)
            generated = result.c if backend == "c" else result.rust
            for optimize in (False, True):
                self.serial += 1
                artifact = self.root / ("native-" + str(self.serial))
                if backend == "c":
                    built = compile_c(generated, cc="gcc", crate_type="bin", output=artifact,
                                      optimize=optimize, sanitize=True)
                    self.assertIn("-O3" if optimize else "-O0", built["flags"])
                    self.assertIn("-fsanitize=undefined", built["flags"])
                    self.assertIn("-fno-sanitize-recover=all", built["flags"])
                else:
                    built = compile_rust(generated, rustc=self.rustc, crate_type="bin", output=artifact,
                                         optimize=optimize)
                    self.assertFalse(built["check_only"])
                    self.assertEqual(built["rustc_crate_type"], "bin")
                    self.assertIn("opt-level=" + ("3" if optimize else "0"), built["flags"])
                    self.assertIn("overflow-checks=yes", built["flags"])
                self.assertTrue(built["ok"], built)
                self.assertEqual(built["source_sha256" if backend == "c" else "rust_sha256"], sha(generated.encode()))
                self.assertEqual(built["artifact_sha256"], sha(artifact.read_bytes()))
                process = subprocess.run([str(artifact)], capture_output=True, timeout=10)
                value = (process.returncode, process.stdout, process.stderr)
                self.assertEqual(value, (expected, b"", b""))
                observed.append(value)
                receipt = {"method": self.id(), "backend": backend, "optimize": optimize,
                           "selected": selected, "locked": locked, "expected": expected,
                           "returncode": process.returncode, "stdout": "", "stderr": "",
                           "source_sha256": sha(generated.encode()), "artifact_sha256": sha(artifact.read_bytes()),
                           "flags": built["flags"], "toolchain": built["toolchain"]}
                RECEIPTS.append(receipt)
                print("VERSIONED_CONTEXT_NATIVE " + json.dumps(receipt, sort_keys=True), flush=True)
            self.assertTrue(result.project.unchanged())
        self.assertEqual(observed, [observed[0]] * 4)
        self.assertEqual((app / "Hepta.lock").read_bytes(), lock)

    def test_highest_version_both_orders_and_lock_modes(self):
        for reverse in (False, True):
            app = self.graph(reverse=reverse)
            write_lock(app)
            for locked in (False, True):
                self.parity(app, "high", 42, locked=locked)

    def test_transitive_fallback_both_orders_and_lock_modes(self):
        for reverse in (False, True):
            app = self.graph(reverse=reverse, backtrack=True)
            write_lock(app)
            for locked in (False, True):
                self.parity(app, "low", 24, locked=locked)

    def test_fixed_and_versioned_aliases_share_selected_context(self):
        app = self.graph(fixed=True)
        write_lock(app)
        for locked in (False, True):
            self.parity(app, "high", 42, locked=locked, fixed=True)

    def test_unselected_local_file_uses_application_context(self):
        app = self.graph()
        entry = app / "src/main.hepta"
        source = entry.read_text().replace("fn main", "import low::src::lib as local;\nfn main")
        self.put(entry, source.replace("return first::answer();", "assert(local::answer()==7); return first::answer();"))
        write_lock(app)
        for locked in (False, True):
            self.parity(app, "high", 42, locked=locked, local=True)

    def test_upgrade_stales_lock_then_refresh_changes_native_result(self):
        app = self.graph()
        before = write_lock(app)["snapshot"]
        old_bytes = (app / "Hepta.lock").read_bytes()
        old_project = load_project(app, locked=True)
        self.parity(app, "high", 42)
        self.manifest(app / "src/low", "vendor", "2.1.0")
        self.assertFalse(old_project.unchanged())
        with self.assertRaises(HeptaError) as caught:
            load_project(app, locked=True)
        self.assertEqual(caught.exception.diagnostic.code, "E_LOCK_STALE")
        self.assertEqual((app / "Hepta.lock").read_bytes(), old_bytes)
        old_path = self.root / "before.lock"
        self.put(old_path, json.dumps(before))
        after = write_lock(app)["snapshot"]
        self.assertEqual(verify_lock(load_package(app)), after)
        diff = compare_locks(old_path, app / "Hepta.lock")
        self.assertEqual(diff["compatibility"], "not_assessed")
        self.assertEqual([p["path"] for p in diff["packages"]["added"]], ["src/low"])
        self.assertEqual([p["path"] for p in diff["packages"]["removed"]], ["src/high"])
        self.assertEqual(diff["dependencies"]["retargeted"], [
            {"package": p, "alias": a, "before": "src/high", "after": "src/low"}
            for p, a in ((".", "first"), (".", "second"), ("../bridge", "pick"))])
        self.parity(app, "low", 24)

    def test_selected_context_rejects_before_compilers_and_recovers(self):
        for backtrack in (False, True):
            app = self.graph(backtrack=backtrack)
            selected = "low" if backtrack else "high"
            entry = app / "src/main.hepta"
            original = entry.read_text()
            for local_first in (False, True):
                local = "import " + selected + "::src::lib as unused;\n"
                dep = "import first;\n"
                self.put(entry, (local + dep if local_first else dep + local) +
                         "fn main()->i32 effects {} { return first::answer(); }\n")
                write_lock(app)
                lock = (app / "Hepta.lock").read_bytes()
                roots = (app, app / "src" / selected) if local_first else (app / "src" / selected, app)
                lines = entry.read_text().splitlines(keepends=True)
                expected = {"code": "E_MODULE_PACKAGE_CONTEXT", "phase": "module", "notes": [],
                            "message": f"Module {app / 'src' / selected / 'src/lib.hepta'} is imported under conflicting package roots: {roots[0]} and {roots[1]}",
                            "span": {"path": str(entry), "start": len(lines[0]),
                                     "end": len(lines[0]) + len(lines[1].rstrip("\n")), "line": 2, "column": 1}}
                for backend in ("c", "rust"):
                    with patch("hepta.pipeline.compile_rust", side_effect=AssertionError("Rust invoked on rejected context")) as rust, \
                         patch("hepta.c_backend.compile_c", side_effect=AssertionError("C invoked on rejected context")) as cc:
                        with self.assertRaises(HeptaError) as caught:
                            analyze_project(app, locked=True, native=True, backend=backend, crate_type="bin")
                        self.assertEqual(caught.exception.diagnostic.to_dict(), expected)
                        rust.assert_not_called()
                        cc.assert_not_called()
                self.assertEqual((app / "Hepta.lock").read_bytes(), lock)
            self.put(entry, original)
            write_lock(app)
            self.parity(app, selected, 24 if backtrack else 42)

    def test_invalid_candidate_refresh_preserves_lock_then_recovers(self):
        app = self.graph()
        write_lock(app)
        self.parity(app, "high", 42)
        lock = (app / "Hepta.lock").read_bytes()
        for invalid in ([], {}):
            self.manifest(app / "src/low", "vendor", "2.1.0", kind=invalid)
            with self.assertRaises(HeptaError) as caught:
                write_lock(app)
            diagnostic = caught.exception.diagnostic
            self.assertEqual((diagnostic.code, diagnostic.phase), ("E_PACKAGE_SCHEMA", "package"))
            self.assertEqual(diagnostic.span.path, str(app / "src/low/hepta.toml"))
            self.assertEqual((app / "Hepta.lock").read_bytes(), lock)
        self.manifest(app / "src/low", "vendor", "2.1.0")
        write_lock(app)
        self.parity(app, "low", 24)

    def test_public_cli_runs_locked_rust_and_c(self):
        app = self.graph(backtrack=True)
        write_lock(app)
        lock = (app / "Hepta.lock").read_bytes()
        env = dict(os.environ, PYTHONPATH=str(ROOT), PYTHONDONTWRITEBYTECODE="1", RUSTC=self.rustc)
        probe = subprocess.run([sys.executable, "-B", "-c", "import hepta; print(hepta.__file__)"],
                               cwd=self.root, env=env, capture_output=True, text=True, timeout=10, check=True)
        self.assertEqual(Path(probe.stdout.strip()).resolve(), ROOT / "hepta/__init__.py")
        for backend in ("c", "rust"):
            process = subprocess.run([sys.executable, "-B", "-m", "hepta", "run", str(app),
                                      "--locked", "--backend", backend, "--json"],
                                     cwd=self.root, env=env, capture_output=True, text=True, timeout=120)
            self.assertEqual(process.returncode, 24, process.stdout + process.stderr)
            self.assertEqual(process.stderr, "")
            report = json.loads(process.stdout)
            self.assertEqual((report["returncode"], report["stdout"], report["stderr"]), (24, "", ""))
            receipt = {"method": self.id(), "backend": backend, "report": report}
            CLI_RECEIPTS.append(receipt)
            print("VERSIONED_CONTEXT_NATIVE_CLI " + json.dumps(receipt, sort_keys=True), flush=True)
        self.assertEqual((app / "Hepta.lock").read_bytes(), lock)
