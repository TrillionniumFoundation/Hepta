"""Offline package-graph checks only: no native compiler or Hepta execution."""
from __future__ import annotations

import itertools
import json
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta.ast import HeptaError
from hepta.modules import load_project
from hepta.package_resolution import requirement, satisfies
from hepta.packages import load_package, package_snapshot, verify_lock, write_lock


class LocalResolutionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="hepta-local-resolution-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def package(self, directory, name=None, version="1.0.0", deps=None, kind="lib", source=""):
        root = self.root / directory
        (root / "src").mkdir(parents=True, exist_ok=True)
        manifest = f'[package]\nname = "{name or directory}"\nversion = "{version}"\nkind = "{kind}"\n'
        if deps:
            manifest += "\n[dependencies]\n"
            for alias, spec in deps.items():
                fields = ", ".join(f"{key} = {json.dumps(value)}" for key, value in spec.items())
                manifest += f"{alias} = {{ {fields} }}\n"
        (root / "hepta.toml").write_text(manifest, encoding="utf-8")
        (root / "src" / ("main.hepta" if kind == "bin" else "lib.hepta")).write_text(source, encoding="utf-8")
        return root

    def spec(self, *paths, name="math", version=">=1.0.0, <3.0.0"):
        return {"package": name, "version": version, "candidates": ["../" + p for p in paths]}

    def reject(self, code, action):
        with self.assertRaises(HeptaError) as caught:
            action()
        self.assertEqual(caught.exception.diagnostic.code, code)
        self.assertEqual(caught.exception.diagnostic.phase, "package")
        return caught.exception.diagnostic

    def basic(self, spec=None):
        self.package("v1", "math", "1.9.0")
        self.package("v2", "math", "2.0.0")
        return self.package("app", deps={"m": spec or self.spec("v1", "v2")})

    def test_highest_numeric_version_and_array_order_independence(self):
        self.package("v9", "math", "1.9.0")
        self.package("v10", "math", "1.10.0")
        for candidates in [("v9", "v10"), ("v10", "v9")]:
            app = self.package("app", deps={"m": self.spec(*candidates)})
            self.assertEqual(load_package(app).dependencies["m"].version, "1.10.0")

    def test_equal_versions_use_stable_path_order(self):
        self.package("a", "math")
        self.package("b", "math")
        for candidates in [("a", "b"), ("b", "a")]:
            app = self.package("app", deps={"m": self.spec(*candidates)})
            self.assertEqual(load_package(app).dependencies["m"].root, self.root / "a")

    def test_exact_and_comparator_boundaries(self):
        for text, expected in [("1.9.0", "1.9.0"), ("=2.0.0", "2.0.0"),
                               (">1.9.0, <=2.0.0", "2.0.0"),
                               (">=1.9.0, <2.0.0", "1.9.0")]:
            with self.subTest(text=text):
                app = self.basic(self.spec("v1", "v2", version=text))
                self.assertEqual(load_package(app).dependencies["m"].version, expected)

    def test_range_language_rejects_unsupported_and_malformed_forms(self):
        for text in [None, 1, [], {}, "", "^1.0.0", "~1.0.0", "1.*", "1.0", "01.0.0",
                     "1.0.0-alpha", "1.0.0+build", "1.0.0 || 2.0.0", ">=1.0.0,", "1.0.0\n2.0.0",
                     ",".join([">=1.0.0"] * 9), "1" * 257]:
            with self.subTest(text=text):
                self.reject("E_PACKAGE_REQUIREMENT", lambda: requirement(text, self.root / "hepta.toml"))

    def test_version_order_does_not_require_python_integer_conversion(self):
        large = "9" * 5000
        self.assertTrue(satisfies(large + ".0.0", requirement(">1.0.0", self.root)))

    def test_transitive_constraints_backtrack_and_share_one_object(self):
        app = self.basic()
        self.package("bridge", deps={"also_math": self.spec("v1", "v2", version="<2.0.0")})
        app = self.package("app", deps={"a_math": self.spec("v1", "v2"), "z_bridge": {"path": "../bridge"}})
        result = load_package(app)
        self.assertEqual(result.dependencies["a_math"].version, "1.9.0")
        self.assertIs(result.dependencies["a_math"], result.dependencies["z_bridge"].dependencies["also_math"])

    def test_backtracking_discards_failed_candidate_dependency_edges(self):
        self.basic()
        self.package("high", "front", "2.0.0", {"m": self.spec("v2")})
        self.package("low", "front", "1.0.0", {"m": self.spec("v1")})
        app = self.package("app", deps={"a_front": self.spec("low", "high", name="front"),
                                         "z_math": self.spec("v1")})
        result = load_package(app)
        self.assertEqual(result.dependencies["a_front"].version, "1.0.0")
        self.assertEqual(set(package_snapshot(result)["packages"]), {".", "../low", "../v1"})

    def test_candidate_cycle_can_backtrack_to_acyclic_version(self):
        self.package("low", "math", "1.0.0")
        self.package("high", "math", "2.0.0", {"back": {"path": "../app"}})
        app = self.package("app", deps={"m": self.spec("low", "high")})
        self.assertEqual(load_package(app).dependencies["m"].version, "1.0.0")

    def test_all_candidate_cycles_are_unsatisfiable(self):
        self.package("high", "math", "2.0.0", {"back": {"path": "../app"}})
        app = self.package("app", deps={"m": self.spec("high")})
        self.reject("E_PACKAGE_RESOLUTION", lambda: load_package(app))

    def test_fixed_path_cycle_keeps_original_diagnostic(self):
        app = self.package("app", deps={"back": {"path": "../app"}})
        self.reject("E_PACKAGE_CYCLE", lambda: load_package(app))

    def test_disjoint_candidate_sources_conflict_even_at_same_version(self):
        self.package("a", "math")
        self.package("b", "math")
        app = self.package("app", deps={"a": self.spec("a"), "b": self.spec("b")})
        self.reject("E_PACKAGE_RESOLUTION", lambda: load_package(app))

    def test_unsatisfied_version_reports_dependency_and_manifest(self):
        app = self.basic(self.spec("v1", "v2", version=">3.0.0"))
        diag = self.reject("E_PACKAGE_RESOLUTION", lambda: load_package(app))
        self.assertIn("m (math)", diag.message)
        self.assertEqual(diag.span.path, str(app / "hepta.toml"))

    def test_fixed_paths_preserve_multiple_versions_and_existing_lock_shape(self):
        self.basic()
        app = self.package("app", deps={"old": {"path": "../v1"}, "new": {"path": "../v2"}})
        result = load_package(app)
        self.assertEqual({p.version for p in result.dependencies.values()}, {"1.9.0", "2.0.0"})
        snapshot = package_snapshot(result)
        self.assertEqual(snapshot["schema"], "hepta.lock.v1")
        self.assertEqual(set(snapshot), {"schema", "packages", "files", "sha256"})

    def test_candidate_schema_errors_do_not_silently_fallback(self):
        self.basic()
        cases = [{"git": "https://example.invalid/repo"}, {"path": "../v1", "version": "1.9.0"},
                 {**self.spec("v1"), "extra": True}, {**self.spec("v1"), "package": []},
                 {**self.spec("v1"), "candidates": []}, {**self.spec("v1"), "candidates": "../v1"},
                 {**self.spec("v1"), "candidates": [1]}, {**self.spec("v1"), "candidates": [""]},
                 self.spec("v1", "v1"), self.spec(*(["v1"] * 33))]
        for spec in cases:
            with self.subTest(spec=spec):
                app = self.package("app", deps={"m": spec})
                self.reject("E_PACKAGE_DEPENDENCY", lambda: load_package(app))

    def test_wrong_name_or_bin_candidate_is_not_ignored(self):
        self.basic()
        for kwargs in [{"name": "other"}, {"name": "math", "kind": "bin"}]:
            with self.subTest(kwargs=kwargs):
                self.package("wrong", version="1.0.0", **kwargs)
                app = self.package("app", deps={"m": self.spec("v2", "wrong")})
                self.reject("E_PACKAGE_DEPENDENCY", lambda: load_package(app))

    def test_missing_candidate_is_not_silently_ignored(self):
        app = self.basic(self.spec("v2", "missing"))
        self.reject("E_PACKAGE_MANIFEST", lambda: load_package(app))

    def test_reached_dependency_schema_errors_are_not_version_conflicts(self):
        self.package("low", "math", "1.0.0")
        self.package("high", "math", "2.0.0", {"bad": {"git": "https://example.invalid/repo"}})
        app = self.package("app", deps={"m": self.spec("low", "high")})
        self.reject("E_PACKAGE_DEPENDENCY", lambda: load_package(app))
        # A lower candidate's dependency graph is not traversed when a higher
        # version already yields a complete solution.
        self.package("low", "math", "1.0.0", {"bad": {"git": "https://example.invalid/repo"}})
        self.package("high", "math", "2.0.0")
        self.assertEqual(load_package(app).dependencies["m"].version, "2.0.0")

    def test_attempt_limit_is_not_reported_as_unsatisfiable(self):
        app = self.basic()
        with patch("hepta.package_resolution.MAX_ATTEMPTS", 1):
            self.reject("E_PACKAGE_RESOLUTION_LIMIT", lambda: load_package(app))

    def test_identity_limit_is_explicit(self):
        app = self.basic()
        with patch("hepta.package_resolution.MAX_IDENTITIES", 0):
            self.reject("E_PACKAGE_RESOLUTION_LIMIT", lambda: load_package(app))

    def test_lock_and_locked_project_bind_selected_sources(self):
        app = self.basic()
        (app / "src/lib.hepta").write_text("import m;", encoding="utf-8")
        write_lock(app)
        project = load_project(app, locked=True)
        self.assertEqual(project.package.dependencies["m"].version, "2.0.0")
        (self.root / "v2/src/lib.hepta").write_text("// changed\n", encoding="utf-8")
        self.reject("E_LOCK_STALE", lambda: load_project(app, locked=True))
        self.assertFalse(project.unchanged())

    def test_newly_preferred_candidate_invalidates_lock(self):
        app = self.basic()
        write_lock(app)
        self.package("v1", "math", "2.1.0")
        self.reject("E_LOCK_STALE", lambda: verify_lock(load_package(app)))
        write_lock(app)
        self.assertEqual(load_package(app).dependencies["m"].version, "2.1.0")
        verify_lock(load_package(app))

    def test_public_lock_cli_succeeds_and_conflict_preserves_existing_lock(self):
        app = self.basic()
        def run():
            p = subprocess.run([sys.executable, "-m", "hepta", "lock", str(app)],
                               capture_output=True, text=True, timeout=20)
            return p, json.loads(p.stdout)
        p, report = run()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertTrue(report["ok"])
        old = (app / "Hepta.lock").read_bytes()
        self.basic(self.spec("v1", "v2", version=">3.0.0"))
        p, report = run()
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(report["diagnostics"][0]["code"], "E_PACKAGE_RESOLUTION")
        self.assertEqual((app / "Hepta.lock").read_bytes(), old)

    def test_relocated_selected_graph_keeps_portable_lock(self):
        import shutil
        app = self.basic()
        old = write_lock(app)["snapshot"]
        with tempfile.TemporaryDirectory(prefix="hepta-relocated-resolution-") as directory:
            moved = Path(directory) / "workspace"
            shutil.copytree(self.root, moved)
            current = verify_lock(load_package(moved / "app"))
            self.assertEqual(current, old)
            self.assertNotIn(str(self.root), json.dumps(current))

    def test_success_only_publishes_complete_legacy_cache(self):
        app = self.basic()
        cache = {}
        result = load_package(app, _cache=cache)
        self.assertIs(cache[app], result)
        self.assertEqual(set(cache), {app, self.root / "v2"})
        bad = self.basic(self.spec("v1", "v2", version=">3.0.0"))
        failed_cache = {}
        self.reject("E_PACKAGE_RESOLUTION", lambda: load_package(bad, _cache=failed_cache))
        self.assertEqual(failed_cache, {})

    def test_nonempty_legacy_cache_cannot_bypass_transitive_constraints(self):
        self.basic()
        bridge = self.package("bridge", deps={"m": self.spec("v1")})
        cache = {}
        previous = load_package(bridge, _cache=cache)
        before = dict(cache)
        app = self.package("app", deps={"a_math": self.spec("v2"),
                                         "z_bridge": {"path": "../bridge"}})
        self.reject("E_PACKAGE_RESOLUTION", lambda: load_package(app, _cache=cache))
        self.assertEqual(cache, before)
        self.assertIs(cache[bridge], previous)
        app = self.package("app", deps={"a_math": self.spec("v1", "v2"),
                                         "z_bridge": {"path": "../bridge"}})
        result = load_package(app, _cache=cache)
        self.assertEqual(result.dependencies["a_math"].version, "1.9.0")
        self.assertIs(result.dependencies["a_math"], result.dependencies["z_bridge"].dependencies["m"])
        self.assertIsNot(result.dependencies["z_bridge"], previous)

    def test_candidate_manifest_read_is_shared_with_graph_construction(self):
        from hepta.packages import read_package
        app = self.basic()
        with patch("hepta.package_resolution.read_package", wraps=read_package) as read:
            result = load_package(app)
        counts = [call.args[0] for call in read.call_args_list]
        self.assertEqual(sorted(counts), sorted({app, self.root / "v1", self.root / "v2"}))
        self.assertEqual(result.dependencies["m"].manifest_bytes,
                         (self.root / "v2/hepta.toml").read_bytes())

    def test_small_graphs_match_independent_exhaustive_oracle(self):
        rng = random.Random(7151026)
        versions = ("1.0.0", "2.0.0", "3.0.0")
        for case in range(40):
            # Each front version constrains math through explicit source sets.
            # Enumerate all nine combinations independently of production code.
            sets = [set(rng.sample(range(3), rng.randrange(1, 4))) for _ in range(3)]
            root_set = set(rng.sample(range(3), rng.randrange(1, 4)))
            for i, version in enumerate(versions):
                self.package(f"m{i}", "math", version)
            for i, version in enumerate(versions):
                self.package(f"f{i}", "front", version,
                             {"m": self.spec(*(f"m{j}" for j in sorted(sets[i])), version=">=1.0.0")})
            app = self.package("app", deps={
                "front": self.spec("f0", "f1", "f2", name="front", version=">=1.0.0"),
                "math": self.spec(*(f"m{j}" for j in sorted(root_set)), version=">=1.0.0")})
            solutions = [(f, m) for f, m in itertools.product(range(3), repeat=2)
                         if m in sets[f] and m in root_set]
            with self.subTest(case=case):
                if not solutions:
                    self.reject("E_PACKAGE_RESOLUTION", lambda: load_package(app))
                else:
                    f, m = max(solutions)
                    result = load_package(app)
                    self.assertEqual(result.dependencies["front"].version, versions[f])
                    self.assertEqual(result.dependencies["math"].version, versions[m])
                    self.assertIs(result.dependencies["math"], result.dependencies["front"].dependencies["m"])


if __name__ == "__main__":
    unittest.main()
