"""Training-only PGO registration, native preparation and refusal controls."""
from __future__ import annotations

from copy import deepcopy
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from tools import hia_rust_pgo as pgo
from tools.qualify_hia_native_ndu import build, file_identity, run_command
from tools.qualify_hia_release_parity import _validate_release_registration, specification

CLANG = os.environ.get("CLANG", "clang")
RUSTC = os.environ.get("RUSTC", "rustc")
PROFDATA = os.environ.get("LLVM_PROFDATA", "llvm-profdata")


class RustPgoAdmissionTests(unittest.TestCase):
    def test_new_profile_keeps_old_workload_axes_and_thresholds(self):
        old = specification("verified-reduction-narrowed-release-v1")
        new = specification(pgo.PROFILE)
        self.assertEqual(old["schema"], "hepta.hia.release-parity.protocol.v1")
        self.assertEqual(new["schema"], "hepta.hia.release-parity.protocol.v2")
        excluded = {"schema", "build_profile", "rust_pgo"}
        self.assertEqual({k: v for k, v in old.items() if k not in excluded},
                         {k: v for k, v in new.items() if k not in excluded})
        self.assertEqual(new["rust_pgo"], pgo.training_registration())
        _validate_release_registration(new)

    def test_holdout_cannot_enter_the_preparation_interface(self):
        registration = pgo.training_registration()
        registration["holdout_sizes"] = specification(pgo.PROFILE)["holdout_sizes"]
        with self.assertRaisesRegex(ValueError, "E_RUST_PGO_REGISTRATION"):
            pgo.prepare_rust_pgo("never-created", None, None, None, {}, {}, registration=registration)

    def test_changed_training_plan_or_schema_cannot_reuse_formal_registration(self):
        for mutation in ("seed", "schema", "flags"):
            spec = specification(pgo.PROFILE)
            if mutation == "seed":
                spec["rust_pgo"]["seeds"][0] += 1
            elif mutation == "schema":
                spec["schema"] = "hepta.hia.release-parity.protocol.v1"
            else:
                spec["rust_pgo"]["rust_flags"].remove("lto=fat")
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, "E_RELEASE_COHORT"):
                _validate_release_registration(spec)

    def test_successful_exit_with_missing_profile_warning_still_refuses(self):
        with tempfile.TemporaryDirectory() as folder:
            stderr = Path(folder) / "rust.stderr"
            # LLVM's actual missing-function diagnostic can accompany exit 0.
            stderr.write_text("warning: no profile data available for function not_profiled Hash = 742261418966908927\n")
            receipt = {"returncode": 0, "stderr": file_identity(stderr)}
            with self.assertRaisesRegex(ValueError, "E_RUST_PGO_WARNING"):
                pgo._no_warnings(receipt)
            stderr.write_text("")
            pgo._no_warnings({"returncode": 0, "stderr": file_identity(stderr)})

    def test_absent_empty_and_excessive_raw_profiles_refuse(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(ValueError, "E_RUST_PGO_PROFILE"):
                pgo.profile_inventory(folder)

            path = Path(folder) / "empty.profraw"
            path.write_bytes(b"")
            with self.assertRaisesRegex(ValueError, "E_RUST_PGO_PROFILE"):
                pgo.profile_inventory(folder)
            path.unlink()
            for index in range(pgo.MAX_PROFILE_FILES + 1):
                (Path(folder) / (str(index) + ".profraw")).write_bytes(b"x")
            with self.assertRaisesRegex(ValueError, "E_RUST_PGO_PROFILE"):
                pgo.profile_inventory(folder)


    def test_empty_or_partial_identity_set_cannot_qualify_preparation(self):
        for partial in ({}, {"identities": {}, "status": "passed"},
                        {"identities": {"used_profile": {"path": "no-profile"}}, "status": "passed"}):
            with self.subTest(partial=partial):
                self.assertFalse(pgo.check_pgo_identities(partial))


@unittest.skipUnless(shutil.which(CLANG) and shutil.which(RUSTC) and shutil.which(PROFDATA),
                     "actual Clang, Rust and LLVM profile tools required")
class RustPgoNativeTests(unittest.TestCase):
    def test_real_training_merge_profile_use_and_profile_identity(self):
        with tempfile.TemporaryDirectory() as folder:
            output, report = Path(folder), {}
            clang, rustc, profdata = [str(Path(shutil.which(tool)).resolve())
                                     for tool in (CLANG, RUSTC, PROFDATA)]
            products = build(output, clang, rustc, report,
                             build_profile="optimized-release-v1")
            before = deepcopy(products["rust"])
            pgo.prepare_rust_pgo(output, clang, rustc, profdata, products, report,
                                 registration=pgo.training_registration())
            preparation = report["rust_pgo"]
            self.assertEqual(preparation["status"], "passed", preparation)
            self.assertEqual(preparation["holdout_inputs_used"], 0)
            self.assertEqual(preparation["identities"]["unprofiled_rust"], before)
            self.assertEqual(products["rust"], preparation["identities"]["optimized_rust"])
            self.assertEqual(report["native_artifacts"]["rust"], products["rust"])
            observed = {(row["n"], row["seed"]) for row in preparation["training_requests"]}
            expected = {(n, seed) for n in preparation["registration"]["sizes"]
                        for seed in preparation["registration"]["seeds"]}
            self.assertEqual(observed, expected)
            self.assertEqual(len(preparation["training_requests"]), len(expected))
            self.assertTrue(all(row["bytes"] > 0 for row in preparation["raw_profiles"]))
            self.assertTrue(pgo.check_pgo_identities(preparation))
            negative = output / "missing-function-control"
            negative.mkdir()
            changed_source = negative / "kernel.rs"
            changed_source.write_text((pgo.FIXTURES / "kernel.rs").read_text() +
                '\n#[no_mangle]\npub extern "C" fn not_profiled(x: u64) -> u64 { x ^ 7 }\n')
            use = next(row for row in reversed(report["build_commands"])
                       if any(argument.startswith("profile-use=") for argument in row["argv"]))
            arguments = list(use["argv"])
            arguments[-1] = str(changed_source)
            for index, argument in enumerate(arguments):
                if argument.startswith("--emit="):
                    arguments[index] = "--emit=link=" + str(negative / "rust.so") + ",asm=" + str(negative / "rust.s")
            run_command(arguments, output, report["build_commands"], cwd=negative)
            self.assertEqual(report["build_commands"][-1]["returncode"], 0)
            with self.assertRaisesRegex(ValueError, "E_RUST_PGO_WARNING"):
                pgo._no_warnings(report["build_commands"][-1])
            # A valid compiler result cannot excuse later profile substitution.
            Path(preparation["profile_use_argument"]).write_bytes(b"changed after compilation")
            self.assertFalse(pgo.check_pgo_identities(preparation))


if __name__ == "__main__":
    unittest.main()
