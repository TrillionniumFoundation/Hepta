"""Native-economics observations cannot outlive their actual build inputs.

The campaign fixtures below isolate the identity boundary with ordinary files;
they do not execute those files or represent native performance observations.
"""
from contextlib import ExitStack
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tools import qualify_hia_native_ndu as native


class NativeEconomicsIdentityTests(unittest.TestCase):
    def campaign(self, root, change=None):
        files = {}
        for name in ("c", "cpp", "rust", "hia", "driver", "clang", "rustc", "objdump"):
            path = root / name
            path.write_bytes(("original-" + name).encode())
            files[name] = path
        bridge, identity = root / "bridge", root / "identity.json"
        bridge.write_bytes(b"unit-input-not-executed")
        identity.write_text('{}')
        output = root / "observation"

        def build(directory, clang, rustc, report, **unused):
            products = {name: native.file_identity(files[name])
                        for name in ("c", "cpp", "rust", "hia")}
            report["native_artifacts"] = products
            report["driver_identity"] = native.file_identity(files["driver"])
            report["toolchains"] = {name: native.file_identity(files[name])
                                    for name in ("clang", "rustc", "objdump")}
            return products

        def training(*unused):
            if change is not None:
                # Change the bytes while keeping the same path and byte count.
                path = files[change]
                path.write_bytes(path.read_bytes().replace(b"original", b"modified"))
            return {}

        source = {"head": "unit-source-unchanged", "status": ""}
        args = SimpleNamespace(output=str(output), bridge=str(bridge), identity=str(identity),
                               clang=str(files["clang"]), rustc=str(files["rustc"]),
                               build_profile="optimized-release-v1", expected_source=None)
        with ExitStack() as stack:
            for name, value in (
                ("source_state", lambda: dict(source)),
                ("source_inventory", lambda: {"unit": "unchanged"}),
                ("build", build), ("measure_training", training),
                ("calibrate_controllers", lambda *args: args[-1].update(
                    controller_calibration={"actual_total_ns": 0})),
                ("execute_policies", lambda *unused: None),
                ("evaluate", lambda *unused: {"performance_gate_passed": True,
                                              "service_scope_net_ndu_benefit_established": True}),
            ):
                stack.enter_context(patch.object(native, name, value))
            # Avoid changing the test process's actual affinity in this unit control.
            if hasattr(native.os, "sched_getaffinity"):
                stack.enter_context(patch.object(native.os, "sched_setaffinity"))
            stack.enter_context(patch("tools.qualify_hia_ndu_stateful.translation_refusal_probe",
                                      return_value=({"status": "actual-refusal-observed"}, None)))
            return native.qualify(args)

    def assert_campaign_refuses_drift(self, name):
        with tempfile.TemporaryDirectory() as directory:
            report = self.campaign(Path(directory), name)
        self.assertTrue(report["source_unchanged"])
        self.assertEqual(report["status"], "failed", report)
        self.assertFalse(report["acceptance_observation_valid"])
        self.assertNotIn("acceptance", report)

    def test_library_drift_with_unchanged_source_withdraws_acceptance(self):
        self.assert_campaign_refuses_drift("hia")

    def test_driver_drift_with_unchanged_source_withdraws_acceptance(self):
        self.assert_campaign_refuses_drift("driver")

    def test_compiler_drift_with_unchanged_source_withdraws_acceptance(self):
        self.assert_campaign_refuses_drift("clang")

    def test_matching_build_inputs_keep_the_scoped_observation_valid(self):
        with tempfile.TemporaryDirectory() as directory:
            report = self.campaign(Path(directory))
        self.assertEqual(report["status"], "completed", report)
        self.assertTrue(report["acceptance_observation_valid"])

    def test_replaced_library_refuses_before_load_dispatch(self):
        with tempfile.TemporaryDirectory() as directory:
            library = Path(directory) / "c.so"
            library.write_bytes(b"original")
            products = {"c": native.file_identity(library)}
            library.write_bytes(b"modified")
            owner = native.Driver.__new__(native.Driver)
            owner.loaded, owner.path_ids = set(), {}
            with patch.object(owner, "ask", return_value={"loaded": 0}) as dispatch, \
                    patch.object(owner, "mapping", return_value={"mapped_bytes": 4096}):
                with self.assertRaisesRegex(ValueError, "identity"):
                    owner.load("c", products)
            dispatch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
