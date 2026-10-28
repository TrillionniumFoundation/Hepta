"""Actual isolated limits on this host; synthetic Darwin policy is not host qualification."""
from pathlib import Path
import copy
import json
import os
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hepta import c_parameter_types as worker
from hepta.clang_capture import run_bounded
from tools.preflight_c_original_types import check_process_limits


class OriginalTypeProcessLimits(unittest.TestCase):
    def fake_resource(self, memory=(-1, -1), file_size=(-1, -1)):
        state = {1: memory, 2: file_size}
        calls = []
        def set_limit(kind, pair):
            calls.append((kind, pair))
            state[kind] = pair
        return SimpleNamespace(RLIM_INFINITY=-1, RLIMIT_AS=1, RLIMIT_FSIZE=2,
                               getrlimit=lambda kind: state[kind], setrlimit=set_limit), state, calls

    def test_actual_isolated_process_probe_enforces_and_reports_this_hosts_limits(self):
        result = run_bounded([sys.executable, "-I", str(Path(worker.__file__).resolve()),
                              "--process-limits"], timeout=10, stdin_limit=0,
                             stdout_limit=128_000, stderr_limit=128_000)
        self.assertEqual(result.returncode, 0, result.stderr)
        observed = json.loads(result.stdout)
        self.assertEqual(observed["platform"], sys.platform)
        self.assertIs(observed["whole_process_rss_bounded"], False)
        check_process_limits(observed)
        for key in ("address_space", "file_size"):
            altered = copy.deepcopy(observed)
            if os.name == "posix":
                altered[key]["after"][1] = altered[key]["requested_bytes"] + 1
            else:
                altered[key]["mode"] = "enforced_and_read_back"
            with self.assertRaises(ValueError):
                check_process_limits(altered)

    def test_inherited_soft_or_hard_limits_are_never_increased(self):
        for before, expected in (((-1, -1), 1024), ((700, 900), 700),
                                 ((-1, 500), 500), ((0, 200), 0)):
            with self.subTest(before=before):
                resource, state, calls = self.fake_resource(memory=before)
                result = worker._enforce_process_limit(resource, 1, 1024, "RLIMIT_AS")
                self.assertEqual(result["before"], list(before))
                self.assertEqual(result["after"], [expected, expected])
                self.assertEqual(state[1], (expected, expected))

    def test_kernel_refusal_and_ineffective_readback_cannot_become_success(self):
        resource, state, calls = self.fake_resource()
        def refuse(kind, pair):
            raise ValueError("current usage exceeds requested VM limit")
        resource.setrlimit = refuse
        with self.assertRaisesRegex(ValueError, "original-type process limit failed") as caught:
            worker._enforce_process_limit(resource, 1, 1024, "RLIMIT_AS")
        details = json.loads(str(caught.exception).split(": ", 1)[1])
        self.assertEqual(details["before"], [-1, -1])
        self.assertEqual(details["applied_pair"], [1024, 1024])
        self.assertEqual(details["after"], [-1, -1])
        self.assertEqual(state[1], (-1, -1))
        resource.setrlimit = lambda kind, pair: None
        with self.assertRaisesRegex(ValueError, "readback mismatch"):
            worker._enforce_process_limit(resource, 1, 1024, "RLIMIT_AS")

    def test_infinity_and_noninteger_requests_reject_before_setting_limits(self):
        resource, state, calls = self.fake_resource()
        for infinity in (-1, (1 << 63) - 1):
            resource.RLIM_INFINITY = infinity
            for requested in (infinity, True, -2, float("inf"), 1024.0):
                with self.subTest(infinity=infinity, requested=requested):
                    with self.assertRaisesRegex(ValueError, "finite nonnegative"):
                        worker._enforce_process_limit(resource, 1, requested, "RLIMIT_AS")
        self.assertEqual(calls, [])

    def test_darwin_policy_limits_growth_without_raising_inherited_limits(self):
        baseline, growth = 40 << 30, 2 << 30
        for inherited, expected in (((-1, -1), baseline + growth),
                                     ((baseline + 1024, baseline + 2048), baseline + 1024)):
            with self.subTest(inherited=inherited):
                resource, state, calls = self.fake_resource(memory=inherited)
                with patch.object(worker, "os", SimpleNamespace(name="posix")), \
                        patch.object(worker.sys, "platform", "darwin"), \
                        patch.object(worker, "_darwin_virtual_size", return_value=baseline), \
                        patch.dict(sys.modules, {"resource": resource}):
                    result = worker._set_process_limits()
                    check_process_limits(result)
                self.assertEqual(result["address_space"]["baseline_virtual_bytes"], baseline)
                self.assertEqual(result["address_space"]["growth_budget_bytes"], growth)
                self.assertEqual(state[1], (expected, expected))
                self.assertEqual(state[2], (worker.MAX_AST_BYTES, worker.MAX_AST_BYTES))
                self.assertIs(result["whole_process_rss_bounded"], False)


if __name__ == "__main__":
    unittest.main()
