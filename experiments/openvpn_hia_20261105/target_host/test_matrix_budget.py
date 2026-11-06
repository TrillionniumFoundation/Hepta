#!/usr/bin/env python3
"""Fail before privileged target work if the frozen 54-case/216-workload plan cannot fit its budget.

The #749 exact-head artifact reached the 1,800-second deadline after 42 performance
cases. Those cases had a 39.94-second median wall span; this contract reserves 30
seconds of setup/inspection per performance case in addition to every fixed
iperf workload duration, plus a separate 600-second non-performance allowance.
"""
import json
import re
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PLAN = json.loads((HERE / "plan.json").read_text())
WORKFLOW = (ROOT / ".github/workflows/hia-openvpn-target-host.yml").read_text()
RUNNER = (HERE / "run_matrix.py").read_text()


class MatrixBudgetTests(unittest.TestCase):
    def test_budget_covers_every_fixed_workload_and_case_reserve(self):
        performance = PLAN["performance"]
        case_count = performance["expected_case_count"]
        workload_count = len(performance["workloads"])
        self.assertEqual(
            performance["expected_workload_count"],
            case_count * workload_count,
        )
        self.assertGreaterEqual(performance["case_setup_reserve_seconds"], 30)
        self.assertGreaterEqual(performance["non_performance_reserve_seconds"], 600)
        minimum = (
            case_count
            * (
                workload_count * performance["seconds_per_workload"]
                + performance["case_setup_reserve_seconds"]
            )
            + performance["non_performance_reserve_seconds"]
        )
        self.assertGreaterEqual(
            PLAN["budget_seconds"],
            minimum,
            f"budget {PLAN['budget_seconds']}s is below full-matrix envelope {minimum}s",
        )

    def test_workflow_and_runner_use_the_same_budget_and_timeout_envelope(self):
        budget = PLAN["budget_seconds"]
        workflow_budget = re.search(r"'--budget-seconds',\s*'(\d+)'", WORKFLOW)
        process_timeout = re.search(r"timeout=(\d+)", WORKFLOW)
        job_timeout = re.search(r"timeout-minutes:\s*(\d+)", WORKFLOW)
        runner_default = re.search(
            r"add_argument\('--budget-seconds',type=int,default=(\d+)\)",
            RUNNER,
        )
        self.assertIsNotNone(workflow_budget)
        self.assertIsNotNone(process_timeout)
        self.assertIsNotNone(job_timeout)
        self.assertIsNotNone(runner_default)
        self.assertEqual(int(workflow_budget.group(1)), budget)
        self.assertEqual(int(runner_default.group(1)), budget)
        self.assertEqual(int(process_timeout.group(1)), budget + 60)
        self.assertGreaterEqual(int(job_timeout.group(1)) * 60, budget + 600)
        self.assertIn("research/openvpn-hia-matrix-budget-20261106", WORKFLOW)


if __name__ == "__main__":
    unittest.main(verbosity=2)
