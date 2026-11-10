from copy import deepcopy
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch
import unittest



class NativeEconomicsContractTests(unittest.TestCase):







    @staticmethod
    def native_fixture(schedules):
        states = {"empty": {"ready": []}, "cpp": {"ready": ["cpp"]},
                  "rust": {"ready": ["rust"]}, "both": {"ready": ["cpp", "rust"]}}
        plans = {}
        for index, schedule in enumerate(schedules):
            actions, source = [], "empty"
            for target in schedule:
                actions.append({"source": source, "target": target, "status": "verified"})
                source = target
            plans[f"plan-{index}"] = {"verified": True, "actions": actions}
        return ({"plans": plans, "stateful_binding": {"states": states}},
                {"authority": "DENY_ALL", "safety_certificate": False,
                 "advisory_candidate_id": None, "pareto_candidate_ids": list(plans)})








if __name__ == "__main__":
    unittest.main()
