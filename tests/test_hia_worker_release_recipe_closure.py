"""Guard the installed Worker's checked HIA policies against release-plan drift."""
from hashlib import sha256
from pathlib import Path
import unittest

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools import generate_hia_worker_install_owner as author

ROOT = Path(__file__).resolve().parents[1]


class WorkerReleaseRecipeClosureTests(unittest.TestCase):
    def test_all_checked_worker_policies_match_the_complete_release_generator(self):
        cases = (
            ("worker_install_owner", author.policy_source()),
            ("worker_install_dag", author.policy_source(stage=True)),
            ("worker_install_owner_packer", author.packer_source()),
        )
        for name, source in cases:
            with self.subTest(policy=name):
                expected = render_assembly(document(source, name)).encode()
                actual = (ROOT / "examples/hia_bootstrap" / (name + ".hepta")).read_bytes()
                self.assertTrue(
                    actual == expected,
                    f"{name}: checked {len(actual)} bytes / {sha256(actual).hexdigest()} "
                    f"differs from current release plan {len(expected)} bytes / "
                    f"{sha256(expected).hexdigest()}",
                )


if __name__ == "__main__":
    unittest.main()
