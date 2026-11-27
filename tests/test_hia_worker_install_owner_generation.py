"""Keep generated native Worker policies synchronized with the complete Store DAG.

These host qualification checks compare the full generated HIA sources. They
caught the actual five-stage Worker owner that omitted the later Store stages;
native stage decisions and the complete installation remain separate gates.
"""
from hashlib import sha256
from pathlib import Path
import unittest

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_worker_install_owner import policy_source

ROOT = Path(__file__).resolve().parents[1]


class WorkerInstallOwnerGenerationTests(unittest.TestCase):
    def assert_current(self, name, source):
        path = ROOT / "examples" / "hia_bootstrap" / (name + ".hepta")
        actual = path.read_bytes()
        expected = render_assembly(document(source, name)).encode()
        self.assertTrue(
            actual == expected,
            f"{name} is stale: actual {sha256(actual).hexdigest()}, "
            f"current full Store and Worker composition {sha256(expected).hexdigest()}",
        )

    def test_worker_owner_keeps_current_store_release_composition(self):
        self.assert_current("worker_install_owner", policy_source())

    def test_worker_dag_keeps_current_store_and_worker_stage_boundaries(self):
        self.assert_current("worker_install_dag", policy_source(stage=True))


if __name__ == "__main__":
    unittest.main()
