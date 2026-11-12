"""P7: mutable owner labels must never retire another live registered owner.

Each subprocess uses real Linux memfd mappings and a Clang-built C fixture.
We mutate only the exposed Python owner label after successful registration.
The registry must identify the owner by object identity, not by that label.
"""
from __future__ import annotations

import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest

from tests.hia_host_region_fixture import build_fixture


PROBE = r'''
import sys
from hepta.hia_host_region import (
    HostRegion, NativeRegionLibrary, TrustedRegionContract, retained_host_regions,
)

path, digest, scenario = sys.argv[1:]
contract = TrustedRegionContract((("region_fill", "write"),), True)
is_region = scenario.startswith("region-")
is_collision = scenario.endswith("-collision")
if is_region:
    retiring = HostRegion(7)
    survivor = HostRegion(7)
    library = NativeRegionLibrary(path, digest, contract)
    start = retained_host_regions()
    assert len(start["regions"]) == 2 and len(start["libraries"]) == 1, start
    retiring._token = survivor._token if is_collision else None
    retiring.close()
    after = retained_host_regions()
    assert len(after["regions"]) == 1 and after["regions"][0]["state"] == "ready", after
    assert len(after["libraries"]) == 1, after
    assert survivor.call(library, "region_fill", generation=0, argument=13) == sum(range(13, 20))
    assert survivor.snapshot()["observed_mapping_permissions"] == "---s"
    survivor.close()
    library.close()
else:
    region = HostRegion(7)
    retiring = NativeRegionLibrary(path, digest, contract)
    survivor = NativeRegionLibrary(path, digest, contract)
    start = retained_host_regions()
    assert len(start["regions"]) == 1 and len(start["libraries"]) == 2, start
    retiring._token = survivor._token if is_collision else None
    retiring.close()
    after = retained_host_regions()
    assert len(after["libraries"]) == 1 and not after["libraries"][0]["closed"], after
    assert len(after["regions"]) == 1, after
    assert region.call(survivor, "region_fill", generation=0, argument=13) == sum(range(13, 20))
    assert region.snapshot()["observed_mapping_permissions"] == "---s"
    region.close()
    survivor.close()
end = retained_host_regions()
assert not end["regions"] and not end["libraries"], end
print("PASS retained owner identity and real C execution", scenario)
'''


class OwnerRetirementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if platform.system() != "Linux" or platform.machine() not in {"x86_64", "amd64"}:
            raise AssertionError("actual Linux x86-64 required; no silent skip")
        compiler = shutil.which(os.environ.get("HEPTA_TEST_CLANG", "clang"))
        if not compiler:
            raise AssertionError("actual Clang required; no silent skip")
        cls.temp = tempfile.TemporaryDirectory()
        cls.path, cls.digest = build_fixture(Path(cls.temp.name), Path(compiler).resolve(), {})

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def _check(self, scenario):
        result = subprocess.run(
            [sys.executable, "-B", "-c", PROBE, str(self.path), self.digest, scenario],
            capture_output=True, text=True, timeout=25, check=False,
        )
        self.assertEqual(
            result.returncode, 0,
            f"scenario={scenario} stdout={result.stdout}\nstderr={result.stderr}",
        )
        self.assertIn("PASS retained owner identity", result.stdout)

    def test_region_identity_collision_does_not_retire_other_memfd_owner(self):
        self._check("region-collision")

    def test_region_malformed_mutation_does_not_leak_closed_owner(self):
        self._check("region-malformed")

    def test_library_identity_collision_does_not_retire_other_native_code(self):
        self._check("library-collision")

    def test_library_malformed_mutation_does_not_leak_closed_owner(self):
        self._check("library-malformed")


if __name__ == "__main__":
    unittest.main()
