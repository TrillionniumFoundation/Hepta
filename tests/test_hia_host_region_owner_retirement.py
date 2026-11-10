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




if __name__ == "__main__":
    unittest.main()
