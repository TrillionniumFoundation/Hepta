"""Adversarial process-wide owner-registry identity checks on real Linux memfd+C.

Injected entropy collisions or malformed outputs must be rejected before
registration, preserving the existing live owner and its retained accounting.
These are deterministic fault injections, not claims about OS RNG behavior.
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
from unittest.mock import patch
from hepta.hia_host_region import (
    HostRegion, HostRegionRejected, NativeRegionLibrary,
    TrustedRegionContract, retained_host_regions,
)

path, digest, scenario = sys.argv[1:]
region = HostRegion(7, max_leases=3, max_native_calls=2)
contract = TrustedRegionContract(
    (("region_fill", "write"), ("region_sum", "read")), True
)
library = NativeRegionLibrary(path, digest, contract)
before = retained_host_regions()
assert len(before["regions"]) == len(before["libraries"]) == 1, before

def reject_new_owner(create, expected):
    try:
        create()
    except HostRegionRejected as error:
        assert expected in str(error), repr(error)
    else:
        raise AssertionError("malformed/repeated global owner identity was admitted")

if scenario == "region-duplicate":
    with patch("hepta.hia_host_region.secrets.token_hex", return_value=region._token):
        reject_new_owner(lambda: HostRegion(7), "region identity")
elif scenario == "library-duplicate":
    with patch("hepta.hia_host_region.secrets.token_hex", return_value=library._token):
        reject_new_owner(lambda: NativeRegionLibrary(path, digest, contract), "library identity")
elif scenario == "region-malformed":
    with patch("hepta.hia_host_region.secrets.token_hex", return_value=None):
        reject_new_owner(lambda: HostRegion(7), "region identity")
elif scenario == "library-malformed":
    with patch("hepta.hia_host_region.secrets.token_hex", return_value=None):
        reject_new_owner(lambda: NativeRegionLibrary(path, digest, contract), "library identity")
else:
    raise AssertionError("unknown scenario " + scenario)

# Registry must retain BOTH originals, not a shadow duplicate.
after = retained_host_regions()
assert len(after["regions"]) == len(after["libraries"]) == 1, after
assert after["regions"][0]["state"] == "ready", after
assert after["libraries"][0]["artifact_sha256"] == digest, after
with region.borrow("write", generation=0) as grant:
    grant.write(b"1234567")
assert region.call(library, "region_fill", generation=0, argument=13) == sum(range(13, 20))
assert region.snapshot()["observed_mapping_permissions"] == "---s"
region.close()
library.close()
end = retained_host_regions()
assert not end["regions"] and not end["libraries"], end
print("PASS strict global owner registration, native C execution, complete release", scenario)
'''




if __name__ == "__main__":
    unittest.main()
