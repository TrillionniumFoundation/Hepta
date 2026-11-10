"""Real Linux memfd/Clang probes: failed lease token must not expose unowned writable pages.

A token-generation failure before a lease is registered cannot authorize any
page-access transition. Covers public host borrowing and internal native call
admission on the unmodified parent source for a reproducible RED baseline.
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

from hepta.hia_host_region import HostRegion, NativeRegionLibrary, TrustedRegionContract

path, digest, scenario = sys.argv[1:]
region = HostRegion(7, max_leases=2, max_native_calls=2)
library = NativeRegionLibrary(path, digest, TrustedRegionContract((("region_fill", "write"),), True))

with patch("hepta.hia_host_region.secrets.token_hex",
           side_effect=RuntimeError("lease identity generation refused")):
    try:
        if scenario == "external":
            region.borrow("write", generation=0)
        elif scenario == "native":
            region.call(library, "region_fill", generation=0, argument=13)
        else:
            raise AssertionError("unknown fault scenario")
    except RuntimeError as exc:
        assert str(exc) == "lease identity generation refused", repr(exc)
    else:
        raise AssertionError("injected lease identity generation did not fail")

state = region.snapshot()
assert state["state"] == "ready", state
assert state["read_leases"] == state["write_leases"] == state["native_jobs"] == 0, state
assert state["permission"] == "none", state
assert state["observed_mapping_permissions"] == "---s", state
assert library.snapshot()["active_calls"] == 0, library.snapshot()

if scenario == "external":
    with region.borrow("write", generation=0) as grant:
        grant.write(b"1234567")
assert region.call(library, "region_fill", generation=0, argument=13) == sum(range(13, 20))
assert region.snapshot()["state"] == "ready"
region.close()
library.close()
print("PASS no unowned writable mapping and exact C reentry", scenario)
'''




if __name__ == "__main__":
    unittest.main()
