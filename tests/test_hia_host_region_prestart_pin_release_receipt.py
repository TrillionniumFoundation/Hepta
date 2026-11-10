"""P7: an uncertain prestart native code-pin retirement must fence both owners.

The real Linux memfd/Clang C entry executes once before controlled pre/post
decrement native pin-retirement receipt faults. No power-cut assertion.
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
    HostRegion, HostRegionRejected, HostRegionUncertain,
    NativeRegionLibrary, TrustedRegionContract,
)

path, digest, stage = sys.argv[1:]
region = HostRegion(7, max_leases=2, max_native_calls=2)
library = NativeRegionLibrary(
    path, digest, TrustedRegionContract((("region_fill", "write"),), True)
)
# Witness genuine C execution and a balanced code owner before the injection.
assert region.call(library, "region_fill", generation=0, argument=13) == sum(range(13, 20))
assert region.snapshot()["observed_mapping_permissions"] == "---s"
assert library.snapshot()["active_calls"] == 0

original_finish = library._finish
events = []

def failed_finish():
    events.append("finish")
    if stage == "post_decrement":
        original_finish()
    raise OSError("controlled prestart code owner release receipt loss")

# Fresh lease ID then invalid native-job ID => no worker is constructed/started.
# The library has already acquired its active code pin.
with patch("hepta.hia_host_region.secrets.token_hex", side_effect=["e" * 32, None]):
    with patch.object(library, "_finish", side_effect=failed_finish):
        try:
            region.call(library, "region_fill", generation=0, argument=13)
        except BaseException as error:
            failure = error
        else:
            raise AssertionError("invalid job token admitted a native worker")

assert events == ["finish"], events
assert isinstance(failure, HostRegionUncertain), (
    "prestart library finish escaped without a fail-closed receipt: " + repr(failure)
)
state = region.snapshot()
assert state["state"] == "permanent_deny", state
assert state["generation"] > 0, state
assert region._unprovable_quiescence is True, state
assert state["native_jobs"] == state["write_leases"] == state["read_leases"] == 0, state
assert state["observed_mapping_permissions"] == "---s", state
assert library.snapshot()["retirement_uncertain"] is True, library.snapshot()
assert library.snapshot()["active_calls"] == (1 if stage == "pre_decrement" else 0)

for op in (
    lambda: region.borrow("read", generation=state["generation"]),
    lambda: region.call(library, "region_fill", generation=state["generation"], argument=13),
    lambda: region.recover(timeout=1),
    lambda: region.close(),
    lambda: library._acquire("region_fill"),
    lambda: library.close(),
):
    try:
        op()
    except HostRegionRejected:
        pass
    else:
        raise AssertionError("unreceipted native pin release admitted reuse/recovery/unmapping")

print("PASS prestart native code retirement permanently denied", stage)
'''




if __name__ == "__main__":
    unittest.main()
