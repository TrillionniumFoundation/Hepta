"""P7: ambiguous native code-pin retirement after a *completed* C worker must fence both owners.

Real Linux memfd and Clang C worker run before controlled pre/post decrement faults.
This only proves process-local fault containment; it is not power-cut or durable recovery.
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
# One normal genuine C execution establishes the fixture and baseline pin lifecycle.
assert region.call(library, "region_fill", generation=0, argument=13) == sum(range(13, 20))
assert region.snapshot()["observed_mapping_permissions"] == "---s"
assert library.snapshot()["active_calls"] == 0

original_finish = library._finish
attempts = []

def interrupted_finish():
    attempts.append("finish")
    if stage == "post_decrement":
        original_finish()
    # _finish is called only after the second owned native worker has joined.
    raise OSError("controlled post-worker code pin retirement receipt loss")

with patch.object(library, "_finish", side_effect=interrupted_finish):
    try:
        region.call(library, "region_fill", generation=0, argument=13)
    except BaseException as error:
        failure = error
    else:
        raise AssertionError("unreceipted native pin retirement committed")

assert attempts == ["finish"], attempts
assert isinstance(failure, HostRegionUncertain), repr(failure)
state = region.snapshot()
assert state["state"] == "permanent_deny", state
assert state["generation"] > 0, state
assert region._unprovable_quiescence is True, state
assert state["observed_mapping_permissions"] == "---s", state
assert state["native_jobs"] == 1 and state["live_native_workers"] == 0, state
assert state["write_leases"] == state["read_leases"] == 0, state
lib_state = library.snapshot()
assert lib_state["retirement_uncertain"] is True, lib_state
assert lib_state["active_calls"] == (1 if stage == "pre_decrement" else 0), lib_state

# Even if a post-decrement fault makes active_calls zero, the library is NOT
# safe to unload, reuse from another HostRegion, or retry numeric _finish().
for op in (
    lambda: library._acquire("region_fill"),
    lambda: library.close(),
    lambda: region.borrow("read", generation=state["generation"]),
    lambda: region.call(library, "region_fill", generation=state["generation"], argument=13),
    lambda: region.recover(timeout=1),
    lambda: region.close(),
):
    try:
        op()
    except HostRegionRejected:
        pass
    else:
        raise AssertionError("completed native pin with unconfirmed retirement was reused")

assert attempts == ["finish"], attempts
print("PASS completed C worker code pin retirement permanently fenced", stage)
'''




if __name__ == "__main__":
    unittest.main()
