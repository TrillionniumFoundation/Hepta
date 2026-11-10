"""P7: unreceipted recovery mprotect must permanently fence owner and mapping.

A real Clang C worker runs on Linux memfd before a deliberately lost native
return receipt quarantines the region. Each new case injects a process-local
mprotect-result failure before/after the actual syscall during the subsequent
recovery's write-admission or final PROT_NONE revocation. This is neither a
kernel fault observation nor physical crash/restart qualification.
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
phase, timing = stage.split("_", 1)
assert phase in {"write", "none"} and timing in {"before", "after"}

region = HostRegion(7, max_leases=3, max_native_calls=2)
library = NativeRegionLibrary(
    path, digest, TrustedRegionContract((("region_fill", "write"),), True)
)
original_event = region._event
lost = []

def lose_return_receipt(kind, **fields):
    if kind == "native_returned" and not lost:
        lost.append(kind)
        raise OSError("controlled native return receipt loss")
    return original_event(kind, **fields)

with patch.object(region, "_event", side_effect=lose_return_receipt):
    try:
        region.call(library, "region_fill", generation=0, argument=13)
    except HostRegionUncertain:
        pass
    else:
        raise AssertionError("unreceipted real C result unexpectedly committed")
assert lost == ["native_returned"], lost
before = region.snapshot()
assert before["state"] == "quarantined", before
assert before["observed_mapping_permissions"] == "---s", before
assert before["native_jobs"] == before["write_leases"] == 0, before
assert library.snapshot()["active_calls"] == 0

original_protect = region._protect
injected = []

def lose_recovery_protection_receipt(permission):
    if permission == phase and not injected:
        injected.append(permission)
        if timing == "after":
            original_protect(permission)
        # This models a lost mprotect outcome, not an actual syscall errno.
        raise OSError("controlled recovery protection receipt loss: " + stage)
    return original_protect(permission)

with patch.object(region, "_protect", side_effect=lose_recovery_protection_receipt):
    try:
        region.recover(timeout=2)
    except BaseException as error:
        failure = error
    else:
        raise AssertionError("unreceipted recovery mprotect committed")

assert injected == [phase], injected
state = region.snapshot()
expected_permissions = (
    "---s" if stage in {"write_before", "none_after"} else "rw-s"
)
print("controlled_recovery_protection_fault", stage, type(failure).__name__,
      state["state"], state["observed_mapping_permissions"], flush=True)
assert isinstance(failure, HostRegionUncertain), repr(failure)
assert state["state"] == "permanent_deny", state
assert region._unprovable_quiescence is True, state
assert state["generation"] > before["generation"], (before, state)
assert state["observed_mapping_permissions"] == expected_permissions, state
assert state["read_leases"] == state["write_leases"] == state["native_jobs"] == 0, state
assert any(e["kind"] == "quarantined" and e.get("permanent")
           for e in state["events"]), state

# The physical mapping may still be RW, so unmapping and reuse are forbidden.
for action in (
    lambda: region.borrow("read", generation=state["generation"]),
    lambda: region.call(library, "region_fill",
                        generation=state["generation"], argument=13),
    lambda: region.recover(timeout=2),
    lambda: region.close(),
):
    try:
        action()
    except HostRegionRejected:
        pass
    else:
        raise AssertionError("ambiguous mprotect allowed reuse/recovery/unmap")

assert library.snapshot()["active_calls"] == 0
library.close()
print("PASS real C worker and unreceipted recovery mprotect fail closed", stage)
'''




if __name__ == "__main__":
    unittest.main()
