"""P7: a failed lease-admission rollback must not leave writable unowned pages.

The probe first runs a real Linux/Clang C memfd worker. Faults are controlled
process-local failures (borrowed audit and rollback mprotect observation), not
natural kernel failures or power-cut recovery evidence.
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
assert region.call(library, "region_fill", generation=0, argument=13) == sum(range(13, 20))
assert library.snapshot()["active_calls"] == 0
assert region.snapshot()["observed_mapping_permissions"] == "---s"
previous_event = region._event
previous_protect = region._protect
audit_failures = []
revoke_failures = []

def failed_borrow_event(kind, **fields):
    if kind == "borrowed" and not audit_failures:
        audit_failures.append(kind)
        # No authoritative borrowed receipt: simulates failure before append.
        raise OSError("controlled lease admission audit receipt failure")
    return previous_event(kind, **fields)

def failed_rollback(permission):
    if permission == "none" and not revoke_failures:
        revoke_failures.append(permission)
        if stage == "post_revoke":
            # Kernel mprotect genuinely succeeds; its host receipt is lost.
            previous_protect(permission)
        # Before-kernel stage leaves the mapped page writable.
        raise OSError("controlled rollback page revocation receipt loss")
    return previous_protect(permission)

with patch.object(region, "_event", side_effect=failed_borrow_event), \
     patch.object(region, "_protect", side_effect=failed_rollback):
    try:
        region.borrow("write", generation=0)
    except BaseException as error:
        failure = error
    else:
        raise AssertionError("unreceipted admission rollback was accepted")

assert audit_failures == ["borrowed"], audit_failures
assert revoke_failures == ["none"], revoke_failures
assert isinstance(failure, HostRegionUncertain), (
    "rollback lost the real error boundary: " + repr(failure)
)
state = region.snapshot()
assert state["state"] == "permanent_deny", state
assert region._unprovable_quiescence is True, state
assert state["generation"] > 0, state
assert state["read_leases"] == state["write_leases"] == state["native_jobs"] == 0, state
assert state["observed_mapping_permissions"] == (
    "rw-s" if stage == "pre_revoke" else "---s"
), state
assert any(e["kind"] == "quarantined" for e in state["events"]), state
assert library.snapshot()["active_calls"] == 0

for operation in (
    lambda: region.borrow("read", generation=state["generation"]),
    lambda: region.call(library, "region_fill", generation=state["generation"], argument=13),
    lambda: region.recover(timeout=1),
    lambda: region.close(),
):
    try:
        operation()
    except HostRegionRejected:
        pass
    else:
        raise AssertionError("unreceipted rollback admitted execution/recovery/unmapping")

library.close()
print("PASS admission rollback page rights uncertainty permanently denied", stage)
'''




if __name__ == "__main__":
    unittest.main()
