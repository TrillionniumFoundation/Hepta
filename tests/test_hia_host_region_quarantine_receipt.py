"""P7 quarantining a completed native worker needs an acknowledged quarantine event.

This is a real Clang C worker plus intentionally injected, in-process receipt
failures. It is NOT evidence of physical power loss or durable recovery.
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
    NativeRegionLibrary, TrustedRegionContract
)

path, digest, stage = sys.argv[1:]
region = HostRegion(7, max_leases=2, max_native_calls=2)
library = NativeRegionLibrary(
    path, digest, TrustedRegionContract((("region_fill", "write"),), True)
)
original_event = region._event
injected = []

def interrupted_quarantine(kind, **fields):
    if kind == "native_returned" and "native_returned" not in injected:
        # Only reached after the genuine C worker has completed, joined and
        # returned a zero native status through the owned runtime.
        injected.append("native_returned")
        raise RuntimeError("controlled native completion receipt loss")
    if kind == "quarantined" and "quarantined" not in injected:
        injected.append("quarantined")
        if stage == "post_event":
            original_event(kind, **fields)
        raise RuntimeError("controlled quarantine receipt loss")
    return original_event(kind, **fields)

with patch.object(region, "_event", side_effect=interrupted_quarantine):
    try:
        region.call(library, "region_fill", generation=0, argument=13)
    except BaseException as error:
        failure = error
    else:
        raise AssertionError("failed native and quarantine receipts were accepted")

assert injected == ["native_returned", "quarantined"], injected
assert isinstance(failure, HostRegionUncertain), (
    "unreceipted quarantine leaked an unnormalized error: " + repr(failure)
)
state = region.snapshot()
assert state["state"] == "permanent_deny", state
assert region._unprovable_quiescence is True, state
assert state["generation"] > 0, state
assert state["read_leases"] == state["write_leases"] == state["native_jobs"] == 0, state
assert state["observed_mapping_permissions"] == "---s", state
assert any(e["kind"] == "worker_join_confirmed" for e in state["events"]), state
assert library.snapshot()["active_calls"] == 0, library.snapshot()

# Neither a second admission nor recovery nor unmapping may bless missing
# audit evidence. The region remains retained until the process is retired.
for action in (
    lambda: region.borrow("read", generation=state["generation"]),
    lambda: region.recover(timeout=1),
    lambda: region.close(),
):
    try:
        action()
    except HostRegionRejected:
        pass
    else:
        raise AssertionError("unreceipted quarantine permitted reuse or unmapping")

library.close()  # The already joined C worker has no remaining code pin.
print("PASS native+quarantine double receipt loss permanently fenced", stage)
'''




if __name__ == "__main__":
    unittest.main()
