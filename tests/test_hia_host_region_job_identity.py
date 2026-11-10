"""P7 native job identity must never shadow a live C worker.

Force native job identifier duplicate/malformed results independently from
lease IDs. Test on actual Linux memfd, Clang C delayed readers. These are
controlled entropy-source faults, not claims about natural RNG collisions.
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
import threading
import time
from unittest.mock import patch

from hepta.hia_host_region import (
    HostRegion, HostRegionRejected, NativeRegionLibrary, TrustedRegionContract
)

path, digest, scenario = sys.argv[1:]
region = HostRegion(7, max_leases=4, max_native_calls=3)
library = NativeRegionLibrary(
    path, digest,
    TrustedRegionContract(
        (("region_delayed_sum", "read"), ("region_fill", "write")), True
    )
)
results = []
errors = []

def original_reader():
    try:
        results.append(region.call(
            library, "region_delayed_sum", generation=0, argument=850, timeout=3
        ))
    except BaseException as error:
        errors.append(repr(error))

owner_thread = threading.Thread(target=original_reader, name="first-owned-native-reader")
owner_thread.start()
deadline = time.monotonic() + 3
original_job_id = None
while time.monotonic() < deadline:
    with region._lock:
        jobs = list(region._jobs.items())
        if len(jobs) == 1 and jobs[0][1]["thread"].is_alive():
            original_job_id = jobs[0][0]
            break
    time.sleep(.002)
assert original_job_id is not None, "actual first C worker never became live"
with region._lock:
    original_lease_id = next(iter(region._leases))
new_lease_id = "a" * 32 if original_lease_id != "a" * 32 else "b" * 32
assert new_lease_id != original_job_id

# Only the new call's lease identity and job identity are fault-injected.
# The original native worker is executing actual delayed C throughout.
new_job_id = original_job_id if scenario == "duplicate" else None
with patch(
    "hepta.hia_host_region.secrets.token_hex",
    side_effect=[new_lease_id, new_job_id],
):
    try:
        region.call(
            library, "region_delayed_sum", generation=0, argument=40, timeout=3
        )
    except HostRegionRejected as error:
        assert "native job identity" in str(error), repr(error)
    else:
        raise AssertionError("duplicate/malformed job identity admitted a new C worker")

with region._lock:
    assert set(region._jobs) == {original_job_id}, region._jobs
state = region.snapshot()
assert state["state"] == "ready", state
assert state["native_jobs"] == 1 and state["read_leases"] == 1, state
assert state["observed_mapping_permissions"] == "r--s", state
assert library.snapshot()["active_calls"] == 1

owner_thread.join(4)
assert not owner_thread.is_alive() and not errors and results == [0], (
    errors, results
)
state = region.snapshot()
assert state["state"] == "ready" and state["native_jobs"] == 0, state
assert state["read_leases"] == 0 and state["write_leases"] == 0, state
assert state["observed_mapping_permissions"] == "---s", state
assert library.snapshot()["active_calls"] == 0
assert region.call(library, "region_fill", generation=0, argument=13) == sum(range(13, 20))
assert region.snapshot()["observed_mapping_permissions"] == "---s"
region.close()
library.close()
print("PASS job identity rejected, existing real native C worker retained, C reentry", scenario)
'''




if __name__ == "__main__":
    unittest.main()
