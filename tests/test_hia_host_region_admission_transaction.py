"""Linux memfd/Clang regression: post-grant bookkeeping failures are atomic.

The original #531 source mprotects the mapping, then registers a lease and
records a borrowed event without rollback on an exception. A failed registry
write or audit event must not strand an inaccessible capability and writable
kernel pages. Injection is limited to the Python bookkeeping boundary; page
permissions and the subsequent C call are observed on a real Linux host.
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
region = HostRegion(7, max_leases=3, max_native_calls=2)
library = NativeRegionLibrary(path, digest, TrustedRegionContract((("region_fill", "write"),), True))

class RefusingGrants(dict):
    def __setitem__(self, key, value):
        raise RuntimeError("owner grant registration refused")

def operation():
    if scenario.startswith("native"):
        region.call(library, "region_fill", generation=0, argument=13)
    else:
        region.borrow("write", generation=0)

if scenario == "read-peer-event":
    anchor = region.borrow("read", generation=0)
    with patch.object(region, "_event", side_effect=RuntimeError("borrow receipt refused")):
        try:
            region.borrow("read", generation=0)
        except RuntimeError as error:
            assert str(error) == "borrow receipt refused", repr(error)
        else:
            raise AssertionError("audit receipt fault was not injected")
    state = region.snapshot()
    assert state["state"] == "ready", state
    assert state["read_leases"] == 1 and state["write_leases"] == 0, state
    assert state["permission"] == "read" and state["observed_mapping_permissions"] == "r--s", state
    anchor.close()
elif scenario.endswith("-registry"):
    original = region._lease_grants
    region._lease_grants = RefusingGrants(original)
    try:
        operation()
    except RuntimeError as error:
        assert str(error) == "owner grant registration refused", repr(error)
    else:
        raise AssertionError("registry fault was not injected")
    finally:
        region._lease_grants = dict(region._lease_grants)
elif scenario.endswith("-event"):
    with patch.object(region, "_event", side_effect=RuntimeError("borrow receipt refused")):
        try:
            operation()
        except RuntimeError as error:
            assert str(error) == "borrow receipt refused", repr(error)
        else:
            raise AssertionError("audit receipt fault was not injected")
else:
    raise AssertionError("unknown post-grant fault scenario")

state = region.snapshot()
assert state["state"] == "ready", state
assert state["read_leases"] == state["write_leases"] == state["native_jobs"] == 0, state
assert state["permission"] == "none" and state["observed_mapping_permissions"] == "---s", state
assert library.snapshot()["active_calls"] == 0, library.snapshot()
with region.borrow("write", generation=0) as lease:
    lease.write(b"1234567")
assert region.call(library, "region_fill", generation=0, argument=13) == sum(range(13, 20))
region.close()
library.close()
print("PASS atomic admission, no unowned page and subsequent real C call", scenario)
'''




if __name__ == "__main__":
    unittest.main()
