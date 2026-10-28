"""Bind resolved native entry addresses to the exact sealed Linux file object.

The dynamic loader may retain a pathname cache after its numeric memfd has
closed. Reusing /proc/self/fd/N can consequently return a previous library.
Hashing the new descriptor alone does not identify the code returned by dlsym.
This local admission check requires every resolved entry to be in a nonwritable
executable mapping of the still-open, fully sealed descriptor. It does not grant
authority to serialized evidence or defend a malicious Python host/kernel.
"""
from __future__ import annotations

import ctypes
import os
import stat
import sys

_MAX_MAPS_BYTES = 16 * 1024 * 1024


class NativeMappingRejected(ValueError):
    pass


def verify_loaded_symbols(fd, symbols):
    """Observe actual loaded entries before any native function is invoked.

    The caller retains both the descriptor and its own dlopen reference until
    all native calls finish. No mutable publication pathname or memfd display
    name is used as identity. Missing kernel evidence is a refusal.
    """
    def reject(reason):
        raise NativeMappingRejected("E_NATIVE_MAPPING: " + reason)

    if sys.platform != "linux" or type(fd) is not int or fd < 0:
        reject("qualified Linux descriptor required")
    if (type(symbols) is not dict or not 1 <= len(symbols) <= 128
            or any(type(name) is not str or not name or len(name) > 512 for name in symbols)):
        reject("bounded explicit native symbol set required")
    try:
        import fcntl
        initial = os.fstat(fd)
        # Linux UAPI values, also used by the artifact-sealing path. A Python
        # build may omit these names while the running kernel supports them;
        # the actual kernel readback remains mandatory and fail-closed.
        required = 0x0008 | 0x0004 | 0x0002 | 0x0001
        get_seals = getattr(fcntl, "F_GET_SEALS", 1034)
        seals = fcntl.fcntl(fd, get_seals)
        if not stat.S_ISREG(initial.st_mode) or initial.st_size <= 0 or seals & required != required:
            reject("native descriptor is not a fully sealed nonempty regular file")
        expected_device = (os.major(initial.st_dev), os.minor(initial.st_dev))
        addresses = {}
        for name, function in symbols.items():
            if not isinstance(function, ctypes._CFuncPtr):
                reject("resolved entry is not a native function")
            address = ctypes.cast(function, ctypes.c_void_p).value
            if not address:
                reject("resolved native entry has a null address")
            addresses[name] = address
        with open("/proc/self/maps", "rb") as handle:
            contents = handle.read(_MAX_MAPS_BYTES + 1)
        if len(contents) > _MAX_MAPS_BYTES:
            reject("process mapping inventory exceeds its bound")
        matches = {name: [] for name in symbols}
        for line in contents.splitlines():
            fields = line.split(None, 5)
            if len(fields) < 5:
                reject("incomplete kernel mapping record")
            bounds = fields[0].split(b"-")
            device = fields[3].split(b":")
            if len(bounds) != 2 or len(device) != 2:
                reject("unrecognized kernel mapping record")
            lower, upper = (int(value, 16) for value in bounds)
            offset = int(fields[2], 16)
            major, minor = (int(value, 16) for value in device)
            inode = int(fields[4], 10)
            permissions = fields[1].decode("ascii")
            if not 0 <= lower < upper or offset < 0 or major < 0 or minor < 0 or inode < 0:
                reject("invalid kernel mapping interval or identity")
            for name, address in addresses.items():
                if lower <= address < upper:
                    if permissions != "r-xp":
                        reject("native entry is not in a private nonwritable executable mapping")
                    if (major, minor) != expected_device or inode != initial.st_ino:
                        reject("native entry maps a different file object; retained loader mapping refused")
                    file_offset = offset + address - lower
                    if not 0 <= file_offset < initial.st_size:
                        reject("native entry lies outside the sealed file bytes")
                    matches[name].append({"file_offset": file_offset, "permissions": permissions})
        if any(len(rows) != 1 for rows in matches.values()):
            reject("native entry has no unique identity-matched executable mapping")
        final = os.fstat(fd)
        if ((final.st_dev, final.st_ino, final.st_size) != (initial.st_dev, initial.st_ino, initial.st_size)
                or fcntl.fcntl(fd, get_seals) & required != required):
            reject("sealed descriptor changed during mapping admission")
        return {"schema": "hepta.native.loaded-symbol-identity.v1",
                "device_major": expected_device[0], "device_minor": expected_device[1],
                "inode": initial.st_ino, "file_bytes": initial.st_size, "seals": seals,
                "symbols": {name: rows[0] for name, rows in matches.items()},
                "basis": "actual entry address in kernel executable mapping of the sealed descriptor",
                "serialized_evidence_is_authority": False}
    except NativeMappingRejected:
        raise
    except (OSError, ValueError, TypeError, AttributeError, ImportError, OverflowError) as error:
        raise NativeMappingRejected("E_NATIVE_MAPPING: unable to establish actual loaded file identity") from error
