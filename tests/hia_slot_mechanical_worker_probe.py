"""Pass through the original installed observer; append only C custody evidence."""
from __future__ import annotations
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import fcntl
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tests.hia_slot_operations_installed_observer import main as original_main


def main():
    try:
        return original_main()
    finally:
        mechanical = sys.modules.get("hepta.hia_slot_mechanical")
        loaded = None if mechanical is None else mechanical._EXTENSION
        record = {"schema": "hepta.slot.mechanical.worker-custody.v1",
                  "argv": list(sys.argv), "pid": os.getpid(), "ppid": os.getppid(),
                  "pgid": os.getpgrp(), "loaded": loaded is not None}
        if loaded is not None:
            captured = mechanical._CAPTURED
            fd, seals = mechanical._SEALED
            mechanical._check_exports(loaded)
            record.update({"abi": loaded.ABI, "modes": loaded.MODES, "ports": loaded.PORTS,
                "module_file": loaded.__file__,
                "actual_binary": {"bytes": len(captured["binary"]),
                    "sha256": sha256(os.pread(fd, len(captured["binary"]) + 1, 0)).hexdigest()},
                "receipt": {"bytes": len(captured["manifest"]),
                    "sha256": sha256(captured["manifest"]).hexdigest()},
                "seals": fcntl.fcntl(fd, fcntl.F_GET_SEALS), "required_seals": seals,
                "actual_live_exports_unchanged": True,
                "execution_counters": loaded.execution_counters()})
        print("SLOT_MECHANICAL_WORKER=" + json.dumps(record, ensure_ascii=True,
            sort_keys=True, separators=(",", ":"), allow_nan=False), file=sys.stderr, flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
