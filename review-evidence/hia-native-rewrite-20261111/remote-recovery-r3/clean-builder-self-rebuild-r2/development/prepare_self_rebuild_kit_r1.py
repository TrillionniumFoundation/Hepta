"""Construct independent development input for the explicit v2 HIA kit ABI."""
from pathlib import Path
import hashlib
import json
import struct
import sys

ROOT = Path(__file__).resolve().parent
ORIGINAL = ROOT / "original-r13"
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT))
from clean_build_self_rebuild_r2 import OWN_NAMES

OUT = ROOT / "development/self-rebuild-kit-r1"
OUT.mkdir(parents=True, exist_ok=False)
old_packet = (ORIGINAL / "development/gate-actual-r1/input.hiabuild").read_bytes()
assert old_packet[16:48] == hashlib.sha256(old_packet[64:]).digest()
old_kit = old_packet[64:]
assert hashlib.sha256(old_kit).hexdigest() == "c7434fb3bea1782bfecf00d763233d087bd4b451ca103b1bcd15f81cbb8842ff"
header = struct.unpack_from("<8Q", old_kit)
assert header == (int.from_bytes(b"HIABKT01", "little"), 1, 0, 644, 669556, 77245, 0, 0)
paths = {name: ORIGINAL / name for name in OWN_NAMES}
paths.update({
    "tools/clean_build_self_rebuild.py": ROOT / "clean_build_self_rebuild_r2.py",
    "tools/hia_agent_edit_source_views.py": ORIGINAL / "development/driver-compile-r3/source/15/hia_agent_edit_source_views.py",
    "examples/hia_bootstrap/clean_build_driver.hiaasm": ROOT / "development/generate-self-rebuild-r2/clean_build_driver.hiaasm",
    "examples/hia_bootstrap/clean_build_packer.hiaasm": ORIGINAL / "development/driver-compile-r2/source/1/clean_build_packer.hiaasm",
})
kit = bytearray(old_kit)
struct.pack_into("<Q", kit, 8, 2)
struct.pack_into("<Q", kit, 48, len(OWN_NAMES))
inverse = bytearray(kit)
struct.pack_into("<Q", inverse, 8, 1)
struct.pack_into("<Q", inverse, 48, 0)
assert bytes(inverse) == old_kit
rows = []
for name in OWN_NAMES:
    path = paths[name]
    raw = path.read_bytes()
    assert 0 < len(raw) <= 1048576
    encoded_name = name.encode("ascii")
    kit += struct.pack("<4Q", len(encoded_name), len(raw), 0, 0)
    kit += encoded_name
    at = len(kit)
    kit += raw
    rows.append({"name": name, "original_path": str(path), "kit_offset": at,
                 "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
raw = bytes(kit)
digest = hashlib.sha256(raw).hexdigest()
(OUT / "source-kit.hiabuild").write_bytes(raw)
result = {"schema": "hia-clean-builder-self-rebuild-input-r1", "scope": "DEVELOPMENT_INPUT_NOT_NEW_COLD",
          "kit_bytes": len(raw), "kit_sha256": digest, "old_complete_kit_sha256": hashlib.sha256(old_kit).hexdigest(),
          "old_base_records_identical": True, "old_base_count": 644, "own_source_count": len(rows),
          "own_sources": rows, "expected_new_builder_source_sha256": rows[-2]["sha256"],
          "source_region_authority": "explicit operator whole-kit SHA; not the prior cold qualification"}
(OUT / "manifest.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
print(json.dumps({k: v for k, v in result.items() if k != "own_sources"}, sort_keys=True), flush=True)
