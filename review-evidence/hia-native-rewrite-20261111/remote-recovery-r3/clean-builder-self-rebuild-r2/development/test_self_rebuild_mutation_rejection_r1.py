"""Reach the changed native refusal using complete real gate predecessors.

The changed reason is a private RWW BAD event, not public stderr text.  Both
fixed ELF processes retain their original exit126/empty-output contract.
No fabricated decoded arena, cold acceptance or terminal event is supplied.
"""
from pathlib import Path
import ctypes
import hashlib
import json
import mmap
import struct
import sys
import zlib

ROOT = Path(__file__).resolve().parent
REFERENCE = ROOT / "reference-kit-r13"
BUILD = ROOT / "development/build-self-rebuild-r2"
MUTATION = ROOT / "development/self-rebuild-mutation-r2"
FIRST = ROOT / "development/self-rebuild-mutation-generation1-r1"
sys.dont_write_bytecode = True
sys.path[:0] = [str(ROOT), str(REFERENCE)]
from self_rebuild_test_common import Gate, digest, identity

installed_summary = ROOT / "development/self-rebuild-installed-generation2-r2/summary.json"
installed = json.loads(installed_summary.read_bytes())
nominal_exe = Path(installed["installed_inventory"]["hia-build"]["path"])
changed_exe = FIRST / "package-files/hia-build"
sources = [Path(__file__), ROOT / "self_rebuild_test_common.py", installed_summary, nominal_exe, changed_exe,
           FIRST / "summary.json", FIRST / "post-output-budget.json",
           ROOT / "development/self-rebuild-kit-r2/source-kit.hiabuild", ROOT / "development/self-rebuild-kit-r2/manifest.json",
           BUILD / "clean-build-driver.image.bin", BUILD / "agent-data-json.image.bin",
           MUTATION / "mutated-clean-build-driver.image.bin", MUTATION / "mutation.json",
           REFERENCE / "hepta/hia_json_preflight_native.py"]
gate = Gate(ROOT / "development/self-rebuild-mutation-rejection-r1", sources,
            "LOCAL_ACTUAL_ORIGINAL_COLD_AND_CONTRACT_THEN_CHANGED_PRIVATE_REASON_130_137")
CAS = gate.out / "raw"
CAS.mkdir()
cas_rows = {}
entries = []

def cas(raw):
    raw = bytes(raw)
    sha = digest(raw)
    if sha not in cas_rows:
        path = CAS / (sha + ".zlib")
        with path.open("xb") as out: out.write(zlib.compress(raw, 1))
        assert zlib.decompress(path.read_bytes()) == raw
        cas_rows[sha] = {"bytes": len(raw), "sha256": sha, "file": path.name, "compression": "zlib"}
    return cas_rows[sha]

class Buffer:
    def __init__(self, raw, readonly=False):
        self.size = len(raw)
        self.map = mmap.mmap(-1, max(1, self.size), prot=mmap.PROT_READ | mmap.PROT_WRITE)
        self.map[:self.size] = raw
        self.ptr = ctypes.addressof(ctypes.c_char.from_buffer(self.map))
        self.readonly = readonly
        if readonly:
            libc = ctypes.CDLL(None, use_errno=True)
            libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
            libc.mprotect.restype = ctypes.c_int
            assert libc.mprotect(self.ptr, max(1, self.size), mmap.PROT_READ) == 0
    def bytes(self): return self.map[:self.size]
    def close(self): self.map.close()

def actual_call(label, image, first, second, work):
    a, b, c = first.bytes(), second.bytes(), work.bytes()
    result = int(image._entry(first.ptr, first.size, second.ptr, second.size, work.ptr, work.size))
    after_a, after_b, after_c = first.bytes(), second.bytes(), work.bytes()
    assert after_a == a
    if second.readonly: assert after_b == b
    row = {"entry": len(entries), "label": label, "return_value": result,
           "first": cas(a), "first_after": cas(after_a), "second_before": cas(b), "second_after": cas(after_b),
           "work_before": cas(c), "work_after": cas(after_c), "first_readonly": first.readonly,
           "second_readonly": second.readonly}
    entries.append(row)
    with (gate.out / "entries.jsonl").open("ab") as out: out.write((json.dumps(row, sort_keys=True) + "\n").encode())
    return result

def run_gate(label, image, decoder, packet, expected_reason):
    first = Buffer(packet, True)
    reply = Buffer(b"", True)
    work = Buffer(bytes(8192))
    decodes = 0
    terminals = []
    try:
        for iteration in range(32):
            result = actual_call(label + "/controller", image, first, reply, work)
            event = struct.unpack_from("<16Q", work.bytes(), 1024)
            assert event[0] == int.from_bytes(b"HIABBE01", "little")
            if result == 0xfffffffd:
                assert event[1] == 4 and event[6] == expected_reason
                assert struct.unpack_from("<Q", work.bytes(), 8)[0] == 1
                assert decodes == 2 and event[2] == 2
                before = work.bytes()
                assert actual_call(label + "/poisoned-reentry", image, first, reply, work) == 0xfffffffd
                assert work.bytes() == before
                terminals.append({"words": list(event), "workspace": cas(before), "actual_decoders": decodes,
                                  "reason": expected_reason, "complete_base_gates_real": True})
                return terminals[0]
            if result == 0xfffffffe:
                assert event[1] == 2 and work.size < event[5] <= 1 << 30
                grown = Buffer(work.bytes() + bytes(event[5] - work.size))
                work.close()
                work = grown
                continue
            assert result == 128 and event[1] == 1 and event[2] == decodes + 1
            offset, size = event[3:5]
            assert offset <= len(packet) and size <= len(packet) - offset
            assert 0 < event[5] <= 1 << 30 and 64 <= event[6] <= 1 << 30
            wire = Buffer(packet[offset:offset + size], True)
            output = Buffer(bytes(event[5]))
            scratch = Buffer(bytes(event[6]))
            try:
                struct.pack_into("<2Q", scratch.map, 48, event[8], event[9])
                decoded = actual_call(label + "/actual-agent-data-json", decoder, wire, output, scratch)
                assert 0 < decoded < 0xfffffffc and decoded <= output.size
                data = output.bytes()[:decoded]
                actual_reply = struct.pack("<8Q", int.from_bytes(b"HIABRP01", "little"), event[2], 1, decoded, len(data), 0, 0, 0) + data
            finally:
                wire.close(); output.close(); scratch.close()
            reply.close()
            reply = Buffer(actual_reply, True)
            decodes += 1
        raise AssertionError("controller did not reach bounded original refusal")
    finally:
        first.close(); reply.close(); work.close()

try:
    assert installed["status"] == "PASS" and json.loads((FIRST / "summary.json").read_bytes())["status"] == "PASS"
    from hepta.hia_json_preflight_native import NativeHiaJsonImage
    nominal_image = (BUILD / "clean-build-driver.image.bin").read_bytes()
    changed_image = (MUTATION / "mutated-clean-build-driver.image.bin").read_bytes()
    decoder_raw = (BUILD / "agent-data-json.image.bin").read_bytes()
    # Load the actual product bytes, checking the independent expected full
    # image and the complete installed/produced ELF source beforehand.
    for exe, image in ((nominal_exe, nominal_image), (changed_exe, changed_image)):
        raw = exe.read_bytes()
        assert len(raw) == 2744 + len(image) + len(decoder_raw)
        assert raw[2744:2744 + len(image)] == image and raw[2744 + len(image):] == decoder_raw
    manifest = json.loads((ROOT / "development/self-rebuild-kit-r2/manifest.json").read_bytes())
    kit = (ROOT / "development/self-rebuild-kit-r2/source-kit.hiabuild").read_bytes()
    row = manifest["own_sources"][0]
    end = row["kit_offset"] - len(row["name"].encode()) - 32
    truncated_kit = kit[:end]
    assert struct.unpack_from("<Q", truncated_kit, 8)[0] == 2 and struct.unpack_from("<Q", truncated_kit, 48)[0] == 13
    path = gate.out / "missing-first-own-record.hiabuild"
    path.write_bytes(truncated_kit)
    packet = struct.pack("<2Q", int.from_bytes(b"HIABIN01", "little"), 1) + hashlib.sha256(truncated_kit).digest() + struct.pack("<2Q", len(truncated_kit), 0) + truncated_kit
    cas(packet)
    decoder = NativeHiaJsonImage(decoder_raw, digest(decoder_raw))
    results = []
    for label, image_bytes, reason in (("nominal", nominal_image, 130), ("changed", changed_image, 137)):
        image = NativeHiaJsonImage(image_bytes, digest(image_bytes))
        results.append(run_gate(label, image, decoder, packet, reason))
    assert [r["reason"] for r in results] == [130, 137]
    for label, exe in (("nominal", nominal_exe), ("changed", changed_exe)):
        _, out, err = gate.run("fixed-elf-" + label + "-same-refusal", exe, [digest(truncated_kit)], input_path=path, expected=126, wall=40)
        assert out == b"" and err == b""
    for sha, row in cas_rows.items():
        data = zlib.decompress((CAS / row["file"]).read_bytes())
        assert len(data) == row["bytes"] and digest(data) == sha
    gate.write("complete-cas-custody.json", sorted(cas_rows.values(), key=lambda r: r["sha256"]))
    gate.write("actual-native-terminal-events.json", results)
    gate.summary.update(status="PASS", actual_native_entries=len(entries), actual_decoders=4,
                        actual_native_reasons=[130, 137], actual_poison_reentries=2, actual_fixed_elf_refusals=2,
                        fixed_elf_contract="exit126; stdout empty; stderr empty", public_stderr_reason_not_claimed=True,
                        complete_original_base_inventory_cold_and_contract_gates_executed=True,
                        complete_buffers_and_originals_retained=True, unique_full_buffer_objects=len(cas_rows),
                        private_diagnostic_semantics_changed_not_only_image_hash=True)
except BaseException as exc:
    gate.fail(exc)
finally:
    gate.finish()
