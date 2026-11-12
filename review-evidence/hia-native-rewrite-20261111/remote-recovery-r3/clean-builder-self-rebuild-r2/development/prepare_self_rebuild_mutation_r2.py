"""Change one reachable own-source refusal constant, then compile independently.

The change is private reason 130 -> 137 in own_sources' first extent check.
No cold/base source, recipe, packer, executor, schema, or budget changes.
"""
from pathlib import Path
import hashlib
import importlib.util
import json
import struct
import sys
import traceback

ROOT = Path(__file__).resolve().parent
ORIGINAL = ROOT / "original-r13"
REFERENCE = ROOT / "reference-kit-r13"
OUT = ROOT / "development/self-rebuild-mutation-r2"
OUT.mkdir(parents=True, exist_ok=False)
sys.dont_write_bytecode = True
sys.path[:0] = [str(ROOT / "authoring-dependencies"), str(REFERENCE), str(ORIGINAL / "tools"), str(ROOT)]

from self_rebuild_test_common import Gate, digest, identity
import clean_build_self_rebuild_r4 as baseline
inputs = [Path(__file__), ROOT / "self_rebuild_test_common.py", ROOT / "clean_build_self_rebuild_r4.py",
          ROOT / "development/self-rebuild-kit-r2/source-kit.hiabuild",
          ROOT / "development/self-rebuild-kit-r2/manifest.json",
          ROOT / "development/generate-self-rebuild-r4/clean_build_driver.hiaasm",
          ROOT / "development/build-self-rebuild-r2/clean-build-driver.image.bin",
          ROOT / "development/build-self-rebuild-r2/agent-data-json.image.bin",
          ROOT / "development/build-self-rebuild-r2/clean-build-packer.image.bin",
          ORIGINAL / "development/executor-prefix-r1.bin", ORIGINAL / "development/executor-layout-r1.json",
          ROOT / "B3-35ee.original.image.bin"]
inputs += list(ORIGINAL.joinpath("tools").glob("*.py")) + list(REFERENCE.rglob("*.py"))
gate = Gate(OUT / "evidence", inputs, "LOCAL_INDEPENDENT_OWN_SOURCE_MUTATION_AND_B3_REFERENCE", wall=150)
try:
    from build_authoring import document, profile
    from hepta.hia_agent_assembly import render_assembly
    from tools.qualify_hia_selfhost import compile_stage, invoke
    original_author = (ROOT / "clean_build_self_rebuild_r4.py").read_bytes()
    old, new = b"bad(w, 130)", b"bad(w, 137)"
    assert original_author.count(old) == 1
    changed_author = original_author.replace(old, new, 1)
    assert changed_author.replace(new, old, 1) == original_author
    author_path = OUT / "clean_build_self_rebuild.py"
    author_path.write_bytes(changed_author)
    spec = importlib.util.spec_from_file_location("selfbuild_mutant_author", author_path)
    mutant = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mutant)
    old_body, old_edits = baseline.source()
    new_body, new_edits = mutant.source()
    assert old_edits == new_edits
    old_doc = document(old_body, "clean_build_driver")
    new_doc = document(new_body, "clean_build_driver")
    old_raw = render_assembly(old_doc).encode()
    new_raw = render_assembly(new_doc).encode()
    assert old_raw == (ROOT / "development/generate-self-rebuild-r4/clean_build_driver.hiaasm").read_bytes()
    differences = []
    def compare(a, b, path=()):
        assert type(a) is type(b), path
        if isinstance(a, dict):
            assert a.keys() == b.keys(), path
            for key in a: compare(a[key], b[key], (*path, key))
        elif isinstance(a, list):
            assert len(a) == len(b), path
            for index, (x, y) in enumerate(zip(a, b)): compare(x, y, (*path, index))
        elif a != b: differences.append({"path": list(path), "old": a, "new": b})
    compare(old_doc, new_doc)
    assert len(differences) == 1 and differences[0]["old"] == 130 and differences[0]["new"] == 137
    assert differences[0]["path"][-2:] == ["attrs", "value"]
    assert profile(old_doc) == profile(new_doc)
    source_path = OUT / "clean_build_driver.hiaasm"
    source_path.write_bytes(new_raw)
    image_path, receipt = compile_stage(OUT, "mutated-clean-build-driver", ROOT / "B3-35ee.original.image.bin", new_raw)
    image = image_path.read_bytes()
    assert digest(image) != digest((ROOT / "development/build-self-rebuild-r2/clean-build-driver.image.bin").read_bytes())
    decoder = (ROOT / "development/build-self-rebuild-r2/agent-data-json.image.bin").read_bytes()
    packet = struct.pack("<4Q", int.from_bytes(b"HIABPK01", "little"), len(image), len(decoder), 0) + image + decoder
    pack_receipt, packed = invoke(OUT, "independent-mutated-builder-pack", ROOT / "development/build-self-rebuild-r2/clean-build-packer.image.bin", packet)
    assert pack_receipt["status"] == "returned" and pack_receipt["abi_status"] == 0
    size = pack_receipt["core_u32"]
    assert 0 < size <= len(packed)
    executable = packed[:size]
    prefix = bytearray((ORIGINAL / "development/executor-prefix-r1.bin").read_bytes())
    holes = json.loads((ORIGINAL / "development/executor-layout-r1.json").read_bytes())["holes"]
    expected_size = len(prefix) + len(image) + len(decoder)
    struct.pack_into("<Q", prefix, 96, expected_size)
    struct.pack_into("<Q", prefix, 104, expected_size)
    struct.pack_into("<I", prefix, holes["driver_call_hole"], len(prefix) - holes["driver_call_hole"] - 4)
    struct.pack_into("<Q", prefix, holes["decoder_offset_value"], len(prefix) + len(image))
    struct.pack_into("<Q", prefix, holes["self_size_value"], expected_size)
    assert executable == bytes(prefix) + image + decoder
    target = OUT / "independent-mutated-builder"
    target.write_bytes(executable)
    target.chmod(0o700)
    prior_manifest = json.loads((ROOT / "development/self-rebuild-kit-r2/manifest.json").read_bytes())
    old_kit = (ROOT / "development/self-rebuild-kit-r2/source-kit.hiabuild").read_bytes()
    assert digest(old_kit) == prior_manifest["kit_sha256"]
    first = prior_manifest["own_sources"][0]
    base_end = first["kit_offset"] - len(first["name"].encode()) - 32
    kit = bytearray(old_kit[:base_end])
    rows = []
    for row in prior_manifest["own_sources"]:
        name = row["name"]
        data = old_kit[row["kit_offset"]:row["kit_offset"] + row["bytes"]]
        assert digest(data) == row["sha256"]
        if name == "tools/clean_build_self_rebuild.py": data = changed_author
        if name == "examples/hia_bootstrap/clean_build_driver.hiaasm": data = new_raw
        encoded = name.encode()
        kit += struct.pack("<4Q", len(encoded), len(data), 0, 0) + encoded
        at = len(kit)
        kit += data
        rows.append({"name": name, "kit_offset": at, "bytes": len(data), "sha256": digest(data)})
    kit_path = OUT / "source-kit.hiabuild"
    kit_path.write_bytes(kit)
    assert len(kit) == len(old_kit) and digest(kit) != digest(old_kit)
    proof = {"schema": "hia-clean-builder-own-source-mutation-r2", "original_author_sha256": digest(original_author),
             "mutated_author": identity(author_path), "old_source_sha256": digest(old_raw), "new_source": identity(source_path),
             "exact_structural_differences": differences, "original_profile": profile(old_doc),
             "mutated_profile": profile(new_doc), "independent_compiler_image": identity(image_path),
             "independent_mutated_builder": identity(target), "kit": identity(kit_path), "own_sources": rows,
             "old_base_bytes_unchanged": bytes(kit[:base_end]) == old_kit[:base_end],
             "cold_and_original_seven_recipes_unchanged": True, "native_source_mutation_observed": True}
    (OUT / "mutation.json").write_text(json.dumps(proof, indent=2, sort_keys=True) + "\n")
    gate.summary.update(status="PASS", exact_structural_differences=differences,
                        independent_driver_image_sha256=digest(image), independent_mutated_builder_sha256=digest(executable),
                        mutated_kit_sha256=digest(kit), native_compiler_calls=1, native_packer_calls=1,
                        complete_host_template_and_native_packer_bytes_equal=True)
except BaseException as exc:
    gate.fail(exc)
finally:
    gate.finish()
