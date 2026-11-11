"""Read-only independent audit of the original GitHub qualification artifact.

This validates retained hashes, exact observations and proof/replay consistency.
It does not execute a supplied image or issue a new semantic proof.
"""
from pathlib import Path, PurePosixPath
from hashlib import sha256, sha1
import json
import struct
import zipfile

ARCHIVE = Path("/tmp/hia-1ac5-extension-8dae-original-artifact.zip")
OUTPUT = Path("/tmp/hia-1ac5-extension-independent-audit")
ROOT = Path("/tmp/hia-1ac5-upgrade-contract")
HEAD = "8dae9d0b74f8520d1522548e0a04c0c077b3f074"
TREE = "b2d32f112431a7b0afd7a98fe41084996e0b818a"
EXPECTED = "d693288200f6c51d2e99f3c7f5e3225d055f7921cb3327bea4cb7e1186bcfc76"
PREFIX = "qualification/"
WIDTHS = {"u8": 8, "u32": 32, "u64": 64, "usize": 64, "bool": 1}
PINS = {"original": "85288cfc4b649b2be13175675880f5372f16bf3d9c5d4b78ba21ffa2c90b6b44",
        "candidate": "2dd847d9df46392e4ef4b99c781b45f56c9841ae61127a260be6e8523f042845",
        "patch": "e74f3c27d6ea7e7ccfc1c9e2a4e7674fecabef08ee0e05236e5a6e2b5bd75cb4"}

def digest(raw):
    return sha256(raw).hexdigest()

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()

def save(name, value):
    (OUTPUT / name).write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")

def text_section(raw):
    assert raw[:6] == b"\x7fELF\x02\x01"
    shoff = struct.unpack_from("<Q", raw, 40)[0]
    entsize, count, strings = struct.unpack_from("<HHH", raw, 58)
    assert entsize == 64 and 0 < strings < count
    entries = [struct.unpack_from("<IIQQQQIIQQ", raw, shoff + index * entsize) for index in range(count)]
    string_offset, string_size = entries[strings][4:6]
    table = raw[string_offset:string_offset + string_size]
    result = []
    for entry in entries:
        offset = entry[0]
        if table[offset:table.index(b"\0", offset)] == b".text":
            start, length = entry[4:6]
            assert start + length <= len(raw)
            result.append(raw[start:start + length])
    assert len(result) == 1
    return result[0]

raw = ARCHIVE.read_bytes()
assert len(raw) == 6104008 and digest(raw) == EXPECTED
git_blob = sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
assert git_blob == "69602084059dd0db06cdecd9e5b95a0d2d4fbfbc"
OUTPUT.mkdir(exist_ok=False)

with zipfile.ZipFile(ARCHIVE) as z:
    names = z.namelist()
    assert len(names) == len(set(names))
    retained = {}
    for name in names:
        path = PurePosixPath(name)
        assert not path.is_absolute() and ".." not in path.parts
        data = z.read(name)
        retained[name] = {"bytes": len(data), "sha256": digest(data)}
    assert len(retained) == 851
    save("raw-artifact-manifest.json", retained)

    def read(name):
        return z.read(PREFIX + name)

    def doc(name):
        return json.loads(read(name))

    assert z.read("source.sha").decode().strip() == HEAD
    assert z.read("expected-source.sha").decode().strip() == HEAD
    assert z.read("source.tree").decode().strip() == TREE
    assert z.read("source-status-before.txt") == b""
    assert z.read("source-status-after.txt") == b""
    assert z.read("source-diff-after.log") == b""
    for prefix, manifest_name in ((PREFIX, "artifact-manifest.json"),
            (PREFIX + "new-domain/", "new-domain/artifact-manifest.json")):
        manifest = doc(manifest_name)
        for name, expected in manifest.items():
            path = PurePosixPath(name)
            assert not path.is_absolute() and ".." not in path.parts
            assert retained[prefix + name]["sha256"] == expected
    outer_manifest_count = len(doc("artifact-manifest.json"))
    inner_manifest_count = len(doc("new-domain/artifact-manifest.json"))
    assert outer_manifest_count == 830 and inner_manifest_count == 555
    report, domain = doc("qualification.json"), doc("domain.json")
    assert report["status"] == "PASS_REGISTERED_FINITE_UPGRADE_DOMAIN"
    assert report["profile"] == domain["profile"] == "original-select.exact-sources-and-inputs.v1"
    assert report["domain_sha256"] == digest(read("domain.json")) == "ae336aa8b7f25d266fc0c06a73616d49ef8840eb7f9705181310a4eb7e687018"
    assert report["source_checkout"] == {"kind": "git_checkout", "commit": HEAD, "tree": TREE,
        "worktree_clean": True, "identity_authority": "source_manifest; git metadata is supplemental"}
    assert report["original_agent_four_claim_gate"] == "HOLD"
    assert all(report[key] is False for key in ("adoption_authorized", "agent_proof_receipt_issued", "evaluation_performed"))
    assert not any(report["proof_boundary"].values())
    owner = report["process_owner"]
    assert owner == doc("worker.process.json")
    assert owner["status"] == "completed" and owner["returncode"] == 0 and owner["termination"] is None
    assert owner["owned_process_group"] > 0 and owner["timeout_seconds"] == 600
    assert digest(z.read("original-raw-evidence.zip")) == "0b18f5665657601141ada5fe67990ee192d91665eb5463f806b495d6240a2d3a"
    for name, expected in PINS.items():
        suffix = ".patch" if name == "patch" else ".hiaasm"
        assert digest(read("frozen-inputs/" + name + suffix)) == expected
        assert read("frozen-inputs/" + name + suffix) == read("archive-inputs/" + name + suffix)
    assert read("patch-reconstruction/examples/hia_bootstrap/selfhost.hiaasm") == read("frozen-inputs/candidate.hiaasm")
    assert doc("patch-apply.json")["returncode"] == 0

    inventory = doc("source-before.json")
    assert inventory == doc("new-domain/source-before.json")
    overrides = json.loads(Path("/tmp/hia-1ac5-extension-audit-source-overrides-complete.json").read_bytes())
    for name, expected in inventory.items():
        actual = overrides[name].encode() if name in overrides else (ROOT / name).read_bytes()
        assert digest(actual) == expected, name
    before, after = report["compiler_before"], report["compiler_after"]
    assert before["source_sha256"] == PINS["original"] and after["source_sha256"] == PINS["candidate"]
    assert before["checker"] == after["checker"]
    assert before["checker"]["source_inventory_sha256"] == digest(canonical(inventory))
    assert before["checker"]["native_selection_sha256"] == digest(canonical(before["checker"]["native_selection"]))
    assert len(before["checker"]["native_selection"]) == 15 and all(value is None for value in before["checker"]["native_selection"].values())
    seed_images = {"before": read("before-compiler/B0.so"), "after": read("new-domain/frozen-c1-seed/B0.so")}
    assert digest(seed_images["before"]) == before["image_sha256"]
    assert digest(seed_images["after"]) == after["image_sha256"]
    runner_sha256 = inventory["tools/hia_selfhost_child.py"]

    def observation(directory, label, source, image, expected_result=None, expected_output=None):
        request = doc(directory + "/" + label + ".request.json")
        receipt = doc(directory + "/" + label + ".receipt.json")
        stdout = json.loads(read(directory + "/" + label + ".stdout.log"))
        actual_source = read(directory + "/" + label + ".input.bin")
        output = read(directory + "/" + label + ".output.bin")
        assert actual_source == source
        assert request["source_sha256"] == receipt["input_sha256"] == stdout["source_sha256"] == digest(source)
        assert request["image_sha256"] == receipt["artifact_sha256"] == stdout["image_sha256"] == digest(image)
        assert receipt["runner_sha256"] == runner_sha256
        for record in (receipt, stdout):
            assert record["status"] == "returned" and record["abi_status"] == 0
            assert record["source_unchanged"] is True and record["forbidden_compiler_modules_loaded"] == []
            assert record["output_sha256"] == digest(output)
            if expected_result is not None:
                assert record["core_u32"] == expected_result
        if expected_output is not None:
            assert output == expected_output
        return receipt, output

    sample = read("old-domain/bytesum/before.input.bin")
    assert digest(sample) == domain["old_sources"][0]["source_sha256"] == "74bbcc3a6e0ac0962ec32017f4d8c971c91bca0f53c3de7846d65de6194ce4ae"
    old_images = {}
    for row in report["old_domain_results"]:
        name = row["id"]
        source = sample if name == "bytesum" else read("frozen-inputs/original.hiaasm")
        assert digest(source) == row["source_sha256"]
        images = [read("old-domain/" + name + "/" + version + ".image.bin") for version in ("before", "after")]
        assert images[0] and images[0] == images[1]
        assert digest(images[0]) == row["emitted_image_sha256"]
        old_images[name] = images[0]
        for version in ("before", "after"):
            receipt, output = observation("old-domain/" + name, version, source, seed_images[version], len(images[0]))
            assert output[:receipt["core_u32"]] == images[0]
    old_calls = 0
    for index, item in enumerate(domain["old_sources"][0]["inputs"]):
        data = bytes.fromhex(item["input_hex"])
        result = 5381
        for byte in data:
            result = ((result * 33) ^ byte) & 0xffffffff
        assert result == item["expected_u32"]
        for version in ("before", "after"):
            observation("old-domain/bytesum", version + "-input-" + str(index), data,
                        old_images["bytesum"], result, bytes([result & 255]))
            old_calls += 1
    for version in ("before", "after"):
        receipt, output = observation("old-domain/compiler-c0", version + "-compile-bytesum",
                                     sample, old_images["compiler-c0"], len(old_images["bytesum"]))
        assert output[:receipt["core_u32"]] == old_images["bytesum"]
        old_calls += 1

    controls = 0
    for item in domain["old_refusal_controls"]:
        data = sample.replace(b"int.mul.wrap", b"int.bad.wrap", 1) if item["id"] == "unknown-opcode" else sample
        assert digest(data) == item["source_sha256"]
        for version in ("before", "after"):
            observation("refusal-controls", item["id"] + "-" + version, data, seed_images[version],
                        item["expected_u32"], b"\xa5" * (1 << 20))
            controls += 1

    new_calls = projection_calls = obligation_instances = 0
    queries = []
    for registered, row in zip(domain["new_sources"], report["new_domain_results"]):
        typ = row["type"]
        assert typ == registered["id"]
        directory = "new-domain/" + typ
        source, image = read(directory + "/actual-c1-output.input.bin"), read(directory + "/actual-c1-output.image.bin")
        assert digest(source) == registered["source_sha256"] == row["source_binding"]["source_sha256"]
        receipt, output = observation(directory, "actual-c1-output", source, seed_images["after"], len(image))
        assert output[:receipt["core_u32"]] == image
        observation("refusal-controls", "c0-rejects-" + typ, source, seed_images["before"],
                    0xffffffff, b"\xa5" * (1 << 20))
        for index, case in enumerate(registered["inputs"]):
            data = bytes.fromhex(case["input_hex"])
            left, right = int.from_bytes(data[1:9], "little"), int.from_bytes(data[9:17], "little")
            expected = (left if data[0] else right) & ((1 << WIDTHS[typ]) - 1)
            assert expected == case["expected_u64"]
            observation(directory, "whole-output-case-" + str(index), data, image,
                        expected & 0xffffffff, expected.to_bytes(8, "little"))
            new_calls += 1
        site, projection = row["source_binding"], row["projection"]
        fragment = image[site["start"]:site["end"]]
        assert len(fragment) == 35 and fragment == bytes.fromhex(site["fragment_hex"])
        assert fragment == read(directory + "/copied-fragment.bin")
        assert digest(fragment) == site["fragment_sha256"] and digest(image) == site["compiler_output_sha256"]
        obj, final = read(directory + "/projection.o"), read(directory + "/projection.so")
        assert digest(obj) == row["projection_object_sha256"] and digest(final) == row["projection_image_sha256"]
        for supplied in (obj, final):
            text = text_section(supplied)
            assert text[projection["copied_text_start"]:projection["copied_text_end"]] == fragment
        native = doc(directory + "/native-process.json")
        assert native["returncode"] == 0
        actual = json.loads(native["stdout"])
        assert actual["image_sha256"] == digest(final)
        assert len(actual["vectors"]) == len(actual["results"]) == 40
        expected = [(vector[1] if vector[0] & 1 else vector[2]) & ((1 << WIDTHS[typ]) - 1)
                    for vector in actual["vectors"]]
        assert actual["results"] == expected
        projection_calls += len(expected)
        old, fresh = doc(directory + "/validation.json"), doc("fragment-replay/" + typ + "-validation.json")
        for proof in (old, fresh):
            assert proof["ok"] and proof["complete"] and proof["status"] == "smt_validated"
            assert len(proof["obligations"]) == 5
            assert proof["checker"]["native_selection"] == before["checker"]["native_selection"]
            for name, source_sha in proof["checker"]["source_identity"].items():
                assert inventory["hepta/" + name] == source_sha
        for key in ("subject", "property", "profile", "assumptions", "checker", "unproved_obligations"):
            assert old[key] == fresh[key]
        for source_prefix, proof in ((directory + "/queries/", old), ("fragment-replay/" + typ + "-queries/", fresh)):
            for obligation in proof["obligations"]:
                assert obligation["result"] == obligation["expected"] in {"sat", "unsat"}
                assert digest(read(source_prefix + obligation["query_file"])) == obligation["query_sha256"]
                saved = doc(source_prefix + obligation["query_file"] + ".result.json")
                assert saved == obligation
        assert [(q["name"], q["query_sha256"], q["result"]) for q in old["obligations"]] == [
            (q["name"], q["query_sha256"], q["result"]) for q in fresh["obligations"]]
        queries.extend(q["query_sha256"] for q in old["obligations"])
        obligation_instances += len(old["obligations"])

    replay = doc("fragment-replay/replay.json")
    assert replay["status"] == "PASS" and replay["original_agent_four_claim_gate"] == "HOLD"
    assert replay["compiler_execution_performed"] is False and replay["native_execution_performed"] is False
    assert replay["new_agent_receipts"] is False
    assert replay["manifest_sha256"] == report["copied_fragment_manifest_sha256"] == digest(read("new-domain/artifact-manifest.json"))
    assert len(replay["cases"]) == 5 and replay["retained_artifacts_checked"] == inner_manifest_count
    assert (old_calls, controls, new_calls, projection_calls, obligation_instances, len(set(queries))) == (18, 4, 64, 200, 25, 8)
    result = {"schema": "hia.compiler-extension.independent-retained-artifact-audit.v1",
        "status": "PASS_RETAINED_BYTES_AND_OBSERVATIONS", "candidate_commit": HEAD, "candidate_tree": TREE,
        "github_run_id": 43005144464, "github_job_id": 130470632725, "github_artifact_id": 13848136473,
        "original_artifact_bytes": len(raw), "original_artifact_sha256": EXPECTED, "original_artifact_git_blob": git_blob,
        "artifact_members_hashed_and_crc_checked": len(retained), "expanded_bytes": sum(row["bytes"] for row in retained.values()),
        "outer_manifest_members_checked": outer_manifest_count, "copied_fragment_manifest_members_checked": inner_manifest_count,
        "exact_current_source_files_matched": len(inventory),
        "current_source_overrides_read_from_exact_github_candidate": sorted(overrides),
        "historical_compiler_source_pins": PINS,
        "compiler_before_image_sha256": before["image_sha256"], "compiler_after_image_sha256": after["image_sha256"],
        "checker_before_equals_after": True, "checker_binding": before["checker"],
        "old_output_images": {name: {"bytes": len(image), "sha256": digest(image)} for name, image in old_images.items()},
        "old_native_runtime_observations_recomputed": old_calls, "old_refusal_observations_rechecked": controls,
        "new_admission_deltas_rechecked": len(WIDTHS), "whole_new_program_native_observations_recomputed": new_calls,
        "projection_native_values_recomputed": projection_calls, "typed_case_obligation_instances": obligation_instances,
        "distinct_smt_query_hashes": len(set(queries)), "replayed_instances_not_added_to_proof_count": 25,
        "process_owner": owner, "finite_qualification_elapsed_seconds": report["elapsed_seconds"],
        "domain_sha256": report["domain_sha256"], "qualification_sha256": digest(read("qualification.json")),
        "native_execution_performed_by_this_audit": False, "new_smt_execution_performed_by_this_audit": False,
        "original_agent_four_claim_gate": "HOLD", "whole_language_refinement_proved": False,
        "audit_source_sha256": digest(Path(__file__).read_bytes())}
    save("audit.json", result)
    for name in ("qualification.json", "domain.json", "source-before.json", "worker.process.json"):
        (OUTPUT / ("retained-" + name)).write_bytes(read(name))
    print(json.dumps({"status": result["status"], "artifact_members": len(retained), "source_files": len(inventory),
        "old_runtime": old_calls, "new_runtime": new_calls, "projection_values": projection_calls,
        "typed_case_obligations": obligation_instances, "unique_queries": len(set(queries)),
        "audit_sha256": digest((OUTPUT / "audit.json").read_bytes())}, sort_keys=True))

