QUALIFY_SHA = "a1c76c165856927bfbaded5610568fa79456f15e1eb356dda7a8b882bb602c92"
CHILD_SHA = "1d298396e97b6d362bcd51121eff1d2f411305133fadb1c974477b2dd9052c29"

def observe_compiler_bundle(source, directory):
    """Actual original B0/B1/B2/request/receipt/image binding; never a cold claim."""
    records = {}
    def actual(path, maximum):
        raw, record = read(path, maximum)
        records[str(path)] = record
        return raw
    selfhost = actual(source / "examples/hia_bootstrap/selfhost.hiaasm", 1 << 20)
    assembly = actual(source / GENERATED, 1 << 20)
    require(sha256(actual(source / "tools/qualify_hia_selfhost.py", 1 << 20)).hexdigest() == QUALIFY_SHA
            and sha256(actual(source / "tools/hia_selfhost_child.py", 1 << 20)).hexdigest() == CHILD_SHA,
            "unchanged native compiler supervisor or child differs")
    seed_raw = actual(directory / "B0.so", 16 << 20)
    seed = json.loads(actual(directory / "B0.receipt.json", 8 << 20))
    require(seed["schema"] == "hepta.hia.program.direct-native.v1" and seed["ok"] is True
            and seed["kind"] == "shared" and seed["output"] == str(directory / "B0.so")
            and seed["artifact_sha256"] == sha256(seed_raw).hexdigest()
            and type(seed["artifact_bytes"]) is int and seed["artifact_bytes"] == len(seed_raw)
            and seed["seed_only"] is True and seed["source_sha256"] == sha256(selfhost).hexdigest()
            and seed["python"]["isolated"] is True and seed["python"]["no_site"] is True,
            "actual explicit B0 seed binding differs")
    require(seed["support_contract_sha256"] == sha256(actual(
        source / "docs/HIA_SELFHOST_CORE_SUPPORT.json", 8 << 20)).hexdigest(),
        "B0 observed checked-in support bytes differ")
    require(type(seed["loaded_seed_modules"]) is dict and seed["loaded_seed_modules"], "seed observations absent")
    for name, expected in seed["loaded_seed_modules"].items():
        require(type(name) is str and name.startswith("hepta/") and "\\" not in name
                and all(p not in ("", ".", "..") for p in name.split("/")), "unsafe seed module path")
        require(sha256(actual(source / name, 8 << 20)).hexdigest() == expected, "loaded seed source differs")
    predecessor, predecessor_raw = directory / "B0.so", seed_raw
    results = {}
    for label, input_raw, image_format in (("B1", selfhost, "seed-shared"),
            ("B2", selfhost, "flat-x86-64"), ("bounded-read", assembly, "flat-x86-64")):
        request_path = directory / (label + ".request.json")
        input_path = directory / (label + ".input.bin")
        output_path = directory / (label + ".output.bin")
        image_path = directory / (label + ".image.bin")
        request = json.loads(actual(request_path, 1 << 20))
        wanted = {"format": image_format, "image": str(predecessor),
                  "image_sha256": sha256(predecessor_raw).hexdigest(), "source": str(input_path),
                  "source_sha256": sha256(input_raw).hexdigest(), "capacity": 1 << 20,
                  "workspace_size": 1 << 20, "workspace_fill": 0, "output": str(output_path)}
        require(request == wanted and actual(input_path, 1 << 20) == input_raw, "native request differs")
        receipt = json.loads(actual(directory / (label + ".receipt.json"), 4 << 20))
        image_raw, output_raw = actual(image_path, 1 << 20), actual(output_path, 1 << 20)
        require(receipt["case"] == label and receipt["status"] == "returned"
                and type(receipt["abi_status"]) is int and receipt["abi_status"] == 0
                and receipt["source_unchanged"] is True and receipt["forbidden_compiler_modules_loaded"] == []
                and receipt["limits"] == NATIVE_LIMITS and receipt["format"] == image_format
                and receipt["runner_sha256"] == CHILD_SHA
                and receipt["artifact_sha256"] == wanted["image_sha256"]
                and receipt["image_sha256"] == sha256(predecessor_raw).hexdigest()
                and receipt["source_sha256"] == sha256(input_raw).hexdigest()
                and receipt["output_sha256"] == sha256(output_raw).hexdigest()
                and receipt["input_sha256"] == wanted["source_sha256"] and receipt["input_bytes"] == len(input_raw)
                and receipt["produced_image"] == str(image_path) and type(receipt["core_u32"]) is int
                and 0 < receipt["core_u32"] == receipt["produced_bytes"] == len(image_raw) <= 1 << 20
                and receipt["produced_sha256"] == sha256(image_raw).hexdigest()
                and len(output_raw) == 1 << 20 and output_raw[:len(image_raw)] == image_raw,
                "actual native compile output differs")
        child_stdout = json.loads(actual(directory / (label + ".stdout.log"), 4 << 20))
        # Exact original invoke() additions followed by compile_stage() additions.
        # All other fields must be the complete actual child JSON, not a subset.
        producer_fields = {"case", "input_sha256", "input_bytes", "artifact_sha256", "format",
                           "runner_sha256", "wall_elapsed_ns", "produced_image",
                           "produced_bytes", "produced_sha256"}
        require(producer_fields <= set(receipt) and type(child_stdout) is dict
                and child_stdout == {key: value for key, value in receipt.items()
                                     if key not in producer_fields},
                "actual complete child stdout differs from the producer receipt projection")
        actual(directory / (label + ".stderr.log"), 4 << 20)
        results[label] = {"request": request, "receipt": receipt,
            "image_sha256": sha256(image_raw).hexdigest(), "image_bytes": len(image_raw)}
        predecessor, predecessor_raw = image_path, image_raw
    require(actual(directory / "B1.image.bin", 1 << 20) == actual(directory / "B2.image.bin", 1 << 20),
            "actual B1/B2 bytes differ")
    return {"scope": "CURRENT_SOURCE_B0_B1_B2_DEVELOPMENT_NOT_COLD", "B1_equals_B2": True,
            "compiler_sha256": results["B2"]["image_sha256"],
            "image_sha256": results["bounded-read"]["image_sha256"], "records": records, "stages": results,
            "old_compiler_reused": False, "B3_or_mutation_qualification_claimed": False}
