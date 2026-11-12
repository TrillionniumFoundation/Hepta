"""Restore an independently revised Actions control from exact66a3 source.

This authoring script does not import or run any product/qualification code.
"""
from pathlib import Path
import ast
import hashlib
import json
import shutil

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "control"
OUT.mkdir(exist_ok=True)

def replace(source, old, new):
    assert source.count(old) == 1, old[:120]
    return source.replace(old, new)

def save(name, source):
    ast.parse(source, filename=name)
    (OUT / name).write_text(source)

for name in ("source_common.py", "process_owner_impl.py", "source-manifest.json", "populations.json"):
    shutil.copyfile(ROOT / "originals" / name, OUT / name)
shutil.copyfile(ROOT / "authoring/git_binding.py", OUT / "git_binding.py")

support = (ROOT / "originals/native_support.py").read_text()
support = replace(support, 'COMPILER_SHA = "0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8"\nCOMPILER_BYTES = 668608\n', '')
support += (ROOT / "authoring/compiler_lineage.inc").read_text()
save("native_support.py", support)

prep = (ROOT / "originals/prepare_native.py").read_text()
prep = replace(prep, 'STATIC UNEXECUTED controller. The supplied original B3 is a development input;\nthis is not a cold build or proof of an installed/public replacement.',
    'Fresh current-source B0/B1/B2 Actions development. No prior binary is reused;\nthis is not B3, mutation, a cold build, or installed/public qualification.')
prep = replace(prep, 'import os\n', 'import os\nimport shutil\nimport subprocess\n')
prep = replace(prep, 'CANDIDATE, CANDIDATE_TREE, COMPILER_BYTES, COMPILER_SHA,', 'CANDIDATE, CANDIDATE_TREE,')
prep = replace(prep, 'GENERATED, LIMITS, NATIVE_LIMITS, OVERLAYS, generated_rows, source_manifest)',
    'GENERATED, LIMITS, NATIVE_LIMITS, OVERLAYS, generated_rows, source_manifest,\n    observe_compiler_bundle)')
prep = replace(prep, '    parser.add_argument("--compiler", type=Path, required=True)\n', '')
prep = replace(prep, '    rows = before = manifest_raw = manifest_pin = compiler_pin = None',
    '    rows = before = manifest_raw = manifest_pin = compiler_pin = None\n    compiler = compiler_bundle = linker = linker_pin = git_before = None')
prep = replace(prep, '''        compiler_raw, compiler_pin = read(args.compiler, COMPILER_BYTES)
        require(len(compiler_raw) == COMPILER_BYTES and compiler_pin["sha256"] == COMPILER_SHA,
                "fixed original B3 development input differs")
        report["compiler_before"] = compiler_pin
''', '''        from git_binding import source_git
        git_before = source_git(source, rows)
        report["source_git_before"] = git_before
        linker = Path(shutil.which("ld")).resolve(strict=True)
        _, linker_pin = read(linker, 64 << 20, system_binary=True)
        version = subprocess.run([str(linker), "--version"], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5, check=True)
        report["linker"] = {"resolved": str(linker), "binary_before": linker_pin,
            "version_stdout": create(output / "linker-version.stdout.log", version.stdout),
            "version_stderr": create(output / "linker-version.stderr.log", version.stderr)}
''')
prep = replace(prep, '        def forbid_seed(*unused, **ignored):', '''        selfhost_raw, selfhost_pin = read(source / "examples/hia_bootstrap/selfhost.hiaasm", 1 << 20)
        require(qualify.SOURCE == source / "examples/hia_bootstrap/selfhost.hiaasm", "bootstrap source differs")
        seed, seed_receipt = qualify.build_seed(output)
        report["fresh_seed"] = {"receipt": seed_receipt, "image": read(seed, 16 << 20)[1], "selfhost": selfhost_pin}
        def forbid_seed(*unused, **ignored):''')
prep = replace(prep, '        image, receipt = qualify.compile_stage(output, "bounded-read", args.compiler, assembly)', '''        first, first_receipt = qualify.compile_stage(output, "B1", seed, selfhost_raw, image_format="seed-shared")
        compiler, second_receipt = qualify.compile_stage(output, "B2", first, selfhost_raw)
        first_raw, first_pin = read(first, 1 << 20)
        compiler_raw, compiler_pin = read(compiler, 1 << 20)
        require(first_raw == compiler_raw, "fresh B1/B2 bytes differ")
        report["development_compiler"] = {"scope": "CURRENT_SOURCE_B0_B1_B2_DEVELOPMENT_NOT_COLD",
            "B1": first_receipt, "B2": second_receipt, "B1_equals_B2": True,
            "compiler_sha256": compiler_pin["sha256"], "old_compiler_reused": False,
            "cold_qualification_claimed": False, "B3_or_mutation_qualification_claimed": False}
        report["compiler_before"] = compiler_pin
        image, receipt = qualify.compile_stage(output, "bounded-read", compiler, assembly)''')
prep = replace(prep, 'receipt.get("artifact_sha256") == COMPILER_SHA', 'receipt.get("artifact_sha256") == compiler_pin["sha256"]')
prep = replace(prep, '"image_sha256": image_pin["sha256"], "compiler_sha256": COMPILER_SHA}',
    '"image_sha256": image_pin["sha256"], "compiler_sha256": compiler_pin["sha256"]}')
prep = replace(prep, '        report["manifest"] = manifest\n', '''        report["manifest"] = manifest
        report["entry_abi_file"] = create(output / "entry-abi.json", wire({
            "schema": "hepta.hia.bounded-read-generated-entry-abi.v1", "function": value["functions"][0]["name"],
            "parameters": value["functions"][0]["params"], "returns": value["functions"][0]["returns"],
            "source_sha256": sha256(assembly).hexdigest(), "image_sha256": image_pin["sha256"],
            "compiler_sha256": compiler_pin["sha256"], "qualification_claimed": False}))
        compiler_bundle = observe_compiler_bundle(source, output)
        report["compiler_bundle_before"] = compiler_bundle
''')
prep = replace(prep, '''                report["compiler_after"] = read(args.compiler, COMPILER_BYTES)[1]
                require(report["compiler_after"] == compiler_pin, "B3 development input changed")''', '''                report["compiler_after"] = read(compiler, 1 << 20)[1]
                require(report["compiler_after"] == compiler_pin, "fresh B2 input changed")
            if compiler_bundle is not None:
                report["compiler_bundle_after"] = observe_compiler_bundle(source, output)
                require(report["compiler_bundle_after"] == compiler_bundle, "fresh compiler lineage changed")
            if linker_pin is not None:
                report["linker"]["binary_after"] = read(linker, 64 << 20, system_binary=True)[1]
                require(report["linker"]["binary_after"] == linker_pin, "actual linker changed")
            if git_before is not None:
                report["source_git_after"] = source_git(source, rows)
                require(report["source_git_after"] == git_before, "actual source Git identity changed")''')
prep = replace(prep, '"cold_qualification": False, "whole_native_delivery_qualified": False}',
    '"cold_qualification": False, "whole_native_delivery_qualified": False,\n        "checked_in_global_contract_updated": False,\n        "checked_in_contract_and_coverage_qualification_claimed": False}')
save("prepare_native.py", prep)

driver = (ROOT / "originals/native_driver.py").read_text()
driver = replace(driver, 'CANDIDATE_TREE, COMPILER_BYTES, COMPILER_SHA,', 'CANDIDATE_TREE,')
driver = replace(driver, 'owned_step, source_manifest)', 'owned_step, source_manifest,\n    observe_compiler_bundle)\nfrom git_binding import source_git')
driver = replace(driver, 'def bundle(source, manifest):', 'def bundle(source, manifest, compiler_sha256):')
driver = replace(driver, 'and value["compiler_sha256"] == COMPILER_SHA', 'and value["compiler_sha256"] == compiler_sha256')
driver = replace(driver, '    parser.add_argument("--compiler", type=Path, required=True)\n', '')
driver = replace(driver, '    configuration = None', '    configuration = None\n    compiler_lineage = git_before = None')
driver = replace(driver, '''        compiler_raw, compiler_before = read(args.compiler, COMPILER_BYTES)
        require(len(compiler_raw) == COMPILER_BYTES and compiler_before["sha256"] == COMPILER_SHA,
                "exact original B3 developer input differs")
        report["compiler_before"] = compiler_before''', '''        git_before = source_git(source, rows)
        report["source_git_before"] = git_before''')
driver = replace(driver, '            "--compiler", str(args.compiler), "--output", str(output / "build")]', '            "--output", str(output / "build")]')
driver = replace(driver, '''        manifest = output / "build/manifest.json"
        bundle_before, generated = bundle(source, manifest)''', '''        compiler_lineage = observe_compiler_bundle(source, output / "build")
        require(build["compiler_bundle_before"] == build["compiler_bundle_after"] == compiler_lineage
                and build["source_git_before"] == build["source_git_after"] == git_before,
                "actual fresh compiler lineage/Git identity differs")
        compiler_before = read(output / "build/B2.image.bin", 1 << 20)[1]
        report["compiler_before"] = compiler_before
        report["compiler_bundle_before"] = compiler_lineage
        manifest = output / "build/manifest.json"
        bundle_before, generated = bundle(source, manifest, compiler_before["sha256"])''')
driver = replace(driver, 'require(bundle(source, manifest)[0] == bundle_before,', 'require(bundle(source, manifest, compiler_before["sha256"])[0] == bundle_before,')
driver = replace(driver, '''                    report["compiler_after"] = read(args.compiler, COMPILER_BYTES)[1]
                    require(report["compiler_after"] == compiler_before,
                            "original B3 input changed before terminal")''', '''                    report["compiler_after"] = read(output / "build/B2.image.bin", 1 << 20)[1]
                    require(report["compiler_after"] == compiler_before, "fresh B2 input changed")
                if compiler_lineage is not None:
                    report["compiler_bundle_after"] = observe_compiler_bundle(source, output / "build")
                    require(report["compiler_bundle_after"] == compiler_lineage, "fresh compiler lineage changed")
                if git_before is not None:
                    report["source_git_after"] = source_git(source, rows)
                    require(report["source_git_after"] == git_before, "candidate Git identity changed")''')
driver = replace(driver, 'bundle(source, output / "build/manifest.json")[0]', 'bundle(source, output / "build/manifest.json", compiler_before["sha256"])[0]')
driver = replace(driver, '"whole_native_delivery_qualified": False}',
    '"whole_native_delivery_qualified": False, "fresh_B0_B1_B2_requested": True,\n        "old_B3_input_reused": False, "checked_in_global_contract_updated": False,\n        "checked_in_contract_and_coverage_qualification_claimed": False}')
save("native_driver.py", driver)

print(json.dumps({"status": "AUTHORING_AND_AST_PARSE_ONLY", "product_execution": False,
    "files": [{"path": p.name, "bytes": p.stat().st_size,
               "sha256": hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted(OUT.iterdir())]}, indent=2))
