"""Build the two native Core bytes dependency images from matching cold source."""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def build(output: Path, compiler: Path, cold_report: Path) -> Path:
    from hepta.hia_core_bytes_native import SCHEMA
    from hepta.hia_core_admission_native import SCHEMA as CORE_SCHEMA
    from tools.build_hia_json_preflight import admit_cold_build, current_sources
    from tools.qualify_hia_selfhost import compile_stage
    cold = cold_report.read_bytes()
    compiler_bytes = compiler.read_bytes()
    sources = admit_cold_build(compiler_bytes, cold)
    declarations = (
        ("core-bytes", "examples/hia_bootstrap/core_bytes.hepta", SCHEMA, "manifest.json"),
        ("core-admission", "examples/hia_bootstrap/core_admission.hepta", CORE_SCHEMA,
         "admission-manifest.json"),
    )
    captured = {relative: (ROOT / relative).read_bytes()
                for _, relative, _, _ in declarations}
    if any(sources.get(relative) != sha256(source).hexdigest()
           for relative, source in captured.items()):
        raise ValueError("Core bytes dependency source is not bound by the admitted cold report")
    output.mkdir(mode=0o700)
    manifests = {}
    receipts = {}
    images = {}
    for label, relative, schema, filename in declarations:
        image, receipt = compile_stage(output, label, compiler, captured[relative])
        image_bytes = image.read_bytes()
        images[str(image)] = image_bytes
        manifests[filename] = {
            "schema": schema, "source_sha256": sha256(captured[relative]).hexdigest(),
            "image_path": image.name, "image_sha256": sha256(image_bytes).hexdigest(),
            "compiler_sha256": sha256(compiler_bytes).hexdigest()}
        receipts[label] = receipt
    if (any((ROOT / relative).read_bytes() != source for relative, source in captured.items())
            or compiler.read_bytes() != compiler_bytes or cold_report.read_bytes() != cold
            or current_sources() != sources
            or any(Path(path).read_bytes() != image for path, image in images.items())):
        raise ValueError("Core bytes dependency build inputs changed")
    for filename, manifest in manifests.items():
        path = output / filename
        data = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()
        with path.open("xb") as handle:
            handle.write(data)
        if path.read_bytes() != data:
            raise ValueError("Core bytes dependency manifest changed at publication")
    (output / "build.json").write_text(json.dumps({
        "schema": "hepta.hia.core-bytes-build.v1", "status": "NATIVE_CANDIDATE_BUILT",
        "source_manifest": sources, "manifests": manifests,
        "cold_report_sha256": sha256(cold).hexdigest(),
        "native_compile_receipts": receipts,
        "typed_object_owner_replaced": False, "composite_owner_replaced": False,
        "whole_verify_program_replaced": False, "default_provider_selected": False,
    }, sort_keys=True, indent=2) + "\n")
    return output / "manifest.json"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", type=Path, required=True)
    parser.add_argument("--cold-report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(build(args.output.resolve(), args.compiler.resolve(), args.cold_report.resolve()))


if __name__ == "__main__":
    main()
