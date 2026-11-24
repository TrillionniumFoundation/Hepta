"""Actual complete nominal executables for the public selfhost API tests."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path

from hepta.hia_nominal_program_native import (
    PIN_SELECTOR, SELECTOR, SOURCE_FILES, _Selection, manifest_value,
)

LEGACY_SELECTORS = (
    "HEPTA_HIA_COMPOSITE_CONSTRUCTOR_MANIFEST", "HEPTA_HIA_COMPOSITE_FUNCTIONS_MANIFEST",
    "HEPTA_HIA_COMPOSITE_TYPES_MANIFEST", "HEPTA_HIA_TASK_HELPERS_MANIFEST",
    "HEPTA_HIA_COMPOSITE_OUTER_MANIFEST",
)


@dataclass(frozen=True)
class NominalProgramFixture:
    manifest: Path
    pin: str
    selection: object
    scope: str

    @property
    def complete_environment(self):
        return {**dict.fromkeys(LEGACY_SELECTORS, ""), SELECTOR: str(self.manifest),
                PIN_SELECTOR: self.pin}

    @property
    def reference_environment(self):
        return dict.fromkeys((*LEGACY_SELECTORS, SELECTOR, PIN_SELECTOR), "")

    def check_custody(self):
        self.selection.check()


def build_fixture(output, compiler, cold_report=None):
    """Keep cold qualification and explicit development construction distinct."""
    from tools.build_hia_nominal_constructor import (
        ADAPTER, COMPONENTS, CONSTRUCTOR_IMAGES, DRIVER, ORDINARY_CLI_IMAGE_CAPACITY,
        TRANSPORT_ROLES, TRANSPORT_TEMPLATES, build,
    )
    output, compiler = Path(output), Path(compiler)
    root = Path(__file__).resolve().parents[1]
    compiler_body = compiler.read_bytes()
    if cold_report is not None:
        executable = build(output, compiler, Path(cold_report))
        scope = "MATCHING_SOURCE_COLD_BUILD"
    else:
        from tools.build_hia_nominal_json import admit_compile_receipt
        from tools.build_hia_sqlite_pager import (
            EMBED_SOURCE, build_embedder, embed, link, load_static_object, verify_executable,
        )
        from tools.qualify_hia_selfhost import compile_stage

        output.mkdir(mode=0o700)
        names = (*COMPONENTS.values(), EMBED_SOURCE, *TRANSPORT_TEMPLATES.values(),
                 *TRANSPORT_ROLES, DRIVER, *SOURCE_FILES)
        inputs = {name: (root / name).read_bytes() for name in names}
        images, receipts = {}, {}
        for role, name in COMPONENTS.items():
            path, receipt = compile_stage(output, role, compiler, inputs[name])
            image = path.read_bytes()
            admit_compile_receipt(receipt, compiler_bytes=compiler_body,
                                  source_bytes=inputs[name], image_bytes=image)
            images[role], receipts[role] = image, receipt
        templates = {name: build_embedder(output, compiler, inputs[path], label=name + "-adapters")
                     for name, path in TRANSPORT_TEMPLATES.items()}
        objects = [load_static_object(templates["constructor"], 0, inputs[ADAPTER],
                                      continuations=(templates["constructor-tail"],))]
        objects.extend(load_static_object(templates["publication"], role, inputs[adapter])
                       for role, adapter in enumerate(TRANSPORT_ROLES[1:], 1))
        embedder = build_embedder(output, compiler, inputs[EMBED_SOURCE])
        for role, label in CONSTRUCTOR_IMAGES.items():
            objects.append(embed(output, label, "constructor-" + role, images[role], embedder))
        binary, link_receipt = link(output, images["linker"], images["owner"], objects,
            wire_magic=b"HIALNK01", executable_limit=ORDINARY_CLI_IMAGE_CAPACITY)
        for role in CONSTRUCTOR_IMAGES:
            verify_executable(binary, images[role])
        if (compiler.read_bytes() != compiler_body
                or any((root / name).read_bytes() != raw for name, raw in inputs.items())):
            raise ValueError("development nominal inputs changed during actual compilation")
        executable = output / "hia-nominal-constructor"
        executable.write_bytes(binary)
        executable.chmod(0o500)
        value = manifest_value(executable, compiler_sha256=sha256(compiler_body).hexdigest(),
            source_sha256={name: sha256(inputs[name]).hexdigest() for name in SOURCE_FILES},
            cold_report_sha256=None)
        (output / "program-manifest.json").write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
        report = {"scope": "DEVELOPMENT_ONLY", "matching_source_cold_claim": False,
                  "compiler_sha256": sha256(compiler_body).hexdigest(),
                  "executable_sha256": sha256(binary).hexdigest(),
                  "source_sha256": {name: sha256(raw).hexdigest() for name, raw in inputs.items()},
                  "receipts": receipts, "link_receipt": link_receipt}
        (output / "development-build.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        scope = "DEVELOPMENT_ONLY"
    manifest = output / "program-manifest.json"
    pin = sha256(manifest.read_bytes()).hexdigest()
    selection = _Selection(manifest, pin)
    return NominalProgramFixture(manifest, pin, selection, scope)
