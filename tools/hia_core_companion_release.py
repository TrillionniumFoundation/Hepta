"""Native construction and independent admission of the three Core companions."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import struct

COMPANIONS = ((11, "compare"), (12, "integer"), (13, "unpack"))
OWNER = "source_core_companion_manifest.hepta"
CHECKER = "source_core_companion_stage.hepta"


def inputs(family):
    if type(family) is not str or family not in {kind for _, kind in COMPANIONS}:
        raise ValueError("unknown Core companion")
    return (
        "examples/hia_bootstrap/core_" + family + ".hepta",
        "hepta/hia_core_" + family + "_abi.json",
        "hepta/hia_core_" + family + "_native.py",
        "hepta/hia_core_" + family + "_selection.py",
    )


def manifest_request(role, parts):
    if type(role) is not int or role not in {value for value, _ in COMPANIONS}:
        raise ValueError("unknown Core companion role")
    parts = tuple(parts)
    if len(parts) != 7 or any(type(raw) is not bytes or not 1 <= len(raw) <= 1048576
                              for raw in parts):
        raise ValueError("Core companion requires seven bounded physical inputs")
    return struct.pack("<8s8Q", b"HIACCM01", role, *map(len, parts)) + b"".join(parts)


def check_request(role, parts):
    if type(role) is not int or role not in {value for value, _ in COMPANIONS}:
        raise ValueError("unknown Core companion role")
    parts = tuple(parts)
    if (len(parts) != 7 or any(type(raw) is not bytes for raw in parts)
            or not 1 <= len(parts[0]) <= 16384
            or any(not 1 <= len(raw) <= 1048576 for raw in parts[1:])):
        raise ValueError("Core checker requires a manifest and six bounded inputs")
    return (struct.pack("<8s4Q", b"HIASTC01", 14, role, 7, 0)
            + b"".join(struct.pack("<Q", len(raw)) + raw for raw in parts))


def stage_core_companions(work, seed, compile_sources, call, compiler, publish):
    """Use the captured HIA compiler, owner and independent checker before publishing."""
    from tools.build_hia_native_store_release import release_sources
    from tools.hia_core_host_custody import ARCHIVE_PATH, DECODER_SOURCE, REQUEST_MAGIC

    builds = release_sources(seed, compile_sources, call)
    author, author_images, author_sources = builds.kit_objects(OWNER, "source_build_packer.hepta")
    checker, checker_images, _ = builds.kit_objects(CHECKER, "source_build_packer.hepta")
    decoder, decoder_images, _ = builds.kit_objects(Path(DECODER_SOURCE).name, "source_build_packer.hepta")
    if any(images["selfhost.hepta"] != compiler for images in (author_images, checker_images, decoder_images)):
        raise ValueError("Core companion kit compiler differs from the admitted compiler")
    names = {"core_" + family + ".hepta": inputs(family)[0] for _, family in COMPANIONS}
    _, images, sources = builds(names)
    additional = {Path(inputs(family)[1]).name: inputs(family)[1] for _, family in COMPANIONS}
    additional[Path(ARCHIVE_PATH).name] = ARCHIVE_PATH
    raw_inputs = builds.capture_sources(additional)
    custody = raw_inputs[Path(ARCHIVE_PATH).name]
    work = Path(work)
    for role, family in COMPANIONS:
        name = "core_" + family + ".hepta"
        source, image = sources[name], images[name]
        abi = raw_inputs[Path(inputs(family)[1]).name]
        bridge, selection = (call(decoder, "build",
            struct.pack("<8s2Q", REQUEST_MAGIC, role, kind) + custody) for kind in (1, 2))
        parts = (source, image, author_sources["selfhost.hepta"], compiler, abi, bridge, selection)
        manifest = call(author, "build", manifest_request(role, parts))
        checked = call(checker, "build", check_request(
            role, (manifest, source, image, compiler, abi, bridge, selection)))
        if checked != struct.pack("<8s3Q", b"HIASTOK1", 14, role, len(manifest)):
            raise ValueError("independent native Core companion checker rejected publication")
        # This is an additional host readback. Both production decisions above are HIA.
        expected = {
            "schema": "hepta.hia.core-" + family + "-native.v1",
            "source_sha256": sha256(source).hexdigest(),
            "abi_sha256": sha256(abi).hexdigest(),
            "bridge_sha256": sha256(bridge).hexdigest(),
            "selection_sha256": sha256(selection).hexdigest(),
            "image_path": "core-" + family + ".image.bin",
            "image_sha256": sha256(image).hexdigest(),
            "compiler_sha256": sha256(compiler).hexdigest(),
        }
        if json.loads(manifest) != expected:
            raise ValueError("native Core companion fields differ from captured bytes")
        manifest_path = work / ("core-" + family + "-manifest.json")
        image_path = work / expected["image_path"]
        with manifest_path.open("xb") as stream:
            stream.write(manifest)
        with image_path.open("xb") as stream:
            stream.write(image)
        publish(manifest_path)
        publish(image_path, expected=expected["image_sha256"])
