"""Bind a rebuilt Core companion group to its closed Page and scheduler base."""
from __future__ import annotations

from hashlib import sha256
import importlib
import json
import os
from pathlib import Path

from hepta import hia_native_helpers as authority
from hepta.hia_core_companion_worker_bundle import SCHEMA
from tools.hia_core_companion_release import COMPANIONS

_EXECUTED_SOURCE = Path(__file__).resolve().read_bytes()


def build(output, *, base_bundle, compiler):
    output = Path(output).absolute()
    base = authority._read(Path(base_bundle).absolute(), authority.MAX_BUNDLE_BYTES)
    compiler = authority._read(Path(compiler).absolute(), authority.MAX_IMAGE_BYTES)
    own = authority._read(Path(__file__).resolve(), authority.MAX_SOURCE_BYTES)
    if own.raw != _EXECUTED_SOURCE:
        raise ValueError("executing Core Worker binding author changed after import")
    base_record = authority._decode(base.raw)
    if (type(base_record) is not dict
            or base_record.get("schema") != "hepta.hia.artifact-page-worker-bundle.v1"):
        raise ValueError("the default Core companion Worker requires its exact Page wrapper")
    captured = [(base, authority.MAX_BUNDLE_BYTES), (compiler, authority.MAX_IMAGE_BYTES),
                (own, authority.MAX_SOURCE_BYTES)]
    source_groups, entries = [], []
    compiler_sha = sha256(compiler.raw).hexdigest()
    for _, family in COMPANIONS:
        selection = importlib.import_module("hepta.hia_core_" + family + "_selection")
        physical = selection.current_inputs()
        selection.checked_abi(physical[selection.ABI_SOURCE])
        hashes = {name: sha256(raw).hexdigest() for name, raw in physical.items()}
        manifest = authority._read(output.parent / "core" / family / "manifest.json", 16384)
        value = selection._manifest(manifest.raw, hashes, compiler_sha)
        image = authority._read(manifest.path.parent / value["image_path"], authority.MAX_IMAGE_BYTES)
        if sha256(image.raw).hexdigest() != value["image_sha256"]:
            raise ValueError("Core Worker image differs from its complete manifest")
        captured.extend(((manifest, 16384), (image, authority.MAX_IMAGE_BYTES)))
        source_groups.append((selection, physical))
        entries.append(dict(kind=family,
                            manifest_path=manifest.path.relative_to(output.parent).as_posix(),
                            manifest_sha256=sha256(manifest.raw).hexdigest()))
    record = dict(schema=SCHEMA, target=authority.TARGET, abi=authority.ABI,
                  base_bundle=base.path.relative_to(output.parent).as_posix(),
                  base_bundle_sha256=sha256(base.raw).hexdigest(),
                  compiler_sha256=compiler_sha, companions=entries)
    raw = (json.dumps(record, sort_keys=True, indent=2) + "\n").encode()

    def unchanged():
        if any(authority._read(item.path, limit) != item for item, limit in captured):
            raise ValueError("Core Worker composition inputs changed")
        if any(selection.current_inputs() != original for selection, original in source_groups):
            raise ValueError("Core Worker physical source changed")
        if Path(__file__).resolve().read_bytes() != _EXECUTED_SOURCE:
            raise ValueError("executing Core Worker binding author changed")

    unchanged()
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
    unchanged()
    if output.read_bytes() != raw:
        raise ValueError("Core Worker composition changed at publication")
    return output


def stage_installed(output, scratch, release, compiler, cold_report, base_bundle):
    """Rebuild all three complete inputs and require the installed HIA owner's exact bytes."""
    from tools.hia_core_companion_build import build as build_companion
    from tools.build_hia_worker_release import _copy_report

    output, scratch, release = Path(output), Path(scratch), Path(release)
    captured = []
    for _, family in COMPANIONS:
        manifest = _copy_report(
            build_companion(family, scratch / ("core-" + family), compiler, cold_report),
            output / "core" / family)
        old = authority._read(release / ("core-" + family + "-manifest.json"), 16384)
        new = authority._read(manifest, 16384)
        if old.raw != new.raw:
            raise ValueError("installed Core manifest differs from matching cold rebuild: " + family)
        image_name = "core-" + family + ".image.bin"
        old_image = authority._read(release / image_name, authority.MAX_IMAGE_BYTES)
        new_image = authority._read(manifest.parent / image_name, authority.MAX_IMAGE_BYTES)
        if old_image.raw != new_image.raw:
            raise ValueError("installed Core image differs from matching cold rebuild: " + family)
        captured.extend(((old, 16384), (new, 16384),
                         (old_image, authority.MAX_IMAGE_BYTES), (new_image, authority.MAX_IMAGE_BYTES)))
    result = build(output / "core-worker.json", base_bundle=base_bundle, compiler=compiler)
    snapshot = authority._read(result, authority.MAX_BUNDLE_BYTES)
    for item, limit in captured:
        if authority._read(item.path, limit) != item:
            raise ValueError("installed Core input changed after its rebuild")
    if authority._read(snapshot.path, authority.MAX_BUNDLE_BYTES) != snapshot:
        raise ValueError("installed Core Worker changed at terminal readback")
    result.chmod(0o400)
    return result
