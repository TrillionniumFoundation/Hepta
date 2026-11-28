"""Read the exact stage-19 HIA policy publication without executing a host policy."""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import struct

MAGIC = b"HIACPUB1"
MANIFEST = "carrier-policies.hiadat"
ROLES = (
    ("image", 1, "examples/hia_bootstrap/carrier_image_policy.hepta", "carrier-image-policy.flat"),
    ("cell", 2, "examples/hia_bootstrap/carrier_cell_policy.hepta", "carrier-cell-policy.flat"),
)


def pin(raw):
    return {"bytes": len(raw), "sha256": sha256(raw).hexdigest()}


def parse(raw):
    if type(raw) is not bytes or len(raw) != 304:
        raise ValueError("carrier policy publication must have its exact 304-byte extent")
    if struct.unpack_from("<8s3Q", raw) != (MAGIC, 1, 2, 0):
        raise ValueError("carrier policy publication magic/version/role count differs")
    compiler_size = struct.unpack_from("<Q", raw, 32)[0]
    seed_size = struct.unpack_from("<Q", raw, 72)[0]
    if not 0 < compiler_size <= 16777216 or not 0 < seed_size <= 16777216:
        raise ValueError("carrier policy compiler/seed extent differs")
    value = {
        "compiler": {"bytes": compiler_size, "sha256": raw[40:72].hex()},
        "seed": {"bytes": seed_size, "sha256": raw[80:112].hex()},
        "roles": {},
    }
    for index, (kind, role, source_name, image_name) in enumerate(ROLES):
        at = 112 + index * 96
        actual_role, reserved, source_size, image_size = struct.unpack_from("<4Q", raw, at)
        if (actual_role != role or reserved != 0
                or not 0 < source_size <= 1048576 or not 0 < image_size <= 1048576):
            raise ValueError("carrier policy role or physical extent differs")
        value["roles"][kind] = {
            "source_path": source_name, "image_path": image_name,
            "source": {"bytes": source_size, "sha256": raw[at + 32:at + 64].hex()},
            "image": {"bytes": image_size, "sha256": raw[at + 64:at + 96].hex()},
        }
    return value


def capture(directory, expected_sha256, package, read):
    directory, package = Path(directory), Path(package)
    if (type(expected_sha256) is not str or len(expected_sha256) != 64
            or any(c not in "0123456789abcdef" for c in expected_sha256)
            or directory != directory.resolve(strict=True)):
        raise ValueError("carrier policy release needs an exact pin and canonical directory")
    raw = read(directory / MANIFEST)
    if sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("carrier policy publication identity differs")
    value = parse(raw)
    captured = {directory / MANIFEST: raw}
    from .hia_carrier_build_identity import source_path
    for kind, _role, name, image_name in ROLES:
        source_file = source_path(package, name)
        source = read(source_file)
        image_file = directory / image_name
        image = read(image_file)
        record = value["roles"][kind]
        if pin(source) != record["source"] or pin(image) != record["image"]:
            raise ValueError("carrier installed policy source/image differs")
        captured[source_file] = source
        captured[image_file] = image
    for path, original in captured.items():
        if read(path) != original:
            raise ValueError("carrier installed policy inputs changed during capture")
    return value, captured


from .hia_loaded_source import register_loaded_module as _register_loaded_source
_register_loaded_source(__name__)
