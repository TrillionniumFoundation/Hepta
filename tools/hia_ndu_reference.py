"""Read the retired Rust scalar oracle from its immutable review archive.

This module is for independent tests and explicit reference rebuilds. Production
admission and package selection do not import it or extract the old executor.
"""
from hashlib import sha256
import io
import json
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE = 'review-evidence/hia-ndu-persistent-20261108-5e6c/originals.tar.xz'
ARCHIVE_SHA256 = '7f46424cdfb8171650bcf77dfb9b0c25412b4e877c413a90a9108b7604cd8cfd'
PREFIX = 'frozen-source/rust/hia-ndu-bridge/'
FILES = {
    'Cargo.toml': '4644c96a667aa65eaf2dd05ea8035e84839f36d2845b1e6f605d68aa6ec150ac',
    'Cargo.lock': '912c2f5520311284a89e452670415404523b8a5ffa18246f2ec3e2e727a0cf37',
    'src/main.rs': 'cf61b6055fb7299d661092d7e75a3e5c05125b780cbca72545f2de717bf4f574',
    'upstream.json': '84205481f743eb00e3e8da8e79a45c382f47ff0673e67eaf24a952ed38ecc997',
}


def reference_files():
    raw = (ROOT / ARCHIVE).read_bytes()
    if sha256(raw).hexdigest() != ARCHIVE_SHA256:
        raise ValueError('retired NDU reference archive differs from the original')
    result = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:xz') as archive:
        members = archive.getmembers()
        for name, expected in FILES.items():
            matches = [item for item in members if item.name == PREFIX + name]
            if len(matches) != 1 or not matches[0].isfile() or matches[0].size > 65536:
                raise ValueError('invalid retired NDU reference member')
            data = archive.extractfile(matches[0]).read()
            if sha256(data).hexdigest() != expected:
                raise ValueError('retired NDU reference source differs')
            result[name] = data
    return result


def reference_pin():
    return json.loads(reference_files()['upstream.json'])


def materialize_reference(directory):
    """Write only four verified ordinary files to a new explicit oracle folder."""
    sources = reference_files()
    directory = Path(directory)
    directory.mkdir(mode=0o700)
    for name, raw in sources.items():
        target = directory / name
        target.parent.mkdir(exist_ok=True)
        with target.open('xb') as stream:
            stream.write(raw)
    return directory
