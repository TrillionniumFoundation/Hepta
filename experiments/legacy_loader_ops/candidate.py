"""Fail-closed source recipe for isolated modules, not production monkeypatching.

Exact pinned pre-extraction sources are immutable historical test inputs. This
recipe remains the #621 isolated oracle after normal-source production extraction.
It is not a second maintained production implementation. Drift requires review;
there is no fuzzy matching, generated source download or silent fallback.
"""
import hashlib
from pathlib import Path
import sys
from types import ModuleType

PINS = {
    'packages': '5623c715a0aae116e6aae8211b7eef93cfc6058bf11d503b913389e322d38cc1',
    'modules': 'c933a5ab29a1a54b5b36e0e0b2554ce250db3303a559c742fddf2b65fcf0fcea',
}

# Each tuple is (old, new, exact occurrence count). No free-form replacements.
PACKAGE_EDITS = [
    ('from .ast import', 'from hepta.ast import', 1),
    ('def load_package(root, _stack=None, _cache=None) -> Package:',
     'def load_package(root, _stack=None, _cache=None, *, ops=None) -> Package:\n    ops = LegacyLoaderOps() if ops is None else ops', 1),
    ('data = manifest.read_bytes()', "data = ops.read(manifest, 'manifest')", 1),
    ('tomllib.loads(data.decode("utf-8"))', 'ops.toml(data, manifest)', 1),
    ('load_package(dep_root, stack + [root], cache)', 'load_package(dep_root, stack + [root], cache, ops=ops)', 1),
    ('def package_snapshot(package: Package) -> dict:',
     'def package_snapshot(package: Package, *, ops=None) -> dict:\n    ops = LegacyLoaderOps() if ops is None else ops', 1),
    ('digest(manifest.read_bytes())', "digest(ops.read(manifest, 'manifest'))", 1),
    ('p.source_root.rglob("*")', 'ops.inventory(p.source_root)', 1),
    ('digest(f.read_bytes())', "digest(ops.read(f, 'source'))", 1),
    ('digest(sidecar.read_bytes())', "digest(ops.read(sidecar, 'sidecar'))", 1),
    ('def verify_lock(package: Package) -> dict:',
     'def verify_lock(package: Package, *, ops=None) -> dict:\n    ops = LegacyLoaderOps() if ops is None else ops', 1),
    ('json.loads(file.read_bytes())', "ops.json(ops.read(file, 'lock'), file)", 1),
    ('expected = package_snapshot(package)', 'expected = package_snapshot(package, ops=ops)', 1),
    ('def write_lock(root) -> dict:',
     'def write_lock(root, *, ops=None) -> dict:\n    ops = LegacyLoaderOps() if ops is None else ops', 1),
    ('package = load_package(root)', 'package = load_package(root, ops=ops)', 1),
    ('snapshot = package_snapshot(package)', 'snapshot = package_snapshot(package, ops=ops)', 1),
    ('package_snapshot(load_package(package.root))',
     'package_snapshot(load_package(package.root, ops=ops), ops=ops)', 1),
]
MODULE_EDITS = [
    ('from .ast import', 'from hepta.ast import', 1),
    ('from dataclasses import dataclass, fields, is_dataclass', 'from dataclasses import dataclass, field, fields, is_dataclass', 1),
    ('from .parser import parse\nfrom .lexer import tokenize\n', '', 1),
    ('    c_imports: list[dict]\n', '    c_imports: list[dict]\n    _ops: object = field(default_factory=LegacyLoaderOps, repr=False, compare=False)\n', 1),
    ('Path(p).read_bytes()', "self._ops.read(Path(p), 'revalidation')", 1),
    ('package_snapshot(load_package(self.package.root))',
     'package_snapshot(load_package(self.package.root, ops=self._ops), ops=self._ops)', 1),
    ('def load_project(entry, *, locked=False, source_overrides=None) -> LoadedProject:',
     'def load_project(entry, *, locked=False, source_overrides=None, ops=None) -> LoadedProject:\n    ops = LegacyLoaderOps() if ops is None else ops', 1),
    ('package = load_package(entry)', 'package = load_package(entry, ops=ops)', 1),
    ('package = load_package(entry.parent)', 'package = load_package(entry.parent, ops=ops)', 1),
    ('package = load_package(root)', 'package = load_package(root, ops=ops)', 1),
    ('state = verify_lock(package) if locked else (package_snapshot(package) if package else None)',
     'state = verify_lock(package, ops=ops) if locked else (package_snapshot(package, ops=ops) if package else None)', 1),
    ('data = path.read_bytes()', "data = ops.read(path, 'source')", 1),
    ('metadata_bytes = sidecar.read_bytes()', "metadata_bytes = ops.read(sidecar, 'sidecar')", 1),
    ('metadata = json.loads(metadata_bytes)', 'metadata = ops.json(metadata_bytes, sidecar)', 1),
    ('original_data = original_header.read_bytes()', "original_data = ops.read(original_header, 'header')", 1),
    ('for token in tokenize(text, str(path)):', 'for token in ops.tokenize(text, str(path)):', 1),
    ('program = parse(text, str(path))', 'program = ops.parse(text, str(path))', 1),
    ('package, state, locked, bindings, c_imports)', 'package, state, locked, bindings, c_imports, ops)', 1),
]


def source(name):
    raw = (Path(__file__).resolve().parent / 'baseline' / (name + '.py')).read_bytes()
    if hashlib.sha256(raw).hexdigest() != PINS[name]:
        raise RuntimeError('upstream drift: review extraction recipe for ' + name)
    text = raw.decode('utf-8')
    for old, new, count in PACKAGE_EDITS if name == 'packages' else MODULE_EDITS:
        if text.count(old) != count:
            raise RuntimeError('recipe occurrence mismatch: ' + old)
        text = text.replace(old, new)
    # Import after __future__, without changing the algorithms or their errors.
    anchor = 'from __future__ import annotations\n'
    return text.replace(anchor, anchor + '\nfrom .ops import LegacyLoaderOps\n', 1)


def _load(name):
    qualified = __package__ + '.' + name
    module = ModuleType(qualified)
    module.__package__ = __package__
    module.__file__ = '<isolated extraction: ' + name + '>'
    sys.modules[qualified] = module  # New experiment namespace only; dataclasses need it.
    try:
        exec(compile(source(name), module.__file__, 'exec'), module.__dict__)
    except BaseException:
        sys.modules.pop(qualified, None)
        raise
    return module


packages = _load('packages')
modules = _load('modules')
