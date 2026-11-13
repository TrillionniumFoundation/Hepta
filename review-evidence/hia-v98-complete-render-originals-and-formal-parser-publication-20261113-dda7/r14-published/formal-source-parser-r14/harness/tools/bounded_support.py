"""Read-only source observation for the fixed parser controls, not product code."""
import hashlib
import json
import os
from pathlib import Path
import stat

ROOT = Path(os.environ['HIA_PARSER_CONTROL_ROOT']).resolve(strict=True)
SOURCE = Path(os.environ['HIA_PARSER_CONTROL_SOURCE']).resolve(strict=True)


def snapshot():
    expected = json.loads((ROOT / 'FIXED-SOURCE-MANIFEST.json').read_bytes())
    actual = {}
    caches = []
    for directory, dirs, files in os.walk(SOURCE, followlinks=False):
        directory = Path(directory)
        if directory == SOURCE:
            dirs[:] = [name for name in dirs if name != '.git']
        for name in dirs:
            assert not (directory / name).is_symlink(), ('source directory symlink', name)
        for name in files:
            path = directory / name
            info = path.lstat()
            assert stat.S_ISREG(info.st_mode), ('source not regular', path)
            relative = path.relative_to(SOURCE).as_posix()
            if '__pycache__' in path.relative_to(SOURCE).parts and path.suffix == '.pyc':
                caches.append(relative)
                continue
            assert relative in expected, ('unregistered source file', relative)
            raw = path.read_bytes()
            actual[relative] = {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
                                'mode': stat.S_IMODE(info.st_mode)}
    assert set(actual) == set(expected), ('missing frozen source', sorted(set(expected) - set(actual)))
    return dict(sorted(actual.items()))
