"""Lossless bounded export of the exact executing interpreter tool dependency."""
from pathlib import Path
import hashlib
import io
import json
import os
import stat
import sys
import tarfile


def identity(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def export_interpreter(output):
    prefix = Path(sys.base_prefix)
    selected = {'bin/python3.14': Path(sys.executable).resolve()}
    library = prefix / 'lib' / 'libpython3.14.so.1.0'
    assert library.is_file()
    selected['lib/libpython3.14.so.1.0'] = library.resolve()
    omitted = []
    standard = prefix / 'lib' / 'python3.14'
    for path in sorted(standard.rglob('*')):
        rel = path.relative_to(prefix).as_posix()
        if path.is_file():
            if 'site-packages' in path.parts or '__pycache__' in path.parts or path.suffix in ('.pyc', '.a'):
                omitted.append(rel)
            else:
                selected[rel] = path.resolve()
    manifest = []
    archive = output / 'cpython3144-tool.tar.gz'
    with tarfile.open(archive, 'w:gz', compresslevel=1) as tar:
        for name, path in sorted(selected.items()):
            raw = path.read_bytes()
            mode = stat.S_IMODE(path.stat().st_mode)
            row = {'path': name, **identity(raw), 'mode': mode}
            manifest.append(row)
            info = tarfile.TarInfo(name)
            info.size = len(raw); info.mode = mode; info.mtime = 0
            tar.addfile(info, io.BytesIO(raw))
    report = {'schema': 'hia.exact-interpreter-development-tool-export.v1',
              'python': sys.version, 'executable': str(Path(sys.executable)),
              'prefix': str(prefix), 'archive': identity(archive.read_bytes()),
              'archive_path': archive.name, 'files': manifest, 'omitted_tool_paths': omitted,
              'scope': 'DEVELOPMENT_TOOL_DEPENDENCY_NOT_PRODUCT_QUALIFICATION',
              'relocation_environment': ['PYTHONHOME=<export-root>', 'LD_LIBRARY_PATH=<export-root>/lib']}
    (output / 'INTERPRETER-EXPORT.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    return {'archive': report['archive'], 'files': len(manifest),
            'scope': report['scope']}
