"""Regenerate the three Worker assets from one explicit native authority.

This is development-only authoring. Published builds use the emitted HIA
policies, pinned tables and recipes; they do not execute this module.
"""
from pathlib import Path
from hashlib import sha256
import argparse, json, subprocess, sys
ROOT = Path(__file__).resolve().parents[1]
AUTHORITY = 'docs/HIA_NATIVE_SOURCE_AUTHORITY.json'
MODULES = ('tools.generate_hia_worker_manifest',
           'tools.generate_hia_worker_install_identity',
           'tools.generate_hia_worker_install_recipes')
def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--native-source-authority', type=Path, default=ROOT / AUTHORITY)
    p.add_argument('--check', action='store_true')
    args = p.parse_args()
    path = args.native_source_authority.resolve(strict=True)
    before = path.read_bytes()
    from tools.hia_native_worker_source_authority import load_native_source_authority
    paths = load_native_source_authority(path)
    for module in MODULES:
        command = [sys.executable, '-m', module, '--native-source-authority', str(path)]
        if args.check:
            command.append('--check')
        subprocess.run(command, cwd=ROOT, check=True)
        if path.read_bytes() != before:
            raise RuntimeError('native authority changed during regeneration')
    print(json.dumps({'native_source_paths': len(paths),
                      'authority_sha256': sha256(before).hexdigest(),
                      'assets': len(MODULES), 'check': args.check}, sort_keys=True))
if __name__ == '__main__':
    main()
