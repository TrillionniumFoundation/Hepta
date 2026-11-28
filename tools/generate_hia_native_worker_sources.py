"""Regenerate the current Worker assets from one explicit native authority.

This is development-only authoring. Published builds use the emitted HIA
policies, pinned tables and recipes; they do not execute this module.
"""
from pathlib import Path
from hashlib import sha256
import argparse, json, subprocess, sys
ROOT = Path(__file__).resolve().parents[1]
AUTHORITY = 'docs/HIA_NATIVE_SOURCE_AUTHORITY.json'
AUTHORITY_MODULES = ('tools.generate_hia_worker_install_identity',
                     'tools.generate_hia_worker_protocol_sources')
MODULES = ('tools.generate_hia_core_host_custody',
           'tools.generate_hia_core_companion_manifest',
           'tools.generate_hia_core_companion_stage',
           'tools.generate_hia_core_companion_recipe',
           'tools.generate_hia_core_companion_worker_manifest',
           'tools.generate_hia_source_agent_helper_manifest',
           'tools.generate_hia_agent_helper_recipe',
           'tools.generate_hia_release_extension_catalog',
           *AUTHORITY_MODULES)
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
        command = [sys.executable, '-m', module]
        if module in AUTHORITY_MODULES:
            command.extend(('--native-source-authority', str(path)))
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
