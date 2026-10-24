#!/usr/bin/env python3
"""Build the isolated pinned Debian Clang 19.1.7 scalar frontend; no downloads."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--include', type=Path, required=True, help='Matching llvm-19/include root')
    p.add_argument('--clang-library', type=Path, required=True)
    p.add_argument('--llvm-library', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--cxx', default='g++')
    args = p.parse_args()
    inputs = [ROOT/'tools/c_frontend.cpp', args.include/'clang/Basic/Version.inc',
              args.clang_library, args.llvm_library]
    for path in inputs:
        if not path.is_file():
            p.error('Missing explicit build dependency: '+str(path))
    version = inputs[1].read_text()
    for marker in ('#define CLANG_VERSION_MAJOR 19', '#define CLANG_VERSION_MINOR 1', '#define CLANG_VERSION_PATCHLEVEL 7'):
        if marker not in version:
            p.error('Requires pinned Clang 19.1.7 development headers')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    cmd = [args.cxx, '-std=c++17', '-O0', '-I', str(args.include.resolve()),
           str(inputs[0]), str(args.clang_library.resolve()), str(args.llvm_library.resolve()),
           '-o', str(args.output.resolve())]
    subprocess.run(cmd, check=True, timeout=120)
    receipt = {'command': cmd, 'inputs': {str(x.resolve()): hashlib.sha256(x.read_bytes()).hexdigest() for x in inputs},
               'output_sha256': hashlib.sha256(args.output.read_bytes()).hexdigest(),
               'qualification': 'build only; runtime protocol also requires exact Debian 19.1.7 (3+b1)'}
    args.output.with_suffix(args.output.suffix+'.build.json').write_text(json.dumps(receipt, indent=2)+'\n')
    print(json.dumps(receipt, indent=2))

if __name__ == '__main__':
    main()
