"""Exercise the native Worker's release-directory custody at its real command boundary.

The external fixture supplies one already admitted capsule and kernel observation
per branch. It executes each complete generated launcher policy; it does not
qualify capsule contents, mutable Store custody, or a complete installation.
"""
from pathlib import Path
from hashlib import sha256
import argparse
import ctypes
import json
import mmap
import stat
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.generate_hia_worker_flow_packer import (
    PROGRAMS, LAUNCHER_KIND, REPLAY_LAUNCHER_KIND, INTAKE_LAUNCHER_KIND, FULL_LAUNCHER_KIND)
from tools.generate_hia_readonly_worker_capsule import (
    NATIVE_ROLES, PROOF_TRUST_BYTES, replay_inventory)
from tools.generate_hia_worker_evaluate_launcher import inventory

BAD = 0xfffffffd
OBSERVATION = int.from_bytes(b'HIADFO01', 'little')

def qualify(build, output):
    receipt = json.loads((build / 'build.json').read_bytes())
    output.mkdir(mode=0o700, exist_ok=False)
    cases = []
    kinds = ((LAUNCHER_KIND, len(NATIVE_ROLES)),
             (REPLAY_LAUNCHER_KIND, len(replay_inventory())),
             (INTAKE_LAUNCHER_KIND, len(replay_inventory(intake=True))),
             (FULL_LAUNCHER_KIND, len(inventory())))
    vectors = (
        ('own-private-directory', 1000, 1000, stat.S_IFDIR | 0o700, True),
        ('own-readable-directory', 1000, 1000, stat.S_IFDIR | 0o755, True),
        ('root-readonly-directory', 64788, 0, stat.S_IFDIR | 0o555, True),
        ('root-readonly-group-directory', 64788, 0, stat.S_IFDIR | 0o550, True),
        ('root-caller-private-directory', 0, 0, stat.S_IFDIR | 0o700, True),
        ('foreign-readonly-directory', 64788, 1000, stat.S_IFDIR | 0o555, False),
        ('root-owner-writable-directory', 64788, 0, stat.S_IFDIR | 0o755, False),
        ('root-group-writable-directory', 64788, 0, stat.S_IFDIR | 0o575, False),
        ('root-other-writable-directory', 64788, 0, stat.S_IFDIR | 0o557, False),
        ('own-group-writable-directory', 1000, 1000, stat.S_IFDIR | 0o770, False),
        ('own-other-writable-directory', 1000, 1000, stat.S_IFDIR | 0o707, False),
        ('root-regular-file', 64788, 0, stat.S_IFREG | 0o444, False),
        ('root-symbolic-link', 64788, 0, stat.S_IFLNK | 0o555, False),
    )
    for kind, role_count in kinds:
        source = PROGRAMS[kind][0]
        source_bytes = (ROOT / source).read_bytes()
        if receipt['source_sha256'][source] != sha256(source_bytes).hexdigest():
            raise ValueError('component receipt does not bind current source')
        record = receipt['flats'][Path(source).name]
        flat = (build / record['path']).read_bytes()
        if sha256(flat).hexdigest() != record['sha256']:
            raise ValueError('component image changed')
        image = mmap.mmap(-1, len(flat), prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
        image.write(flat)
        entry = ctypes.CFUNCTYPE(ctypes.c_uint32, ctypes.c_void_p, ctypes.c_size_t,
                                 ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
                                 ctypes.c_size_t)(ctypes.addressof(ctypes.c_ubyte.from_buffer(image)))
        for name, caller, owner, mode, wanted in vectors:
            work = ctypes.create_string_buffer(4096)
            result = ctypes.create_string_buffer(4096)
            def invoke(raw):
                inp = ctypes.create_string_buffer(raw)
                count = entry(inp, len(raw), result, len(result), work, len(work))
                if count == BAD:
                    return count, None
                if not 512 <= count <= len(result):
                    raise AssertionError((kind, name, count))
                return count, struct.unpack_from('<8Q', result.raw)
            def observe(command, fd, size, payload=b'', offset=0):
                return (struct.pack('<8Q', OBSERVATION, command[1], command[2], 0,
                                    fd, size, offset, len(payload)) + payload)
            extents = (PROOF_TRUST_BYTES + 313, 1, 1, 1)
            capsule_size = 56 + 48 * role_count + sum(extents)
            count, command = invoke(b'HIALEN02/' + b'0' * 64)
            assert command[2] == 19, (kind, name, command)
            count, command = invoke(observe(command, 3, capsule_size))
            assert command[2] == 20, (kind, name, command)
            count, command = invoke(observe(command, 4, 8, struct.pack('<Q', 1)))
            assert command[2] == 2, (kind, name, command)
            count, command = invoke(observe(command, 3, capsule_size,
                                             struct.pack('<4Q', *extents), 24))
            assert command[2] == 18, (kind, name, command)
            count, command = invoke(observe(command, 3, 24, struct.pack('<3Q', caller, owner, mode)))
            admitted = count != BAD
            assert admitted == wanted, (kind, name, count, command)
            if admitted:
                assert command[2] == 2
            cases.append({'kind': kind, 'case': name, 'caller_uid': caller, 'owner_uid': owner,
                          'mode': oct(mode), 'admitted': admitted, 'passed': True})
        image.close()
    report = {
        'schema': 'hia.worker-release-directory-custody-qualification.v1',
        'scope': 'four complete native policies at the capsule/release command boundary',
        'status': 'passed', 'case_count': len(cases), 'cases': cases,
        'build_receipt_sha256': sha256((build / 'build.json').read_bytes()).hexdigest(),
        'component_build_scope': receipt['scope'],
        'mutable_state_qualified': False, 'whole_installation_qualified': False,
    }
    (output / 'qualification.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'status': report['status'], 'case_count': report['case_count']}))
    return report

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    qualify(args.build.resolve(), args.output.resolve())

if __name__ == '__main__':
    main()
