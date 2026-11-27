"""Construct the audit history component from four pinned native seed programs.

This records component construction and actual native composition controls. It
does not replace the complete cold source admission or release qualification.
"""
from __future__ import annotations
import argparse
import ctypes
from hashlib import sha256
import json
from pathlib import Path
import struct

from hepta.hia_json_preflight_native import NativeHiaJsonImage
from tools.generate_hia_mcp_request_audit import ROLES, PACK_MAGIC, adapter_source
from tools.hia_native_seed_test_support import NativeSeeds


class HistorySeeds(NativeSeeds):
    def backend(self, profile):
        if profile != 'div-word' or profile in self.profiles:
            return super().backend(profile)
        # The unchanged word profile initializes the existing native packer.
        self.backend('word')
        source = self.root/'examples/hia_bootstrap/seed_div_word_backend.hepta'
        flat = self.compile(source.read_bytes(), 'v1')
        packed = self.invoke(self.profiles['seed-packer'],
                             b'HIAFLT01'+struct.pack('<Q', len(flat))+flat)
        target = self.output/'seed-div-word'
        target.write_bytes(packed)
        target.chmod(0o500)
        self.profiles[profile] = target
        return target


def native_call(image: bytes, raw: bytes, capacity: int, *, workspace_bytes: int = 4096):
    code = NativeHiaJsonImage(image, sha256(image).hexdigest())
    source = ctypes.create_string_buffer(raw, max(1, len(raw)))
    output = ctypes.create_string_buffer(capacity)
    scratch = ctypes.create_string_buffer(workspace_bytes)
    result = code._entry(source, len(raw), output, capacity, scratch, len(scratch))
    return result, output.raw[:result] if result <= capacity else b''


def build(source: Path, bootstrap: Path, output: Path):
    seeds = HistorySeeds(source, bootstrap, output)
    assert (source/'tools/hia_mcp_request_audit_syscalls.S').read_text() == adapter_source()
    records, images = {}, {}
    try:
        for role in (*ROLES, 'packer'):
            path = source/'examples/hia_bootstrap'/f'mcp_request_audit_{role}.hepta'
            raw = path.read_bytes()
            flat = seeds.compile(raw, 'div-word')
            assert 0 < len(flat) <= 1 << 20
            (output/(role+'.flat')).write_bytes(flat)
            images[role] = flat
            records[role] = {'source': path.relative_to(source).as_posix(),
                             'source_sha256': sha256(raw).hexdigest(),
                             'image_sha256': sha256(flat).hexdigest(), 'image_bytes': len(flat)}
            print('NATIVE_AUDIT_COMPILED', role, len(flat), flush=True)
        parts = [images[role] for role in ROLES]
        packet = struct.pack('<8s'+str(len(parts))+'Q', PACK_MAGIC, *map(len, parts))+b''.join(parts)
        result, elf = native_call(images['packer'], packet, 16 << 20)
        assert result == len(elf) and 176 < result <= 16 << 20 and elf.startswith(b'\x7fELF')
        assert struct.unpack_from('<Q', elf, 96)[0] == result
        assert struct.unpack_from('<Q', elf, 104)[0] == result
        assert elf.endswith(b''.join(parts))
        refusals = []
        bad = [('empty', b''), ('truncated', packet[:-1]), ('trailing', packet+b'\0'),
               ('old-composition-version', b'HIARAU01'+packet[8:])]
        for index, role in enumerate(ROLES):
            changed = bytearray(packet)
            struct.pack_into('<Q', changed, 8+8*index, 0)
            bad.append(('empty-'+role, bytes(changed)))
        for label, raw in bad:
            status, emitted = native_call(images['packer'], raw, 16 << 20)
            assert status == 4294967295 and not emitted, (label, status)
            refusals.append({'case': label, 'status': status})
        image = output/'hia-mcp-request-audit'
        image.write_bytes(elf)
        image.chmod(0o500)
        report = {'schema': 'hepta.hia.request-history-native-seed-component.v1',
                  'scope': 'native component construction; not complete cold or release qualification',
                  'whole_cold_source_admission_claimed': False,
                  'parts': records, 'composition_magic': PACK_MAGIC.decode(),
                  'executable': str(image), 'executable_sha256': sha256(elf).hexdigest(),
                  'executable_bytes': len(elf), 'exact_component_suffix': True,
                  'refusals': refusals}
        (output/'qualification.json').write_text(json.dumps(report, indent=2, sort_keys=True)+'\n')
        return report
    finally:
        seeds.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--bootstrap', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = build(args.source.resolve(), args.bootstrap.resolve(), args.output.resolve())
    print(json.dumps({key: result[key] for key in ('scope', 'executable_sha256', 'executable_bytes')}))


if __name__ == '__main__':
    main()
