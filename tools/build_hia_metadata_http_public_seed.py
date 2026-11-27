"""Build the actual HTTP metadata component with the four fixed native roots.

The existing qualified controller members are copied only after their manifest
pins are checked.  HTTP policy and the HTTP packer are compiled natively here.
This component construction does not qualify a complete cold release.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
from pathlib import Path
import struct

from tools.qualify_hia_mcp_request_history_seed import HistorySeeds, native_call
from tools import generate_hia_mcp_http as http

ROOT = Path(__file__).resolve().parents[1]


def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def build(bootstrap, existing, audit, output):
    seeds = HistorySeeds(ROOT, bootstrap, output)
    report = {'schema': 'hepta.hia.metadata-http-native-seed-component.v1',
              'passed': False, 'whole_cold_qualified': False,
              'installed_worker_claimed': False, 'sources': {}, 'refusals': []}
    images = {}
    bundle = output/'controller'
    bundle.mkdir(mode=0o700)
    try:
        manifest_raw = (existing/'hia-controller.json').read_bytes()
        manifest = json.loads(manifest_raw)
        for name, expected in manifest['files'].items():
            raw = (existing/name).read_bytes()
            assert sha256(raw).hexdigest() == expected, name
            target = bundle/name
            target.write_bytes(raw)
            target.chmod(0o500 if raw.startswith(b'\x7fELF') else 0o400)
        (bundle/'hia-controller.json').write_bytes(manifest_raw)
        (bundle/'hia-controller.json').chmod(0o400)
        report['controller_manifest'] = pin(manifest_raw)
        parent_report = json.loads((existing.parent/'qualification.json').read_text())
        assert parent_report['passed'] is True
        for name, row in parent_report['sources'].items():
            assert pin((ROOT/name).read_bytes()) == row['source'], name
        report['existing_controller_construction'] = pin((existing.parent/'qualification.json').read_bytes())
        embedded = []
        for name in ('hia-mcp-job-bridge', 'hia-mcp-request-audit'):
            if name == 'hia-mcp-request-audit':
                raw = audit.read_bytes()
                audit_report_raw = (audit.parent/'qualification.json').read_bytes()
                expected = parent_report['audit_component']
                assert pin(raw) == expected['executable']
                assert pin(audit_report_raw) == expected['construction_report']
                audit_report = json.loads(audit_report_raw)
                assert audit_report['executable_sha256'] == sha256(raw).hexdigest()
                for part in audit_report['parts'].values():
                    assert sha256((ROOT/part['source']).read_bytes()).hexdigest() == part['source_sha256']
                report['audit_component'] = expected
            else:
                raw = (existing/name).read_bytes()
                assert pin(raw) == parent_report['products'][name]['executable']
            embedded.append(raw)
        def compiled(relative):
            raw = (ROOT/relative).read_bytes()
            if relative in images:
                assert pin(raw) == report['sources'][relative]['source']
                return images[relative]
            flat = seeds.compile(raw, 'div-word')
            assert 0 < len(flat) <= 1 << 20, (relative, len(flat))
            (output/(Path(relative).stem+'.flat')).write_bytes(flat)
            report['sources'][relative] = {'source': pin(raw), 'image': pin(flat)}
            images[relative] = flat
            print('NATIVE_HTTP_COMPILED', relative, len(flat), flush=True)
            return flat
        parts = [compiled(http.COMPANIONS.get(role, http.source_path(role)))
                 for role in http.ROLES if role not in ('bridge', 'audit')]+embedded
        extra = sha256(embedded[0]).digest()+sha256(embedded[1]).digest()
        wire = struct.pack('<8s'+'Q'*len(parts), b'HIAMHP01', *map(len, parts))+extra+b''.join(parts)
        packer = compiled('examples/hia_bootstrap/mcp_http_packer.hepta')
        status, elf = native_call(packer, wire, 64 << 20)
        assert status == len(elf) and 176 < status <= 64 << 20 and elf.startswith(b'\x7fELF')
        prefix, holes = http.template()
        expected = bytearray(prefix)
        struct.pack_into('<2Q', expected, 96, len(elf), len(elf))
        target = len(prefix)
        for role, part in zip(http.ROLES, parts):
            at = holes[role]
            struct.pack_into('<I', expected, at, target-at-4)
            target += len(part)
        for role, part, offset in [('bridge', embedded[0], 0), ('audit', embedded[1], 32)]:
            struct.pack_into('<I', expected, holes[role+'_size'], len(part))
            expected[holes[role+'_pin']:holes[role+'_pin']+32] = extra[offset:offset+32]
        assert elf == bytes(expected)+b''.join(parts)
        for label, malformed in [('truncated', wire[:-1]), ('trailing', wire+b'\0'),
                                 ('wrong-magic', b'\0'*8+wire[8:])]:
            reason, result = native_call(packer, malformed, 64 << 20)
            assert reason == 4294967295 and not result, (label, reason)
            report['refusals'].append({'case': label, 'status': reason})
        path = bundle/'hia-mcp-http'
        path.write_bytes(elf)
        path.chmod(0o500)
        report.update(passed=True, executable=pin(elf),
                      exact_complete_template_and_parts=True,
                      embedded={'bridge': pin(embedded[0]), 'audit': pin(embedded[1])})
        return report
    finally:
        seeds.save()
        (output/'qualification.json').write_text(json.dumps(report, indent=2, sort_keys=True)+'\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('bootstrap', 'existing', 'audit', 'output'):
        parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(build(args.bootstrap.resolve(), args.existing.resolve(), args.audit.resolve(), args.output.resolve())))


if __name__ == '__main__':
    main()
