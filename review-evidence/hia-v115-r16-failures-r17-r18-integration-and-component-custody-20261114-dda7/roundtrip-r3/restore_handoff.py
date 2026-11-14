"""Restore exact selected evidence/source delta from saved full Git responses.

The fixed base repository and large raw buffers are deliberately not fabricated
by this helper. This restores the complete published delta and selected reports,
and preserves the exact full-source manifest and upstream base identities.
"""
from pathlib import Path, PurePosixPath
import argparse
import base64
import hashlib
import json
import os
import stat
import zlib

INDEX_SHA256 = 'd79c9dc8b15fe8a62924671ee791cfa7dd728d195f72abfac7e50d7d44ba198c'
INDEX_GIT = '7c7b12db0cc335adf69d85de11a36d23d8dd4713'


def identity(raw, mode=0o644):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(), 'mode': mode,
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def checked(raw, expected):
    assert identity(raw, expected['mode']) == expected
    return raw


def decode(raw):
    wrapper = json.loads(raw)
    assert wrapper['schema'] == 'hia.lossless-utf8-zlib-capsule.v1'
    compressed = checked(base64.b64decode(wrapper['data'], validate=True), wrapper['compressed'])
    decoder = zlib.decompressobj()
    unpacked = decoder.decompress(compressed) + decoder.flush()
    assert decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
    return json.loads(checked(unpacked, wrapper['payload']))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--index', type=Path, required=True)
    parser.add_argument('--publication', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    index_raw = args.index.read_bytes()
    assert hashlib.sha256(index_raw).hexdigest() == INDEX_SHA256
    assert identity(index_raw)['git_blob'] == INDEX_GIT
    index = json.loads(index_raw)
    args.output.mkdir(exist_ok=False)
    written = {}
    def write(path, raw, mode=0o644):
        relative = PurePosixPath(path)
        assert not relative.is_absolute() and '..' not in relative.parts and str(relative) == path
        assert path not in written
        target = args.output.joinpath(*relative.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.open('xb').write(raw)
        target.chmod(mode)
        written[path] = identity(raw, mode)
    values = {}
    for name, item in index['entries'].items():
        response = json.loads((args.publication / (item['publish_name'] + '-readback.response.json')).read_bytes())
        assert not response.get('isError', False)
        content = response['structuredContent']['content']
        assert type(content) is str
        raw = checked(content.encode('utf-8'), item['pin'])
        receipt = json.loads((args.publication / (item['publish_name'] + '-receipt.json')).read_bytes())
        assert receipt['status'] == 'ACK_FULL_GET_MATCH'
        assert {k: receipt[k] for k in item['pin']} == item['pin']
        values[name] = raw
        write('transport/' + name, raw)
    transport = json.loads(values['SOURCE-TRANSPORT.json'])
    reconstructed = bytearray()
    for ordinal, part in enumerate(transport['parts']):
        fragment = json.loads(values[part['path']])
        assert fragment['ordinal'] == ordinal and fragment['offset'] == len(reconstructed) == part['offset']
        piece = checked(fragment['text'].encode('utf-8'), fragment['payload'])
        assert fragment['payload'] == part['payload']
        reconstructed.extend(piece)
    packet_raw = checked(bytes(reconstructed), transport['content'])
    assert transport['content'] == index['source_file_content_identity']
    write('transport/SOURCE-PACKET.zlib.json', packet_raw)
    packet = decode(packet_raw)
    assert packet['base'] == index['base'] and packet['after'] == index['after']
    assert len(packet['files']) == 13 and len(packet['all_file_manifest']) == 3142
    for name, entry in packet['files'].items():
        raw = checked(entry['text'].encode('utf-8'), entry['after'])
        assert packet['all_file_manifest'][name] == entry['after']
        write('source-delta/' + name, raw, entry['after']['mode'])
        if entry['before'] is not None:
            old = checked(entry['before_text'].encode('utf-8'), entry['before'])
            write('original-before/' + name, old, entry['before']['mode'])
    write('SOURCE-PACKET.json', (json.dumps(packet, indent=2, sort_keys=True) + '\n').encode())
    reports = decode(values['SELECTED-REPORTS.zlib.json'])
    for name, row in reports['members'].items():
        raw = checked(row['text'].encode('utf-8'), row['pin'])
        write('selected-originals/' + name, raw, row['pin']['mode'])
    scripts = decode(values['CONTROL-SCRIPTS.zlib.json'])
    for name, row in scripts['files'].items():
        raw = checked(row['text'].encode('utf-8'), row['pin'])
        write('control-scripts/' + name, raw, row['pin']['mode'])
    inputs = decode(values['ORIGINAL-130-INPUTS.zlib.json'])
    assert len(inputs['ordered_rows']) == len(inputs['inputs']) == 130
    assert len({r['name'] for r in inputs['ordered_rows']}) == 130
    for row in inputs['ordered_rows']:
        item = inputs['inputs'][row['name']]
        raw = checked(base64.b64decode(item['base64'], validate=True), item['pin'])
        assert len(raw) == row['input_bytes'] and identity(raw)['sha256'] == row['input_sha256']
        write('original-inputs/' + row['name'] + '.json', raw, item['pin']['mode'])
    for name, expected in written.items():
        path = args.output / name
        state = path.lstat()
        assert stat.S_ISREG(state.st_mode) and stat.S_IMODE(state.st_mode) == expected['mode']
        checked(path.read_bytes(), expected)
    actual = {p.relative_to(args.output).as_posix() for p in args.output.rglob('*') if p.is_file()}
    assert actual == set(written)
    report = {'schema': 'hia.roundtrip.Git-full-readback-selected-restore.v1', 'status': 'RESTORED_SELECTED_FULLY',
        'actual_inputs': 'saved complete original Git fetch responses plus independent per-object receipts',
        'Git_objects_read': len(index['entries']), 'source_fragments': len(transport['parts']),
        'source_delta_files': len(packet['files']), 'before_files': sum(x['before'] is not None for x in packet['files'].values()),
        'original_input_count': len(inputs['ordered_rows']), 'selected_reports': len(reports['members']),
        'control_scripts': len(scripts['files']), 'restored_files': len(written),
        'restored_bytes': sum(v['bytes'] for v in written.values()), 'full_readback_all_bytes_modes_Git_SHA': True,
        'source_base_is_external_fixed_R8': True, 'large_raw_buffers_Git_custody_complete': False,
        'base': packet['base'], 'after': packet['after'], 'files': written,
        'no_HIA_or_native_or_product_tests_run': True, 'matching_cold': False, 'whole': False}
    args.report.open('x').write(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({k: v for k, v in report.items() if k != 'files'}, indent=2))


if __name__ == '__main__':
    main()
