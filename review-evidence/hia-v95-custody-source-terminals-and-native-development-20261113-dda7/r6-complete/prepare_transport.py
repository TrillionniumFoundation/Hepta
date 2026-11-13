"""Create bounded immutable UTF-8 transports for the completed R6 originals."""
from pathlib import Path
import base64
import json
import zlib
from freeze_inputs import canonical, byte_identity

ROOT = Path(__file__).resolve().parent


def write(name, raw):
    with (ROOT / name).open('xb') as output:
        output.write(raw)
    return {'file': name, **byte_identity(raw)}


def main():
    capsule_raw = (ROOT / 'METADATA-CAPSULE.json').read_bytes()
    capsule = json.loads(capsule_raw)
    decoded = zlib.decompress(base64.b64decode(capsule['data'], validate=True))
    assert byte_identity(decoded) == capsule['decoded']
    members = json.loads(decoded)['files']
    extras = {}
    for name, row in members.items():
        raw = row['text'].encode()
        assert byte_identity(raw) == {key: row[key] for key in ('bytes', 'sha256', 'git_blob')}
        local = name.removeprefix('metadata/')
        assert raw == (ROOT / local).read_bytes()
        extras[name] = byte_identity(raw)
    write('EXTRA-MEMBERS.json', canonical(extras))

    (ROOT / 'metadata-fragments').mkdir()
    fragments = []
    for offset in range(0, len(capsule_raw), 524288):
        raw = capsule_raw[offset:offset + 524288]
        raw.decode('utf-8')
        row = write(f'metadata-fragments/part-{len(fragments):03d}.txt', raw)
        fragments.append({**row, 'offset': offset})
    assert b''.join((ROOT / row['file']).read_bytes() for row in fragments) == capsule_raw
    write('METADATA-FRAGMENTS.json', canonical({
        'schema': 'hepta.exact-text-fragments.v1',
        'encoding': 'concatenate exact UTF-8 bytes in listed order without separators',
        'whole': byte_identity(capsule_raw), 'fragments': fragments,
        'whole_capsule_raw_Git_blob_uploaded': False,
    }))

    outer = json.loads((ROOT / 'OUTER-ZIP-RETENTION.json').read_text())
    summary = {'schema': 'hia.R6-outer-ZIP-retention-summary.v1', 'archives': {}}
    for name, row in outer['archives'].items():
        summary['archives'][name] = {key: value for key, value in row.items() if key != 'members'}
    summary['complete_central_directory_and_member_identities'] = 'metadata/OUTER-ZIP-RETENTION.json in both the complete archive and the seven-fragment metadata capsule'
    summary['original_compressed_outer_bytes_recoverable_from_this_Git_capsule'] = False
    write('OUTER-ZIP-SUMMARY.json', canonical(summary))

    published = (ROOT / 'PRODUCT-PUBLICATION-GIT-EXACT.json').read_bytes()
    original = (ROOT.parent / 'v88-r6-product-publication-r1/PUBLICATION.json').read_bytes()
    assert published == original
    assert byte_identity(published)['git_blob'] == 'ed94a7b5b07c926584f48dc77114adae616ad13e'
    write('PRODUCT-PUBLICATION-MATCH.json', canonical({
        'schema': 'hia.R6-publication-copy-exact-Git-readback.v1',
        'local_and_actual_Git_bytes_equal': True, 'identity': byte_identity(published),
        'historical_PENDING_native_field_preserved': True,
        'later_product_Native_failure_is_a_distinct_original_record': True,
    }))

    readme = '''# Complete R6 formal Source and product Core originals

This fixed evidence scope preserves 10,060 logical files and 787,835,354 original bytes. It includes the independent formal Source run 43422327653, the exact 3024-file candidate, the later product Core run 43430503183, its native/wire/source-VM artifacts and complete logs, and the original product publication receipt. The completed R5 failure and R6 local-only package are separate and are not recaptured here.

The independent CPython 3.14.4 Source job 131875092858 completed 1224 methods with no failures, errors or skips. Its source tree is 78155bac080168d2946116ede1607e48b221ec1b. That result is Source qualification only. The exact candidate was published as cec2f44bd4bc0d12298a0282c1eb8ce1d7a7b95f. In the subsequent product Core run, Source job 131902501822 again passed all 1224 methods, while Native job 131902502212 failed. The complete original failures and not-executed later stages remain intact. This custody work does not turn the failed Native job into a pass.

All four outer Actions ZIPs remain at their original local paths and in their original Actions records. Their complete size/SHA, central-directory compression fields, comments, CRC observations and every member identity are preserved. Their compressed wrapper bytes are deliberately excluded from this Git capsule and are not claimed reconstructible from member bytes. Every logical member, including nested ZIPs, wheels and machine images, is preserved in full. All 7011 outer file members were independently streamed through CRC and compared with the retained extracted bytes.

The original publication receipt is byte-exact with Git blob ed94a7b5b07c926584f48dc77114adae616ad13e. Its historical PENDING native field is left unchanged; the later Native failure has its own original records. All source/log/report bytes and modes remain unchanged.

The deterministic archive uses content-addressed objects to restore every logical path and mode. Its raw bytes are transported as canonical no-newline UTF-8 base64 wrappers; computed binary Git identities are identity checks, not claims that raw binary objects were uploaded. The large manifest, frozen input inventory and complete outer ZIP catalog are also available through the seven exact UTF-8 metadata fragments.

Use restore.py with TRANSPORT.json, EXTRA-MEMBERS.json, the wrapper directory and a new empty destination. The helper verifies every encoded and decoded identity, the complete gzip CRC/ISIZE, every CAS object, every logical file and directory mode. This package preserves the logical originals; reproducing the historical CI environment still requires its exact original Git/toolchain dependencies. No product generator, test body, compiler or native workload was rerun for custody. Whole-native closure is false.
'''
    write('README.md', readme.encode())
    print(json.dumps({'metadata_fragments': len(fragments), 'metadata_members': len(extras),
                      'publication_copy_exact': True, 'original_outer_ZIPs_excluded': 4,
                      'raw_chunks': len(json.loads((ROOT / 'TRANSPORT.json').read_text())['chunks'])}, sort_keys=True))


if __name__ == '__main__':
    main()
