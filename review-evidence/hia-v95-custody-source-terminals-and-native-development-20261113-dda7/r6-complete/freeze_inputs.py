"""Freeze completed R6 formal originals without running product code or tests."""
from pathlib import Path, PurePosixPath
import base64
import hashlib
import json
import os
import stat
import time
import zipfile

ROOT = Path(__file__).resolve().parent
WORK = ROOT.parent
SOURCE = WORK / 'v87-source-r6-original'
PRODUCT = WORK / 'v88-r6-native-original'
PUBLICATION = WORK / 'v88-r6-product-publication-r1'


def canonical(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode()


def byte_identity(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def stat_record(value):
    return {key: getattr(value, key) for key in (
        'st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns')}


def read_identity(path):
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode):
        raw = os.fsencode(os.readlink(path))
        identity = byte_identity(raw)
        kind = 'symlink'
    else:
        assert stat.S_ISREG(before.st_mode), path
        digest = hashlib.sha256()
        git = hashlib.sha1(b'blob ' + str(before.st_size).encode() + b'\0')
        count = 0
        with path.open('rb') as source:
            while True:
                chunk = source.read(1 << 20)
                if not chunk:
                    break
                count += len(chunk)
                digest.update(chunk)
                git.update(chunk)
        assert count == before.st_size
        identity = {'bytes': count, 'sha256': digest.hexdigest(), 'git_blob': git.hexdigest()}
        kind = 'file'
    assert stat_record(before) == stat_record(path.lstat()), ('source changed during read', path)
    return {**identity, 'source': str(path), 'source_stat': stat_record(before),
            'kind': kind, 'mode': f'{stat.S_IMODE(before.st_mode):04o}'}


def git_tree(rows, prefix):
    root = {}
    for name, row in rows.items():
        if not name.startswith(prefix + '/'):
            continue
        parts = name[len(prefix) + 1:].split('/')
        node = root
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        assert parts[-1] not in node
        node[parts[-1]] = row

    def build(node):
        entries = []
        for name, item in node.items():
            if 'git_blob' in item:
                mode = b'120000' if item['kind'] == 'symlink' else (
                    b'100755' if int(item['mode'], 8) & 0o111 else b'100644')
                entries.append((name.encode(), mode, item['git_blob']))
            else:
                entries.append((name.encode() + b'/', b'40000', build(item)))
        raw = b''.join(mode + b' ' + name.rstrip(b'/') + b'\0' + bytes.fromhex(oid)
                       for name, mode, oid in sorted(entries))
        return hashlib.sha1(b'tree ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    return build(root)


def main():
    started = time.monotonic_ns()
    nodes, directories, groups, excluded_git = {}, {}, {}, []

    def add(path, logical, group):
        assert logical not in nodes
        row = read_identity(path)
        nodes[logical] = row
        item = groups.setdefault(group, {'paths': [], 'count': 0, 'bytes': 0})
        item['paths'].append(logical)
        item['count'] += 1
        item['bytes'] += row['bytes']

    def walk(path, prefix, group, source_checkout=False):
        assert path.is_dir() and not path.is_symlink()
        for parent, dirs, files in os.walk(path, followlinks=False):
            here = Path(parent)
            relative = here.relative_to(path)
            logical_parent = prefix if relative == Path('.') else prefix + '/' + relative.as_posix()
            directories[logical_parent] = {'mode': f'{stat.S_IMODE(here.lstat().st_mode):04o}'}
            for name in list(dirs):
                child = here / name
                if source_checkout and name == '.git':
                    excluded_git.append(str(child))
                    dirs.remove(name)
                elif child.is_symlink():
                    add(child, logical_parent + '/' + name, group)
                    dirs.remove(name)
            for name in sorted(files):
                add(here / name, logical_parent + '/' + name, group)

    walk(SOURCE / 'artifact', 'independent-source/artifact', 'independent_Source_all_artifact_members')
    walk(SOURCE / 'candidate-ci314', 'independent-source/candidate-ci314',
         'independent_Source_exact3024_source', True)
    directories['independent-source/root'] = {'mode': '0755'}
    for path in sorted(SOURCE.iterdir()):
        if path.is_file() and path.name != 'artifact.zip':
            add(path, 'independent-source/root/' + path.name, 'independent_Source_root_originals')
    for name in ('native', 'wire', 'source-vm'):
        walk(PRODUCT / name, 'product-core/' + name, 'product_Core_' + name + '_all_members')
    directories['product-core/root'] = {'mode': '0755'}
    for path in sorted(PRODUCT.iterdir()):
        if path.is_file() and path.name not in ('native.zip', 'wire.zip', 'source-vm.zip'):
            add(path, 'product-core/root/' + path.name, 'product_Core_root_originals')
    walk(PUBLICATION, 'product-publication', 'exact_product_publication_originals')

    assert len(nodes) == 10060, len(nodes)
    assert groups['independent_Source_exact3024_source']['count'] == 3024
    tree = git_tree(nodes, 'independent-source/candidate-ci314')
    assert tree == '78155bac080168d2946116ede1607e48b221ec1b', tree

    outer_specs = [
        ('independent_source', SOURCE / 'artifact.zip', SOURCE / 'artifact', 4441,
         '3105b20b4e4cc68badbac217380218e5be7eb01a1ea2f8508c819eaad2ab6fc0'),
        ('product_native', PRODUCT / 'native.zip', PRODUCT / 'native', 2500,
         '0ea4008a213a0a215e2844d12208525794684a2f5af17a89a39a9aa77d5d9f69'),
        ('product_wire', PRODUCT / 'wire.zip', PRODUCT / 'wire', 1,
         '16268d031159ca2b97d5977957a27b5b8aa27f50039829168ddb73df7752c768'),
        ('product_source_vm', PRODUCT / 'source-vm.zip', PRODUCT / 'source-vm', 69,
         'd0928605487316722cbe72e4f55d178088ea14e7dbb1f5fa817000504ce251a0'),
    ]
    outer = {}
    for label, archive, extracted, expected_count, expected_sha in outer_specs:
        identity = read_identity(archive)
        assert identity['sha256'] == expected_sha
        members, seen = [], set()
        with zipfile.ZipFile(archive) as source:
            comment = base64.b64encode(source.comment).decode()
            start_dir = source.start_dir
            for index, info in enumerate(source.infolist()):
                name = info.filename
                path = PurePosixPath(name)
                assert not path.is_absolute() and path.parts and '..' not in path.parts, name
                assert name not in seen, name
                seen.add(name)
                row = {key: getattr(info, key) for key in (
                    'filename', 'file_size', 'compress_size', 'compress_type', 'CRC',
                    'date_time', 'flag_bits', 'create_system', 'create_version',
                    'extract_version', 'reserved', 'volume', 'internal_attr',
                    'external_attr', 'header_offset')}
                row.update(index=index, extra_base64=base64.b64encode(info.extra).decode(),
                           comment_base64=base64.b64encode(info.comment).decode(),
                           is_directory=info.is_dir())
                if not info.is_dir():
                    sha = hashlib.sha256()
                    git = hashlib.sha1(b'blob ' + str(info.file_size).encode() + b'\0')
                    count = 0
                    with source.open(info) as entry:
                        while True:
                            chunk = entry.read(1 << 20)
                            if not chunk:
                                break
                            count += len(chunk)
                            sha.update(chunk)
                            git.update(chunk)
                    assert count == info.file_size
                    row['uncompressed_identity'] = {'bytes': count, 'sha256': sha.hexdigest(), 'git_blob': git.hexdigest()}
                    local = read_identity(extracted.joinpath(*path.parts))
                    assert row['uncompressed_identity'] == {key: local[key] for key in ('bytes', 'sha256', 'git_blob')}
                    row['extracted_mode'] = local['mode']
                members.append(row)
            assert sum(not row['is_directory'] for row in members) == expected_count
        assert read_identity(archive) == identity
        outer[label] = {
            'identity': identity, 'zip_comment_base64': comment, 'central_directory_start': start_dir,
            'members': members, 'file_members': expected_count,
            'all_CRC_and_uncompressed_bytes_independently_read': True,
            'all_extracted_member_byte_identities_equal': True,
            'outer_bytes_in_new_Git_capsule': False,
            'retained_at_original_local_path_and_Actions': True,
            'outer_compressed_bytes_not_claimed_reconstructible_from_Git_members': True,
        }

    original_source_report = json.loads((SOURCE / 'artifact/ARTIFACT-FULL-READBACK.json').read_text())
    native_report = json.loads((PRODUCT / 'ARTIFACT-READBACK.json').read_text())
    product_source_report = json.loads((PRODUCT / 'PRODUCT-SOURCE-READBACK.json').read_text())
    publication = json.loads((PUBLICATION / 'PUBLICATION.json').read_text())
    assert original_source_report['source_status'] == 'PASS'
    assert original_source_report['actual_source_methods'] == 1224
    assert native_report['native_conclusion'] == 'FAIL'
    assert product_source_report['source_tests'] == 1224 and product_source_report['source_conclusion'] == 'success'
    assert publication['commit'] == 'cec2f44bd4bc0d12298a0282c1eb8ce1d7a7b95f'
    assert publication['tree'] == tree
    summary = {
        'independent_formal_Source': {
            'run': 43422327653, 'job': 131875092858,
            'harness_commit': 'a6026cdb141c79f657b1b097e97f4de34e634974',
            'runtime': 'CPython3.14.4', 'tests': 1224, 'failures': 0, 'errors': 0, 'skipped': 0,
            'status': 'SOURCE_PASS', 'seconds': 1521.086862444, 'source_tree': tree,
            'source_files': 3024, 'native_qualification': False,
        },
        'product_Core': {
            'run': 43430503183, 'commit': publication['commit'], 'source_tree': tree,
            'Source_job': 131902501822, 'Source_status': 'PASS', 'Source_tests': 1224,
            'Source_seconds': 1019.321, 'Native_job': 131902502212, 'Native_status': 'FAIL',
            'whole_run_pass': False,
        },
        'outer_zip_bytes_not_in_archive': {key: row['identity']['sha256'] for key, row in outer.items()},
        'all_four_original_outer_ZIPs_retained': True,
        'all_nested_archives_and_wheels_preserved_as_complete_logical_files': True,
        'earlier_R5_failure_and_R6_local_package_not_recaptured': True,
        'original_historical_publication_PENDING_field_not_rewritten_with_later_Native_failure': True,
        'no_product_or_test_or_generator_execution': True,
        'whole_native': False,
    }
    frozen = {
        'schema': 'hia.completed-R6-formal-originals-frozen.v1',
        'created_utc_ns': time.time_ns(), 'logical_files': nodes, 'directories': directories,
        'logical_count': len(nodes), 'logical_bytes': sum(row['bytes'] for row in nodes.values()),
        'groups': groups, 'excluded_git': excluded_git, 'scope_summary': summary,
        'fixed_inputs_only': True, 'self_contained_logical_originals': True,
        'historical_execution_environment_requires_original_Git_dependencies': True,
        'intentional_exclusions': [str(item[1]) for item in outer_specs],
        'elapsed_ns': time.monotonic_ns() - started,
    }
    for name, value in [('INPUTS-FROZEN.json', frozen), ('SCOPE-SUMMARY.json', summary),
                        ('OUTER-ZIP-RETENTION.json', {'schema': 'hia.four-outer-ZIPs-identity-complete-member-readback.v1', 'archives': outer})]:
        with (ROOT / name).open('xb') as output:
            output.write(canonical(value))
    print(json.dumps({'status': 'FROZEN', 'files': len(nodes), 'bytes': frozen['logical_bytes'],
                      'directories': len(directories), 'source_tree': tree,
                      'outer_ZIPs': len(outer), 'outer_members_read': sum(row['file_members'] for row in outer.values()),
                      'groups': {key: {k: value[k] for k in ('count', 'bytes')} for key, value in groups.items()},
                      'product_execution': 0}, sort_keys=True))


if __name__ == '__main__':
    main()
