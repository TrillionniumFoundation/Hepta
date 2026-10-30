"""Freeze and read back existing observations; never run a qualified program."""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tarfile
import tempfile

ROOT = Path('/workspace/scratch/b484d4086829')
OWNER = ROOT / 'native-abi-artifact-retention-20261030'
PEER = ROOT / 'native-abi-artifact-retention-independent-review-20261030'
PACKAGE = Path(__file__).resolve().parent
PREFIX = 'evidence/hia_core_closure_20261030/native-abi-retention-local2f-owner'
SOURCE = '2f4891ce7c5b92979ffb4c65575075367a1ecb15'
TREE = 'bc41b0509bd343821a985cae7f22bcb338897cef'
PARENT = 'a6cfb7e00a1c08276d27459bdcc5628aa7622079'


def write(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + '\n')


def identify(path: Path) -> dict:
    assert path.is_file() and not path.is_symlink(), path
    data = path.read_bytes()
    mode = stat.S_IMODE(path.stat().st_mode)
    assert not mode & ~0o777, path
    return {
        'path': str(path.relative_to(ROOT)), 'bytes': len(data),
        'sha256': hashlib.sha256(data).hexdigest(),
        'git_blob_sha1': hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest(),
        'mode': format(mode, '04o'),
    }


assert not (PACKAGE / 'publication-files.json').exists(), 'Never overwrite a frozen package'
parent = json.loads((OWNER / 'parent-a6-gcc/receipt.json').read_bytes())
protocol = json.loads((PEER / 'frozen25/receipt.json').read_bytes())
review = json.loads((PEER / 'review.json').read_bytes())
export = json.loads((OWNER / 'source-export/manifest.json').read_bytes())
assert parent['source_head'] == PARENT and parent['native_matrix_execution_passed']
assert parent['original_temporary_binaries_remaining'] == 0 and parent['retained_binaries'] == []
assert not parent['retention_requirement_satisfied']
assert protocol['source']['head'] == SOURCE and protocol['exact_once']
assert protocol['tests'] == {'run': 25, 'errors': 0, 'failures': 0, 'skipped': 0, 'expected_failures': 0, 'unexpected_successes': 0}
assert protocol['native_matrix_executions'] == 0
assert review['ok'] and review['source']['head'] == SOURCE and review['blocking_findings'] == []
assert review['readback_extra_native_compiler_checker_or_oracle_executions'] == 0
assert export['local_commit'] == SOURCE and export['tree'] == TREE and export['isolated_parent_index_rebuild'] == TREE
matrices = {}
for family in ('gcc', 'clang'):
    folder = OWNER / 'frozen2f-native' / family
    receipt = json.loads((folder / 'receipt.json').read_bytes())
    assert receipt['source_head'] == SOURCE and receipt['source_tree'] == TREE
    assert receipt['native_matrix_execution_passed'] and receipt['retention_requirement_satisfied']
    assert receipt['actual_successful_profiles'] == 2 and receipt['foreign_calls_per_profile'] == [181, 181]
    assert receipt['type_counterexamples'] == 3 and receipt['compiled_wrong_echo_rejected']
    assert receipt['original_temporary_binaries_remaining'] == 0
    assert len(receipt['retained_binaries']) == 4
    for binary in receipt['retained_binaries']:
        actual = identify(Path(binary['path']))
        assert actual['bytes'] == binary['bytes'] and actual['sha256'] == binary['sha256']
        assert int(actual['mode'], 8) == binary['mode']
    matrices[family] = receipt
summary = {
    'schema': 'hepta.native-abi-retention-local-owner.v1',
    'source': {'local_commit': SOURCE, 'tree': TREE, 'public_parent': PARENT},
    'local_candidate_not_public_execution': True,
    'scope': 'Existing finite frontend-to-Rust-object ABI matrix on actual Linux x86_64 GCC and Clang',
    'parent_matrix_passed_but_retained_binaries': 0,
    'candidate_actual_compilers': ['gcc', 'clang'],
    'successful_profiles_per_compiler': 2,
    'foreign_calls_per_profile': 181,
    'type_counterexample_refusals_per_compiler': 3,
    'real_wrong_echo_rejected_per_compiler': True,
    'retained_actual_binaries_per_compiler': 4,
    'frozen_protocol_methods': 25,
    'protocol_new_plus_existing': [14, 11],
    'protocol_methods_have_no_native_matrix_execution': True,
    'initial_dirty_attempt': {'methods': 24, 'ordinary_passes': 22, 'failures': 2, 'preserved': True},
    'source_scope': {'materialized_files': 1426, 'git_tree_files': 7700, 'unmaterialized_files_are_not_execution_coverage': True},
    'independent_review': {'ok': True, 'read_only_checks': 38486, 'new_native_executions': 0, 'original_path': str((PEER / 'review.json').relative_to(ROOT)), 'sha256': identify(PEER / 'review.json')['sha256']},
    'baseline_producer_before_after_identity_was_not_recorded': True,
    'candidate_two_producer_inputs_before_after_unchanged': True,
    'overlapping_peer_originals_are_not_extra_test_populations': True,
    'all_27_strict_blockers_open': True,
    'production_authority': 'Python', 'optimization_policy': 'no_change',
    'other_hosts_general_abi_or_full_release_qualification': False,
}
write(OWNER / 'owner-summary.json', summary)
(OWNER / 'README.md').write_text('''# Retain the actual native ABI binaries: local 2f owner evidence

The CLI now preserves the Rust object, O0 driver, O2 driver and deliberately incorrect echo binary from each actual finite host matrix. Existing output reports are refused and the final report is created exclusively, so previous or concurrently created reports cannot be overwritten. Partial failures retain already compiled binaries and remain failed qualifications.

## Exact source and actual observations

Local source `2f4891ce7c5b92979ffb4c65575075367a1ecb15`, tree `bc41b0509bd343821a985cae7f22bcb338897cef`, derives from public `a6cfb7e00a1c08276d27459bdcc5628aa7622079`. The five-file patch was independently applied to the public parent's index and reconstructed the exact tree. This package contains local executions; it does not relabel them as a later public integration's execution.

| Observation | Actual result |
| --- | --- |
| Public-parent GCC baseline | Two successful profiles, 181 foreign calls each, three type counterexamples and the real compiled wrong-echo rejection. All four temporary binary paths disappeared after cleanup; zero original binaries were retained. The retention requirement remains false for that original run. |
| Frozen candidate GCC | The same finite two-profile matrix passed; all four actual binary byte streams, modes, hashes and role/origin links remain available after temporary cleanup. |
| Frozen candidate Clang | The same finite two-profile matrix passed with its own original commands and four retained binaries. |
| Initial independent protocol controls | 24 methods: 22 ordinary passes and two real failures exposing output overwrite and concurrent report overwrite. Original post-run source metadata, initial test source and stdout/stderr are retained. |
| Frozen protocol qualification | Exactly 25 methods: 14 new artifact-custody controls and 11 existing host-driver/evidence controls; no failure, error, skip, expected failure or unexpected success. These controls use explicitly fake binary/compiler inputs and are not native execution evidence. |
| Independent read-only audit | 38,486 consistency checks passed, including original host commands, all retained bytes/modes/hash/origin links and exact source reconstruction. No native/compiler/checker/oracle replay was performed. |

The actual native compiler runs are Linux x86_64 GCC and Clang. Each candidate matrix has two profiles with 181 calls each, three C type refusal controls, and the independently compiled wrong echo returning -6. Profile counts, call counts, custody checks and repeated peer readbacks are not extra test-method populations. The source identity scope is 1,426 materialized files of 7,700 tracked files; the other 6,274 paths are not represented as executed coverage. The parent baseline materialized 1,425 files.

## Production behavior and preserved boundaries

The existing v2 report, finite ABI claims, two profiles, type controls and wrong-echo checks remain. The optional Python API retains its previous temporary-only behavior when no artifact directory is requested. CLI output automatically has a fresh sibling artifact directory; no new CLI option is required. The workflow preserves its setup-failure placeholder separately before invoking the CLI and uploads the real artifact directory.

Copies require a nonempty regular file of at most 16 MiB, stable file identity, ordinary permission bits, matching expected digest and an exclusive destination. Symlinks, invalid or duplicated role entries, mismatched origin/hash metadata, changed bytes and malformed custody records are rejected. The actual bytes are retained before execution; driver and wrong-echo hashes are rechecked after execution. The CLI validates the exact directory for this invocation. Offline validators may explicitly map the retained directory after archive restoration while preserving original producer paths.

The root agent authored production/workflow/docs changes and ran the native matrices. The independent reviewer authored and executed the 14 new protocol controls, disclosed that test authorship, and independently reviewed production source and root's native originals. Both initial failures and final success are preserved; no failed record is rewritten.

## Retained originals and reproduction of the archive

The archive contains the entire owner observation directory, the independent review's original controls and read-only audit, and this packaging script. It preserves file permission modes. `archive-members.json` lists every original byte stream; `owner-input-manifest.json` freezes the original observations before packaging. `archive-readback.json` records full gzip CRC, every archive member and actual safe extraction/readback into a temporary directory. No member was executed during packaging. The separately published peer package intentionally overlaps these peer originals and must not be counted as another execution.

Candidate producer inputs, selected tool identities and materialized source identities are checked before and after. The parent baseline records source and tool identities; its outer producer was not separately hashed before and after that baseline, so this package does not assert that missing check retroactively. Original path names in reports remain unchanged when archiving.

The parent artifact gap cannot be repaired by newly compiled bytes. This change qualifies future retention on the two actual local compiler lanes. It does not qualify other hosts, general callbacks/reentry/threads, direct-LLVM aggregate exports, foreign lifetimes, complete release gates or semantic refinement. Python remains production authority, optimization remains `no_change`, and all 27 original strict P0-P7 obligations remain open.
''')

inputs = [p for folder in (OWNER, PEER) for p in folder.rglob('*') if p.is_file() and p.name != 'owner-input-manifest.json']
inputs.append(Path(__file__).resolve())
inputs.sort(key=lambda p: str(p.relative_to(ROOT)))
before = [identify(p) for p in inputs]
manifest = {'schema': 'hepta.native-retention-owner-inputs.v1', 'files': before, 'files_count': len(before), 'bytes': sum(x['bytes'] for x in before)}
write(OWNER / 'owner-input-manifest.json', manifest)
archive_inputs = sorted(inputs + [OWNER / 'owner-input-manifest.json'], key=lambda p: str(p.relative_to(ROOT)))
members = [identify(p) for p in archive_inputs]
write(PACKAGE / 'archive-members.json', {'schema': 'hepta.original-archive-members.v1', 'members': members})
archive_path = PACKAGE / 'native-abi-retention-local2f-owner.tar.gz'
with archive_path.open('xb') as raw:
    with gzip.GzipFile(fileobj=raw, mode='wb', filename='', mtime=0, compresslevel=9) as compressed:
        with tarfile.open(fileobj=compressed, mode='w') as archive:
            for path, record in zip(archive_inputs, members):
                data = path.read_bytes()
                assert identify(path) == record
                item = tarfile.TarInfo(record['path'])
                item.size, item.mode, item.mtime = len(data), int(record['mode'], 8), 0
                archive.addfile(item, io.BytesIO(data))
with gzip.open(archive_path, 'rb') as stream:
    while stream.read(1024 * 1024):
        pass
with tempfile.TemporaryDirectory(prefix='hepta-retention-owner-readback-') as temporary:
    destination = Path(temporary)
    with tarfile.open(archive_path, 'r:gz') as archive:
        actual = archive.getmembers()
        assert len(actual) == len(members) and len({x.name for x in actual}) == len(actual)
        for item, record in zip(actual, members):
            assert item.isfile() and item.name == record['path'] and item.size == record['bytes']
            assert not Path(item.name).is_absolute() and '..' not in Path(item.name).parts
            assert item.mode == int(record['mode'], 8)
            data = archive.extractfile(item).read()
            assert hashlib.sha256(data).hexdigest() == record['sha256']
            target = destination / item.name
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open('xb') as output:
                output.write(data)
            os.chmod(target, item.mode)
            assert target.read_bytes() == data and stat.S_IMODE(target.stat().st_mode) == item.mode
assert before == [identify(p) for p in inputs], 'Original observations changed during packaging'
archive_record = identify(archive_path)
write(PACKAGE / 'archive-readback.json', {
    'schema': 'hepta.native-retention-owner-archive-readback.v1', 'ok': True,
    'archive': archive_record, 'members': len(members), 'original_inputs': len(inputs),
    'complete_gzip_crc': True, 'every_member_size_mode_sha256': True,
    'actual_safe_extraction_and_readback': True, 'original_inputs_unchanged': True,
    'executed_archive_members': 0,
})
publish = [
    (OWNER / 'README.md', 'README.md'), (OWNER / 'owner-summary.json', 'owner-summary.json'),
    (OWNER / 'owner-input-manifest.json', 'owner-input-manifest.json'),
    (OWNER / 'source-export/manifest.json', 'source-export/manifest.json'),
    (OWNER / 'source-export/source-change.patch', 'source-export/source-change.patch'),
    (PACKAGE / 'archive-members.json', 'archive-members.json'),
    (PACKAGE / 'archive-readback.json', 'archive-readback.json'),
    (Path(__file__).resolve(), 'build_package.py'), (archive_path, archive_path.name),
]
files = []
for path, name in publish:
    record = identify(path)
    files.append({**record, 'local_path': str(path), 'repository_path': PREFIX + '/' + name, 'mode': '100644'})
publication = {
    'schema': 'hepta.native-retention-owner-publication.v1', 'source_commit': SOURCE,
    'source_tree': TREE, 'public_parent': PARENT, 'public_source_execution': False,
    'files': files, 'payload_files': len(files), 'payload_bytes': sum(x['bytes'] for x in files),
    'archive': archive_record, 'all_original_inputs_unchanged': True,
    'map_repository_path': PREFIX + '/publication-files.json', 'also_publish_this_map': True,
    'all_27_strict_blockers_open': True,
}
write(PACKAGE / 'publication-files.json', publication)
print(json.dumps({'ok': True, 'payload_files': len(files), 'payload_bytes': publication['payload_bytes'], 'archive': archive_record, 'members': len(members), 'original_inputs': len(inputs)}))
