"""Author an exact R20 successor of the retained CI phase diagnostic.

This preparation reads immutable reports and sixteen ZIP members.  It does not
import product code, invoke a product entry point, create a Git object/ref, or
execute the diagnostic.  The output directory must not already exist.
"""
from __future__ import annotations

import ast
import base64
import difflib
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
import zipfile
import zlib


ROOT = Path('/workspace/scratch/dda74a4fae35')
SCOPE = Path(__file__).resolve().parent
OUT = SCOPE / 'prepared-r1'
OLD = ROOT / 'v94-native-namespace-budget-r1/ci-phase-r1'
OLD_HARNESS = OLD / 'harness'
PRODUCT = ROOT / 'v120-union-r20/source'
ACTUAL = ROOT / 'v120-native-product-original'
SOURCE_MANIFEST = ROOT / 'v120-source-parser-r20-original/source-manifest-readback-r1/CANDIDATE-MANIFEST.json'
METHOD = 'test_expired_evaluation_is_rejected_before_any_reference_or_native_runner'
TEST_ID = 'tests.test_hia_agent_native_tools.NativeLifecycleTests.' + METHOD
SOURCE_COMMIT = '26fd6c4c1a71dc970ae11b00c8a9ff74c5c8508d'
SOURCE_TREE = '84df4b42f1e20fd7d0c7229e658cf3b458984ffb'
BRANCH = 'codex/hia-namespace-sections-v131-r20-20261114-dda7'
NATIVE_ZIP_SHA = '8c64560057b6156fae6e4ccfd4f04fa297bdd1ff6db5b3104501f29e907911c3'
NATIVE_ZIP_BYTES = 100028087


def identity(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def encoded(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2) + '\n').encode()


def capture(path):
    raw = path.read_bytes()
    info = path.lstat()
    assert stat.S_ISREG(info.st_mode)
    return {'identity': identity(raw), 'stat': stats(path)}


def stats(path):
    info = path.lstat()
    return {name: getattr(info, name) for name in
            ('st_dev', 'st_ino', 'st_nlink', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns')}


def write(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(raw)
    path.chmod(0o644)
    assert path.read_bytes() == raw
    return identity(raw)


def replace_once(text, before, after):
    assert text.count(before) == 1, before
    return text.replace(before, after, 1)


def tree_identity(files):
    root = {}
    for row in files:
        parts = row['path'].split('/')
        node = root
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        assert parts[-1] not in node
        node[parts[-1]] = row

    def visit(node):
        entries = []
        for name, value in node.items():
            if 'sha' in value and 'path' in value:
                mode, sha, key = value['mode'], value['sha'], name.encode()
            else:
                mode, sha, key = '40000', visit(value), (name + '/').encode()
            entries.append((key, mode.encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(sha)))
        raw = b''.join(row for _, row in sorted(entries))
        return hashlib.sha1(b'tree ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    return visit(root)


def summary_of_old_evidence():
    base = ROOT / 'v94-native-namespace-budget-r1'
    names = [
        'ci-phase-r1/actual/raw/evidence/REPORT.json',
        *['ci-phase-r1/actual/raw/evidence/case-%d/observations/REPORT.json' % n for n in range(3)],
        'ci-phase-r1/STORE-OBSERVER-ADDENDUM.md',
        'ci-components-r1/actual/raw/evidence/REPORT.json',
        'ci-guard-r2/actual/raw/evidence/REPORT.json',
        'memo-handoff-r1/SUMMARY.json',
    ]
    sources = {name: identity((base / name).read_bytes()) for name in names}
    cases = []
    for number in range(3):
        row = json.loads((base / names[number + 1]).read_bytes())
        profile = row['profile']
        totals = {}
        for span in profile['rows']:
            key = span['kind'] + ':' + span['label']
            total = totals.setdefault(key, {'calls': 0, 'wall_ns': 0, 'process_cpu_ns': 0})
            total['calls'] += 1
            total['wall_ns'] += span['inclusive_wall_ns']
            total['process_cpu_ns'] += span['inclusive_process_cpu_ns']
        cases.append({
            'case': number, 'method': row['method'], 'outcome': row['original_outcome'],
            'tests_run': row['tests_run'], 'failures': row['failures'], 'errors': row['errors'],
            'counters': profile['counters'], 'span_totals': totals,
            'aggregates': profile['aggregates'],
            'client_stages': [span for span in profile['rows'] if span['kind'] == 'client-stage'],
            'store_receipt_entries': row['original_store_receipt_entries'],
            'store_modes': row['store_modes'],
            'native_raw_observer_counts': {key: value['calls'] for key, value in profile['native'].items()},
            'native_store_count_is_double_observation_not_machine_entry_count': True,
            'limitations': profile['limitations'],
        })
    components = json.loads((base / names[5]).read_bytes())
    scans = []
    for number, row in enumerate(components['scans']):
        observed = dict(row)
        observed['ordinal'] = number
        if 'components' in row:
            observed['inclusive_percent_of_outer_wall'] = {
                key: 100 * value['wall_ns'] / row['wall_ns']
                for key, value in row['components']['inclusive_totals'].items()}
            observed['percentages_are_nested_not_additive'] = True
        scans.append(observed)
    guard = json.loads((base / names[6]).read_bytes())
    memo = json.loads((base / names[7]).read_bytes())
    return {
        'schema': 'hepta.namespace-existing-ci-evidence-readback.v1',
        'sources': sources, 'product_executions_in_this_readback': 0,
        'phase_original_source': {'commit': 'abeef212e34023534d91f8f952280e2a8d0cbde6',
                                  'tree': 'f2bc61c11104136d3f56e3c4aefa00a4dada910b', 'files': 3055},
        'phase_cases': cases,
        'components': {
            'inputs': components['inputs'], 'scans': scans,
            'owned_byte_hash_runs': components['owned_byte_hash_runs'],
            'capabilities': components['capabilities'],
            'measurement_cpu': components['measurement_cpu'],
            'affinity_restored': components['affinity_restored'],
            'warmup_original_scans': components['warmup_original_scans'],
            'instrumentation_transform_counts': components['instrumentation_transform_counts'],
            'methodological_limits': components['methodological_limits'],
            'cpu_flags_are_not_actual_openssl_dispatch_evidence': True,
        },
        'guard_r2': {
            'status': guard['status'], 'python': guard['python'],
            'guard_controls': guard['guard_controls'], 'foreign_keys': guard['foreign_keys'],
            'comparison_means_ns': guard['comparison']['means_ns'],
            'comparison_limits': guard['comparison']['limits'],
            'original_business_tests_run': guard['original_business_tests_run'],
            'native_compilations': guard['native_compilations'],
            'not_applied_to_r20': True,
        },
        'memo_history': memo,
        'interpretation_limits': [
            'No prior diagnostic becomes R20 observation or deadline qualification.',
            'Old expired/reference failures reached second emit; R20 original failures reached first emit.',
            'Old timeout diagnostic passed its unchanged five-second assertion; R20 original failed it.',
            'Old Store raw counter 2422 is doubled instrumentation; original receipt predicate remained single.',
            'Pure owned-byte hashing is not production read/close/hash/provider ordering.',
            'Hardware flags and hashlib provider identity do not establish OpenSSL assembly dispatch.',
            'Memo R1/R2/R3 are all NOT_ADOPTED; observable refcount/monitoring/MemoryError failures remain.',
            'No state-copy optimization priority follows from these reports; measured state-call totals are small.',
        ],
    }


def main():
    OUT.mkdir(exist_ok=False)
    harness = OUT / 'harness'
    harness.mkdir()
    old_publication = json.loads((OLD / 'publication/PUBLICATION.json').read_bytes())
    old_manifest = json.loads((OLD / 'publication/HARNESS-MANIFEST.json').read_bytes())
    assert old_publication['commit'] == '6ef7266b6c539e2c6f0cb7d45eef81aac5e3a9a2'
    assert len(old_manifest) == 12
    old_before = {}
    old_bytes = {}
    for row in old_manifest:
        path = OLD_HARNESS / row['path']
        raw = path.read_bytes()
        assert identity(raw) == {'bytes': row['bytes'], 'sha256': row['sha256'], 'git_blob': row['sha']}
        assert stat.S_IMODE(path.stat().st_mode) == int(row['mode'][-3:], 8)
        old_before[row['path']] = capture(path)
        old_bytes[row['path']] = raw

    manifest_raw = SOURCE_MANIFEST.read_bytes()
    assert identity(manifest_raw)['git_blob'] == '9094a23b34d332dd115c79371b9400c3a34573bc'
    source_rows = json.loads(manifest_raw)
    assert len(source_rows) == 3177
    source_tree_rows = [{'path': name, 'mode': row['git_mode'], 'sha': row['git_blob']}
                        for name, row in source_rows.items()]
    assert tree_identity(source_tree_rows) == SOURCE_TREE
    product_files = ('tests/test_hia_agent_native_tools.py', 'tools/qualify_hia_store_lifecycle.py',
                     '.github/workflows/hia-core.yml', 'tools/hia_selfhost_contract.py')
    product_before = {}
    for name in product_files:
        path = PRODUCT / name
        raw = path.read_bytes()
        assert identity(raw) == {key: source_rows[name][key] for key in ('bytes', 'sha256', 'git_blob')}
        assert stat.S_IMODE(path.stat().st_mode) == source_rows[name]['mode']
        product_before[name] = capture(path)

    custody_raw = (ACTUAL / 'COMPLETE-TERMINAL-CUSTODY.json').read_bytes()
    custody = json.loads(custody_raw)
    native = custody['artifacts']['native']
    assert native['original']['bytes'] == NATIVE_ZIP_BYTES
    assert native['original']['sha256'] == NATIVE_ZIP_SHA
    assert native['all_member_crc_sha_git_and_actual_modes_verified'] is True
    assert custody['head'] == SOURCE_COMMIT and custody['product_tree'] == SOURCE_TREE
    members_raw = (ACTUAL / 'custody-native-r1/native-MEMBERS.json').read_bytes()
    assert identity(members_raw) == native['member_manifest']
    members = {row['path']: row for row in json.loads(members_raw)}
    assert len(members) == native['members'] == 10061
    old_retained = json.loads((OLD / 'actual/raw/evidence/RETAINED-INPUT-READBACK.json').read_bytes())
    assert len(old_retained) == 16
    archive = ACTUAL / 'native.zip'
    zip_before = stats(archive)
    assert zip_before['st_size'] == NATIVE_ZIP_BYTES
    packet_files = {}
    retained_changes = []
    decoded_json = {}
    with zipfile.ZipFile(archive) as opened:
        infos = {entry.filename: entry for entry in opened.infolist()}
        assert len(infos) == len(opened.infolist()) == len(members)
        for name, old_row in old_retained.items():
            relative = PurePosixPath(name)
            assert not relative.is_absolute() and '..' not in relative.parts
            member = old_row['archive_member']
            row = members[member]
            info = infos[member]
            assert not info.is_dir() and info.file_size == row['bytes'] and info.CRC == row['crc32']
            assert info.external_attr == row['external_attr'] and info.compress_size == row['compressed_bytes']
            assert stat.S_ISREG(info.external_attr >> 16)
            raw = opened.read(info)
            assert (zlib.crc32(raw) & 0xffffffff) == info.CRC
            assert identity(raw) == {key: row[key] for key in ('bytes', 'sha256', 'git_blob')}
            mode = stat.S_IMODE(info.external_attr >> 16)
            assert mode == row['permission_mode']
            packet_files[name] = {'archive_member': member, 'mode': mode, 'crc32': info.CRC,
                                  **identity(raw), 'base64': base64.b64encode(raw).decode('ascii')}
            retained_changes.append({'path': name, 'original': old_row,
                                     'r20': {key: value for key, value in packet_files[name].items() if key != 'base64'},
                                     'bytes_and_mode_same': old_row['git_blob'] == row['git_blob'] and old_row['mode'] == mode})
            if name.endswith('.json'):
                decoded_json[name] = json.loads(raw)
    assert stats(archive) == zip_before
    assert sum(row['bytes_and_mode_same'] for row in retained_changes) == 9
    fresh = decoded_json['original-nested-evidence/ArtifactNamespaceNativeTests/joint-build.json']['source_manifest']
    assert len(fresh) == 1552
    for name, sha in fresh.items():
        assert source_rows[name]['sha256'] == sha
    packet = {'schema': 'hepta.exact-original-namespace-retained-files.v1',
              'source_commit': SOURCE_COMMIT, 'source_tree': SOURCE_TREE,
              'original_run': 43560753071, 'original_native_job': 132343657673,
              'original_artifact': {'id': 14101031842, **native['original']}, 'files': packet_files}
    decoded = encoded(packet)
    transport = encoded({'schema': 'hepta.exact-retained-files.zlib-base64.v1',
                         'decoded': identity(decoded), 'members': 16,
                         'payload': base64.b64encode(zlib.compress(decoded, 9)).decode('ascii')})
    write(OUT / 'RETAINED-PACKET.zlib.json', transport)
    restored = json.loads(zlib.decompress(base64.b64decode(json.loads(transport)['payload'], validate=True)))
    assert restored == packet
    parts = []
    for number, offset in enumerate(range(0, len(transport), 327680)):
        raw = transport[offset:offset + 327680]
        name = 'retained-%02d.json.part' % number
        write(harness / 'inputs' / name, raw)
        parts.append({'path': name, 'offset': offset, **identity(raw)})
    assert len(parts) == 4
    write(harness / 'inputs/RETAINED-PARTS.json', encoded({
        'schema': 'hepta.ordered-exact-text-parts.v1', 'complete': identity(transport), 'parts': parts}))
    write(harness / 'inputs/SOURCE-MANIFEST.json', manifest_raw)
    addendum = (OLD / 'STORE-OBSERVER-ADDENDUM.md').read_bytes()
    write(harness / 'inputs/STORE-OBSERVER-ADDENDUM.md', addendum)
    history = summary_of_old_evidence()
    history_raw = encoded(history)
    write(harness / 'inputs/DIAGNOSTIC-HISTORY.json', history_raw)

    test_raw = (PRODUCT / 'tests/test_hia_agent_native_tools.py').read_bytes()
    test_tree = ast.parse(test_raw)
    cls = next(node for node in test_tree.body if isinstance(node, ast.ClassDef) and node.name == 'NativeLifecycleTests')
    method = next(node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == METHOD)
    method_ast = ast.dump(method, include_attributes=False)
    old_case = json.loads((OLD / 'actual/raw/evidence/REPORT.json').read_bytes())
    assert old_case['original_method_ast'][METHOD] == method_ast
    inputs = json.loads(old_bytes['inputs/INPUTS.json'])
    inputs.update({
        'methods': [METHOD], 'test_id': TEST_ID,
        'source_commit': SOURCE_COMMIT, 'source_tree': SOURCE_TREE, 'source_files': 3177,
        'source_manifest': identity(manifest_raw), 'original_test_file': identity(test_raw),
        'original_run': 43560753071, 'original_native_job': 132343657673,
        'original_artifact': {'id': 14101031842, 'bytes': NATIVE_ZIP_BYTES, 'sha256': NATIVE_ZIP_SHA},
        'retained_packet': identity(transport),
        'scope': 'instrumented unchanged original expired method on exact R20 source and retained R20 inputs; no fixture compilation/cold/qualification',
        'prior_diagnostic_commit': old_publication['commit'],
        'store_observer_addendum': identity(addendum),
        'store_observer_revision': 'EXACT_STORE_GENERIC_BASE_OBSERVER_BYPASS_V1',
        'expected_full_current_source_paths': len(fresh),
        'expected_fresh_file_paths_without_contract': len(fresh) - 1,
        'expected_fresh_file_bytes_without_contract': sum(source_rows[name]['bytes'] for name in fresh if name != 'docs/HIA_SELFHOST_CORE_SUPPORT.json'),
        'known_evidence': identity(history_raw),
        'toolchain_prerequisites': 'Exact original production Clang20 setup and pip pins; original Store qualifier _prerequisites outside observed test',
    })
    write(harness / 'inputs/INPUTS.json', encoded(inputs))

    observer = old_bytes['tools/observe_case.py'].decode()
    observer = replace_once(observer, "    parser.add_argument('--source', type=Path, required=True)\n",
                            "    parser.add_argument('--source', type=Path, required=True)\n    parser.add_argument('--inputs', type=Path, required=True)\n")
    observer = replace_once(observer, "    args = parser.parse_args()\n",
                            "    args = parser.parse_args()\n    expected = json.loads(args.inputs.read_bytes())\n    assert expected['methods'] == [args.method]\n    assert tuple(sys.version_info[:3]) == tuple(expected['python_version'])\n")
    observer = replace_once(observer, "'schema': 'hepta.original-namespace-method-section-diagnostic.v1'",
                            "'schema': 'hepta.original-namespace-method-section-diagnostic.v2'")
    observer = replace_once(observer,
        "        'source_commit': 'abeef212e34023534d91f8f952280e2a8d0cbde6',\n        'original_run': 43459534648, 'original_native_job': 132002437588,\n",
        "        'source_commit': expected['source_commit'], 'source_tree': expected['source_tree'],\n        'original_run': expected['original_run'], 'original_native_job': expected['original_native_job'],\n        'original_test_id': expected['test_id'],\n        'store_observer_revision': expected['store_observer_revision'],\n        'store_observer_addendum': expected['store_observer_addendum'],\n")
    observer = replace_once(observer, "    def json_init(image, raw, expected):\n        label = type(image).__name__\n",
        "    def json_init(image, raw, expected):\n        # Only the exact Store image is observed by store_init below.  Its original\n        # receipt predicate and constructor still run; the generic sampled wrapper\n        # must not wrap the same entry a second time (immutable prior addendum).\n        if type(image) is NativeStoreLifecycleImage:\n            return original_json_init(image, raw, expected)\n        label = type(image).__name__\n")
    write(harness / 'tools/observe_case.py', observer.encode())

    runner = old_bytes['tools/run_phase.py'].decode()
    runner = replace_once(runner, 'Supervise three unchanged methods on the fixed source; no build or qualification.',
                          'Supervise one unchanged R20 method; no fixture build or qualification.')
    runner = replace_once(runner, "'schema': 'hepta.original-namespace-three-method-diagnostic.v1'",
                          "'schema': 'hepta.original-namespace-single-method-diagnostic.v2'")
    runner = replace_once(runner,
        "        before = snapshot(source, expected)\n        write_json(evidence / 'SOURCE-BEFORE.json', before)\n",
        "        before = snapshot(source, expected)\n        write_json(evidence / 'SOURCE-BEFORE.json', before)\n        manifest_raw = (harness / 'inputs/SOURCE-MANIFEST.json').read_bytes()\n        assert identity(manifest_raw) == expected['source_manifest']\n        expected_files = json.loads(manifest_raw)\n        assert before['files'] == {name: {'mode': row['git_mode'], **{key: row[key]\n            for key in ('bytes', 'sha256', 'git_blob')}} for name, row in expected_files.items()}\n        # Original production prerequisite admission, before the observed group.\n        # The child remains a fresh interpreter; no product provider is replaced.\n        sys.path.insert(0, str(source))\n        from tools.qualify_hia_store_lifecycle import _prerequisites\n        report['prerequisites'] = _prerequisites(dict(os.environ))\n        write_json(evidence / 'PREREQUISITES.json', report['prerequisites'])\n")
    runner = replace_once(runner, "        tree = ast.parse(test_path.read_bytes())\n",
                          "        assert identity(test_path.read_bytes()) == expected['original_test_file']\n        tree = ast.parse(test_path.read_bytes())\n")
    runner = replace_once(runner, "        assert len(expected['methods']) == len(set(expected['methods'])) == 3\n",
                          "        assert len(expected['methods']) == len(set(expected['methods'])) == 1\n        assert expected['test_id'] == 'tests.test_hia_agent_native_tools.NativeLifecycleTests.' + expected['methods'][0]\n")
    runner = replace_once(runner,
        "                '--source', str(source), '--retained', str(retained),\n",
        "                '--source', str(source), '--inputs', str(harness / 'inputs/INPUTS.json'),\n                '--retained', str(retained),\n")
    write(harness / 'tools/run_phase.py', runner.encode())
    for name in ('tools/budget_profile.py', 'tools/diagnose_source_scan.py'):
        write(harness / name, old_bytes[name])

    workflow = old_bytes['.github/workflows/diagnostic.yml'].decode()
    workflow = replace_once(workflow, 'name: Fixed original namespace three-method sections',
                             'name: Fixed R20 original namespace expired-method sections')
    workflow = replace_once(workflow, old_publication['branch'], BRANCH)
    workflow = replace_once(workflow, '  original-three-method-sections:', '  original-expired-method-sections:')
    workflow = replace_once(workflow, old_publication['source'], SOURCE_COMMIT)
    production_workflow = (PRODUCT / '.github/workflows/hia-core.yml').read_text()
    begin = production_workflow.index('      - name: Install qualified Clang 20 native execution prerequisites\n')
    end = production_workflow.index('      - name: Prepare original locked Rust caller dependencies\n', begin)
    exact_prerequisite_block = production_workflow[begin:end]
    workflow = replace_once(workflow,
        '      - name: Install original discovery dependencies\n        run: python -m pip install jsonschema==4.26.0 setuptools==78.1.1 wheel==0.46.3\n',
        exact_prerequisite_block)
    workflow = replace_once(workflow, 'name: namespace-sections-${{ github.sha }}',
                             'name: namespace-r20-expired-sections-${{ github.sha }}')
    workflow = replace_once(workflow, '            harness/.github/workflows/diagnostic.yml\n',
        '            harness/.github/workflows/diagnostic.yml\n            ${{ runner.temp }}/hia-llvm.asc\n')
    write(harness / '.github/workflows/diagnostic.yml', workflow.encode())

    readme = f'''# Exact R20 original namespace expired-method diagnostic

## Frozen target and scope

This successor is authored, not published or executed. Product source is exactly
`{SOURCE_COMMIT}`, tree `{SOURCE_TREE}`, all 3,177 files. It selects only
`{TEST_ID}` from the original complete test module. The full module bytes and
the selected original method AST match the retained prior diagnostic. No product
source, original assertion, 3,000 ms total-context budget, 1,000 ms native budget,
reference poison, method name or test body is changed.

The parent harness is `{old_publication['commit']}`. Its old three-case results
and Store-counter correction are kept as immutable provenance. One method in a
fresh process is not the original 35-method order and cannot grant that group's
qualification. R20's original Native job remains failed; the other two original
failures are not rerun here.

## Exact retained inputs and source admission

The four-part transport reconstructs sixteen exact members of Native artifact
14101031842 from run 43560753071 / job 132343657673. Each actual member's ZIP CRC,
mode, complete bytes, SHA-256 and Git identity were checked while preparing this
packet. Nine inputs are byte/mode-identical to the old diagnostic; seven source-
bound records are replaced with the actual R20 originals, without rewriting any
manifest. Five original images are reused; no fixture compilation or cold replay
is performed. Original test business builds and process effects still execute
if the test reaches them.

Both complete checkout snapshots are checked against Git HEAD/tree and the fixed
3,177-path actual CI manifest. The original `current_sources()` must equal the
retained joint-build source manifest before observation. Every observed fresh
map must equal all 1,551 original R20 file entries, in sorted order. The actual
read/close/hash/provider sequence remains inside each public admission. No memo,
cached digest, guard candidate, manifest pruning or substituted provider is used.

## Observers retained and the exact correction

All original phase timers, public Store methods, source admission, publication,
subprocess, request/budget/namespace state, client-stage and service observers
are retained. Both diagnostic context-created SELECT reads remain; their cost
stays in the real enclosing budget. Namespace/request/budget policy poisons and
Store's two retained methods plus two fixed aliases remain unchanged.

Only the exact `NativeStoreLifecycleImage` bypasses the generic initializer's
diagnostic sampled wrapper. Its original initializer still executes, and the
Store initializer installs the same complete per-return receipt observer with
the same predicate, output/workspace checks and mode counting. This removes the
old duplicate native timing/count/metadata wrapper. It changes diagnostic
overhead and sample ordinal selection, so before/after wall times are not a
controlled optimization comparison. `inputs/STORE-OBSERVER-ADDENDUM.md` is the
unchanged historical correction; old 2,422 counts are not distinct machine calls.

`budget_profile.py` and `diagnose_source_scan.py` remain byte-identical. Only the
latter's identity/snapshot/write helpers are called; its standalone cProfile
entry is not run. Timings are descriptive instrumentation with ctypes overhead,
not exact native CPU. Process CPU excludes children. Inclusive component totals
are nested and cannot be added as exclusive shares.

## Real environment, supervision and output

CPython remains 3.14.4. The Clang 20 fingerprint/repository/install block and pip
pins are copied exactly from the R20 Native workflow, including Z3 4.15.4.0.
The old phase workflow did not explicitly install Clang 20 or Z3; that omission
is not carried forward as an environment claim. The original Store qualifier's
prerequisite checker records actual versions and tool identities before timing.

The job retains 40 minutes, one shared 1,800-second group deadline and the same
3-second timeout cleanup. The inherited supervisor observes child exit and
process-group absence; it is not described as an ECHILD/subreaper owner. It does
not modify test clocks or subtract observer cost. The complete original outcome
is saved even when the unchanged assertion fails. `OBSERVATIONS_COMPLETE` means
observation plus source/retained-byte integrity completed, never business PASS.

The always artifact includes evidence, all exact harness files and the downloaded
LLVM key. GitHub's harness SHA is distinct from the fixed product checkout SHA.
Only the proposed isolated branch `{BRANCH}` may trigger this workflow after
separate approval. No branch, commit, ref, product run, pure-SHA experiment or ABBA
measurement was created by this preparation. The old 78-member local context
plan remains history and was not materialized.
'''
    write(harness / 'README.md', readme.encode())

    # Only syntax/AST/byte comparisons; never import or execute authored tools.
    for path in (harness / 'tools').glob('*.py'):
        ast.parse(path.read_bytes(), filename=str(path))
    def functions(raw):
        return {node.name: ast.dump(node, include_attributes=False)
                for node in ast.walk(ast.parse(raw)) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
    old_functions = functions(old_bytes['tools/observe_case.py'])
    new_functions = functions(observer.encode())
    unchanged_observer_functions = sorted(set(old_functions) - {'main', 'json_init'})
    assert all(old_functions[name] == new_functions[name] for name in unchanged_observer_functions)
    assert old_functions['store_init'] == new_functions['store_init']
    assert old_functions['counted_entry'] == new_functions['counted_entry']
    before_runner = functions(old_bytes['tools/run_phase.py'])
    after_runner = functions(runner.encode())
    assert all(before_runner[name] == after_runner[name] for name in ('retained_map', 'unpack', 'run_case'))
    assert exact_prerequisite_block in workflow
    for token in ('timeout-minutes: 40', 'contents: read', 'if: always()', 'retention-days: 7'):
        assert workflow.count(token) == 1
    assert ast.dump(ast.parse((PRODUCT / 'tests/test_hia_agent_native_tools.py').read_bytes()), include_attributes=False) == ast.dump(test_tree, include_attributes=False)
    assert {name: capture(OLD_HARNESS / name) for name in old_before} == old_before
    assert {name: capture(PRODUCT / name) for name in product_before} == product_before
    assert stats(archive) == zip_before

    files = []
    for path in sorted(p for p in harness.rglob('*') if p.is_file()):
        raw = path.read_bytes()
        files.append({'path': path.relative_to(harness).as_posix(), 'mode': '100644', 'type': 'blob',
                      'sha': identity(raw)['git_blob'], 'bytes': len(raw), 'sha256': identity(raw)['sha256']})
    tree = tree_identity(files)
    write(OUT / 'HARNESS-MANIFEST.json', encoded(files))
    after_by_name = {row['path']: row for row in files}
    diffs = {}
    patch = []
    for name in sorted(set(old_bytes) | set(after_by_name)):
        before = old_bytes.get(name)
        after = (harness / name).read_bytes() if name in after_by_name else None
        if before == after:
            continue
        diffs[name] = {'before': identity(before) if before is not None else None,
                       'after': identity(after) if after is not None else None}
        if name.endswith(('.py', '.yml', '.md')) and before is not None and after is not None:
            patch.extend(difflib.unified_diff(before.decode().splitlines(True), after.decode().splitlines(True),
                         fromfile='before/' + name, tofile='after/' + name))
    write(OUT / 'EXACT-DIFFS.json', encoded(diffs))
    write(OUT / 'HANDWRITTEN-DIFF.patch', ''.join(patch).encode())
    write(OUT / 'RETAINED-INPUT-COMPARISON.json', encoded(retained_changes))
    write(OUT / 'BEFORE-READBACK.json', encoded({'old_harness': old_before, 'read_product_files': product_before,
                                               'native_zip_stat': zip_before,
                                               'native_zip_original_identity_from_prior_complete_custody': native['original'],
                                               'prior_complete_custody': identity(custody_raw),
                                               'native_member_manifest': identity(members_raw)}))
    plan = {
        'schema': 'hepta.namespace-r20-single-original-phase-plan.v1', 'status': 'AUTHORED_NOT_EXECUTED_NOT_PUBLISHED',
        'repository': 'TrillionniumFoundation/Hepta', 'sole_parent_intent': old_publication['commit'],
        'branch_intent': BRANCH, 'harness_tree': tree, 'harness_files': len(files),
        'harness_manifest': identity((OUT / 'HARNESS-MANIFEST.json').read_bytes()),
        'source_commit': SOURCE_COMMIT, 'source_tree': SOURCE_TREE, 'source_files': 3177,
        'actual_source_manifest': identity(manifest_raw), 'test_id': TEST_ID,
        'original_method_ast': method_ast, 'original_test_module': identity(test_raw),
        'original_context_ms': 3000, 'original_native_ms': 1000,
        'group_seconds': 1800, 'cleanup_seconds': 3, 'workflow_minutes': 40,
        'python': [3, 14, 4], 'fixture_compilations_planned': 0, 'cold_replay_planned': False,
        'original_business_builds_if_reached': True, 'selected_original_methods': 1,
        'selected_original_scope_is_not_complete_35_method_group': True,
        'original_r20_run': 43560753071, 'original_r20_native_job': 132343657673,
        'original_r20_artifact_id': 14101031842,
        'retained_members': 16, 'retained_total_raw_bytes': sum(row['bytes'] for row in packet_files.values()),
        'retained_old_same': 9, 'retained_r20_changed_source_bound_records': 7,
        'retained_packet': identity(transport), 'retained_transport_parts': parts,
        'prior_complete_custody': identity(custody_raw), 'prior_phase_publication': old_publication,
        'unchanged_helper_paths': ['tools/budget_profile.py', 'tools/diagnose_source_scan.py'],
        'unchanged_observer_function_asts': unchanged_observer_functions,
        'unchanged_runner_function_asts': ['retained_map', 'unpack', 'run_case'],
        'unchanged_store_receipt_observer_ast': True,
        'unchanged_selected_method_ast_vs_old_ci_phase': True,
        'production_prerequisite_block': identity(exact_prerequisite_block.encode()),
        'proposed_execution': ['python', '-B', 'harness/tools/run_phase.py', '--source', 'source',
                               '--harness', 'harness', '--evidence', 'evidence'],
        'guard_candidate_applied': False, 'memo_applied': False,
        'old_78_member_local_context_constructed': False,
        'product_execution_count': 0, 'git_object_publication_count': 0, 'ref_mutation_count': 0,
        'qualification': False, 'whole_native': False,
        'publication_requires_parent_review': True,
    }
    write(OUT / 'PLAN.json', encoded(plan))
    result = {'status': 'AUTHORING_AND_STATIC_READBACK_COMPLETE', 'harness_files': len(files),
              'harness_tree': tree, 'source_tree': SOURCE_TREE, 'retained_members': 16,
              'retained_total_raw_bytes': plan['retained_total_raw_bytes'],
              'retained_packet': identity(transport), 'plan': identity((OUT / 'PLAN.json').read_bytes()),
              'harness_manifest': identity((OUT / 'HARNESS-MANIFEST.json').read_bytes()),
              'inputs': identity((harness / 'inputs/INPUTS.json').read_bytes()),
              'product_executions': 0, 'git_publications': 0, 'originals_unchanged': True}
    write(OUT / 'PREPARATION.json', encoded(result))
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
