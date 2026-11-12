"""Prepare exact seven source deltas after closed source102 and historical19 controls."""
from pathlib import Path
import hashlib
import json
import stat
import subprocess

CONTROL = Path(__file__).resolve().parent
ROOT = CONTROL.parent.parent / 'combined-native-v88-r1'
BASE = '677cca3eb7a781726578aa51172012df34e7d627'
BASE_TREE = 'dc29b16468d5ae1e558f317c7ab360b31ac2a002'
OUT = CONTROL / 'pure-publication-r2'

def command(*args):
    return subprocess.check_output(['git', '-C', str(ROOT), *args])

def blob(raw):
    return hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()

def leaves(tree):
    result = []
    for row in command('ls-tree', '-r', '-z', tree).split(b'\0'):
        if not row:
            continue
        spec, path = row.split(b'\t', 1)
        mode, kind, sha = spec.decode().split()
        if kind != 'blob':
            raise ValueError('non-blob source leaf')
        result.append({'path': path.decode(), 'mode': mode, 'type': kind, 'sha': sha})
    return sorted(result, key=lambda row: row['path'])

validation = json.loads((CONTROL / 'source-controls-r1/VALIDATION.json').read_bytes())
old19 = json.loads((CONTROL / 'custody19-controls-r1/VALIDATION.json').read_bytes())
if not (validation['status'] == 'SOURCE_ONLY_PASS_NOT_NATIVE_QUALIFICATION'
        and validation['expected_loaded_executed_methods'] == 102
        and validation['all_five_anomaly_counts_zero'] is True and validation['natural_and_closed'] is True
        and old19['status'] == 'ORIGINAL19_SOURCE_CONTROLS_PASS_NOT_PRODUCT_QUALIFICATION'
        and old19['expected_loaded_executed'] == 19 and old19['zero_five_anomalies_and_loader_errors'] is True
        and old19['owner_natural_and_ECHILD_closed'] is True and old19['source_preserved'] is True):
    raise ValueError('both original source populations must actually pass')
if OUT.exists() or command('rev-parse', 'HEAD').decode().strip() != 'b7c2f79e04965e53a1c198703f20b1ff22df4765':
    raise ValueError('create-only source publication base differs')
if command('diff', '--name-only') or command('ls-files', '--others', '--exclude-standard', '-z'):
    raise ValueError('candidate changed after closed verification')
tree = command('write-tree').decode().strip()
if tree != validation['final_source_tree'] or tree != old19['source_tree']:
    raise ValueError('source tree differs from both actual checks')
base, current = leaves(BASE_TREE), leaves(tree)
base_map, current_map = {r['path']: r for r in base}, {r['path']: r for r in current}
if len(base) != 4074 or len(current) != 4075 or not set(base_map) <= set(current_map):
    raise ValueError('complete source population differs or an old path was removed')
if command('rev-parse', 'HEAD^{tree}').decode().strip() != BASE_TREE:
    raise ValueError('exact pure v87 base tree differs')
after = json.loads((CONTROL / 'custody19-controls-r1/SOURCE-AFTER.json').read_bytes())
if [(r['path'], r['mode'], r['sha']) for r in current] != [tuple(r[:3]) for r in after]:
    raise ValueError('full staged leaves differ from actual original19 source snapshot')
entries = []
for row in current:
    path = ROOT / row['path']
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError('nonregular source path')
    raw = path.read_bytes()
    if blob(raw) != row['sha']:
        raise ValueError('source byte mismatch: ' + row['path'])
    row['size'] = len(raw)
    if row['path'] not in base_map or any(row[k] != base_map[row['path']][k] for k in ('mode', 'type', 'sha')):
        text = raw.decode('utf-8')
        if '\0' in text:
            raise ValueError('changed binary requires a separate publication path')
        entries.append({**row, 'sha256': hashlib.sha256(raw).hexdigest(), 'text': text})
if len(entries) != 7 or sum(r['path'] not in base_map for r in entries) != 1:
    raise ValueError('expected six modified files and one new test file')
contract = json.loads((ROOT / 'docs/HIA_SELFHOST_CORE_SUPPORT.json').read_bytes())
declared = len(contract['source_identity']['files'])
python_modules = sum(r['path'].startswith('hepta/') and r['path'].endswith('.py') for r in current)
if declared != 839 or python_modules != 172:
    raise ValueError('declared-source or retained Python module denominator differs')
package = {'schema': 'hia.combined-v88.pure-source-publication.v1',
           'status': 'SOURCE102_AND_ORIGINAL19_VERIFIED_STANDARD_CI_NOT_RUN',
           'base_commit': BASE, 'base_tree': BASE_TREE, 'source_tree': tree,
           'source_leaves': len(current), 'source_bytes': sum(r['size'] for r in current),
           'package_python_modules': python_modules, 'declared_source_files': declared,
           'entries': entries, 'leaves': current, 'source_validation': validation, 'original19_validation': old19,
           'pure_commit_message': '[skip ci] Admit complete cold evidence through bounded publication custody ingress',
           'CI_commit_message': 'Run original HIA standard gates on frozen combined v88 source',
           'CI_branch': 'codex/hia-combined-native-v88-20261112-e26e',
           'expected_standard_source_methods': 453, 'historical19_included_in_standard_source_population': False,
           'full_native_rewrite': False, 'old_stack_deleted': False,
           'original_failures_hold_unknown_preserved': True}
raw = (json.dumps(package, ensure_ascii=True, separators=(',', ':')) + '\n').encode('ascii')
OUT.mkdir(mode=0o700)
(OUT / 'BUNDLE.json').write_bytes(raw)
summary = {'path': str(OUT / 'BUNDLE.json'), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
           'source_tree': tree, 'source_leaves': len(current), 'changed_files': 7, 'added': 1, 'removed': 0,
           'source_methods': 102, 'separate_original19_methods': 19, 'standard_CI_started': False}
(OUT / 'SUMMARY.json').write_text(json.dumps(summary, indent=2) + '\n')
print(json.dumps(summary, indent=2))
