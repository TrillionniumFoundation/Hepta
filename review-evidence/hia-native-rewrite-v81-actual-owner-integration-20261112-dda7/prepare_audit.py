"""Append complete immutable original evidence without replacing older audits."""
from pathlib import Path
from hashlib import sha1, sha256
import json
import re
import sys

ROOT = Path(__file__).resolve().parent
WORK = ROOT.parent
sys.path.insert(0, str(WORK/'v80-joint-audit-publication-r1'))
from prepare_audit import tree_hash

LEAF = 'hia-native-rewrite-v81-actual-owner-integration-20261112-dda7'


def read(path):
    return json.loads(path.read_bytes())


def ident(path):
    raw = path.read_bytes()
    return {'bytes': len(raw), 'chars': len(raw.decode()), 'sha256': sha256(raw).hexdigest(),
            'sha': sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}


def main():
    entries, new = {}, []
    def add(path, sha, mode='100644', kind='blob'):
        assert re.fullmatch('[0-9a-f]{40}', sha), (path, sha)
        assert not path.startswith('/') and all(p not in ('', '.', '..') for p in path.split('/'))
        row = {'path': path, 'mode': mode, 'type': kind, 'sha': sha}
        if path in entries:
            assert entries[path] == row, path
        entries[path] = row
    def local(path, source, known=None):
        row = ident(source)
        if known:
            assert row['sha'] == known, path
        else:
            new.append({'path': path, 'local': str(source), **row})
        add(path, row['sha'])
    def recipe(name, source, prefix, known=None, strip=None):
        local('recipes/'+name, source, known)
        data = read(source)
        rows = data if isinstance(data, list) else data['entries']
        for row in rows:
            path = row['path']
            if strip:
                assert path.startswith(strip), path
                path = path[len(strip):]
            add(prefix+'/'+path, row['sha'], row['mode'], row['type'])

    recipe('GLOBAL-SOURCE-DEV-RECIPE.json', ROOT/'GLOBAL-SOURCE-DEV-RECIPE.json',
        'global/source-r1-and-development', '4dbb7cf01851a7efd0b9b50d702f1433ded446a4')
    recipe('GLOBAL-SOURCE-R1-ZIP-RECIPE.json', ROOT/'GLOBAL-SOURCE-R1-ZIP-RECIPE.json',
        'global/complete-source-r1-zip', 'cece63d3384a2a9ede17e27284882c178c048ad7')
    recipe('GLOBAL-SOURCE-R2-RECIPE.json', ROOT/'GLOBAL-SOURCE-R2-RECIPE.json',
        'global/published-source-r2', '51d4834c1d49b3ce2a940e80330ec94baebeda5f')
    recipe('FULL-RETAINED-STATIC-LAUNCH-RECIPE.json', ROOT/'FULL-RETAINED-STATIC-LAUNCH-RECIPE.json',
        'full-retained/static-and-launch', 'bf523f2a5cfb48c14471cb20f36afda43291993f')
    for name, known in (
        ('EVALUATION-R6-RECIPE.json', 'f7ce7447af84eb2eebeee86b6deb9c333beea627'),
        ('EVALUATION-R6-ACTUAL-RECIPE.json', 'd67a46a6ac758176cb6d028b41c20f8b9eaf7466')):
        recipe(name, ROOT/name, 'evaluation', known,
            'review-evidence/hia-native-rewrite-v81-evaluation-fresh-scan-20261112-dda7/')
    recipe('FRONT-R2-R4-RECIPE.json', ROOT/'FRONT-R2-R4-RECIPE.json',
        'core-assembly-front', '83095bee45b9a25a63cc48eac4627b4f0421a5cb')
    recipe('ROOT-LOCAL-DEVELOPMENT-RECIPE.json', WORK/'v81-root-development-evidence-r1/remote/TREE-RECIPE.json',
        'root-local-development', '4b5c8d67818f965631b0cd60f88a51763da46983')
    recipe('REQUESTS-ACTUAL-CI-RECIPE.json', WORK/'v81-requests-ci-evidence-r1/remote/TREE-RECIPE.json',
        'requests-actual-ci', 'ae466317ef06259f24552eb894abc76ce78bd12f')

    known = {
        'GLOBAL-SOURCE-DEV-INDEX.json':'d52059b01f78d5247665c0419e7170925a0aba15',
        'GLOBAL-SOURCE-R1-ZIP-INDEX.json':'c37bb9439e9a5fcaf243e572d257b7c07f635d90',
        'GLOBAL-SOURCE-R2-INDEX.json':'5dfdd1bded7107313050f34b7e4345c91b6bde50',
        'FULL-RETAINED-STATIC-LAUNCH-INDEX.json':'bc1f5d3003758136dd6cdfb68bca274d36db97c2',
        'EVALUATION-R6-INDEX.json':'f4eeb5c8ed8b3a71fdb872dbe527adb769fe6594',
        'EVALUATION-R6-ACTUAL-INDEX.json':'2c8204d56acb3e807af298b69e2e3d1795623a45',
        'EVALUATION-R6-ACTUAL-TERMINAL.json':'361e02993a7c2e5e79297609087461f65abec41f',
        'EVALUATION-R7-TEST-PROPOSAL.json':'68d305b393e77ee13349129cd2278c311b41e114',
        'EVALUATION-BUDGET-METADATA-CORRECTION.json':'0a135bf3bacab102616527774578f556bc6567de',
        'FRONT-R2-INDEX.json':'b892b1d46ed1f76857d278cc7bfe3fb651216692',
        'FRONT-R2-R4-HANDOFF.json':'f028effecef6ce8b123c9085ba31353fbde74449',
    }
    for name, sha in known.items():
        local('indices/'+name, ROOT/name, sha)
    for version in ('311', '314'):
        local('requests-actual-ci/extracted-binary-reclamation-'+version+'.json',
            WORK/('v81-service-requests-development-r1/ci-r1/actual'+version+'-r1/EXTRACTED-BINARY-RECLAMATION.json'))
    for name in ('README.md', 'prepare_audit.py', 'PR889-BEFORE-UPDATE.json',
        'PR889-BEFORE-UPDATE.md', 'FULL-RETAINED-RUN-OBSERVATION.json',
        'EVALUATION-PHASE-RUN-OBSERVATION.json', 'PUBLISHED65CE-CORE-RUN-OBSERVATION.json',
        'RECEIVER-ARGUMENT-EXTENT-FAILURE.json'):
        local(name, ROOT/name)
    for name in ('SOURCE-PACKAGING.json', 'DEFAULT-COMPATIBILITY-APPLIED.json',
        'registration-controls-r2/REPORT.json', 'registration-controls-r2/LOADER.json',
        'compatibility-source-controls-r1/observations/REPORT.json',
        'compatibility-source-controls-r1/stderr',
        'compatibility-source-controls-r2/observations/REPORT.json',
        'proof-scope-native-r1/REPORT.json',
        'proof-scope-native-r1/observations/REPORT.json',
        'proof-scope-native-r1/component-evidence/ServiceRequestsNativeTests/real-proof-scope-integration.json',
        'proof-scope-native-r1/component-evidence/ServiceRequestsNativeTests/actual-entries.json',
        'ci-r2/preparation-controls-r1/REPORT.json'):
        local('requests-r2-scope/'+name, WORK/'v81-service-requests-development-r2'/name)

    old_root, old_review = read(ROOT/'PREVIOUS-ROOT.json'), read(ROOT/'PREVIOUS-REVIEW.json')
    assert old_root['sha'] == '3f7eed453273cb4c2f04edc738690988ac83bffb'
    assert old_review['sha'] == '06e442e95c7147403364cbc8954088293b9f8025'
    clean = lambda rows: [{k: r[k] for k in ('path','mode','type','sha')} for r in rows]
    assert tree_hash(clean(old_root['tree'])) == old_root['sha']
    assert tree_hash(clean(old_review['tree'])) == old_review['sha']
    ordered = [entries[n] for n in sorted(entries)]
    leaf_sha = tree_hash(ordered)
    review = clean(old_review['tree']) + [{'path':LEAF,'mode':'040000','type':'tree','sha':leaf_sha}]
    review_sha = tree_hash(review)
    root = [{**row,'sha':review_sha if row['path']=='review-evidence' else row['sha']}
            for row in clean(old_root['tree'])]
    plan = {'schema':'hia.actual-owner-integration.additive-audit.v81.r1',
        'previous_commit':'06f4856e6adee5af8597941201382ab0eddabd13',
        'previous_root':old_root['sha'],'previous_review':old_review['sha'],
        'leaf_name':LEAF,'leaf_entries':ordered,'leaf_sha':leaf_sha,
        'leaf_steps':[{'count':min(i+12,len(ordered)),'sha':tree_hash(ordered[:i+12])}
                      for i in range(0,len(ordered),12)],
        'review_entries':review,'review_sha':review_sha,'root_entries':root,'root_sha':tree_hash(root),
        'prior_audit_subtrees_preserved':len(old_review['tree']),'new_blobs':new,'whole_native':False}
    with (ROOT/'AUDIT-PLAN.json').open('x') as f:
        json.dump(plan,f,sort_keys=True,indent=2);f.write('\n')
    print(json.dumps({k:plan[k] for k in ('leaf_sha','review_sha','root_sha','prior_audit_subtrees_preserved')}))
    print(json.dumps({'leaf_files':len(ordered),'new_blobs':len(new),'batches':len(plan['leaf_steps'])}))


if __name__ == '__main__':
    main()
