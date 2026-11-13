"""Author only: one fixed full Source run followed by the original62 controls."""
from __future__ import annotations
import ast
import difflib
import hashlib
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parent
HARNESS = ROOT / 'formal-harness'
OLD = ROOT.parent / 'v94-cli-parser-context-r11-r2'
BRANCH = 'codex/hia-combined-source-parser-v94-r12-r2-20261113-dda7'


def encode(x):
    return (json.dumps(x, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode()


def pin(b):
    return {'bytes':len(b),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest(),
            'sha256':hashlib.sha256(b).hexdigest(),'mode':'100644'}


def put(p,b):
    p.parent.mkdir(parents=True,exist_ok=True)
    with p.open('xb') as f:f.write(b)


def replace_function(source, name, replacement):
    node = next(n for n in ast.parse(source).body if isinstance(n,ast.FunctionDef) and n.name==name)
    lines=source.splitlines(keepends=True)
    return ''.join(lines[:node.lineno-1])+replacement+''.join(lines[node.end_lineno:])


def main():
    plan_raw=(ROOT/'harness/inputs/MATERIALIZATION-R12-R2.json').read_bytes()
    plan=json.loads(plan_raw)
    put(HARNESS/'inputs/MATERIALIZATION.json',plan_raw)
    for row in plan['harness_files']:
        b=(ROOT/'harness'/row['path']).read_bytes()
        assert pin(b)['git_blob']==row['blob'] and len(b)==row['bytes']
        put(HARNESS/row['path'],b)
    driver=(ROOT/'harness/tools/materialize_candidate_r14.py').read_bytes()
    assert pin(driver)['git_blob']=='cfe319279641b124bcd724437857686f36d1aa07'
    put(HARNESS/'tools/materialize_candidate.py',driver)
    expected_raw=(ROOT/'FORMAL-EXPECTED-IDS.json').read_bytes()
    put(HARNESS/'inputs/FORMAL-EXPECTED-IDS.json',expected_raw)
    compiler=json.loads((OLD/'diagnostic-ci-r1/harness/inputs.json').read_bytes())['compiler']
    for row in compiler['parts']:
        b=(OLD/'diagnostic-ci-r1/harness'/row['path']).read_bytes()
        assert all(pin(b)[k]==row['encoded'][k] for k in ('bytes','git_blob','sha256'))
        put(HARNESS/row['path'],b)

    projections={}
    for name in ('run_build.py','run_group.py','probe_fresh_selected.py'):
        original=(OLD/name).read_text()
        # The previously authored portable draft already uses the same compiler bytes
        # under ROOT/inputs and the actual interpreter for packaging.
        draft=(OLD/'diagnostic-ci-r1/harness/runners'/name).read_text()
        new=draft
        if name=='probe_fresh_selected.py':
            old="ROOT = Path(__file__).resolve().parent\nSOURCE = ROOT / 'source'\nsys.path.insert(0, str(SOURCE))"
            fresh="from bounded_support import ROOT, SOURCE, snapshot\nsys.path.insert(0, str(SOURCE))"
        else:
            old="ROOT=Path(__file__).resolve().parent;SOURCE=ROOT/'source';sys.path.insert(0,str(SOURCE))"
            fresh="from bounded_support import ROOT, SOURCE, snapshot\nsys.path.insert(0,str(SOURCE))"
        assert new.count(old)==1
        new=new.replace(old,fresh)
        new=replace_function(new,'snapshot','')
        new=new.replace('ACTUAL_CPYTHON314_LOCAL_DEVELOPMENT_NOT_COLD','FORMAL_ACTUAL314_BOUNDED_DEVELOPMENT_NOT_COLD')
        if name=='run_group.py':
            oldline="report.update(loaded_ids=ids,loaded=suite.countTestCases(),loader_errors=loader.errors)"
            assert new.count(oldline)==1
            new=new.replace(oldline,oldline+"\n fixed=json.loads((ROOT/'FORMAL-EXPECTED-IDS.json').read_bytes())['bounded_groups'][group]\n assert ids==fixed")
        ast.parse(new)
        put(HARNESS/'tools'/name,new.encode())
        projections[name]={'actual_local_before':pin(original.encode()),'previous_authored_portable_draft':pin(draft.encode()),
            'formal_after':pin(new.encode()),'unified_diff_from_actual_local':''.join(difflib.unified_diff(original.splitlines(keepends=True),new.splitlines(keepends=True),fromfile='local/'+name,tofile='formal/'+name)),
            'product_test_files_changed':False}
    original=(OLD/'supervise.py').read_text()
    old="ROOT=Path(__file__).resolve().parent;sys.path.insert(0,str(ROOT/'source'))"
    replacement="TOOLS=Path(__file__).resolve().parent\nsys.path.insert(0,str(TOOLS))\nfrom bounded_support import ROOT, SOURCE\nsys.path.insert(0,str(SOURCE))"
    assert original.count(old)==1
    supervisor=original.replace(old,replacement)
    assert supervisor.count('str(ROOT/script)')==1
    supervisor=supervisor.replace('str(ROOT/script)','str(TOOLS/script)')
    assert 'qualification_seconds=180,cleanup_seconds=3' in supervisor
    put(HARNESS/'tools/supervise.py',supervisor.encode())
    projections['supervise.py']={'actual_local_before':pin(original.encode()),'formal_after':pin(supervisor.encode()),
        'unified_diff_from_actual_local':''.join(difflib.unified_diff(original.splitlines(keepends=True),supervisor.splitlines(keepends=True),fromfile='local/supervise.py',tofile='formal/supervise.py')),
        'qualification_seconds':180,'cleanup_seconds':3}
    repair=json.loads((ROOT/'SOURCE-REPAIR-FINAL.json').read_bytes())
    fixed={'schema':'hepta.r12-r2-formal-parser-controls.v1','scope':'PURE_ACTUAL314_DEVELOPMENT_CONTROLS_AFTER_FULL_SOURCE_SUCCESS_NOT_COLD',
        'materialization_plan':pin(plan_raw),'materialization_driver':pin(driver),'expected_ids':pin(expected_raw),
        'compiler':compiler,'groups':{'source':10,'original43':43,'native':9},
        'budgets':repair['limits_unchanged'],'original_test_files':repair['unchanged_original_test_files'],
        'repaired_source_files':{row['path']:{k:v for k,v in row['after'].items() if k!='text'} for row in repair['changes']},
        'harness_files':{p.relative_to(HARNESS).as_posix():pin(p.read_bytes()) for p in sorted((HARNESS/'tools').glob('*.py'))},
        'local_original43_packaging312_is_not_formal_qualification':True,'formal_python':[3,14,4],
        'installed_child_and_packaging':'sys.executable','generation_and_tests_not_run_during_harness_authoring':True}
    fixed_raw=encode(fixed)
    put(HARNESS/'inputs/PARSER-CONTROLS.json',fixed_raw)
    old_workflow=(ROOT.parent/'v93-union-r11/published-harness/.github/workflows/hia-combined-source.yml').read_text()
    workflow=old_workflow.replace('codex/hia-combined-source-build-v93-r11-20261113-dda7',BRANCH)
    workflow=workflow.replace('hia-combined-source-v93-r11','hia-combined-source-v94-r12-r2')
    workflow=workflow.replace('c19cd878115b1e9d3d4b81024838b36575a6bf30',pin(plan_raw)['git_blob'])
    marker='      - name: Retain real input sources, partial generated bytes, logs and all outcomes\n'
    assert workflow.count(marker)==1
    step='''      - name: Require complete Source projection and original43 plus Source10 plus Native9 on actual314
        env:
          EXPECTED_PARSER_CONTROLS_BLOB: FIXED_BLOB
        run: |
          python -I -B "${GITHUB_WORKSPACE}/harness/tools/run_parser_bounded.py" \\
            --materialization-root "${RUNNER_TEMP}/hia-combined-source-v94-r12-r2" \\
            --output "${RUNNER_TEMP}/hia-parser-bounded-v94-r12-r2"
'''.replace('FIXED_BLOB',pin(fixed_raw)['git_blob'])
    workflow=workflow.replace(marker,step+marker)
    added='''      - name: Retain every bounded parser outcome and original raw buffer receipt
        if: always()
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02
        with:
          name: hia-parser-bounded-v94-r12-r2-${{ github.run_id }}-${{ github.run_attempt }}
          path: ${{ runner.temp }}/hia-parser-bounded-v94-r12-r2
          if-no-files-found: warn
          include-hidden-files: true
          retention-days: 90
          compression-level: 6
'''
    workflow+=added
    projected=workflow.replace(step,'').replace(added,'')
    projected=projected.replace(BRANCH,'codex/hia-combined-source-build-v93-r11-20261113-dda7').replace('hia-combined-source-v94-r12-r2','hia-combined-source-v93-r11').replace(pin(plan_raw)['git_blob'],'c19cd878115b1e9d3d4b81024838b36575a6bf30')
    assert projected==old_workflow
    put(HARNESS/'.github/workflows/hia-combined-source.yml',workflow.encode())
    for p in sorted((HARNESS/'tools').glob('*.py')):
        compile(ast.parse(p.read_bytes(),filename=str(p)),str(p),'exec',dont_inherit=True)
    put(ROOT/'FORMAL-RUNNER-PROJECTIONS.json',encode(projections))
    files={p.relative_to(HARNESS).as_posix():pin(p.read_bytes()) for p in sorted(HARNESS.rglob('*')) if p.is_file()}
    intent={'schema':'hepta.r12-r2-harness-reviewable-intent.v1','status':'AUTHORED_NOT_PUBLISHED_NOT_EXECUTED',
        'repository':'TrillionniumFoundation/Hepta','branch':BRANCH,
        'sole_parent':'2a91857219e0c676420f02251e1a772f0e0c7362',
        'tree_strategy':'New exact tree of only listed harness files; no product workflows or sources',
        'files':files,'plan':pin(plan_raw),'parser_controls':pin(fixed_raw),
        'Source_expected':1342,'original1329_ordered_projection':True,'bounded_original_ordered_ids':62,
        'extra_fresh_process_observations':5,'compiles':5,'compile_seconds':20,
        'per_bounded_group_qualification_seconds':180,'per_bounded_group_cleanup_seconds':3,
        'Source_original_timeout_seconds':1800,'workflow_original_timeout_minutes':90,
        'original_R14_driver_guard_bytes_unchanged':True,'original_workflow_permissions_unchanged':True,
        'original_source_evidence_always_upload_unchanged':True,'bounded_evidence_separate_always_upload':True,
        'whole_source_and_all62_required_for_job_success':True,'product_Native121_fragment_unchanged':True,
        'same_pure314_packaging_and_installed_child':True,'cold_qualification':False,
        'product_refs_changed':False,'publication_requires_parent_review':True}
    put(ROOT/'HARNESS-PUBLICATION-INTENT.json',encode(intent))
    print(json.dumps({'files':len(files),'harness_bytes':sum(row['bytes'] for row in files.values()),
        'plan':pin(plan_raw),'fixed':pin(fixed_raw),'workflow':pin(workflow.encode()),
        'intent':pin(encode(intent)),'status':intent['status']},indent=2))


if __name__=='__main__':main()
