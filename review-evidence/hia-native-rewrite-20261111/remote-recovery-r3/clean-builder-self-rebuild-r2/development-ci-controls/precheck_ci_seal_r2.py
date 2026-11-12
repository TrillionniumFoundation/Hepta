"""Local full-size seal control only: no HIA, compiler, or old test is run."""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import shutil
import stat
import tarfile

ROOT=Path(__file__).resolve().parent
OUT=ROOT/'ci-seal-precheck-r2'
OUT.mkdir()
spec=importlib.util.spec_from_file_location('selfbuild_ci_seal_control', ROOT/'ci_self_rebuild_r4.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
m.become_subreaper()
archive=Path('/dev/shm/hia-selfbuild-seal-r1/development-compact.tar.xz')
assert m.record(archive)['sha256']=='d377a923d147933837fe42c1d916ee5418eafd0516cdf66c0149c5d2eec5807e'
ledger=Path('/dev/shm/hia-selfbuild-seal-r1/members.json')
if not ledger.is_file():
    ledger=ROOT/'development-archive-members.json'
# Independent current tar members are compared with the durable full ledger.
candidates=list(Path('/dev/shm/hia-selfbuild-seal-r1').glob('*'))
for p in candidates:
    if p.is_file() and m.record(p)['sha256']=='66417fad322faa18695c836e6244c91f20ca5bedc4344d5411603c1157096aed':
        ledger=p;break
rows=json.loads(ledger.read_bytes())
if isinstance(rows,dict):
    rows=rows['rows']
assert len(rows)==1989
expected={r['path']:r for r in rows}
seen=set()
restored=OUT/'completed-originals'
restored.mkdir()
with tarfile.open(archive,'r|xz') as tar:
    for item in tar:
        assert item.name in expected and item.name not in seen
        seen.add(item.name);row=expected[item.name]
        assert item.mode==row['mode'] and item.size==row['bytes']
        path=restored/item.name
        assert path.resolve().is_relative_to(restored.resolve())
        if item.isdir():
            path.mkdir(exist_ok=True,parents=True);path.chmod(item.mode)
        else:
            assert item.isfile() and not item.issparse()
            raw=tar.extractfile(item).read()
            assert len(raw)==row['bytes'] and hashlib.sha256(raw).hexdigest()==row['sha256']
            path.parent.mkdir(exist_ok=True,parents=True);path.write_bytes(raw);path.chmod(item.mode)
assert seen==set(expected)
# Both exact R13 restored copies and all 644 reference files match the formal
# CI's restore/project layout.  This controls full-size compression work without
# re-executing any already completed target group.
for source,name in [(ROOT/'original-r13','original-r13-copy-a'),(ROOT/'original-r13','original-r13-copy-b'),(ROOT/'reference-kit-r13','exact-reference644')]:
    shutil.copytree(source,OUT/name,copy_function=shutil.copy2)
    for p in source.rglob('*'):
        q=OUT/name/p.relative_to(source)
        if p.is_dir():assert stat.S_IMODE(p.stat().st_mode)==stat.S_IMODE(q.stat().st_mode)
        else:assert m.record(p)==m.record(q)
script=ROOT/'ci_self_rebuild_seal_r1.py'
state=m.Qualification(ROOT,OUT,ROOT/'ci-source-index-r2.json')
process=state.run('full-original-seal',script,['--root',OUT],cpu=90,wall=180)
custody=json.loads((OUT/'custody.json').read_bytes())
assert custody['status']=='PASS' and custody['primary'] is None and custody['secondary']==[]
assert custody['complete_member_bytes_sha_mode_and_after_checked'] is True
assert m.record(OUT/'evidence.tar.xz')==custody['archive']
assert m.record(OUT/'evidence-members.json')==custody['member_index']
post=json.loads((OUT/'seal-post-output-budget.json').read_bytes())
assert post['status']=='PASS' and 0<=post['usage']['aggregate_cpu_seconds']<90 and 0<=post['usage']['elapsed_ns']<180000000000
report={'schema':'hia-selfbuild-sealer-full-size-local-precheck-r1','status':'PASS','scope':'DEVELOPMENT_READ_ONLY_SEAL_NO_HIA_B3_OR_ORIGINAL_TEST_EXECUTION','original_tar_members':1989,'raw_file_bytes':custody['raw_file_bytes'],'members':custody['members'],'files':custody['files'],'sealer':m.record(script),'ci_driver':m.record(ROOT/'ci_self_rebuild_r4.py'),'process':process,'custody':m.record(OUT/'custody.json'),'post_output_budget':m.record(OUT/'seal-post-output-budget.json'),'all_inputs_preserved':True,'HIA_entries':0,'B3_calls':0}
m.write_json(ROOT/'ci-seal-precheck-r2-result.json',report)
print(json.dumps({k:report[k] for k in ('status','raw_file_bytes','members','files','HIA_entries','B3_calls')}),flush=True)
