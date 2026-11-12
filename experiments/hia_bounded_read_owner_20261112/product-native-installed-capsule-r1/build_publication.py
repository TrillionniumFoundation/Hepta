"""Prepare immutable review artifacts locally. No network, trigger or product."""
import ast
from hashlib import sha1,sha256
import io
import json
import os
from pathlib import Path
import stat
import tarfile

ROOT=Path(__file__).resolve().parent
OUT=ROOT/'control'
PUB=ROOT/'publication-r3'
PUB.mkdir(mode=0o700)
PREFIX='experiments/hia_bounded_read_owner_20261112/product-native-installed-capsule-r1'
def wire(v):return (json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def pin(raw):return {'bytes':len(raw),'sha256':sha256(raw).hexdigest(),
    'git_blob_sha1':sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}
pins=json.loads((ROOT/'FROZEN-CONTROLS.json').read_bytes())
for name,expected in pins['files'].items():
    assert pin((OUT/name).read_bytes())==expected,name
controller=pins['files']['controller.py'];diag=pins['files']['diagnostics.py'];policy=pins['policy']
text=(ROOT/'references/original-workflow.yml').read_text()
replacement={
 'name: HIA bounded-read r4b native development':'name: HIA bounded-read v80 native and installed development',
 'bounded-read-development:':'bounded-read-native-installation:',
 'codex/hia-bounded-read-native-r4b-run-r2-20261112-e26e':'codex/hia-bounded-read-v80-native-installed-r1-run-20261112-e26e',
 'hia-bounded-read-native-r4b-development-r2':'hia-bounded-read-v80-native-installed-r1',
 'experiments/hia_bounded_read_owner_20261112/actions-native-development-r2':PREFIX,
 '30f053a6585b29bf052e36806e4a657d5bda9935':'CONTROL_COMMIT',
 '0e36619bc65ada7072c1e8a1f1454728036fee4e':'ba714f34b8dcb248c779bb5fc0b9538d9151c685',
 'Exact r4b product checkout':'Exact ba714f v80 pure product checkout',
 'Fresh B0 B1 B2 and all 55 plus original 8 under original 180 seconds':'Fresh compiler, original 55 and 8/7 callers, and nine installed cases under 180 seconds',
 'len(b)==29427':'len(b)=='+str(controller['bytes']),
 '026776460c4597615e3d26d6b802f9c2e43380efbc88890b44f6eadd5959775f':controller['sha256'],
 'len(b)==21252':'len(b)=='+str(diag['bytes']),
 '8f8c9508490dd23fa65a6822cccc5d2409c76a7d58336ca13ddf0653fbee7276':diag['sha256'],
 '7eeec008bc7e8b1dbdf4645c1eee96af6891e4de0de7b6d3e51554665df9451b':policy['sha256'],
 'hia-bounded-read-development-${{ github.sha }}':'hia-bounded-read-v80-native-installed-${{ github.sha }}',
}
for old,new in replacement.items():
    assert old in text,old
    text=text.replace(old,new)
assert text.count('CONTROL_COMMIT')==5
(ROOT/'workflow.template.yml').write_text(text)

# Preserve each real finite-control original and its full original identity;
# tar metadata normalization is explicit, and specials are metadata only.
roots=('static-originals-r1','static-checks-r1','transport-checks-r1')
rows=[];regular={}
for base in roots:
    for directory,dirs,files in os.walk(ROOT/base,followlinks=False):
        for name in sorted(dirs+files):
            path=Path(directory)/name
            info=path.lstat();relative=path.relative_to(ROOT).as_posix()
            row={'path':relative,'original_identity':[info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,
                    info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns]}
            if stat.S_ISREG(info.st_mode):
                raw=path.read_bytes();row.update(kind='regular',**pin(raw));regular[relative]=raw
            elif stat.S_ISDIR(info.st_mode):row['kind']='directory'
            elif stat.S_ISLNK(info.st_mode):row.update(kind='symlink',target=os.readlink(path))
            else:assert stat.S_ISFIFO(info.st_mode);row['kind']='FIFO'
            rows.append(row)
rows.sort(key=lambda r:r['path'])
manifest={'schema':'hepta.hia.bounded-read-capsule-static-originals.v1','originals':rows,
    'regular_bytes_retained':True,'specials_are_metadata_only':True,'tar_uid_gid_mtime_normalized_to_zero':True,
    'no_product_or_native_execution':True}
manifest_raw=wire(manifest)
archive=PUB/'control-check-originals.tar.xz'
with tarfile.open(archive,'w:xz',format=tarfile.PAX_FORMAT) as tar:
    for row in rows:
        member=tarfile.TarInfo(row['path']);member.mode=stat.S_IMODE(row['original_identity'][2])
        member.uid=member.gid=member.mtime=0
        if row['kind']=='regular':
            data=regular[row['path']];member.size=len(data);tar.addfile(member,io.BytesIO(data))
        elif row['kind']=='directory':member.type=tarfile.DIRTYPE;tar.addfile(member)
        elif row['kind']=='symlink':member.type=tarfile.SYMTYPE;member.linkname=row['target'];tar.addfile(member)
        else:member.type=tarfile.FIFOTYPE;tar.addfile(member)
    member=tarfile.TarInfo('STATIC-ORIGINALS-MANIFEST.json');member.mode=0o400;member.size=len(manifest_raw)
    tar.addfile(member,io.BytesIO(manifest_raw))
with tarfile.open(archive,'r:xz') as tar:
    members=tar.getmembers();assert len(members)==len(rows)+1
    actual={m.name:m for m in members};assert len(actual)==len(members)
    for row in rows:
        item=actual[row['path']];assert item.mode==stat.S_IMODE(row['original_identity'][2])
        assert item.uid==item.gid==item.mtime==0
        if row['kind']=='regular':assert item.isfile() and tar.extractfile(item).read()==regular[row['path']]
        elif row['kind']=='directory':assert item.isdir()
        elif row['kind']=='symlink':assert item.issym() and item.linkname==row['target']
        else:assert item.isfifo()
    assert tar.extractfile(actual['STATIC-ORIGINALS-MANIFEST.json']).read()==manifest_raw
(PUB/'STATIC-ORIGINALS-MANIFEST.json').write_bytes(manifest_raw)
check=json.loads((ROOT/'static-checks-r1/REPORT.json').read_bytes())
transport=json.loads((ROOT/'transport-checks-r1/REPORT.json').read_bytes())
assert check['status']=='FINITE_CONTROL_CHECKS_PASS_NOT_PRODUCT_OR_INSTALLATION' and len(check['checks'])==107
assert transport['status']=='NINE_SYNTHETIC_TRANSPORT_CONTROLS_PASS_NOT_PRODUCT' and len(transport['checks'])==9
doc_delta={}
for name,expected in check['source_pins'].items():
    current=(OUT/name).read_bytes()
    if name=='installed_cases.py' and pin(current)!=expected:
        prior=(ROOT/'static-originals-r1/installed-cases-before-doc-clarification.py').read_bytes()
        assert pin(prior)==expected
        a,b=ast.parse(prior),ast.parse(current)
        assert isinstance(a.body[0],ast.Expr) and isinstance(b.body[0],ast.Expr)
        assert isinstance(a.body[0].value,ast.Constant) and isinstance(b.body[0].value,ast.Constant)
        a.body[0]=b.body[0]
        assert ast.dump(a,include_attributes=False)==ast.dump(b,include_attributes=False)
        doc_delta={'file':name,'prior_tested_raw':expected,'current_raw':pin(current),
            'delta':'Only module documentation clarifies retained Python reader and hosted OS/Path/context scope; all remaining AST is identical.',
            'new_native_or_IO_execution_claimed':False}
    else:assert pin(current)==expected
assert transport['decoder']==pin((ROOT/'decode_small.py').read_bytes())
assert transport['targets']==pin((OUT/'diagnostic-targets.json').read_bytes())
# The protocol does not depend on the changed source-doc hash in this policy.
# Its original exact policy remains preserved with the synthetic raw stream.
references={p.name:pin(p.read_bytes()) for p in sorted((ROOT/'references').iterdir()) if p.is_file()}
functions={}
for name in ('guardian.py','process_owner_impl.py','source_common.py'):
    assert (OUT/name).read_bytes()==(ROOT/'references'/name).read_bytes()
    functions[name]='exact entire original bytes'
(PUB/'STATIC-DERIVATION.json').write_bytes(wire({'schema':'hepta.hia.bounded-read-capsule-derivation.v1',
    'references':references,'unchanged_whole_files':functions,
    'local_control_checks':pin((ROOT/'static-checks-r1/REPORT.json').read_bytes()),
    'local_transport_checks':pin((ROOT/'transport-checks-r1/REPORT.json').read_bytes()),
    'post_check_doc_only_delta':doc_delta,
    'actual_archive_readback':{'files':len(rows),'regular_files':len(regular),
        'regular_bytes':sum(map(len,regular.values())),'archive':pin(archive.read_bytes())},
    'actions_driver_and_product_have_not_executed':True,
    'finite_local_control_functions_executed':True,
    'old_success_not_inherited':True,'static_failures_preserved_in_archive':True}))
files={}
for p in sorted(OUT.iterdir()):
    if p.is_file():files[p.name]=p.read_bytes()
for name in ('DESIGN.json','FROZEN-CONTROLS.json','workflow.template.yml','decode_small.py',
             'check_controls.py','check_small_transport.py','build_install_controls.py','derive_base_controls.py',
             'derive_action_controls.py','freeze_layout.py','build_publication.py'):
    files[name]=(ROOT/name).read_bytes()
files['local-control-checks.json']=(ROOT/'static-checks-r1/REPORT.json').read_bytes()
files['local-transport-checks.json']=(ROOT/'transport-checks-r1/REPORT.json').read_bytes()
for p in sorted(PUB.iterdir()):
    if p.is_file():files[p.name]=p.read_bytes()
payload=PUB/'files';payload.mkdir()
for name,raw in files.items():(payload/name).write_bytes(raw)
plan={'prefix':PREFIX,'base_commit':'ba714f34b8dcb248c779bb5fc0b9538d9151c685',
      'base_tree':'3489d2047956c1481b2e0593e2fbd32cf273cc70','files':[
          {'path':PREFIX+'/'+name,'local_path':str(payload/name),'mode':'100644',**pin(raw)} for name,raw in sorted(files.items())],
      'workflow_path':'.github/workflows/hia-bounded-read-v80-native-installed.yml',
      'trigger_branch':'codex/hia-bounded-read-v80-native-installed-r1-run-20261112-e26e',
      'dispatch_authorized_by_this_plan':False}
(PUB/'PUBLICATION-PLAN.json').write_bytes(wire(plan))
print(json.dumps({'files':len(files),'bytes':sum(map(len,files.values())),
    'archive':pin(archive.read_bytes()),'policy':policy,'native_executed':False}))
