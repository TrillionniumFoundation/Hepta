"""Seal original diagnostic development files and exact dependency bytes."""
from hashlib import sha256
import io
import json
from pathlib import Path
import stat
import tarfile

ROOT=Path(__file__).resolve().parents[1]
BASE=ROOT.parent
ARCHIVE=BASE/'hia-core-diagnostics-native-r2-development.tar.xz'
assert not ARCHIVE.exists()
sources={}
for p in ROOT.rglob('*'):
    if p.is_file() and '__pycache__' not in p.parts and p.suffix!='.pyc':
        sources['project/'+str(p.relative_to(ROOT))]=p
pins=json.loads((ROOT/'development/integrated-bundle-r1.source-pins.json').read_bytes())
for path,row in pins.items():
    p=Path(path).resolve();raw=p.read_bytes()
    assert len(raw)==row['bytes'] and sha256(raw).hexdigest()==row['sha256']
    if not p.is_relative_to(ROOT):sources['dependencies/'+str(p.relative_to(BASE))]=p
bundle=json.loads((ROOT/'development/integrated-bundle-r1.json').read_bytes())
missing=[]
for row in bundle['components'].values():
    receipt=Path(row['receipt_path'])
    stem=receipt.name.removesuffix('.receipt.json')
    for suffix in ('.request.json','.input.bin','.stdout.log','.stderr.log'):
        p=receipt.with_name(stem+suffix).resolve()
        if not p.exists():missing.append(str(p));continue
        if not p.is_relative_to(ROOT):sources['dependencies/'+str(p.relative_to(BASE))]=p
compiler=BASE/'native-composite-core-final-recovery-next/dependencies/f50-B3.image.bin'
assert sha256(compiler.read_bytes()).hexdigest()==bundle['compiler_sha256']
sources['dependencies/'+str(compiler.relative_to(BASE))]=compiler
members=[]
with tarfile.open(ARCHIVE,'w:xz',preset=3) as tar:
    for name,p in sorted(sources.items()):
        raw=p.read_bytes();mode=stat.S_IMODE(p.stat().st_mode)
        info=tarfile.TarInfo(name);info.size=len(raw);info.mode=mode;info.mtime=0
        tar.addfile(info,io.BytesIO(raw))
        members.append({'name':name,'original':str(p),'bytes':len(raw),'sha256':sha256(raw).hexdigest(),'mode':mode})
byname={row['name']:row for row in members}
with tarfile.open(ARCHIVE,'r:xz') as tar:
    actual=tar.getmembers();assert len(actual)==len(members)
    for item in actual:
        row=byname[item.name];raw=tar.extractfile(item).read()
        assert item.isfile() and len(raw)==row['bytes'] and sha256(raw).hexdigest()==row['sha256'] and item.mode==row['mode']
        p=Path(row['original']);assert p.read_bytes()==raw and stat.S_IMODE(p.stat().st_mode)==row['mode']
index=ARCHIVE.with_suffix('.members.json')
index.write_text(json.dumps(members,indent=2,sort_keys=True)+'\n')
record={'scope':'COMPLETE_CORE_DIAGNOSTIC_ORIGINAL_DEVELOPMENT_FILES_NARRATIVE_CORRECTED_R2',
 'archive':str(ARCHIVE),'bytes':ARCHIVE.stat().st_size,'sha256':sha256(ARCHIVE.read_bytes()).hexdigest(),
 'members':len(members),'raw_bytes':sum(row['bytes'] for row in members),
 'members_index':str(index),'members_index_sha256':sha256(index.read_bytes()).hexdigest(),
 'all_original_and_tar_member_bytes_sha256_modes_read_back':True,
 'reused_optional_compile_sidecars_absent':missing,
 'own_all_compile_receipts_sources_images_tests_and_failures_included':True,
 'fixed_executor_or_whole_stack_qualification_claimed':False,'production_activation':False}
custody=ARCHIVE.with_suffix('.custody.json');custody.write_text(json.dumps(record,indent=2,sort_keys=True)+'\n')
print(json.dumps(record,sort_keys=True))
