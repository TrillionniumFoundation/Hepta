"""Deterministic lossless custody of the present frozen R1--R5 originals.

This does not reconstruct the three original R1 VM buffers that were never
written. The explicit gap remains in the manifest and every custody report.
No product is imported, compiled, tested, or executed here.
"""
from pathlib import Path, PurePosixPath
import gzip
import hashlib
import io
import json
import stat
import tarfile
import time

ROOT=Path(__file__).resolve().parent
SOURCE=Path('/workspace/scratch/dda74a4fae35/v98-native-file-render-r4')
OUT=ROOT/'attempt-r1'
SCOPES=('', 'successor-r2','successor-r3','successor-r4','successor-r5')

def identity(raw,mode=None):
    row={'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
         'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}
    if mode is not None:
        row.update(mode_bits=stat.S_IMODE(mode),git_mode='100755' if mode&0o111 else '100644')
    return row

def encoded(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()

def put(path,raw):
    with path.open('xb') as stream:stream.write(raw)

def selected_paths():
    selected=[]
    for scope in SCOPES:
        parent=SOURCE/scope
        for folder in ('evidence','authoring','freeze-r1','addendum-r1'):
            directory=parent/folder
            if not directory.exists():continue
            for path in directory.rglob('*'):
                if '__pycache__' in path.parts or path.suffix=='.pyc':continue
                if path.is_symlink():raise AssertionError(path)
                if path.is_file():selected.append(path)
        for name in ('BASE-READBACK.json','BEFORE-MANIFEST.json',
                     'source/tools/generate_hia_file_render_checker_v4.py',
                     'source/examples/hia_bootstrap/file_render_checker_v4.hepta'):
            path=parent/name
            if path.exists():selected.append(path)
    for path in (SOURCE/'checkpoint-r1').rglob('*'):
        if path.is_file() and '__pycache__' not in path.parts:selected.append(path)
    assert len(selected)==len(set(selected))
    return sorted(selected,key=lambda path:path.relative_to(SOURCE).as_posix())

def main():
    OUT.mkdir(exist_ok=False)
    start=time.monotonic_ns();files={};objects={};aliases={}
    original_paths=selected_paths()
    assert len(original_paths)==4588 and sum(p.stat().st_size for p in original_paths)==2275587257
    for path in original_paths:
        mode=path.lstat().st_mode;assert stat.S_ISREG(mode)
        name=path.relative_to(SOURCE).as_posix();raw=path.read_bytes()
        row=identity(raw,mode);files[name]=row;digest=row['sha256']
        if digest in objects:assert raw==objects[digest].read_bytes()
        else:objects[digest]=path
        aliases.setdefault(digest,[]).append(name)
    manifest={'schema':'hia.compact-render-R1-R5.present-originals-CAS.v1',
        'logical_files':len(files),'logical_bytes':sum(x['bytes'] for x in files.values()),
        'files':files,'base_source_tree':'0a59f35ad40399f44287ece9011d6323c4535ce3',
        'frozen_R5_source_tree':'7973dbb45bcbe42f342c0ba19ca747143c397288',
        'frozen_R5_source_capsule':'0c0f99940109dcfffe8029a8008e7994e0812701',
        'frozen_R5_addendum':'23613b922b93db45f7023f031e583a1beef763dc',
        'included':'All selected present R1--R5 evidence/authoring, complete two-source afterimages, base manifests, frozen capsule/ACKs and first failures. R6 is excluded.',
        'source_dependencies':'The remaining3121 product files are exactly the already-rooted v3 base tree; they are not redundantly copied into this evidence archive.',
        'known_missing_originals':[
            'R1 compact-vm-r1 third case edge-256-reversed-origin source/output/workspace failure buffers were not written because the observer then called an invalid report status. Later complete recaptures do not restore those first originals.',
            'R1 compact-generation-r1 first generated HIA bytes were overwritten before a machine execution; the exact generator and generated identity remain, but this archive does not claim an original byte file that is absent.'
        ],'all_historical_originals_retained':False,'all_selected_present_originals_included':True,
        'new_product_executions':0,'new_qualification':False}
    manifest_raw=encoded(manifest);put(OUT/'RAW-MANIFEST.json',manifest_raw)
    archive=OUT/'COMPLETE-PRESENT-RAW.tar.gz'
    with archive.open('xb') as target:
        with gzip.GzipFile(filename='',mode='wb',fileobj=target,compresslevel=1,mtime=0) as zipped:
            with tarfile.open(fileobj=zipped,mode='w|',format=tarfile.USTAR_FORMAT) as tar:
                item=tarfile.TarInfo('RAW-MANIFEST.json');item.size=len(manifest_raw);item.mode=0o644
                item.uid=item.gid=item.mtime=0;tar.addfile(item,io.BytesIO(manifest_raw))
                for digest,path in sorted(objects.items()):
                    raw=path.read_bytes();assert hashlib.sha256(raw).hexdigest()==digest
                    item=tarfile.TarInfo('objects/'+digest);item.size=len(raw);item.mode=0o644
                    item.uid=item.gid=item.mtime=0;tar.addfile(item,io.BytesIO(raw))
    restored=OUT/'restored';restored.mkdir(exist_ok=False);seen=set()
    with tarfile.open(archive,'r:gz') as tar:
        for item in tar:
            assert item.isreg() and item.uid==item.gid==item.mtime==0 and item.mode==0o644
            assert item.name not in seen;seen.add(item.name)
            raw=tar.extractfile(item).read();assert len(raw)==item.size
            if item.name=='RAW-MANIFEST.json':assert raw==manifest_raw;continue
            assert item.name.startswith('objects/')
            digest=item.name[len('objects/'):];assert digest in aliases and hashlib.sha256(raw).hexdigest()==digest
            for name in aliases[digest]:
                safe=PurePosixPath(name);assert not safe.is_absolute() and '..' not in safe.parts and str(safe)==name
                target=restored/name;target.parent.mkdir(parents=True,exist_ok=True)
                put(target,raw);target.chmod(files[name]['mode_bits'])
    assert seen=={'RAW-MANIFEST.json'}|{'objects/'+key for key in objects}
    assert {p.relative_to(restored).as_posix() for p in restored.rglob('*') if p.is_file()}==set(files)
    assert selected_paths()==original_paths
    for name,expected in files.items():
        for parent in (SOURCE,restored):
            path=parent/name;assert identity(path.read_bytes(),path.stat().st_mode)==expected
    raw=archive.read_bytes();assert raw[:10]==bytes.fromhex('1f8b08000000000004ff')
    report={'schema':'hia.compact-render-R1-R5-CAS-readback.v1','status':'PASS',
        'logical_files':len(files),'logical_bytes':manifest['logical_bytes'],
        'unique_objects':len(objects),'unique_bytes':sum(path.stat().st_size for path in objects.values()),
        'archive':identity(raw),'manifest':identity(manifest_raw),
        'all_archive_members_readback':True,'all_selected_paths_restored_bytes_mode_SHA_Git_equal':True,
        'all_original_paths_unchanged':True,'known_missing_originals':manifest['known_missing_originals'],
        'all_historical_originals_retained':False,'elapsed_ns':time.monotonic_ns()-start,
        'restore_directory':str(restored),'new_product_executions':0,'new_qualification':False,
        'archive_Git_persisted':False}
    put(OUT/'REPORT.json',encoded(report));print(json.dumps(report,indent=2),flush=True)

if __name__=='__main__':main()
