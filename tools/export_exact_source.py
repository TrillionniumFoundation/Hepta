"""Export the exact published repository bytes without executing project code."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import stat
import subprocess
import zipfile

HEAD='f8d9680a9b0ae609850c006480a7d1f68ea00979'
TREE='473404cdccc38a7e6bba633ef4a894877540d70e'
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--source',type=Path,required=True)
parser.add_argument('--output',type=Path,required=True)
args=parser.parse_args()
source=args.source.resolve(strict=True)
output=args.output.absolute()
assert not output.exists() and not output.is_relative_to(source)
output.mkdir(mode=0o700)
def git(*args):
    return subprocess.check_output(['git','--no-replace-objects','-C',str(source),*args],timeout=30)
assert git('rev-parse','HEAD').decode().strip()==HEAD
assert git('rev-parse','HEAD^{tree}').decode().strip()==TREE
assert git('status','--porcelain=v1','--untracked-files=all')==b''
tree_raw=git('ls-tree','-r','-z','HEAD')
(output/'git-ls-tree.raw').write_bytes(tree_raw)
records={}
def raw_file(path,mode):
    p=source/path
    if mode=='120000':
        assert p.is_symlink()
        return os.fsencode(os.readlink(p))
    assert p.is_file() and not p.is_symlink()
    assert bool(p.stat().st_mode&0o111)==(mode=='100755')
    return p.read_bytes()
archive=output/'SOURCE.zip'
with zipfile.ZipFile(archive,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as z:
    for line in tree_raw.split(b'\0'):
        if not line:continue
        header,name=line.split(b'\t',1)
        mode,kind,blob=header.decode().split()
        path=name.decode('utf-8','strict')
        assert kind=='blob' and mode in ('100644','100755','120000')
        assert path not in records and not Path(path).is_absolute() and '..' not in Path(path).parts
        raw=raw_file(path,mode)
        actual=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
        assert actual==blob,path
        records[path]={'mode':mode,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'git_blob':blob}
        info=zipfile.ZipInfo('source/'+path,date_time=(1980,1,1,0,0,0))
        info.create_system=3;info.external_attr=int(mode,8)<<16;info.compress_type=zipfile.ZIP_DEFLATED
        z.writestr(info,raw)
    assert len(records)==3120
    manifest={'schema':'hia.exact-published-source-export.v1','head':HEAD,'tree':TREE,
        'files':records,'project_code_executed':False,'tests_executed':False,
        'new_source_commit_created':False,'whole_native_qualification_claimed':False}
    manifest_raw=(json.dumps(manifest,sort_keys=True,indent=2)+'\n').encode()
    z.writestr('SOURCE-MANIFEST.json',manifest_raw)
(output/'SOURCE-MANIFEST.json').write_bytes(manifest_raw)
with zipfile.ZipFile(archive) as z:
    assert z.testzip() is None and len(z.infolist())==3121
    assert z.read('SOURCE-MANIFEST.json')==manifest_raw
    for path,row in records.items():
        raw=z.read('source/'+path)
        assert raw==raw_file(path,row['mode'])
        assert hashlib.sha256(raw).hexdigest()==row['sha256']
assert git('rev-parse','HEAD').decode().strip()==HEAD
assert git('rev-parse','HEAD^{tree}').decode().strip()==TREE
assert git('status','--porcelain=v1','--untracked-files=all')==b''
with archive.open('rb') as f:digest=hashlib.file_digest(f,'sha256').hexdigest()
report={'schema':'hia.exact-published-source-export-result.v1','status':'ALL_EXACT_PUBLISHED_SOURCE_BYTES_EXPORTED',
    'head':HEAD,'tree':TREE,'files':len(records),'archive_bytes':archive.stat().st_size,
    'archive_sha256':digest,'manifest_sha256':hashlib.sha256(manifest_raw).hexdigest(),
    'all_Git_blob_modes_and_SHA256_checked':True,'source_unchanged':True,
    'project_code_executed':False,'tests_executed':False,'new_qualification_claimed':False}
(output/'REPORT.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
print(json.dumps(report,sort_keys=True),flush=True)
