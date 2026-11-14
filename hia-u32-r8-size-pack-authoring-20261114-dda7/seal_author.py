"""Lossless author/input capsule and readback; no product execution."""
from pathlib import Path, PurePosixPath
import base64
import hashlib
import json
import os
import stat
import zlib

ROOT=Path(__file__).resolve().parent
OUTPUTS={'AUTHOR-CAPSULE.zlib.json','AUTHOR-FILE-MANIFEST.json','CAPSULE-READBACK.json',
         'HANDOFF.json','MOUNT-RECIPE.json'}

def pin(raw,mode=None):
    value={'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
           'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}
    if mode is not None:value.update(mode=mode,git_mode='100755' if mode&0o111 else '100644')
    return value

def capture(path):
    before=path.lstat()
    assert stat.S_ISREG(before.st_mode)
    raw=path.read_bytes();after=path.lstat()
    keys=('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_nlink')
    assert tuple(getattr(before,k) for k in keys)==tuple(getattr(after,k) for k in keys)
    return raw,stat.S_IMODE(before.st_mode),{k:getattr(after,k) for k in keys}

def write(name,value):
    raw=(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
    path=ROOT/name
    with path.open('xb') as stream:stream.write(raw)
    os.chmod(path,0o644)
    assert capture(path)[0]==raw
    return pin(raw,0o644)

def main():
    assert not (ROOT/'evidence').exists(), 'author package must precede all product execution'
    assert not (ROOT/'AUTHOR-CAPSULE.zlib.json').exists()
    files=[];stamps={}
    for path in sorted(ROOT.rglob('*')):
        if path.is_dir():
            assert not path.is_symlink()
            continue
        name=path.relative_to(ROOT).as_posix()
        assert name not in OUTPUTS and not name.startswith('publication/'), 'unexpected existing derived output'
        raw,mode,stamp=capture(path)
        files.append({'path':name,'identity':pin(raw,mode),'data_base64':base64.b64encode(raw).decode()})
        stamps[name]=stamp
    body={'schema':'hia.u32-r8.author-and-fixed-input-capsule.v1','state':'AUTHOR_ONLY_NOT_EXECUTED',
          'root':str(ROOT),'files':files,'product_executions':0,'new_CI':0}
    decoded=json.dumps(body,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
    compressed=zlib.compress(decoded,9)
    capsule={'schema':'hia.lossless-author-capsule.zlib-base64.v1','encoding':'zlib+base64',
        'decoded':pin(decoded),'compressed':pin(compressed),'data':base64.b64encode(compressed).decode()}
    capsule_pin=write('AUTHOR-CAPSULE.zlib.json',capsule)
    actual=json.loads(zlib.decompress(base64.b64decode(capsule['data'],validate=True)))
    names=set()
    for row in actual['files']:
        path=PurePosixPath(row['path'])
        assert not path.is_absolute() and '..' not in path.parts and str(path)==row['path'] and row['path'] not in names
        names.add(row['path'])
        raw=base64.b64decode(row['data_base64'],validate=True)
        local,mode,stamp=capture(ROOT/row['path'])
        assert raw==local and pin(raw,mode)==row['identity'] and stamp==stamps[row['path']]
    manifest={'schema':'hia.u32-r8.complete-author-file-manifest.v1','root':str(ROOT),
        'files':[{k:v for k,v in row.items() if k!='data_base64'} for row in files],
        'count':len(files),'logical_bytes':sum(row['identity']['bytes'] for row in files),
        'scope':'Complete pre-execution author directory including 36 fixed input copies and unexecuted draft histories',
        'excludes':sorted(OUTPUTS)+['future publication/ immutable Git transport receipts'],
        'product_executions':0,'source_tree_copied':False,'original_ZIP_copied':False}
    manifest_pin=write('AUTHOR-FILE-MANIFEST.json',manifest)
    proof={'status':'PASS_LOSSLESS_AUTHOR_CAPSULE_READBACK_ONLY','files':len(files),
        'logical_bytes':manifest['logical_bytes'],'capsule':capsule_pin,'decoded':pin(decoded),
        'all_full_bytes_modes_and_current_seven_stats_equal':True,'source_trees_scanned':0,
        'product_executions':0,'new_CI':0,'manifest':manifest_pin}
    proof_pin=write('CAPSULE-READBACK.json',proof)
    selected=('run_size_pack.py','size_support.py','retained_pack_contract.py','retained_buffer_observer.py',
              'retained_buffer_child.py','EXECUTION-PLAN.json','COMMAND-INTENT.json','CONTRACT.md',
              'PROJECTION.json','RETAINED-SUPPORT.json','INPUTS.json','STATIC-READBACK.json',
              'prepare_author.py','finalize_author.py','seal_author.py',
              'AUTHOR-CAPSULE.zlib.json','AUTHOR-FILE-MANIFEST.json','CAPSULE-READBACK.json')
    leaves=[]
    for name in selected:
        raw,mode,_=capture(ROOT/name)
        leaves.append({'path':name,'local_path':str(ROOT/name),**pin(raw,mode)})
    handoff={'schema':'hia.u32-r8.author-handoff.v1','state':'FROZEN_AUTHOR_ONLY_NOT_EXECUTED',
        'leaves':leaves,'leaf_count':len(leaves),'plan':pin(capture(ROOT/'EXECUTION-PLAN.json')[0]),
        'complete_author_capsule':capsule_pin,'capsule_readback':proof_pin,
        'entry20_predecessor_independent_proof':'2d9f44985e60f221919d12b9b6991128cd3f0694',
        'product_executions':0,'new_CI':0,'immutable_publication_only':True,
        'unique_product_attempt_requires_separate_Root_review':True}
    handoff_pin=write('HANDOFF.json',handoff)
    print(json.dumps({'author_files':len(files),'logical_bytes':manifest['logical_bytes'],
        'capsule':capsule_pin,'handoff':handoff_pin,'leaf_count':len(leaves),'products':0},sort_keys=True))

if __name__=='__main__':main()
