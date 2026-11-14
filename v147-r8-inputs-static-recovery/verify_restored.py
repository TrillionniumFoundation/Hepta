"""Read-only verifier of all 948 original references and 944 restored inputs.

This performs no binary/product/binder execution and writes no restored input.
The fixed new stats belong only to this data restoration, never to the lost paths.
"""
from pathlib import Path
import hashlib
import json
import os
import stat

ROOT=Path('/tmp/hia-r8-inputs-recovery-20261114-dda7')

def pin(raw):
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
        'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}

def seven(s):
    return [s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]

def main():
    raw=(ROOT/'RESTORED-MANIFEST.json').read_bytes()
    assert pin(raw)=={'bytes':2889661,
        'sha256':'c992c93e7cadc9b436d7c49d49a8b3dfdfd5fff2d010244e233155ebb8bed3ff',
        'git_blob':'9e2ce96c9b343994932e0e73fd707cf67530f36e'}
    manifest=json.loads(raw)
    raw=(ROOT/'metadata'/'ORIGINAL-MAPPING.json').read_bytes()
    assert pin(raw)=={'bytes':2637276,
        'sha256':'df525b5072508c228474694a6b63f6bbb447b9734a4bf740c7e7842963dfacd0',
        'git_blob':'826f11439e92311a51c0bb2bb8279424ea76160c'}
    mapping=json.loads(raw)['inputs']['rows']
    files=manifest['files']
    assert len(mapping)==len(manifest['references'])==948 and len(files)==944
    by_original={r['original_path']:r for r in files}
    assert len(by_original)==944
    ids={};total=0
    for ordinal,(original,reference) in enumerate(zip(mapping,manifest['references'])):
        assert reference['ordinal']==ordinal and reference['original']==original
        row=by_original[original['path']]
        assert reference['target']==row['target']
        assert row['required_identity']==original['identity']
        assert ordinal in row['reference_ordinals']
        path=ROOT/row['target']
        before=path.lstat()
        assert stat.S_ISREG(before.st_mode) and before.st_nlink==1
        assert seven(before)==row['current']['new_seven_stats']
        assert stat.S_IMODE(before.st_mode)==row['required_identity']['mode']
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as f:
            assert seven(os.fstat(f.fileno()))==seven(before)
            data=f.read()
            assert seven(os.fstat(f.fileno()))==seven(before)
        assert seven(path.lstat())==seven(before)
        p=pin(data)
        for k in p:assert p[k]==original['identity'][k]
        assert p==row['current']['identity']
        inode=(before.st_dev,before.st_ino)
        if inode in ids:assert ids[inode]==original['path']
        else:ids[inode]=original['path']
        total+=len(data)
    assert len(ids)==944 and total==717016014
    assert sum(r['required_identity']['bytes'] for r in files)==710690611
    expected={r['target'] for r in files}
    actual=set()
    for path in (ROOT/'inputs').rglob('*'):
        s=path.lstat()
        if stat.S_ISDIR(s.st_mode):continue
        assert stat.S_ISREG(s.st_mode)
        actual.add(str(path.relative_to(ROOT)))
    assert expected==actual
    for row in files:
        assert seven((ROOT/row['target']).lstat())==row['current']['new_seven_stats']
    print(json.dumps({'status':'PASS_READ_ONLY_948_REFERENCES_944_INPUTS',
        'reference_bytes':total,'unique_bytes':710690611,'new_stat_identity_only':True,
        'products':0,'restored_binary_executions':0},sort_keys=True))

if __name__=='__main__':main()
