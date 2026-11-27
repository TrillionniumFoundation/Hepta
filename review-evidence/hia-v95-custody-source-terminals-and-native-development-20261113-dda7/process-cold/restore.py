"""Restore this exact logical evidence archive; no product imports or execution.

restore.py TRANSPORT.json UTF8_WRAPPER_ROOT NEW_TARGET
The immutable source delta requires the separately named fixed Root baseline.
"""
from pathlib import Path, PurePosixPath
import base64
import gzip
import hashlib
import json
import os
import stat
import sys
import tarfile
import tempfile


def identity(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
    'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}
def verify(raw,row):assert identity(raw)=={key:row[key] for key in ('bytes','sha256','git_blob')}
def safe(name):
    p=PurePosixPath(name)
    assert not p.is_absolute() and p.parts and all(x not in ('','..','.') for x in p.parts)


def main():
    meta=json.loads(Path(sys.argv[1]).read_bytes());wrappers=Path(sys.argv[2]);target=Path(sys.argv[3])
    assert not target.exists()
    with tempfile.TemporaryDirectory(prefix='hia-process-custody-',dir=target.parent) as scratch:
        scratch=Path(scratch);archive=scratch/'COMPLETE.tar.gz';offset=0
        with archive.open('xb') as stream:
            for row in meta['chunks']:
                raw=(wrappers/row['file']).read_bytes();verify(raw,row)
                decoded=base64.b64decode(raw,validate=True)
                assert base64.b64encode(decoded)==raw and b'\n' not in raw and b'\r' not in raw
                assert row['offset']==offset and len(decoded)==row['decoded_bytes']
                assert hashlib.sha256(decoded).hexdigest()==row['decoded_sha256']
                assert identity(decoded)['git_blob']==row['decoded_computed_git_blob']
                stream.write(decoded);offset+=len(decoded)
        verify(archive.read_bytes(),meta['archive'])
        with gzip.open(archive,'rb') as stream:
            while stream.read(1048576):pass
        seen=set();cas={};manifest=None
        with tarfile.open(archive,'r:gz') as tar:
            for member in tar:
                safe(member.name)
                assert member.isfile() and member.mode==0o644 and member.name not in seen
                seen.add(member.name);raw=tar.extractfile(member).read()
                if member.name=='MANIFEST.json':verify(raw,meta['manifest']);manifest=json.loads(raw)
                else:
                    assert member.name.startswith('cas/') and len(member.name)==68
                    assert hashlib.sha256(raw).hexdigest()==member.name[4:]
                    cas[member.name]=raw
        assert manifest is not None and len(seen)==meta['tar_member_count']
        assert seen=={'MANIFEST.json'}|{row['cas'] for row in manifest['logical_files'].values()}
        assert len(manifest['logical_files'])==meta['logical_count']
        target.mkdir()
        for name in sorted(manifest['directories'],key=lambda x:(len(PurePosixPath(x).parts),x)):
            safe(name);(target/name).mkdir(parents=True,exist_ok=True)
        for name,row in manifest['logical_files'].items():
            safe(name);raw=cas[row['cas']];verify(raw,row);path=target/name
            path.parent.mkdir(parents=True,exist_ok=True)
            if row['kind']=='file':
                with path.open('xb') as out:out.write(raw)
                os.chmod(path,int(row['mode'],8));back=path.read_bytes()
                assert stat.S_ISREG(path.lstat().st_mode)
            elif row['kind']=='symlink':
                os.symlink(os.fsdecode(raw),path);back=os.fsencode(os.readlink(path))
            else:raise AssertionError(row['kind'])
            verify(back,row);assert stat.S_IMODE(path.lstat().st_mode)==int(row['mode'],8)
        for name,row in sorted(manifest['directories'].items(),reverse=True):
            os.chmod(target/name,int(row['mode'],8))
            assert stat.S_ISDIR((target/name).lstat().st_mode)
            assert stat.S_IMODE((target/name).lstat().st_mode)==int(row['mode'],8)
        print(json.dumps({'status':'RESTORED_ALL_LOGICAL_ORIGINALS','logical_count':meta['logical_count'],
            'logical_bytes':meta['logical_bytes'],'tar_members':len(seen),
            'all_bytes_sha_git_modes_verified':True,'complete_gzip_crc_isize':True,
            'archive':meta['archive'],'matching_cold':False,'whole_native':False},sort_keys=True))


if __name__=='__main__':main()
