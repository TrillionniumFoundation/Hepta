"""Restore the complete Source22 safe-capture evidence from the mounted UTF8 fragments."""
from pathlib import Path, PurePosixPath
import argparse, base64, gzip, hashlib, io, json, os, stat, tarfile
def pin(raw):
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}
def main():
    p=argparse.ArgumentParser();p.add_argument('mounted');p.add_argument('output');a=p.parse_args()
    mounted=Path(a.mounted);out=Path(a.output);assert not out.exists()
    index=json.loads((mounted/'RAW-INDEX.json').read_bytes());chunks=[];offset=0
    for row in index['parts']:
        encoded=(mounted/row['name']).read_bytes();assert pin(encoded)=={k:row[k] for k in pin(encoded)}
        assert row['offset']==offset and b'\n' not in encoded
        raw=base64.b64decode(encoded,validate=True);assert pin(raw)==row['decoded']
        chunks.append(raw);offset+=len(raw)
    compressed=b''.join(chunks);assert pin(compressed)==index['archive']
    raw=gzip.decompress(compressed);assert pin(raw)==index['tar']
    out.mkdir(mode=0o700);seen={};dirs={}
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:') as tar:
        for member in tar.getmembers():
            name=member.name;parts=PurePosixPath(name).parts
            assert parts and not name.startswith('/') and all(x not in ('','.','..') for x in parts)
            target=out.joinpath(*parts)
            if member.isdir():
                assert name in index['directories'] and name not in dirs and member.mode==index['directories'][name]
                target.mkdir(parents=False);os.chmod(target,member.mode);dirs[name]=member.mode
            else:
                assert member.isfile() and name in index['files'] and name not in seen
                data=tar.extractfile(member).read();row={**pin(data),'mode':f'{stat.S_IFREG|member.mode:06o}'}
                assert row==index['files'][name]
                with target.open('xb') as stream:stream.write(data)
                os.chmod(target,member.mode)
                assert target.read_bytes()==data and stat.S_IMODE(target.stat().st_mode)==member.mode
                seen[name]=row
    assert seen==index['files'] and dirs==index['directories']
    print(json.dumps({'status':'FULL_EVIDENCE_RESTORED','files':len(seen),'directories':len(dirs),'logical_bytes':index['logical_bytes'],'source_base_self_contained':False}))
if __name__=='__main__':main()
