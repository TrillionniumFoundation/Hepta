#!/usr/bin/env python3
"""Validate Git-readback wrappers and optionally restore exact evidence files."""
from pathlib import Path, PurePosixPath
import argparse, base64, gzip, hashlib, io, json, re, stat, tarfile
MANIFEST_BLOB='c6ce44ee0ed527a775a00ef4ed019294f04b555f'


def check(ok, message):
    if not ok:
        raise ValueError(message)


def identity(raw):
    return {
        'bytes': len(raw),
        'sha256': hashlib.sha256(raw).hexdigest(),
        'blob': hashlib.sha1(b'blob ' + str(len(raw)).encode('ascii') + b'\0' + raw).hexdigest(),
    }


def verify_tar(archive, members, source_root=None):
    raw_tar = gzip.decompress(archive)  # fully checks gzip CRC and length
    expected = {item['path']: item for item in members}
    check(len(expected) == len(members), 'duplicate expected member')
    observed = []
    names = []
    with tarfile.open(fileobj=io.BytesIO(raw_tar), mode='r:') as tape:
        for member in tape:
            name = member.name
            pp = PurePosixPath(name)
            check(name == pp.as_posix() and not pp.is_absolute() and
                  '..' not in pp.parts and '.' not in pp.parts,
                  'unsafe archive path: ' + name)
            check(name in expected and name not in names, 'unexpected or duplicate archive member: ' + name)
            check(member.isfile() and not member.issym() and not member.islnk(),
                  'nonregular archive member: ' + name)
            check(member.uid == 0 and member.gid == 0 and
                  member.uname == '' and member.gname == '' and member.mtime == 0,
                  'nondeterministic tar metadata: ' + name)
            stream = tape.extractfile(member)
            check(stream is not None, 'missing member stream: ' + name)
            data = stream.read()
            row = {'path': name, 'mode': f'{member.mode:04o}', **identity(data)}
            check(row == expected[name], 'tar identity or mode mismatch: ' + name)
            check(member.size == len(data), 'tar size mismatch: ' + name)
            if source_root is not None:
                original = source_root / name
                original_stat = original.lstat()
                check(stat.S_ISREG(original_stat.st_mode), 'original is not regular: ' + name)
                check(stat.S_IMODE(original_stat.st_mode) == member.mode,
                      'original POSIX mode mismatch: ' + name)
                check(original.read_bytes() == data, 'original byte mismatch: ' + name)
            names.append(name)
            observed.append(row)
    check(names == sorted(expected), 'tar member set or order mismatch')
    return observed, identity(raw_tar)

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--manifest',type=Path,required=True)
    p.add_argument('--wrapper-root',type=Path,required=True)
    p.add_argument('--original-root',type=Path)
    p.add_argument('--restore',type=Path)
    p.add_argument('--report',type=Path,required=True)
    a=p.parse_args();raw=a.manifest.read_bytes()
    check(identity(raw)['blob']==MANIFEST_BLOB,'manifest identity differs')
    manifest=json.loads(raw);parts=[];receipts=[]
    for index,row in enumerate(manifest['chunks']):
        check(row['index']==index and row['offset']==sum(len(x) for x in parts),'chunk ordering differs')
        wire=(a.wrapper_root/row['file']).read_bytes()
        check(identity(wire)=={'bytes':row['utf8_bytes'],'sha256':row['utf8_sha256'],'blob':row['text_blob']},'wrapper identity differs')
        check(re.fullmatch(rb'[A-Za-z0-9+/]*={0,2}',wire) is not None,'noncanonical wrapper')
        decoded=base64.b64decode(wire,validate=True)
        check(base64.b64encode(decoded)==wire,'wrapper roundtrip differs')
        ri=identity(decoded)
        check(ri['bytes']==row['decoded_bytes'] and ri['sha256']==row['decoded_sha256'] and ri['blob']==row['decoded_blob_calculated_not_uploaded'],'decoded identity differs')
        receipts.append({'file':row['file'],'wrapper':identity(wire),'decoded':ri})
        parts.append(decoded)
    archive=b''.join(parts)
    check(identity(archive)==manifest['archive'],'assembled archive differs')
    observed,tar_id=verify_tar(archive,manifest['members'],a.original_root)
    check(tar_id==manifest['tar'],'tar identity differs')
    if a.restore is not None:
        a.restore.mkdir(parents=True,exist_ok=False)
        with tarfile.open(fileobj=io.BytesIO(gzip.decompress(archive)),mode='r:') as tar:
            for member in tar:
                dest=a.restore/member.name;dest.parent.mkdir(parents=True,exist_ok=True)
                with dest.open('xb') as out:out.write(tar.extractfile(member).read())
                dest.chmod(member.mode)
        verify_tar(archive,manifest['members'],a.restore)
    result={'schema':'hepta.backend-source-repair-complete-git-readback.v1','status':'PASS',
            'manifest':identity(raw),'archive':identity(archive),'tar':tar_id,'chunks':receipts,
            'complete_member_readback':observed,'members':len(observed),
            'member_bytes':sum(row['bytes'] for row in observed),
            'strict_wrapper_and_decoded_bytes_verified':True,'full_gzip_crc_and_all_member_bytes_modes_verified':True,
            'all_original_evidence_members_still_equal':True if a.original_root else None,
            'restore_created':str(a.restore) if a.restore else None,
            'product_executed':False,'product_refs_changed':False,'qualification':False,
            'self_contained_product_tree':False}
    with a.report.open('x') as out:json.dump(result,out,indent=2,sort_keys=True);out.write('\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ('chunks','complete_member_readback')},indent=2))

if __name__=='__main__':main()
