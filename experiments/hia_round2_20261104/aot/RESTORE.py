#!/usr/bin/env python3
"""Restore exact retained AOT evidence bytes without executing them."""
import argparse,hashlib,json,lzma,pathlib,shutil,stat,tarfile,tempfile
def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda:f.read(1048576),b''):h.update(b)
    return h.hexdigest()
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=pathlib.Path,required=True)
    p.add_argument('--receipt',type=pathlib.Path)
    args=p.parse_args()
    here=pathlib.Path(__file__).resolve().parent
    manifest=json.loads((here/'MANIFEST.json').read_bytes())
    out=args.output.resolve()
    if out.exists():raise SystemExit('refusing existing output')
    out.mkdir(parents=True)
    expected={x['path']:x for x in manifest['members']}
    if len(expected)!=len(manifest['members']):raise SystemExit('duplicate manifest member')
    seen=set();total=0
    with tempfile.TemporaryFile() as compressed:
        archive_hash=hashlib.sha256();archive_bytes=0
        for part in manifest['archive']['parts']:
            src=here/part['name']
            if not src.is_file() or src.is_symlink():raise SystemExit('invalid archive part')
            if src.stat().st_size!=part['bytes'] or sha(src)!=part['sha256']:raise SystemExit('archive part changed')
            with src.open('rb') as f:
                for b in iter(lambda:f.read(1048576),b''):
                    compressed.write(b);archive_hash.update(b);archive_bytes+=len(b)
        if archive_bytes!=manifest['archive']['bytes'] or archive_hash.hexdigest()!=manifest['archive']['sha256']:
            raise SystemExit('concatenated archive differs')
        compressed.seek(0)
        with lzma.LZMAFile(compressed,'rb') as stream,tarfile.open(fileobj=stream,mode='r|') as tar:
            for member in tar:
                name=member.name
                path=pathlib.PurePosixPath(name)
                if name not in expected or name in seen or path.is_absolute() or '..' in path.parts or not member.isfile():
                    raise SystemExit('unexpected/duplicate/unsafe/nonregular member: '+name)
                item=expected[name]
                if member.size!=item['bytes']:raise SystemExit('member size differs')
                dest=out/path
                dest.parent.mkdir(parents=True,exist_ok=True)
                source=tar.extractfile(member)
                h=hashlib.sha256();size=0
                with dest.open('xb') as target:
                    for b in iter(lambda:source.read(1048576),b''):
                        target.write(b);h.update(b);size+=len(b)
                if size!=item['bytes'] or h.hexdigest()!=item['sha256']:raise SystemExit('member content differs: '+name)
                dest.chmod(item['mode'] & 0o777)
                seen.add(name);total+=size
    if seen!=set(expected):raise SystemExit('missing member')
    for directory in manifest['empty_directories']:
        path=pathlib.PurePosixPath(directory)
        if path.is_absolute() or '..' in path.parts:raise SystemExit('unsafe empty directory')
        (out/path).mkdir(parents=True,exist_ok=True)
    receipt={'schema':'hepta.hia.byte-sum.restore.v1','status':'verified','members':len(seen),
             'member_bytes':total,'archive_sha256':manifest['archive']['sha256'],
             'manifest_sha256':sha(here/'MANIFEST.json'),'output':str(out),
             'all_bytes_matched':True,'executed_native_or_model_code':False}
    if args.receipt:
        with args.receipt.open('x') as f:json.dump(receipt,f,sort_keys=True);f.write('\n')
    print(json.dumps(receipt,sort_keys=True))
if __name__=='__main__':main()
