#!/usr/bin/env python3
"""Reassemble retained original ZIP bytes without running archive contents."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat

def checked_payload(root, relative, expected_size, expected_sha):
    rel=PurePosixPath(relative)
    if rel.is_absolute() or '..' in rel.parts:
        raise ValueError('Unsafe payload path')
    fd=os.open(root/relative,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_NONBLOCK',0))
    with os.fdopen(fd,'rb') as source:
        s=os.fstat(source.fileno())
        if not stat.S_ISREG(s.st_mode) or s.st_size!=expected_size:
            raise ValueError('Payload is not a regular file with the required size')
        data=source.read(expected_size+1)
    if len(data)!=expected_size or hashlib.sha256(data).hexdigest()!=expected_sha:
        raise ValueError('Payload identity mismatch')
    return data

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--evidence-directory',type=Path,default=Path(__file__).resolve().parent)
    p.add_argument('--output-directory',type=Path,required=True)
    args=p.parse_args()
    rows=json.loads((args.evidence_directory/'recovered-archives.json').read_text())
    args.output_directory.mkdir(parents=False,exist_ok=False)
    restored=[]
    for row in rows:
        if row['storage_representation']=='whole-zip':
            data=checked_payload(args.evidence_directory,row['publication_path'],row['bytes'],row['sha256'])
        elif row['storage_representation']=='raw-byte-parts-v1':
            pieces=[];offset=0
            for index,part in enumerate(row['parts']):
                if part['part_index']!=index or part['offset']!=offset:
                    raise ValueError('Non-contiguous or out-of-order ZIP parts')
                chunk=checked_payload(args.evidence_directory,part['publication_path'],part['bytes'],part['sha256'])
                if hashlib.sha1(b'blob '+str(len(chunk)).encode()+b'\0'+chunk).hexdigest()!=part['git_blob_sha']:
                    raise ValueError('Part Git blob mismatch')
                pieces.append(chunk);offset+=len(chunk)
            data=b''.join(pieces)
        else:
            raise ValueError('Unknown storage representation')
        if len(data)!=row['bytes'] or hashlib.sha256(data).hexdigest()!=row['sha256']:
            raise ValueError('Reassembled ZIP identity mismatch')
        if 'sha256:'+row['sha256']!=row['official_digest']:
            raise ValueError('Official Actions digest mismatch')
        dest=args.output_directory/row['source_commit']/f"{row['artifact_id']}.zip"
        dest.parent.mkdir(exist_ok=True)
        with dest.open('xb') as output:output.write(data)
        restored.append({'artifact_id':row['artifact_id'],'bytes':len(data),'sha256':row['sha256']})
    print(json.dumps({'ok':True,'restored_zip_count':len(restored),'archives':restored},indent=2))

if __name__=='__main__':main()
