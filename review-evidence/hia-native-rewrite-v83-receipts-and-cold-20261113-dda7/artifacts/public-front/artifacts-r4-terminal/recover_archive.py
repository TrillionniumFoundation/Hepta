"""Reassemble the exact retained R4 terminal archive from verified Git text blobs."""
from pathlib import Path
import argparse,base64,hashlib,json,tarfile

def digest_file(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        while block:=f.read(1<<20):h.update(block)
    return h.hexdigest()

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--index',type=Path,required=True)
    ap.add_argument('--parts',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args()
    index=json.loads(args.index.read_bytes())
    if index['schema']!='hia.lossless-archive.complete-readback-index.v1' or index['complete'] is not True:
        raise ValueError('complete verified transport index required')
    out=args.output.absolute()
    position=0
    with out.open('xb') as f:
        for number,row in enumerate(index['parts']):
            if row['index']!=number or row['offset']!=position:
                raise ValueError('noncontiguous original archive parts')
            encoded=(args.parts/row['filename']).read_bytes()
            git=hashlib.sha1(b'blob '+str(len(encoded)).encode()+b'\0'+encoded).hexdigest()
            if len(encoded)!=row['encoded_bytes'] or hashlib.sha256(encoded).hexdigest()!=row['encoded_sha256'] or git!=row['git_blob']:
                raise ValueError('original text blob identity differs')
            raw=base64.b64decode(encoded,validate=True)
            if len(raw)!=row['raw_bytes'] or hashlib.sha256(raw).hexdigest()!=row['raw_sha256']:
                raise ValueError('decoded original archive slice differs')
            f.write(raw);position+=len(raw)
    if position!=index['archive']['bytes'] or digest_file(out)!=index['archive']['sha256']:
        raise ValueError('complete archive identity differs')
    observed={};manifest=None
    with tarfile.open(out,'r:xz') as archive:
        for member in archive:
            if not member.isfile() or member.name in observed or member.name.startswith('/') or '..' in Path(member.name).parts:
                raise ValueError('archive member inventory differs')
            stream=archive.extractfile(member)
            if member.name=='MANIFEST.json':
                if manifest is not None:raise ValueError('duplicate manifest')
                manifest_bytes=stream.read()
                if hashlib.sha256(manifest_bytes).hexdigest()!=index['manifest']['sha256']:
                    raise ValueError('original manifest identity differs')
                manifest=json.loads(manifest_bytes)
                continue
            h=hashlib.sha256();g=hashlib.sha1(b'blob '+str(member.size).encode()+b'\0');size=0
            while block:=stream.read(1<<20):h.update(block);g.update(block);size+=len(block)
            observed[member.name]={'bytes':size,'sha256':h.hexdigest(),'git_blob':g.hexdigest(),'mode':format(member.mode,'04o')}
    if manifest is None or observed!=manifest['files']:
        raise ValueError('complete original member bytes or modes differ')
    print(json.dumps({'status':'ARCHIVE_VERIFIED','bytes':position,'sha256':index['archive']['sha256'],
                      'original_members':len(observed),'business_executed':False},sort_keys=True))
if __name__=='__main__':main()
