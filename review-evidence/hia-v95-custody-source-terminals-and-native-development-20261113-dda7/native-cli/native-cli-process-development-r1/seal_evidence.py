from pathlib import Path
import base64
import gzip
import hashlib
import io
import json
import os
import stat
import tarfile
import time

ROOT = Path(__file__).resolve().parent
OUT = ROOT / 'custody'


def sha(raw): return hashlib.sha256(raw).hexdigest()
def git(raw): return hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
def encoded(value): return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()
def dump(path, value): path.write_bytes(encoded(value))


def main():
    started = time.monotonic()
    OUT.mkdir(exist_ok=False)
    objects = OUT / 'objects'; objects.mkdir()
    records, unique = {}, {}
    for subtree in ('authoring', 'evidence', 'handoff'):
        for path in sorted((ROOT / subtree).rglob('*')):
            if not path.is_file(): continue
            st = path.lstat(); assert stat.S_ISREG(st.st_mode)
            raw = path.read_bytes(); digest = sha(raw)
            records[path.relative_to(ROOT).as_posix()] = {'bytes': len(raw), 'sha256': digest,
                'git_blob': git(raw), 'mode': f'{stat.S_IMODE(st.st_mode):04o}'}
            if digest not in unique:
                os.link(path, objects / (digest + '.raw'))
                unique[digest] = {'bytes': len(raw), 'git_blob': git(raw)}
    manifest = {'schema': 'hia.logical-full-evidence-cas.v1',
        'scope': 'v90 independent native CLI process development, including every retained original failure',
        'source_packet': '4bd3ee6c5fb6758d7e4f8413179f6e0857da2d7a',
        'logical_files': records, 'objects': unique,
        'source_tree': 'f3101f9eddfe7cde699f5b9bf1b56e4ddf0e5bf1',
        'complete_source_recovery': 'base packet0e11 plus source packet4bd3; no duplicate full source export in this raw archive',
        'matching_cold': False, 'formal_314': False, 'whole': False}
    manifest_raw = encoded(manifest)
    (OUT / 'MANIFEST.json').write_bytes(manifest_raw)
    archive = OUT / 'EVIDENCE.tar.gz'
    with archive.open('xb') as stream, gzip.GzipFile(filename='', mode='wb', fileobj=stream, mtime=0, compresslevel=1) as gz:
        with tarfile.open(fileobj=gz, mode='w|', format=tarfile.PAX_FORMAT) as tar:
            info = tarfile.TarInfo('MANIFEST.json'); info.size=len(manifest_raw);info.mode=0o444;info.mtime=0
            tar.addfile(info,io.BytesIO(manifest_raw))
            for digest, metadata in sorted(unique.items()):
                path = objects / (digest + '.raw')
                raw = path.read_bytes(); assert len(raw)==metadata['bytes'] and sha(raw)==digest and git(raw)==metadata['git_blob']
                info = tarfile.TarInfo('objects/' + digest + '.raw');info.size=len(raw);info.mode=0o444;info.mtime=0
                tar.addfile(info,io.BytesIO(raw))
    readback={}; manifest_seen=False
    with tarfile.open(archive,'r:gz') as tar:
        for member in tar:
            assert member.isfile() and member.mode==0o444
            raw=tar.extractfile(member).read();assert len(raw)==member.size
            if member.name=='MANIFEST.json':
                assert not manifest_seen and raw==manifest_raw;manifest_seen=True;continue
            assert member.name.startswith('objects/') and member.name.endswith('.raw')
            digest=member.name[8:-4];assert digest in unique and digest not in readback
            assert sha(raw)==digest and len(raw)==unique[digest]['bytes'] and git(raw)==unique[digest]['git_blob']
            readback[digest]=len(raw)
    assert manifest_seen and set(readback)==set(unique)
    for name, record in records.items():
        path=ROOT/name;raw=path.read_bytes()
        assert len(raw)==record['bytes'] and sha(raw)==record['sha256'] and git(raw)==record['git_blob']
        assert f'{stat.S_IMODE(path.stat().st_mode):04o}'==record['mode']
    data=archive.read_bytes(); parts=OUT/'parts';parts.mkdir();rows=[]
    for index, offset in enumerate(range(0,len(data),524288)):
        raw=data[offset:offset+524288]
        part={'schema':'hia.archive-utf8-part.v1','archive_sha256':sha(data),
            'index':index,'offset':offset,'bytes':len(raw),'sha256':sha(raw),
            'encoding':'base64','data':base64.b64encode(raw).decode()}
        wrapper=encoded(part);name=f'part-{index:04}.json';(parts/name).write_bytes(wrapper)
        rows.append({'path':'parts/'+name,'index':index,'offset':offset,'bytes':len(raw),
            'sha256':sha(raw),'wrapper_bytes':len(wrapper),'wrapper_sha256':sha(wrapper),'git_blob':git(wrapper)})
    transport={'schema':'hia.archive-utf8-transport.v1','archive_bytes':len(data),'archive_sha256':sha(data),
        'manifest_bytes':len(manifest_raw),'manifest_sha256':sha(manifest_raw),'manifest_git_blob':git(manifest_raw),
        'parts':rows,'logical_files':len(records),'logical_bytes':sum(x['bytes'] for x in records.values()),
        'unique_objects':len(unique),'unique_bytes':sum(x['bytes'] for x in unique.values())}
    dump(OUT/'TRANSPORT.json',transport)
    dump(OUT/'LOCAL-READBACK.json',{'status':'PASS','archive_sha256':sha(data),
        'all_tar_members':len(unique)+1,'all_logical_files':len(records),'all_originals_unchanged':True,
        'full_tar_bytes_and_modes_readback':True,'wall_seconds':time.monotonic()-started,
        'matching_cold':False,'whole':False})
    print(json.dumps({k:v for k,v in transport.items() if k!='parts'},indent=2))
    print(json.dumps({'parts':len(rows),'wall_seconds':time.monotonic()-started}))


if __name__=='__main__':main()
