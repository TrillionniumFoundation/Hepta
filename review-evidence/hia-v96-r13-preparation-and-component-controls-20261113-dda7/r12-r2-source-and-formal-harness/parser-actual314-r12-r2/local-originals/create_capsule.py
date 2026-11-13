"""Lossless evidence custody only; never import or execute product code."""
from __future__ import annotations
import base64
from collections import Counter
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import tarfile
import time
import zipfile

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT.parent / 'v94-cli-parser-context-r11-r2'
ARCHIVE_REL = 'graph-probe-r2/ORIGINAL-ARTIFACT.zip'
TOOL_MEMBER = 'cpython3144-tool.tar.gz'
PATTERNS = [re.compile(rb'gh[pousr]_[A-Za-z0-9]{30,}'),
            re.compile(rb'github_pat_[A-Za-z0-9_]{50,}'),
            re.compile(rb'Authorization[\x20\t"\x27:=]+Bearer[\x20\t]+[A-Za-z0-9_.-]{25,}')]


def encode(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + '\n').encode()


def pin(raw):
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
            'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}


def stream_pin(stream, size):
    sha=hashlib.sha256();git=hashlib.sha1(b'blob '+str(size).encode()+b'\0');count=0
    while True:
        body=stream.read(1024*1024)
        if not body:break
        count+=len(body);sha.update(body);git.update(body)
    assert count==size,(count,size)
    return {'bytes':count,'sha256':sha.hexdigest(),'git_blob':git.hexdigest()}


def safe(name):
    assert not name.startswith('/') and all(p not in ('','.','..') for p in name.split('/')),name
    return name


def inventory():
    rows=[]
    root_stat=SOURCE.lstat()
    directories=[{'path':'.','mode':stat.S_IMODE(root_stat.st_mode),'mtime_ns':root_stat.st_mtime_ns}]
    for directory,dirs,files in os.walk(SOURCE,followlinks=False):
        directory=Path(directory)
        for name in list(dirs):
            path=directory/name;s=path.lstat();relative=safe(path.relative_to(SOURCE).as_posix())
            if stat.S_ISLNK(s.st_mode):
                dirs.remove(name);files.append(name)
            else:
                assert stat.S_ISDIR(s.st_mode)
                directories.append({'path':relative,'mode':stat.S_IMODE(s.st_mode),'mtime_ns':s.st_mtime_ns})
        for name in files:
            path=directory/name;s=path.lstat();relative=safe(path.relative_to(SOURCE).as_posix())
            row={'path':relative,'mode':stat.S_IMODE(s.st_mode),'mtime_ns':s.st_mtime_ns}
            if stat.S_ISLNK(s.st_mode):
                raw=os.fsencode(os.readlink(path));row.update(kind='symlink',target_base64=base64.b64encode(raw).decode(),**pin(raw))
            else:
                assert stat.S_ISREG(s.st_mode),('unsupported special original',relative)
                raw=path.read_bytes();end=path.lstat()
                assert (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_mode)==(end.st_dev,end.st_ino,end.st_size,end.st_mtime_ns,end.st_mode),relative
                for pattern in PATTERNS:
                    assert pattern.search(raw) is None,('credential-shaped bytes require review before publishing',relative)
                row.update(kind='regular',**pin(raw))
            rows.append(row)
    return sorted(rows,key=lambda r:r['path']),sorted(directories,key=lambda r:r['path'])


def archive_references(rows):
    by_path={row['path']:row for row in rows}
    original=by_path[ARCHIVE_REL]
    assert original['bytes']==39213243 and original['sha256']=='0d5d5ec2672ab066ba1e79ab93d61c206757ebe14ab8b41d26a9b92750c03aad'
    references={};zip_members=[];tar_members=[]
    with zipfile.ZipFile(SOURCE/ARCHIVE_REL) as archive:
        infos=archive.infolist();assert len({i.filename for i in infos})==len(infos)
        for info in infos:
            assert not info.is_dir();safe(info.filename)
            with archive.open(info) as stream:
                observed=stream_pin(stream,info.file_size)
            zip_members.append({'member':info.filename,'crc32':f'{info.CRC:08x}',**observed})
            local='graph-probe-r2/raw/'+info.filename
            if local in by_path:
                assert all(by_path[local][k]==observed[k] for k in observed),local
                references[local]={'kind':'zip_member','archive_path':ARCHIVE_REL,'member':info.filename}
        with archive.open(TOOL_MEMBER) as stream,gzip.GzipFile(fileobj=stream,mode='rb') as gz,tarfile.open(fileobj=gz,mode='r|') as tar:
            seen=set()
            for info in tar:
                name=safe(info.name)
                assert name not in seen;seen.add(name)
                assert info.isfile() and not info.issym() and not info.islnk()
                local='graph-probe-r2/interpreter/'+name
                assert local in by_path,local
                observed=stream_pin(tar.extractfile(info),info.size)
                assert all(by_path[local][k]==observed[k] for k in observed),local
                assert by_path[local]['mode']==info.mode,local
                references[local]={'kind':'tar_gzip_member_inside_zip','archive_path':ARCHIVE_REL,
                    'zip_member':TOOL_MEMBER,'tar_member':name}
                tar_members.append({'member':name,'mode':info.mode,**observed})
            assert len(seen)==2496
            while gz.read(1024*1024):pass
        assert set(name for name in by_path if name.startswith('graph-probe-r2/interpreter/'))=={
            name for name in references if name.startswith('graph-probe-r2/interpreter/')}
    return references,{'archive':{k:original[k] for k in ('path','bytes','sha256','git_blob','mode')},
        'zip_members':zip_members,'tool_tar_members':tar_members,'complete_outer_zip_crc_pass':True,
        'complete_tool_tar_stream_hashes_and_modes_match':True}


def main():
    assert not (ROOT/'COMPLETE-ORIGINALS.tar.gz').exists()
    started=time.time_ns();rows,dirs=inventory()
    references,archive_proof=archive_references(rows)
    (ROOT/'TOOL-ARCHIVE-REFERENCE-PROOF.json').write_bytes(encode(archive_proof))
    pool={}
    for row in rows:
        if row['kind']=='symlink':continue
        name=row['path']
        if name in references:
            row['storage']=references[name]
            continue
        sha=row['sha256']
        if sha in pool:
            assert all(pool[sha][k]==row[k] for k in ('bytes','sha256','git_blob'))
        else:
            pool[sha]={k:row[k] for k in ('bytes','sha256','git_blob')}
            pool[sha]['first_original_path']=name
        row['storage']={'kind':'content_pool','member':'pool/'+sha}
    manifest={'schema':'hepta.cli-parser-repair-complete-original-custody.v1',
        'scope':'ALL_LOCAL_REPAIR_ORIGINALS_INCLUDING_FAILURES_NOT_QUALIFICATION',
        'source_root':str(SOURCE),'source_files_omitted':0,'regular_originals':sum(r['kind']=='regular' for r in rows),
        'symlink_originals':sum(r['kind']=='symlink' for r in rows),'original_regular_bytes':sum(r['bytes'] for r in rows if r['kind']=='regular'),
        'directories':dirs,'files':rows,'pool':pool,'archive_reference_proof':pin(encode(archive_proof)),
        'archive_references_require_only_included_original_zip':True,
        'originals_preserved_in_place':True,'ordinary_metadata_not_a_product_test':True,
        'local_original43_packaging_only_python312_exception_retained':True,
        'local_build_r4_and_original43_r2_overlap_retained_no_performance_claim':True,
        'all_prior_failures_retained':True,'whole_native':False,'cold_qualification':False}
    manifest_raw=encode(manifest);(ROOT/'MANIFEST.json').write_bytes(manifest_raw)
    archive_path=ROOT/'COMPLETE-ORIGINALS.tar.gz'
    with archive_path.open('xb') as target,gzip.GzipFile(filename='',mode='wb',fileobj=target,compresslevel=1,mtime=0) as gz,tarfile.open(fileobj=gz,mode='w|',format=tarfile.PAX_FORMAT) as tar:
        info=tarfile.TarInfo('MANIFEST.json');info.size=len(manifest_raw);info.mode=0o644;info.mtime=0;tar.addfile(info,io.BytesIO(manifest_raw))
        for sha,record in sorted(pool.items()):
            info=tarfile.TarInfo('pool/'+sha);info.size=record['bytes'];info.mode=0o644;info.mtime=0
            with (SOURCE/record['first_original_path']).open('rb') as stream:tar.addfile(info,stream)
    checked=[]
    with gzip.open(archive_path,'rb') as gz,tarfile.open(fileobj=gz,mode='r|') as tar:
        for info in tar:
            assert info.isfile() and info.mode==0o644
            if info.name=='MANIFEST.json':
                assert tar.extractfile(info).read()==manifest_raw;checked.append(info.name);continue
            assert info.name.startswith('pool/') and info.name not in checked
            sha=info.name.split('/',1)[1];assert sha in pool
            observed=stream_pin(tar.extractfile(info),info.size)
            assert all(observed[k]==pool[sha][k] for k in observed)
            checked.append(info.name)
        while gz.read(1024*1024):pass
    assert len(checked)==len(pool)+1
    after_rows,after_dirs=inventory()
    assert [{k:v for k,v in r.items() if k!='storage'} for r in rows]==after_rows
    assert dirs==after_dirs
    with archive_path.open('rb') as stream:archive_pin=stream_pin(stream,archive_path.stat().st_size)
    result={'schema':'hepta.cli-parser-repair-custody-readback.v1','status':'COMPLETE_LOSSLESS_READBACK_PASS',
        'manifest':pin(manifest_raw),'archive':archive_pin,'logical_files':len(rows),
        'regular_originals':manifest['regular_originals'],'symlink_originals':manifest['symlink_originals'],
        'directory_originals':len(dirs),'logical_regular_bytes':manifest['original_regular_bytes'],
        'content_pool_records':len(pool),'content_pool_bytes':sum(r['bytes'] for r in pool.values()),
        'archive_reference_records':len(references),'all_archive_references_byte_and_mode_verified':True,
        'tar_members_read_back':len(checked),'full_gzip_crc_readback':True,
        'all_original_paths_bytes_modes_targets_mtimes_unchanged':True,
        'product_execution_count':0,'wall_ns':time.time_ns()-started,'whole_native':False}
    (ROOT/'READBACK.json').write_bytes(encode(result))
    print(json.dumps(result,indent=2,sort_keys=True))


if __name__=='__main__':main()
