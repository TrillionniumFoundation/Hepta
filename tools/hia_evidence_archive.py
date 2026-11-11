"""Lossless packing of newly owned, completed qualification stages.

Host tooling, not a native replacement or a correctness receipt. Never operates
on an existing/pinned evidence directory without its fresh-stage owner token.
All original files are retained in a verified ZIP before raw files are retired.
"""
from __future__ import annotations
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import tempfile
import zipfile

OWNER='.hia-new-stage-owner'
MAX_FILES=100000
MAX_FILE_BYTES=16*1024*1024
MAX_TOTAL_BYTES=512*1024*1024
MANIFEST='HIA_ARCHIVE_MANIFEST.json'

def digest(data):return sha256(data).hexdigest()

def identity(info):
    return info.st_dev,info.st_ino,info.st_mode,info.st_size,info.st_mtime_ns,info.st_ctime_ns

def _archive_metadata(info):
    return identity(info)+(info.st_uid,info.st_nlink)

def _archive_snapshot(descriptor,path,links,expected=None):
    """Bind a held ordinary inode to its current path, including link count."""
    info=os.fstat(descriptor)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid()
            or info.st_nlink!=links):
        raise ValueError('archive requires owned ordinary bytes and exact links')
    if _archive_metadata(info)!=_archive_metadata(path.lstat()):
        raise ValueError('archive pathname changed while sealing')
    if expected is not None and _archive_metadata(info)!=_archive_metadata(expected):
        raise ValueError('archive changed while sealing')
    return info

def _archive_sha256(descriptor,path,links,expected):
    """Read exactly the held file extent without sharing the ZIP seek offset."""
    before=_archive_snapshot(descriptor,path,links,expected)
    result=sha256();offset=0
    while offset<before.st_size:
        chunk=os.pread(descriptor,min(1024*1024,before.st_size-offset),offset)
        if not chunk:raise ValueError('archive changed while hashing')
        result.update(chunk);offset+=len(chunk)
    _archive_snapshot(descriptor,path,links,before)
    return result.hexdigest()

def verify_archive(path):
    with zipfile.ZipFile(path) as archive:
        names=archive.namelist()
        if len(names)!=len(set(names)) or MANIFEST not in names:raise ValueError('archive inventory mismatch')
        if archive.getinfo(MANIFEST).file_size>32*1024*1024:raise ValueError('archive manifest capacity')
        manifest=json.loads(archive.read(MANIFEST))
        files=manifest['files']
        if len(files)>MAX_FILES or set(names)!=(set(files)|{MANIFEST}):raise ValueError('archive members mismatch')
        total=0
        for name,row in files.items():
            if Path(name).is_absolute() or '..' in Path(name).parts:raise ValueError('archive member path')
            info=archive.getinfo(name)
            if not 0<=info.file_size<=MAX_FILE_BYTES or info.file_size!=row['bytes']:raise ValueError('archive member capacity')
            total+=info.file_size
            if total>MAX_TOTAL_BYTES:raise ValueError('archive total capacity')
            if digest(archive.read(name))!=row['sha256']:raise ValueError('archive member digest')
            if (info.external_attr>>16)&0o777 != row['mode']:raise ValueError('archive member mode')
        if total!=manifest['unpacked_bytes']:raise ValueError('archive total mismatch')
        return manifest

def archive_completed_stage(directory, token):
    directory=Path(directory).absolute()
    if any(p.is_symlink() for p in (directory,*directory.parents)):raise ValueError('stage path symlink')
    if (directory/OWNER).read_text()!=token:raise ValueError('fresh stage owner token required')
    destination=directory.with_name(directory.name+'.zip')
    receipt_path=directory/'ARCHIVED.json'
    if destination.exists() or destination.is_symlink() or receipt_path.exists():raise ValueError('archive requires new paths')
    paths=sorted(p for p in directory.rglob('*') if not p.is_dir() or p.is_symlink())
    if not paths or len(paths)>MAX_FILES:raise ValueError('stage file count')
    inventory={};identities={};total=0
    for path in paths:
        info=path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_uid!=os.getuid():raise ValueError('stage must contain private ordinary files')
        if info.st_size>MAX_FILE_BYTES:raise ValueError('stage member capacity')
        total+=info.st_size
        if total>MAX_TOTAL_BYTES:raise ValueError('stage capacity')
        name=path.relative_to(directory).as_posix()
        if name==MANIFEST or name=='ARCHIVED.json':raise ValueError('reserved archive member')
        data=path.read_bytes()
        if identity(path.stat())!=identity(info):raise ValueError('stage changed while reading')
        inventory[name]={'bytes':len(data),'sha256':digest(data),'mode':stat.S_IMODE(info.st_mode)}
        identities[name]=identity(info)
    manifest={'schema':'hepta.hia.lossless-evidence-archive.v1','files':inventory,
              'unpacked_bytes':total,'source_directory':str(directory),
              'native_or_correctness_authority':False}
    # Keep the created inode held even while writing. Reopening a pathname alone
    # would not bind a later replay or publication to these bytes.
    descriptor,temporary=tempfile.mkstemp(prefix='.hia-archive-',dir=directory.parent)
    temporary=Path(temporary);created=os.fstat(descriptor)
    held=None;published=None;receipt_inode=None;retiring=False
    try:
        with os.fdopen(os.dup(descriptor),'w+b') as stream:
            with zipfile.ZipFile(stream,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=1) as archive:
                for name in inventory:
                    path=directory/name
                    if identity(path.stat())!=identities[name]:raise ValueError('stage changed before archive')
                    archive.write(path,arcname=name)
                archive.writestr(MANIFEST,json.dumps(manifest,sort_keys=True,separators=(',',':')))
        os.fsync(descriptor)
        flags=os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK
        held=os.open(temporary,flags)
        verified=_archive_snapshot(held,temporary,1)
        if ((verified.st_dev,verified.st_ino)!=(created.st_dev,created.st_ino)
                or _archive_metadata(verified)!=_archive_metadata(os.fstat(descriptor))):
            raise ValueError('temporary archive replaced before replay')
        os.close(descriptor);descriptor=None
        packed_sha256=_archive_sha256(held,temporary,1,verified)
        with os.fdopen(os.dup(held),'rb') as stream:
            if verify_archive(stream)!=manifest:raise ValueError('archive replay differs')
        if _archive_sha256(held,temporary,1,verified)!=packed_sha256:
            raise ValueError('archive bytes changed during replay')
        # Check every original before retiring any one original.
        for name,row in inventory.items():
            path=directory/name
            if identity(path.lstat())!=identities[name] or digest(path.read_bytes())!=row['sha256']:raise ValueError('stage changed before seal')
        _archive_snapshot(held,temporary,1,verified)
        os.link(temporary,destination)
        parent=os.open(directory.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(parent)
        finally:os.close(parent)
        linked=_archive_snapshot(held,temporary,2)
        # A hard link necessarily changes ctime/nlink. Every other field remains
        # pinned, and the complete published SHA binds the contents across that
        # unavoidable metadata transition. No second member decompression is
        # needed for a byte-identical container already independently replayed.
        if (identity(linked)[:-1]+(linked.st_uid,)
                !=identity(verified)[:-1]+(verified.st_uid,)):
            raise ValueError('archive changed at publication')
        published=os.open(destination,flags)
        _archive_snapshot(published,destination,2,linked)
        if _archive_sha256(published,destination,2,linked)!=packed_sha256:
            raise ValueError('published archive bytes differ')
        _archive_snapshot(held,temporary,2,linked)
        _archive_snapshot(published,destination,2,linked)
        receipt={'schema':'hepta.hia.archived-stage.v1','archive':str(destination),
                 'archive_sha256':packed_sha256,'files':len(inventory),
                 'unpacked_bytes':total,'packed_bytes':linked.st_size,
                 'manifest_sha256':digest(json.dumps(manifest,sort_keys=True,separators=(',',':')).encode()),
                 'every_original_byte_verified_before_retirement':True,
                 'raw_paths_available':False,'recovery':'ZIP member paths relative to original source_directory; replay manifest hashes and modes',
                 'qualification_or_production_authority':False}
        with receipt_path.open('x') as stream:
            info=os.fstat(stream.fileno());receipt_inode=(info.st_dev,info.st_ino)
            json.dump(receipt,stream,sort_keys=True,indent=2);stream.write('\n');stream.flush();os.fsync(stream.fileno())
        _archive_snapshot(held,temporary,2,linked)
        _archive_snapshot(published,destination,2,linked)
        retiring=True
        for name in inventory:(directory/name).unlink()
        stage_descriptor=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(stage_descriptor)
        finally:os.close(stage_descriptor)
        return receipt
    finally:
        for opened in (published,held,descriptor):
            if opened is not None:os.close(opened)
        if receipt_inode is not None and not retiring:
            try:
                info=receipt_path.lstat()
                if (info.st_dev,info.st_ino)==receipt_inode:receipt_path.unlink()
            except FileNotFoundError:pass
        try:
            info=temporary.lstat()
            if (info.st_dev,info.st_ino)==(created.st_dev,created.st_ino):temporary.unlink()
        except FileNotFoundError:pass


def _ordinary_bytes(path, maximum):
    """Bounded same-owner regular bytes; never block on a substituted FIFO."""
    path=Path(path).absolute()
    if any(part.is_symlink() for part in (path,*path.parents)):
        raise ValueError('retained evidence path symlink')
    descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink!=1
                or before.st_uid!=os.getuid() or before.st_size>maximum):
            raise ValueError('retained evidence requires bounded owned ordinary bytes')
        chunks=[];size=0
        while True:
            chunk=os.read(descriptor,min(65536,maximum+1-size))
            if not chunk:break
            chunks.append(chunk);size+=len(chunk)
            if size>maximum:raise ValueError('retained evidence capacity')
        if identity(before)!=identity(os.fstat(descriptor)) or identity(before)!=identity(path.lstat()):
            raise ValueError('retained evidence changed while reading')
        return b''.join(chunks)
    finally:os.close(descriptor)


def read_retained_evidence(path):
    """Read an original artifact, or its explicitly receipted unchanged ZIP member.

    No extraction, regeneration or implicit sibling substitution. A retired raw
    path is recovered only through its own stage receipt and complete archive
    replay. This is evidence access, not native/correctness admission authority.
    """
    path=Path(path).absolute()
    try:return _ordinary_bytes(path,MAX_FILE_BYTES)
    except FileNotFoundError:pass
    for stage in path.parents:
        receipt_path=stage/'ARCHIVED.json'
        try:receipt=json.loads(_ordinary_bytes(receipt_path,65536))
        except FileNotFoundError:continue
        archive=stage.with_name(stage.name+'.zip')
        if (receipt.get('schema')!='hepta.hia.archived-stage.v1'
                or receipt.get('archive')!=str(archive)
                or receipt.get('raw_paths_available') is not False
                or receipt.get('every_original_byte_verified_before_retirement') is not True):
            raise ValueError('retained stage receipt mismatch')
        before=identity(archive.lstat())
        if digest(_ordinary_bytes(archive,MAX_TOTAL_BYTES+64*1024*1024))!=receipt['archive_sha256']:
            raise ValueError('retained archive digest mismatch')
        manifest=verify_archive(archive)
        encoded=json.dumps(manifest,sort_keys=True,separators=(',',':')).encode()
        if (digest(encoded)!=receipt['manifest_sha256']
                or manifest['source_directory']!=str(stage)
                or len(manifest['files'])!=receipt['files']
                or manifest['unpacked_bytes']!=receipt['unpacked_bytes']):
            raise ValueError('retained archive manifest mismatch')
        member=path.relative_to(stage).as_posix()
        if member not in manifest['files']:raise FileNotFoundError(str(path))
        with zipfile.ZipFile(archive) as packed:data=packed.read(member)
        if identity(archive.lstat())!=before or digest(data)!=manifest['files'][member]['sha256']:
            raise ValueError('retained archive member changed')
        return data
    raise FileNotFoundError(str(path))
