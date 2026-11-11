"""Exact source and lifecycle checks for explicit instruction development."""
from hashlib import sha1, sha256
import json
import os
from pathlib import Path
import stat
import subprocess

def digest(raw):
    return sha256(raw).hexdigest()

def blob(raw):
    return sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()

def save(root, name, value):
    (root/name).write_text(json.dumps(value, sort_keys=True, indent=2)+'\n')

def command(argv, cwd):
    return subprocess.check_output(argv, cwd=cwd).decode().strip()

def original_metadata(path, expected_index):
    subprocess.run(['git','diff','--cached','--quiet',expected_index,'--'],cwd=path,check=True)
    index=subprocess.check_output(['git','ls-files','--stage','-z'],cwd=path)
    return {'head':command(['git','rev-parse','HEAD'],path),
        'head_tree':command(['git','rev-parse','HEAD^{tree}'],path),
        'index_matches':expected_index,'index_sha256':digest(index),
        'tracked_status':command(['git','status','--porcelain','--untracked-files=no'],path),
        'owner_sha256':digest((path/'tools/hia_selfhost_process_owner.py').read_bytes())}

def snapshot(path):
    index=subprocess.check_output(['git','ls-files','--stage','-z'],cwd=path)
    rows=[]
    for entry in index.split(b'\0'):
        if not entry:
            continue
        header, name=entry.split(b'\t',1)
        mode, expected, stage=header.decode().split()
        relative=Path(name.decode())
        if relative.is_absolute() or '..' in relative.parts:
            raise ValueError('invalid index path')
        target=path/relative
        info=target.lstat()
        if stage!='0' or mode!='100644' or not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_mode & 0o111:
            raise ValueError('nonregular or changed mode '+str(relative))
        raw=target.read_bytes()
        if blob(raw)!=expected:
            raise ValueError('working source differs from actual index '+str(relative))
        rows.append({'path':str(relative),'mode':mode,'git_blob':expected,
            'bytes':len(raw),'sha256':digest(raw),'posix_mode':stat.S_IMODE(info.st_mode)})
    return rows

def verified(raw, row):
    if len(raw)!=row['bytes'] or digest(raw)!=row['sha256'] or blob(raw)!=row['sha']:
        raise ValueError('source object differs '+row['path'])

def path_bytes(path):
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:
        raise ValueError('regular private file required '+str(path))
    raw=path.read_bytes()
    return {'path':str(path),'bytes':len(raw),'sha256':digest(raw),
        'mode':stat.S_IMODE(info.st_mode)},raw

def natural_owner(life):
    cleanup=life.get('cleanup',{})
    return bool(life.get('exit_observed_before_deadline') is True
        and life.get('timed_out') is False and not life.get('interrupted_signals')
        and not life.get('event_overflow') and not life.get('owner_error')
        and cleanup.get('complete') is True and cleanup.get('observed_echild') is True
        and cleanup.get('leader_reaped') is True and not cleanup.get('deadline_exceeded')
        and not cleanup.get('errors') and not cleanup.get('remaining_direct_children')
        and not any(e.get('kind')=='owned_child_sigkill' for e in life.get('events',[])))
