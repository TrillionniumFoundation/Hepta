#!/usr/bin/env python3
"""Make an independent exact-blob sparse checkout without changing the source repo."""
from __future__ import annotations

from hashlib import sha1,sha256
import json
import os
from pathlib import Path
import subprocess
import zipfile

MAIN=Path('/workspace/scratch/793cbcdf54ed/Hepta')
OUT=Path('/workspace/scratch/793cbcdf54ed/step21-preflight-46d88')
RAM=Path('/dev/shm/hepta-step21-46d88')
COPY=RAM/'source'
HEAD='46d88bd18b1b3dadb246e92eb22c49fe44ec2d72'
ZIP=Path('/workspace/scratch/793cbcdf54ed/ci-triage-20261030/hia-verified-000ac.zip')


def git(*args,cwd=MAIN,**kwargs):
    return subprocess.check_output(['git','--no-replace-objects',*args],cwd=cwd,**kwargs)


def main():
    assert git('rev-parse','HEAD',text=True).strip()==HEAD
    RAM.mkdir(exist_ok=True)
    assert not COPY.exists()
    specs=['hepta','tools','tests/test_hia_ndu.py','tests/test_hia_ndu_loop.py',
           'examples/hia_recursive_chain/core_v7.json','experiments/hia_optimizer_eval/kernels.hepta',
           '.github/workflows/hepta-verified-optimization.yml','pyproject.toml']
    records=git('ls-tree','-r','-z',HEAD,'--',*specs).split(b'\0')
    chosen=[]
    for record in records:
        if not record:
            continue
        header,raw_name=record.split(b'\t',1)
        mode,kind,blob=header.decode().split()
        assert kind=='blob' and mode in ('100644','100755')
        name=raw_name.decode()
        raw=(MAIN/name).read_bytes()
        observed=sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
        assert observed==blob,name
        chosen.append((name,mode,blob,raw))
    # A whole-history local clone asks upload-pack for missing promisor history.
    # Create an independent checkout borrowing the available object store, then
    # materialize only the exact current-tree blobs required by these gates.
    subprocess.run(['git','init',str(COPY)],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    object_store=Path(git('rev-parse','--git-path','objects',text=True).strip())
    if not object_store.is_absolute():
        object_store=MAIN/object_store
    (COPY/'.git/objects/info/alternates').write_text(str(object_store.resolve())+'\n')
    for name,mode,blob,raw in chosen:
        path=COPY/name
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(raw)
        path.chmod(0o755 if mode=='100755' else 0o644)
    # Materialize any physically restored sparse files in this clone's own
    # object store, never in MAIN. Existing objects remain read-only alternates.
    objects=git('hash-object','-w','--stdin-paths',cwd=COPY,
                input=''.join(name+'\n' for name,_,_,_ in chosen).encode()).decode().splitlines()
    assert objects==[blob for _,_,blob,_ in chosen]
    git('update-ref','--no-deref','HEAD',HEAD,cwd=COPY)
    git('config','core.sparseCheckout','true',cwd=COPY)
    git('config','core.sparseCheckoutCone','false',cwd=COPY)
    (COPY/'.git/info/sparse-checkout').write_text(''.join('/'+spec+('/' if spec in ('hepta','tools') else '')+'\n' for spec in specs))
    git('read-tree','-mu','HEAD',cwd=COPY)
    assert git('rev-parse','HEAD',cwd=COPY,text=True).strip()==HEAD
    assert not git('status','--porcelain','--untracked-files=all',cwd=COPY).strip()
    original=RAM/'recursive-build'
    original.mkdir()
    with zipfile.ZipFile(ZIP) as z:
        manifest_raw=z.read('_temp/hia-recursive-ndu/identity.json')
        binary=z.read('_temp/hia-recursive-ndu/native/hepta-hia-ndu-bridge')
    manifest=json.loads(manifest_raw)
    assert manifest['identity']['source_commit']=='2590c0c94c5bf9a9004caeeb7b75edd6faf3eb8b'
    assert manifest['identity']['rustc'].startswith('rustc 1.90.0 ')
    assert sha256(binary).hexdigest()==manifest['binary_sha256']
    (original/'identity.json').write_bytes(manifest_raw)
    (original/'hepta-hia-ndu-bridge').write_bytes(binary)
    (original/'hepta-hia-ndu-bridge').chmod(0o755)
    observed=subprocess.run([str(original/'hepta-hia-ndu-bridge'),'--identity'],check=True,
                            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
    assert json.loads(observed.stdout)==manifest['identity']
    (OUT/'recursive-identity.stdout').write_bytes(observed.stdout)
    (OUT/'recursive-identity.stderr').write_bytes(observed.stderr)
    report={'head':HEAD,'isolated_checkout':str(COPY),'output_root':str(RAM/'evidence'),
            'source_git_status':'','source_files':{name:{'git_blob':blob,'sha256':sha256(raw).hexdigest(),'bytes':len(raw)}
                                                 for name,_,blob,raw in chosen},
            'recursive_cache_zip':{'path':str(ZIP),'sha256':sha256(ZIP.read_bytes()).hexdigest()},
            'recursive_manifest':str(original/'identity.json'),'recursive_bridge':str(original/'hepta-hia-ndu-bridge'),
            'recursive_manifest_sha256':sha256(manifest_raw).hexdigest(),
            'recursive_binary_sha256':sha256(binary).hexdigest(),'recursive_identity_observed':json.loads(observed.stdout),
            'main_source_files_written':0,'main_git_metadata_written':0}
    (OUT/'SETUP.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    print(json.dumps({'source_files':len(chosen),'checkout':str(COPY),'head':HEAD,'recursive_pin':manifest['identity']['source_commit'],
                      'recursive_binary_sha256':manifest['binary_sha256'],'identity_matches':True}))


if __name__=='__main__':
    main()
