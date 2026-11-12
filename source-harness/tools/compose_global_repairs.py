#!/usr/bin/env python3
"""Compose an exact frozen GLOBAL/import repair and finite registration delta."""
from __future__ import annotations
import argparse,base64,hashlib,json
from pathlib import Path
import zlib

def identity(raw):
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
            'blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}

def tree_hash(rows):
    root={}
    for name,row in rows.items():
        cursor=root;parts=name.split('/')
        for part in parts[:-1]:cursor=cursor.setdefault(part,{})
        cursor[parts[-1]]=(row['mode'],row['blob'])
    def finish(node):
        raw=bytearray()
        for name,value in sorted(node.items(),key=lambda item:(item[0]+('/' if isinstance(item[1],dict) else '')).encode()):
            mode,digest=('40000',finish(value)) if isinstance(value,dict) else value
            raw.extend(mode.encode()+b' '+name.encode()+b'\0'+bytes.fromhex(digest))
        return hashlib.sha1(b'tree '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
    return finish(root)

def main():
    p=argparse.ArgumentParser();p.add_argument('--harness',required=True);p.add_argument('--output',required=True);a=p.parse_args()
    h=Path(a.harness).resolve(strict=True);out=Path(a.output).resolve();out.mkdir(parents=True,exist_ok=False)
    config=json.loads((h/'inputs/CONFIG.json').read_bytes())
    index=json.loads((h/'inputs/INPUTS.json').read_bytes())
    for name,wanted in index['files'].items():
        assert identity((h/name).read_bytes())==wanted, name
    raw=(h/'inputs/SOURCE-CHECKPOINT.zlib.json').read_bytes()
    assert identity(raw)=={'bytes':1192661,'sha256':'4faa4f1738f372284ca4b6fc71cdc2a59afa831353d670c3804b642d8d65a9aa','blob':'c32a398f344e10149d629b064356469baeaa32da'}
    decoded=zlib.decompress(base64.b64decode(json.loads(raw)['payload']))
    assert len(decoded)==3071393 and hashlib.sha256(decoded).hexdigest()=='49603c7788eb619b4e78e26b3d85e25488648b12c4343ad32478eafd0cde5bfc'
    packet=json.loads(decoded)
    assert packet['base_commit']=='64f67ae897c3cb49d45a1e1a4622db974812e3fe'
    assert packet['base_tree']=='b7cf3502931d5fae8f58444b0af04cc642414a4a'
    assert len(packet['base_manifest'])==3255 and len(packet['files'])==20
    rows={n:dict(r) for n,r in packet['base_manifest'].items()};files={}
    def apply(name,change):
        assert name and not name.startswith('/') and all(x not in ('','.','..') for x in name.split('/'))
        before,after=change['before'],change['after']
        if before is None:assert name not in rows,name
        else:
            assert rows[name]=={k:before[k] for k in ('bytes','sha256','blob','mode')},name
            assert identity(before['content'].encode())=={k:before[k] for k in ('bytes','sha256','blob')},name
        assert after['encoding']=='utf-8' if 'encoding' in after else True
        assert identity(after['content'].encode())=={k:after[k] for k in ('bytes','sha256','blob')},name
        assert after['mode'] in ('100644','100755')
        rows[name]={k:after[k] for k in ('bytes','sha256','blob','mode')}
        files[name]={'path':name,**{k:after[k] for k in ('bytes','sha256','blob','mode','content')}}
    assert tree_hash(rows)==packet['base_tree']
    for name,change in packet['files'].items():apply(name,change)
    assert rows==packet['source_manifest']
    assert tree_hash(rows)==packet['source_tree']=='0a3fba637afe252f9bdf192b7a24df67b08efcbe'
    integrations=json.loads((h/'inputs/INTEGRATION-DELTAS.json').read_bytes())
    assert set(integrations)=={'.github/workflows/hia-core.yml','docs/HIA_JOINT_OWNER_INTEGRATION.md','tests/test_hia_joint_owner_integration.py','tools/hia_selfhost_contract.py'}
    for name,change in integrations.items():apply(name,change)
    assert len(rows)==3257 and len(files)==24 and tree_hash(rows)==config['frozen_input_tree']
    overlay={'schema':'hepta.hia.source-overlay.v1','base_commit':packet['base_commit'],'base_tree':packet['base_tree'],
             'files':[files[n] for n in sorted(files)],'expected_generated_paths':config['generated_sources']+[
               'docs/HIA_SELFHOST_LANGUAGE_COVERAGE.json','docs/HIA_SELFHOST_CORE_SUPPORT.json','docs/HIA_NATIVE_REWRITE_INVENTORY.json'],
             'extra_controls':[]}
    target=h/'overlay/source-overlay.json';assert not target.exists();target.parent.mkdir(exist_ok=True)
    target.write_text(json.dumps(overlay,sort_keys=True,indent=2)+'\n')
    report={'schema':'hia.global-import.source-composition.v80.r1','status':'PASS','source_only':True,
            'base_commit':packet['base_commit'],'base_tree':packet['base_tree'],'base_files':3255,
            'repair_paths':20,'registration_paths':sorted(integrations),'authored_files':3257,
            'authored_tree':tree_hash(rows),'overlay':identity(target.read_bytes()),'current_cold':False,'whole_native':False}
    (out/'COMPOSITION.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    print(json.dumps(report,sort_keys=True))

if __name__=='__main__':main()
