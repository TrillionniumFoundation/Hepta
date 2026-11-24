"""Compile and link the checked-in HIA MCP bridge using native HIA owners.

This is an external source-custody/component gate. It does not perform runtime
configuration admission, execute a remote workload, or establish whole-service
qualification. The separate real provider campaign covers those integrations.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import subprocess
import sys


def qualify(source, bootstrap, cold_receipt, output):
    source=Path(source).resolve(strict=True)
    bootstrap=Path(bootstrap).resolve(strict=True)
    cold_receipt=Path(cold_receipt).resolve(strict=True)
    output=Path(output).resolve()
    output.mkdir(mode=0o700)
    sys.path.insert(0,str(source))
    from tools.generate_hia_mcp_job_bridge import ROLES,COMPANIONS,PACKER_MAGIC
    from tools.qualify_hia_selfhost import invoke
    from tools.build_hia_source_build import _check_pack_output
    cold=json.loads(cold_receipt.read_bytes())
    records={}
    images={}
    for name in (*ROLES,'packer','filter-packer'):
        relative=(COMPANIONS.get(name) or
                  ('examples/hia_bootstrap/native_filter_packer.hepta' if name=='filter-packer'
                   else 'examples/hia_bootstrap/mcp_job_bridge_'+name+'.hepta'))
        body=(source/relative).read_bytes()
        run=subprocess.run([str(bootstrap),'compile'],input=body,capture_output=True,
                           env={'PATH':''},timeout=240,cwd=source)
        if run.returncode or run.stderr or not run.stdout:
            raise AssertionError((name,run.returncode,run.stderr[:1000]))
        (output/(name+'.flat')).write_bytes(run.stdout)
        images[name]=run.stdout
        records[name]={'source':relative,'source_sha256':sha256(body).hexdigest(),
                       'flat_sha256':sha256(run.stdout).hexdigest(),'flat_bytes':len(run.stdout)}
    # The existing observer has a 1 MiB input limit. First build the small
    # standalone native filter containing the HIA bridge packer. That filter
    # then carries the full packet under its existing 8 MiB limit.
    small=struct.pack('<8sQ',b'HIAFLT01',len(images['packer']))+images['packer']
    meta,raw=invoke(output,'native-bridge-packer-filter',output/'filter-packer.flat',
                    small,capacity=1<<20,flat_observer=bytes.fromhex(cold['native_flat_observer_hex']))
    packer_elf=_check_pack_output(meta,raw,artifact=images['filter-packer'],source=small,capacity=1<<20)
    packer=output/'hia-mcp-job-bridge-packer';packer.write_bytes(packer_elf);packer.chmod(0o500)
    parts=[images[name] for name in ROLES]
    header=struct.pack('<8s'+str(len(parts))+'Q',PACKER_MAGIC,*map(len,parts))
    packet=header+b''.join(parts)
    run=subprocess.run([str(packer)],input=packet,capture_output=True,env={'PATH':''},timeout=120)
    if run.returncode or run.stderr:
        raise AssertionError(('native packer',run.returncode,run.stderr[:1000]))
    elf=run.stdout
    if not (elf.startswith(b'\x7fELF') and len(elf)<=8<<20 and
            struct.unpack_from('<Q',elf,96)[0]==len(elf) and
            struct.unpack_from('<Q',elf,104)[0]==len(elf) and elf.endswith(b''.join(parts))):
        raise AssertionError('native packer changed exact admitted component bytes')
    image=output/'hia-mcp-job-bridge';image.write_bytes(elf);image.chmod(0o500)
    refusals=[]
    bad=[('empty',b''),('truncated',packet[:-1]),('trailing',packet+b'\0'),
         ('magic',bytes([packet[0]^1])+packet[1:])]
    for index in range(len(parts)):
        changed=bytearray(packet);struct.pack_into('<Q',changed,8+index*8,0)
        bad.append((f'empty-role-{index}',bytes(changed)))
    for name,payload in bad:
        rejected=subprocess.run([str(packer)],input=payload,capture_output=True,env={'PATH':''},timeout=30)
        if rejected.returncode==0 or rejected.stdout:
            raise AssertionError(('native packer admitted malformed composition',name))
        refusals.append({'case':name,'returncode':rejected.returncode,'stdout_bytes':len(rejected.stdout)})
    result={'schema':'hepta.hia.mcp-job-bridge-sources.v1',
            'scope':'NATIVE_MCP_JOB_BRIDGE_COMPONENT_SOURCE_CUSTODY',
            'source':str(source),'bootstrap':str(bootstrap),
            'bootstrap_sha256':sha256(bootstrap.read_bytes()).hexdigest(),
            'cold_receipt_sha256':sha256(cold_receipt.read_bytes()).hexdigest(),
            'parts':records,'native_packer_sha256':sha256(packer_elf).hexdigest(),
            'packet_sha256':sha256(packet).hexdigest(),
            'executable':str(image),'executable_sha256':sha256(elf).hexdigest(),
            'executable_bytes':len(elf),'existing_observer_byte_budget_unchanged':True,
            'exact_component_suffix':True,'refusals':refusals}
    (output/'qualification.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,default=Path(__file__).resolve().parents[1])
    parser.add_argument('--bootstrap',type=Path,required=True)
    parser.add_argument('--cold-receipt',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    result=qualify(args.source,args.bootstrap,args.cold_receipt,args.output)
    print(json.dumps({key:result[key] for key in ('scope','executable','executable_sha256','executable_bytes')},sort_keys=True))


if __name__=='__main__':main()
