"""Build the durable audit daemon entirely through the selected native HIA compiler.

This component source-custody gate is not whole-service or fresh cold admission.
The selected compiler and supplied cold observer are separately identified. The
caller must establish their authority before using the resulting product.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
from pathlib import Path
import struct
import subprocess
import sys


def qualify(source, bootstrap, cold_receipt, output):
    source=Path(source).resolve(strict=True)
    bootstrap=Path(bootstrap).resolve(strict=True)
    cold_receipt=Path(cold_receipt).resolve(strict=True)
    output=Path(output).resolve();output.mkdir(mode=0o700)
    sys.path.insert(0,str(source))
    from tools.generate_hia_mcp_request_audit import ROLES,adapter_source
    from tools.qualify_hia_selfhost import invoke
    from tools.build_hia_source_build import _check_pack_output
    adapter='tools/hia_mcp_request_audit_syscalls.S'
    if (source/adapter).read_text()!=adapter_source():
        raise ValueError('checked-in audit syscall adapter differs from its mechanical source')
    selected=bootstrap.read_bytes();cold_raw=cold_receipt.read_bytes()
    cold=json.loads(cold_raw)
    paths={name:'examples/hia_bootstrap/mcp_request_audit_'+name+'.hepta'
           for name in (*ROLES,'packer')}
    paths['filter-packer']='examples/hia_bootstrap/native_filter_packer.hepta'
    dependencies={adapter,'tools/qualify_hia_mcp_request_audit_sources.py',
                  'tests/hia_request_audit_native_support.py',
                  'tools/qualify_hia_mcp_request_audit_v12.py',
                  'tools/qualify_hia_mcp_request_audit_retention.py',
                  *(p.relative_to(source).as_posix()
                            for p in (source/'tools').glob('generate_hia_mcp_request_audit*.py'))}
    captured={name:(source/name).read_bytes() for name in sorted(set(paths.values())|dependencies)}
    records={};images={}
    for name,relative in paths.items():
        body=captured[relative]
        run=subprocess.run([str(bootstrap),'compile'],input=body,capture_output=True,
                           env={'PATH':''},timeout=240,cwd=source)
        if run.returncode or run.stderr or not 0<len(run.stdout)<=1<<20:
            raise AssertionError((name,run.returncode,run.stderr[:1000]))
        (output/(name+'.flat')).write_bytes(run.stdout);images[name]=run.stdout
        records[name]={'source':relative,'source_sha256':sha256(body).hexdigest(),
                       'flat_sha256':sha256(run.stdout).hexdigest(),'flat_bytes':len(run.stdout)}
    small=struct.pack('<8sQ',b'HIAFLT01',len(images['packer']))+images['packer']
    receipt,raw=invoke(output,'native-audit-packer-filter',output/'filter-packer.flat',
        small,capacity=1<<20,flat_observer=bytes.fromhex(cold['native_flat_observer_hex']))
    packed=_check_pack_output(receipt,raw,artifact=images['filter-packer'],source=small,capacity=1<<20)
    packer=output/'hia-mcp-request-audit-packer';packer.write_bytes(packed);packer.chmod(0o500)
    parts=[images[name] for name in ROLES]
    packet=struct.pack('<8s'+str(len(parts))+'Q',b'HIARAU01',*map(len,parts))+b''.join(parts)
    run=subprocess.run([str(packer)],input=packet,capture_output=True,env={'PATH':''},timeout=120)
    if run.returncode or run.stderr:
        raise AssertionError(('native audit packer',run.returncode,run.stderr[:1000]))
    elf=run.stdout
    if not (176<len(elf)<=8<<20 and elf.startswith(b'\x7fELF') and
            struct.unpack_from('<Q',elf,96)[0]==len(elf) and
            struct.unpack_from('<Q',elf,104)[0]==len(elf) and elf.endswith(b''.join(parts))):
        raise AssertionError('native audit packer changed admitted component bytes')
    invalid=[('empty',b''),('truncated',packet[:-1]),('trailing',packet+b'\0'),
             ('magic',bytes([packet[0]^1])+packet[1:])]
    for index in range(len(parts)):
        changed=bytearray(packet);struct.pack_into('<Q',changed,8+8*index,0)
        invalid.append(('empty-role-'+str(index),bytes(changed)))
    refusals=[]
    for name,frame in invalid:
        rejected=subprocess.run([str(packer)],input=frame,capture_output=True,env={'PATH':''},timeout=30)
        if rejected.returncode==0 or rejected.stdout:
            raise AssertionError(('native audit packer admitted malformed composition',name))
        refusals.append({'case':name,'returncode':rejected.returncode,'stdout_bytes':len(rejected.stdout)})
    if bootstrap.read_bytes()!=selected or cold_receipt.read_bytes()!=cold_raw or any((source/name).read_bytes()!=raw for name,raw in captured.items()):
        raise ValueError('audit source/compiler/observer custody changed during qualification')
    image=output/'hia-mcp-request-audit';image.write_bytes(elf);image.chmod(0o500)
    result={'schema':'hepta.hia.mcp-request-audit-sources.v1',
            'scope':'NATIVE_MCP_REQUEST_AUDIT_COMPONENT_SOURCE_CUSTODY',
            'source':str(source),'bootstrap':str(bootstrap),'bootstrap_sha256':sha256(selected).hexdigest(),
            'cold_receipt_sha256':sha256(cold_raw).hexdigest(),'whole_cold_source_admission_claimed':False,
            'sources':{name:sha256(raw).hexdigest() for name,raw in captured.items()},'parts':records,
            'packet_sha256':sha256(packet).hexdigest(),'packer_sha256':sha256(packed).hexdigest(),
            'executable':str(image),'executable_sha256':sha256(elf).hexdigest(),'executable_bytes':len(elf),
            'exact_component_suffix':True,'existing_observer_budget_unchanged':True,'refusals':refusals}
    (output/'qualification.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,default=Path(__file__).resolve().parents[1])
    parser.add_argument('--bootstrap',type=Path,required=True)
    parser.add_argument('--cold-receipt',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();result=qualify(args.source,args.bootstrap,args.cold_receipt,args.output)
    print(json.dumps({key:result[key] for key in ('scope','executable','executable_sha256','executable_bytes')},sort_keys=True))
if __name__=='__main__':main()
