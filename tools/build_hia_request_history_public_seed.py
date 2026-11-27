"""Construct the real native stdio history test bundle from fixed seed roots.

This development observer executes native compilation and native packers for
every role. The resulting test bundle is explicitly not a full cold release or
an installed Worker. No required executable is replaced by a mock response.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import importlib
import json
from pathlib import Path
import struct

from tools.qualify_hia_mcp_request_history_seed import HistorySeeds, native_call
from tools import generate_hia_mcp_job_bridge as bridge
from tools import generate_hia_mcp_service as service
from tools import generate_hia_native_filter as filters
from tools.generate_hia_worker_config_json import CONTROLLER_FILES

ROOT = Path(__file__).resolve().parents[1]
BOOT = 'examples/hia_bootstrap/'


def pin(raw):
    return {'bytes':len(raw),'sha256':sha256(raw).hexdigest()}


def build(bootstrap, audit, output):
    seeds = HistorySeeds(ROOT,bootstrap,output)
    report={'schema':'hepta.hia.history-public-seed-bundle.v1','passed':False,
            'whole_cold_qualified':False,'installed_worker_claimed':False,
            'scope':'real native component bundle for stdio request_history qualification',
            'sources':{},'products':{},'refusals':[]}
    images={}
    bundle=output/'controller';bundle.mkdir(mode=0o700)
    def compiled(path):
        raw=(ROOT/path).read_bytes()
        if path in images:
            assert report['sources'][path]['source']==pin(raw),path
            return images[path]
        flat=seeds.compile(raw,'div-word')
        assert 0<len(flat)<=1<<20,(path,len(flat))
        images[path]=flat
        report['sources'][path]={'source':pin(raw),'image':pin(flat)}
        (output/(Path(path).stem+'.flat')).write_bytes(flat)
        print('NATIVE_PUBLIC_COMPILED',path,len(flat),flush=True)
        return flat
    def compose(name,magic,paths,packer,cap,*,extra=b'',template=None,embedded=()):
        parts=[compiled(path) for path in paths]+list(embedded)
        wire=struct.pack('<8s'+'Q'*len(parts),magic,*map(len,parts))+extra+b''.join(parts)
        pack=compiled(packer)
        status,elf=native_call(pack,wire,cap)
        assert status==len(elf) and 176<status<=cap and elf.startswith(b'\x7fELF'),(name,status)
        assert struct.unpack_from('<Q',elf,96)[0]==len(elf)
        assert struct.unpack_from('<Q',elf,104)[0]==len(elf)
        assert elf.endswith(b''.join(parts))
        if template is not None:
            prefix,holes,roles=template
            expected=bytearray(prefix);target=len(prefix)
            struct.pack_into('<2Q',expected,96,len(elf),len(elf))
            for role,part in zip(roles,parts):
                at=holes[role];struct.pack_into('<I',expected,at,target-at-4);target+=len(part)
            if embedded:
                for role,part,offset in (('bridge',embedded[0],0),('audit',embedded[1],32)):
                    struct.pack_into('<I',expected,holes[role+'_size'],len(part))
                    expected[holes[role+'_pin']:holes[role+'_pin']+32]=extra[offset:offset+32]
            assert elf==bytes(expected)+b''.join(parts),name
        for label,malformed in [('truncated',wire[:-1]),('trailing',wire+b'\0'),
                                ('wrong-magic',b'\0'*8+wire[8:])]:
            reason,result=native_call(pack,malformed,cap)
            assert reason==4294967295 and not result,(name,label,reason)
            report['refusals'].append({'product':name,'case':label,'status':reason})
        path=bundle/name;path.write_bytes(elf);path.chmod(0o500)
        report['products'][name]={'executable':pin(elf),'parts':[pin(p) for p in parts],
                                  'packer':packer,'exact_suffix':True,
                                  'independent_complete_template_check':template is not None}
        return elf
    try:
        audit_report=json.loads((audit.parent/'qualification.json').read_text())
        audit_raw=audit.read_bytes()
        assert audit_report['executable_sha256']==sha256(audit_raw).hexdigest()
        for role,row in audit_report['parts'].items():
            assert sha256((ROOT/row['source']).read_bytes()).hexdigest()==row['source_sha256']
        report['audit_component']={'executable':pin(audit_raw),'construction_report':pin((audit.parent/'qualification.json').read_bytes())}
        bp,bh=bridge.template()
        bridge_raw=compose('hia-mcp-job-bridge',bridge.PACKER_MAGIC,
            [bridge.COMPANIONS.get(r,BOOT+'mcp_job_bridge_'+r+'.hepta') for r in bridge.ROLES],
            BOOT+'mcp_job_bridge_packer.hepta',16<<20,template=(bp,bh,bridge.ROLES))
        sp,sh=service.template()
        service_raw=compose('hia-mcp-service',b'HIAMSP03',
            [service.COMPANIONS.get(r,BOOT+'mcp_service_'+r+'.hepta')
             for r in service.ROLES if r not in ('bridge','audit')],
            BOOT+'mcp_service_packer.hepta',64<<20,
            extra=sha256(bridge_raw).digest()+sha256(audit_raw).digest(),
            template=(sp,sh,service.ROLES),embedded=(bridge_raw,audit_raw))
        filter_packer=BOOT+'native_filter_packer.hepta'
        pure={
            'hia-worker-prepare':'worker_prepare.hepta',
            'hia-agent-job-terminal-receipt':'job_terminal_receipt.hepta',
            'hia-agent-mcp-request':'mcp_request_route.hepta',
            'hia-agent-mcp-reply':'mcp_reply_wire.hepta',
            'hia-agent-mcp-terminal':'mcp_terminal_admission.hepta',
            'hia-agent-mcp-negotiation':'mcp_negotiation.hepta',
            'hia-agent-mcp-catalog':'mcp_catalog_wire.hepta',
            'hia-agent-mcp-uri':'mcp_resource_uri.hepta',
            'hia-agent-mcp-input-schema':'agent_schema.hepta',
            'hia-agent-mcp-response-schema':'agent_response_schema.hepta',
            'hia-agent-mcp-proof-schema':'agent_verify_response_schema.hepta'}
        fp,fc=filters.template()
        assert len(fc)==1
        for name,source in pure.items():
            compose(name,filters.MAGIC.to_bytes(8,'little'),[BOOT+source],filter_packer,2<<20,
                    template=(fp,{'body':fc[0]},('body',)))
        members=[
            ('hia-job-entry','job_entry',['job_entry','sha256_stream']),
            ('hia-job-launch','job_launch',['job_launch','job_launch_json','sha256_stream']),
            ('hia-job-observation','job_observation',['job_observation','job_observation_json']),
            ('hia-job-cancel','job_cancel',['job_cancel','job_observation_json','sha256_stream']),
            ('hia-job-submit','job_submit',['job_submit','job_submit_launch','job_submit_json','sha256_stream']),
            ('hia-job-supervisor','job_supervisor',['job_supervisor','sha256_stream']),
            ('hia-job-receipt','job_receipt',['job_receipt'])]
        for name,author,parts in members:
            module=importlib.import_module('tools.generate_hia_'+author)
            magic=module.PACKER_MAGIC
            if isinstance(magic,int):magic=magic.to_bytes(8,'little')
            compose(name,magic,[BOOT+part+'.hepta' for part in parts],
                    BOOT+author+'_packer.hepta',4<<20)
        catalog=(ROOT/'docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json').read_bytes()
        (bundle/'HIA_AGENT_NATIVE_TOOL_CATALOG.json').write_bytes(catalog)
        (bundle/'HIA_AGENT_NATIVE_TOOL_CATALOG.json').chmod(0o400)
        pins={name:sha256((bundle/name).read_bytes()).hexdigest() for name in CONTROLLER_FILES}
        assert len(pins)==19
        manifest={'schema':'hepta.hia.mcp.controller.v26','files':pins}
        raw=(json.dumps(manifest,sort_keys=True,separators=(',',':'))+'\n').encode()
        (bundle/'hia-controller.json').write_bytes(raw);(bundle/'hia-controller.json').chmod(0o400)
        report.update(passed=True,manifest=pin(raw),service=pin(service_raw),
                      required_controller_roles=sorted(pins))
        return report
    finally:
        seeds.save()
        (output/'qualification.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bootstrap',type=Path,required=True)
    parser.add_argument('--audit',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    report=build(args.bootstrap.resolve(),args.audit.resolve(),args.output.resolve())
    print(json.dumps({key:report[key] for key in ('passed','scope','service','manifest')}))


if __name__=='__main__':
    main()
