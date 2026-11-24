"""Compose B0, both causal fixed points and every retained base control."""
import struct
from tools.hia_cold_qualification_plan_parts import call,check_flat,observe
from tools.hia_cold_qualification_base_plan import append_base


def append_chain(p,h,*,source_size,wrapper,sample):
    checked=call(p,h['assembly'],h['source'],label='independent-source-assembly',argv=('child','--agent-compact'))
    p.publish(checked,'seed.core.json')
    left=p.literal(b'[');right=p.literal(b',"f0",1]');project_request=p.concat(left,checked,right)
    projected=call(p,h['projector'],project_request,label='independent-Core-reference-projection')
    p.publish(projected,'seed.reference-wire')
    seed=call(p,h['factory'],projected,label='independent-native-B0')
    p.publish(seed,'B0.flat')
    p.drop(left,right,project_request,checked,projected)
    stages=[];previous=seed
    for label in ('B1','B2','B3'):
        observed=observe(p,h['observer'],previous,h['source'],fill=0x5a if label=='B3' else 0,label=label)
        following=check_flat(p,h['check'],observed,h['source'],label=label+'-publication-conditions')
        p.publish(following,label+'.flat');p.drop(observed)
        stages.append(following);previous=following
    p.compare(stages[0],stages[1],label='B1-B2-exact-bytes')
    p.compare(stages[1],stages[2],label='B2-B3-exact-bytes-nonzero-workspace')
    mutation_head=p.literal(b'HIAQMU01'+struct.pack('<2Q',len(wrapper),source_size)+wrapper)
    mutation_request=p.concat(mutation_head,h['source'])
    changed=call(p,h['mutate'],mutation_request,label='single-causal-wrapper-source-edit')
    p.compare(changed,h['source'],different=True,label='modified-source-is-distinct')
    p.publish(changed,'modified-selfhost.hepta');p.drop(mutation_head,mutation_request)
    modified=[]
    for label in ('M1','M2','M3'):
        observed=observe(p,h['observer'],previous,changed,label=label)
        following=check_flat(p,h['check'],observed,changed,label=label+'-publication-conditions')
        p.publish(following,label+'.flat');p.drop(observed)
        modified.append(following);previous=following
    p.compare(modified[0],modified[1],different=True,label='M1-M2-causal-codegen-change')
    p.compare(modified[1],modified[2],label='M2-M3-self-rebuild-fixed-point')
    p.compare(stages[2],modified[2],different=True,label='B3-M3-distinct')
    p.word(stages[2],0,int.from_bytes(bytes.fromhex('554889e54883ec40'),'little'),label='original-wrapper-reserves-64')
    p.word(modified[2],0,int.from_bytes(bytes.fromhex('554889e54883ec50'),'little'),label='modified-wrapper-reserves-80')
    for label,compiler in [('original',stages[2]),('modified',modified[2])]:
        build=observe(p,h['observer'],compiler,h['sample'],label=label+'-bytesum-build')
        image=check_flat(p,h['check'],build,h['sample'],label=label+'-bytesum-publication');p.drop(build)
        p.publish(image,label+'-bytesum.flat')
        for i,data in enumerate((b'',b'HIA native bootstrap',bytes(range(256))*4)):
            value=5381
            for byte in data:value=((value*33)^byte)&0xffffffff
            inp=p.literal(data)
            observation=observe(p,h['observer'],image,inp,cap=1,work=1,label=label+'-bytesum-'+str(i))
            gate=check_flat(p,h['check'],observation,inp,mode=1,cap=1,work=1,initial=b'\xa5',expected=bytes([value&255]),core=value,label=label+'-bytesum-value-'+str(i))
            expected=p.literal(b'HIAQOK01');p.compare(gate,expected,label='actual-source-return-and-output')
            p.drop(inp,observation,gate,expected)
    controls=append_base(p,h,[('original',stages[2]),('modified',modified[2])],sample)
    return {'original':stages[2],'modified':modified[2],'modified_source':changed,'base_controls':controls}
