"""Retain the complete original real-kernel CLI family in a native plan."""
import struct
from tools.hia_cold_qualification_plan_parts import (assert_gate,build,check_flat,
                                                     cli,observe,utility)


def append_cli(p,h,*,label):
    from tools.qualify_hia_selfhost_cli import (echo_source,limit_source,padded_source,
                                               output_capacity_source)
    compiler,source=h['compiler'],h['source']
    observer,check,util=h['observer'],h['check'],h['util']
    names=[]
    def run(name,image,data,**kwargs):
        names.append(label+':cli:'+name)
        return cli(p,check,image,data,label=names[-1],**kwargs)
    def inspect(image,name):
        gate=utility(p,util,3,image,label=label+':cli:ELF-inspection-'+name)
        assert_gate(p,gate,label=label+':cli:ELF-inspection-'+name)
    executable_source=utility(p,util,1,source,module=b'selfhost_exec',label=label+':CLI-actual-source-module')
    first=build(p,observer,check,compiler,executable_source,label=label+':CLI-E1')
    inspect(first,'E1')
    second=run('E2',first,executable_source)
    p.compare(first,second,label=label+':CLI-E1-E2-exact')
    third=run('E3',second,executable_source)
    p.compare(first,third,label=label+':CLI-E1-E3-exact')
    if label=='original':
        changed=utility(p,util,1,h['modified_source'],module=b'selfhost_exec',label='CLI-actual-causally-modified-source')
        images=[];previous=first
        for generation in (1,2,3):
            image=run('upgrade-M'+str(generation),previous,changed)
            inspect(image,'upgrade-M'+str(generation));images.append(image);previous=image
        p.compare(images[0],images[1],different=True,label='CLI-codegen-causality-M1-M2')
        p.compare(images[1],images[2],label='CLI-modified-fixed-point-M2-M3')
        p.compare(first,images[2],different=True,label='CLI-modified-distinct-original')
        p.drop(*images,changed)
    echo=p.literal(echo_source(),label='fixture:CLI-echo')
    echo_source_exec=utility(p,util,1,echo,module=b'selfhost_exec',label='CLI-echo-source-module')
    echo_image=build(p,observer,check,compiler,echo_source_exec,label=label+':CLI-echo-build')
    for generation,image in [(1,first),(3,third)]:
        run('echo-compile-E'+str(generation),image,echo_source_exec,expected_handle=echo_image)
    for value in (0,73,255):
        data=p.literal(bytes([value]));run('echo-'+str(value),echo_image,data,expected=bytes([value]));p.drop(data)
    for name,data in [('empty',b''),('bad-header',b'bad'),('bad-utf8',b'\xff')]:
        inp=p.literal(data);run(name,first,inp,code=2,expected=b'');p.drop(inp)
    empty=p.literal(b'')
    run('argument',first,empty,code=64,expected=b'',argv=('child','unexpected'))
    padding=p.literal(b' '*(1<<20));one=p.literal(b' ');overflow=p.concat(padding,one)
    run('input-overflow',first,overflow,code=3,expected=b'');p.drop(padding,one,overflow)
    limit=p.literal(limit_source(),label='fixture:CLI-exact-limit-source')
    limit_image=build(p,observer,check,compiler,limit,label=label+':CLI-exact-limit-flat')
    padded=p.literal(padded_source(limit_source()),label='fixture:CLI-valid-1MiB-source')
    run('input-exact-limit',first,padded,expected_handle=limit_image)
    p.drop(limit,limit_image,padded)
    target_fd=p.fdword(first);source_fd=p.fdword(echo);reserved=p.literal(bytes(96))
    for mode,name in [(1,'closed-stdin'),(2,'full-stdout'),(3,'mmap-failure')]:
        head=p.literal(b'HIAQCF01'+struct.pack('<Q',mode));request=p.concat(head,target_fd,source_fd,reserved)
        run(name,h['fault'],request,code=4,expected=b'',passed=(first,echo));p.drop(head,request)
    p.drop(target_fd,source_fd,reserved)
    previous=p.literal(output_capacity_source(8),label='fixture:CLI-original-eight-argument-capacity')
    image=build(p,observer,check,compiler,previous,label=label+':CLI-retained-original-capacity-build')
    observation=observe(p,observer,image,empty,cap=0,work=0,label=label+':CLI-retained-original-capacity-run')
    gate=check_flat(p,check,observation,empty,mode=1,cap=0,work=0,core=0,label=label+':CLI-retained-original-capacity-exact')
    assert_gate(p,gate,label=label+':CLI-compacted-original-execution')
    run('compacted-original',first,previous,expected_handle=image)
    p.drop(previous,image,observation)
    large=p.literal(output_capacity_source(),label='fixture:CLI-twelve-argument-output-overflow')
    initial=p.literal(b'\xa5'*(1<<20))
    result=observe(p,observer,compiler,large,label=label+':CLI-output-capacity-flat')
    gate=check_flat(p,check,result,large,mode=1,core=0xfffffffe,initial_handle=initial,expected_handle=initial,label=label+':CLI-output-capacity-transactional')
    assert_gate(p,gate,label=label+':CLI-output-capacity-reference')
    run('output-overflow',first,large,code=3,expected=b'')
    p.drop(executable_source,first,second,third,echo,echo_source_exec,echo_image,empty,large,initial,result)
    return names
