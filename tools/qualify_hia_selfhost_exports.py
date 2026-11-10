"""Finite independent-VM and actual HIA-written ELF scalar-export qualification."""
from __future__ import annotations
from hashlib import sha256
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]


def independent_reference():
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import execute_program
    from hepta.hia_program_native import emit_program_machine
    from tools.hia_selfhost_exports_cases import document,allocated_document,dense_document,assembly,refusals,SCALAR_TYPES
    doc=document();reversed_doc=json.loads(json.dumps(doc));reversed_doc['functions'].reverse();reversed_doc['exports'].reverse()
    programs=[('scalar',doc),('allocator',allocated_document()),('dense',dense_document()),('reordered',reversed_doc)]
    result=[]
    for name,doc in programs:
        source=assembly(doc);checked=assemble_program(source);machine=emit_program_machine(checked)
        calls=[]
        def observe(function,raw,typ):
            args=list(raw);semantic=list(raw)
            if name in ('scalar','reordered'):
                parameters=next(f['params'] for f in doc['functions'] if f['name']==function)
                semantic=[]
                for parameter,value in zip(parameters,raw):
                    scalar=parameter['type'];bits=1 if scalar=='bool' else int(scalar[1:]) if scalar[1:].isdigit() else 64
                    value&=(1<<bits)-1
                    if scalar.startswith('i') and value&(1<<(bits-1)):value-=1<<bits
                    semantic.append(bool(value) if scalar=='bool' else value)
            actual=execute_program(checked,function,semantic)
            if actual['status']!='returned' or actual['resources']['live_owners'] or actual['resources']['live_local_loans']:
                raise AssertionError(actual)
            expected=None if typ=='void' else 0 if typ=='unit' else int(actual['values'][0])
            calls.append({'function':function,'arguments':args,'return_type':typ,'expected':expected,'VM':actual})
        if name in ('scalar','reordered'):
            for typ in SCALAR_TYPES:
                for raw in (0,1,2**64-1,0x123456789abcdef0):observe('identity_'+typ,[raw],typ)
            for n in range(17):observe('sum_'+str(n),[(i+1)*0x1723456789abcd for i in range(n)],'u64')
            for fn,value in (('via_private',41),('_',7),('aaB',8),('aba',9),('block',10),('call',11),('read',12),('exports',13),('long_'+'x'*123,14)):
                observe(fn,[],'u64')
            for pattern in (2**64-1,0x123456789abcdef0):observe('mixed',[pattern-i for i in range(16)],'u64')
            observe('no_result',[],'void');observe('unit_result',[],'unit')
        elif name=='allocator':
            for n in (0,1,17,4096):observe('allocated_size',[n],'usize')
            observe('second',[],'u64')
        else:
            for i in range(128):observe('export_'+str(i),[],'u64')
        result.append({'name':name,'source':source.decode(),'source_sha256':sha256(source).hexdigest(),
            'exports':doc['exports'],'Core_sha256':checked.sha256,'host_object_sha256':machine.sha256,'calls':calls})
    controls=[]
    for name,source in refusals().items():
        row={'name':name,'source':source.decode(),'source_sha256':sha256(source).hexdigest()}
        try:
            checked=assemble_program(source)
        except ValueError as error:
            row.update(Core_accepted=False,Core_error=str(error))
        else:
            row.update(Core_accepted=True,Core_sha256=checked.sha256)
            try:emit_program_machine(checked)
            except ValueError as error:row.update(host_ABI_accepted=False,host_ABI_error=str(error))
            else:row['host_ABI_accepted']=True
        controls.append(row)
    return {'before_B0':True,'programs':result,'refusals':controls,'compiler_words':word_reference(),
        'all_input_correctness_proved':False,'whole_stack_rewrite_complete':False}


def qualify(directory,compiler,checks,reference,label,*,linker_manifest=None):
    from tools.qualify_hia_selfhost import compile_stage,invoke,observe_native_tool,INVALID,NO_SPACE
    from tools.hia_selfhost_process_owner import run_owned
    from hepta.hia_program_native import _inspect_object
    directory=Path(directory);observations=[]
    for row in reference['programs']:
        name=label+'-exports-'+row['name'];source=row['source'].encode()
        if sha256(source).hexdigest()!=row['source_sha256']:raise ValueError('export reference source drift')
        obj,build=compile_stage(directory,name,compiler,source,output_extension='.o')
        inventory=_inspect_object(obj.read_bytes(),tuple(row['exports']))
        checks[name+'-symbol-inventory']=set(inventory['defined'])==set(row['exports'])
        linked=directory/(name+'.so')
        if linker_manifest is None:
            link=observe_native_tool(directory,name+'-link','cc',['-nostartfiles','-shared','-Wl,-z,defs,-z,noexecstack,-z,relro,-z,now,--build-id=none',obj,'-o',linked])
        else:
            from tools.link_hia_elf import link as native_link
            link=native_link([obj],Path(linker_manifest),linked,
                expected_compiler_sha256=sha256(Path(compiler).read_bytes()).hexdigest())
            (directory/(name+'-native-link.json')).write_text(json.dumps(link,sort_keys=True,indent=2)+'\n')
        job=directory/(name+'-observations');job.mkdir()
        request={'schema':'hepta.hia.scalar-export-observation.v1','image':str(linked.resolve()),
            'image_sha256':sha256(linked.read_bytes()).hexdigest(),
            'calls':[{k:call[k] for k in ('function','arguments','return_type')} for call in row['calls']]}
        raw=json.dumps(request,sort_keys=True).encode();path=job/'request.json';path.write_bytes(raw)
        owner=run_owned([sys.executable,'-I','-S','-B',str(ROOT/'tools/hia_selfhost_exports_child.py'),
            '--request',str(path.resolve()),'--sha256',sha256(raw).hexdigest()],cwd=str(job.resolve()),
            env={'PATH':'/usr/bin:/bin','HOME':str(job.resolve()),'LANG':'C.UTF-8','LC_ALL':'C.UTF-8','TZ':'UTC'},
            stdout_path=job/'stdout.json',stderr_path=job/'stderr.raw',receipt_path=job/'owner.json',qualification_seconds=15)
        if owner['status']!='OWNED_PROCESS_COMPLETED' or owner['returncode']!=0 or not owner['cleanup']['complete']:
            raise AssertionError(owner)
        actual=json.loads((job/'stdout.json').read_bytes())
        checks[name+'-isolated-observer']=actual['status']=='SCALAR_EXPORT_OBSERVATIONS_RETURNED' and actual['forbidden_compiler_modules_loaded']==[]
        if len(actual['observations'])!=len(row['calls']):raise AssertionError('native export observation count')
        for i,(call,native) in enumerate(zip(row['calls'],actual['observations'])):
            checks[name+'-call-'+str(i)]=native=={'function':call['function'],'value':call['expected']}
        observations.append({'case':name,'compilation':build,'inventory':inventory,'link':link,'owner':owner,'native':actual})
        short,_=invoke(directory,name+'-short-output',compiler,source,capacity=build['produced_bytes']-1)
        checks[name+'-short-output']=short.get('status')=='returned' and short.get('core_u32')==NO_SPACE and short.get('output_unchanged') and short.get('source_unchanged')
        observations.append(short)
    for i,row in enumerate(reference['refusals']):
        source=row['source'].encode()
        if sha256(source).hexdigest()!=row['source_sha256']:raise ValueError('export refusal source drift')
        receipt,_=invoke(directory,label+'-exports-refusal-'+str(i),compiler,source,capacity=8192,workspace_fill=0xa5)
        checks[label+'-exports-reject-'+row['name']]=receipt.get('status')=='returned' and receipt.get('core_u32')==INVALID and receipt.get('output_unchanged') and receipt.get('source_unchanged')
        observations.append({'case':row['name'],'native':receipt})
    observations.extend(qualify_words(directory,compiler,checks,reference["compiler_words"],label))
    return observations


def word_reference():
    from tools.hia_selfhost_exports_cases import compiler_word_cases
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program_runtime import _Machine,_Owner,_View,HIAProgramTrap
    rows=[]
    for row in compiler_word_cases():
        checked=assemble_program(row['source'].encode());machine=_Machine(checked,1000000,16<<20,None,256)
        owners=[_Owner(-1,bytearray()),_Owner(-2,bytearray.fromhex(row['initial_hex'])),_Owner(-3,bytearray())]
        entry=next(f for f in checked.as_dict()['functions'] if f['name']=='f0')
        try:values=machine.invoke(entry,[_View(owners[0],False),_View(owners[1],True),_View(owners[2],True)])
        except HIAProgramTrap as error:actual=machine.report('f0','trapped',error=error)
        else:actual=machine.report('f0','returned',values=values)
        assert owners[1].data.hex()==row['expected_hex'],row['id']
        if 'expected_trap' in row:assert actual['status']=='trapped' and actual['error']['code']==row['expected_trap'],row['id']
        else:assert actual['status']=='returned' and actual['values']==[row['expected_result']],row['id']
        rows.append({**row,'Core_sha256':checked.sha256,'VM':actual})
    return rows


def qualify_words(directory,compiler,checks,reference,label):
    from tools.qualify_hia_selfhost import compile_stage,invoke
    observations=[]
    for row in reference:
        name=label+'-'+row['id']
        image,build=compile_stage(directory,name+'-build',compiler,row['source'].encode())
        actual,output=invoke(directory,name,image,b'',capacity=len(bytes.fromhex(row['initial_hex'])),
            workspace_size=0,output_initial=bytes.fromhex(row['initial_hex']),observe_trap_writes=True)
        expected=(actual.get('status')=='child_failed' and actual.get('returncode')==-4 if 'expected_trap' in row
            else actual.get('status')=='returned' and actual.get('core_u32')==row['expected_result'] and actual.get('source_unchanged'))
        checks[name]=bool(expected and output.hex()==row['expected_hex'])
        observations.append({'case':row['id'],'compilation':build,'native':actual,'output_hex':output.hex()})
    return observations
