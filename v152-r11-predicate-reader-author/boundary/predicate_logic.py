"""Derive scalar fixtures from actual verified Core; compare physical effects.

All selected instructions are taken from the full actual R10/R11 documents.
No handwritten replacement function is used for either positive VM execution.
"""
import copy

SPECS=(
    {'kind':'delimiter','function':'f16','fn_index':16,'block':'b7','block_index':7,
     'prefix':2,'params':[{'name':'v99','type':'usize'}],'result':'v134'},
    {'kind':'identifier_invalid','function':'f79','fn_index':79,'block':'b4','block_index':4,
     'prefix':3,'params':[{'name':'v62','type':'usize'},{'name':'v46','type':'usize'}],
     'result':'v88'},
)

def derive_fragments(checked,projection,folder,S):
    from hepta.hia_program import verify_program
    documents={label:program.as_dict() for label,program in checked.items()}
    old,new=documents['R10'],documents['R11']
    S.require(checked['R10'].sha256==projection['original_core_sha256']
        and checked['R11'].sha256==projection['after_core_sha256'],
        'actual full programs do not match the actual Core proof')
    for label,count in (('R10',6299),('R11',6270)):
        doc=documents[label]
        S.require([fn['name'] for fn in doc['functions']]==['f'+str(i) for i in range(107)]
            and sum(len(fn['blocks']) for fn in doc['functions'])==1456
            and sum(len(block['ops']) for fn in doc['functions'] for block in fn['blocks'])==count,
            'complete actual program shape differs')
    inverse=copy.deepcopy(new)
    S.require(len(projection['edits'])==2,'actual predicate edit count differs')
    fragments={'R10':{},'R11':{}}
    observed=[]
    for spec,edit in zip(SPECS,projection['edits']):
        fi,bi=spec['fn_index'],spec['block_index']
        S.require(edit['path']==['functions',fi,'blocks',bi,'ops'],
            'actual predicate edit order or location differs')
        a,b=old['functions'][fi]['blocks'][bi],new['functions'][fi]['blocks'][bi]
        S.require(old['functions'][fi]['name']==new['functions'][fi]['name']==spec['function']
            and a['id']==b['id']==spec['block'] and a['params']==b['params']
            and a['term']==b['term'] and a['ops']==edit['before'] and b['ops']==edit['after']
            and a['ops'][:spec['prefix']]==b['ops'][:spec['prefix']],
            'actual retained load/cast, CFG edge or predicate operation list differs')
        inverse['functions'][fi]['blocks'][bi]['ops']=copy.deepcopy(edit['before'])
        item={'spec':spec,'actual_blocks':{'R10':a,'R11':b},'fragments':{}}
        for label,block in (('R10',a),('R11',b)):
            ops=copy.deepcopy(block['ops'][spec['prefix']:])
            defined={p['name'] for p in spec['params']}
            for ins in ops:
                S.require(all(name in defined for name in ins['args']),
                    'fragment has an uncaptured live-in')
                S.require(not (ins['op'].startswith('buffer.') or ins['op']=='call'),
                    'selected scalar slice is not pure')
                for out in ins['out']:
                    S.require(out['name'] not in defined,'fragment redefines an SSA name')
                    defined.add(out['name'])
            S.require(spec['result'] in defined,'fragment has no actual result')
            # trap is declared on both comparison fragments because the new
            # delimiter contains the existing checked-shift opcode. Its real
            # amount remains bounded by &63; no new opcode/provider is added.
            fn={'name':'predicate','params':copy.deepcopy(spec['params']),
                'returns':['bool'],'effects':['trap'],'entry':'entry',
                'blocks':[{'id':'entry','params':copy.deepcopy(spec['params']),
                    'ops':ops,'term':{'op':'ret','values':[spec['result']]}}]}
            doc={'schema':documents[label]['schema'],
                'module':'r11_predicate_boundary','functions':[fn]}
            path=folder/'fragments'/label/spec['kind'];S.mkdir(path)
            S.dump(path/'DERIVED-DOCUMENT.json',doc)
            program=verify_program(doc)
            S.require(program.as_dict()==doc,'verified fragment differs from its exact extracted document')
            S.write(path/'VERIFIED-CORE.json',program.canonical_bytes)
            fragments[label][spec['kind']]=program
            item['fragments'][label]={'Core_sha256':program.sha256,
                'input_sha256':program.input_sha256,'derived_document':S.identity(path/'DERIVED-DOCUMENT.json'),
                'verified_core':S.identity(path/'VERIFIED-CORE.json'),'ops':len(ops)}
        observed.append(item)
    S.require(inverse==old,'whole actual R11 Core does not invert exactly to R10')
    S.dump(folder/'ACTUAL-CORE-INVERSE.json',{'full_programs':{
        label:{'Core_sha256':program.sha256,'input_sha256':program.input_sha256}
        for label,program in checked.items()},'whole_inverse_equal':True,
        '107_functions':True,'1456_blocks':True,'unchanged_functions':105,
        'actual_selected_blocks_and_fragments':observed})
    return fragments

def physical_state(owners,views):
    return {name:{'view_active':view.active,'view_mutable':view.mutable,
        'owner_active':owners[name].active} for name,view in views.items()}

def untouched_bytes(before,after,effects,same_owner):
    written={name:set() for name in before}
    for event in effects:
        if event.get('outcome')!='completed':continue
        op=event['op'];args=event['args']
        if op=='buffer.store':role=args[0]['borrowed_view'];start=args[1];length=1
        elif op=='buffer.fill_range':role=args[0]['borrowed_view'];start=args[1];length=args[2]
        elif op in ('buffer.load','buffer.len','call'):continue
        else:raise ValueError('unaccounted actual buffer effect: '+op)
        affected=tuple(before) if same_owner else (role,)
        for name in affected:
            if not (0<=start<=len(before[name]) and 0<=length<=len(before[name])-start):
                raise ValueError('completed write is outside its physical extent')
            written[name].update(range(start,start+length))
    return {name:len(before[name])==len(after[name]) and all(
        old==after[name][i] for i,old in enumerate(before[name]) if i not in written[name])
        for name in before}
