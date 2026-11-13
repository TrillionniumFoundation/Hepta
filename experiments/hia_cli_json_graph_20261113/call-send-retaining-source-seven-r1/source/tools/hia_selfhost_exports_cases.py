"""Independent scalar-C-ABI witnesses for HIA-written multiple-export objects."""
from __future__ import annotations
import copy
from hepta.hia_agent_assembly import render_assembly

SCALAR_TYPES=('u8','u16','u32','u64','usize','i8','i16','i32','i64','isize','bool')


def function(name,types,returns,ops,values,effects=()):
    params=[{'name':'p'+str(i),'type':typ} for i,typ in enumerate(types)]
    return {'name':name,'params':params,'returns':returns,'effects':list(effects),
        'entry':'start','blocks':[{'id':'start','params':copy.deepcopy(params),
        'ops':ops,'term':{'op':'ret','values':values}}]}


def constant(name,value,typ='u64'):
    return function(name,[],[typ],[{'op':'const','out':[{'name':'result','type':typ}],
        'args':[],'attrs':{'value':value}}],['result'])


def document():
    functions=[]
    for typ in SCALAR_TYPES:
        functions.append(function('identity_'+typ,[typ],[typ],[],['p0']))
    for count in range(17):
        if count==0:
            functions.append(constant('sum_0',0));continue
        ops=[];value='p0'
        for i in range(1,count):
            following='sum'+str(i)
            ops.append({'op':'int.add.wrap','out':[{'name':following,'type':'u64'}],
                'args':[value,'p'+str(i)],'attrs':{}})
            value=following
        functions.append(function('sum_'+str(count),['u64']*count,['u64'],ops,[value]))
    functions.extend([function('no_result',[],[],[],[]),constant('unit_result',None,'unit'),
        constant('_',7),constant('aaB',8),constant('aba',9),
        constant('block',10),constant('call',11),constant('read',12),constant('exports',13),
        constant('long_'+'x'*123,14),constant('private_value',41)])
    caller=function('via_private',[],['u64'],[{'op':'call','out':[{'name':'result','type':'u64'}],
        'args':[],'attrs':{'function':'private_value'}}],['result'])
    functions.append(caller)
    mixed=SCALAR_TYPES+SCALAR_TYPES[:5];ops=[]
    for i in range(16):
        if mixed[i]=='bool':
            for label,value in (('yes',1),('no',0)):
                ops.append({'op':'const','out':[{'name':label+str(i),'type':'u64'}],
                    'args':[],'attrs':{'value':value}})
            ops.append({'op':'select','out':[{'name':'cast'+str(i),'type':'u64'}],
                'args':['p'+str(i),'yes'+str(i),'no'+str(i)],'attrs':{}})
        else:
            ops.append({'op':'int.cast','out':[{'name':'cast'+str(i),'type':'u64'}],
                'args':['p'+str(i)],'attrs':{'mode':'wrap'}})
    last='cast0'
    for i in range(1,16):
        following='total'+str(i)
        ops.append({'op':'int.add.wrap','out':[{'name':following,'type':'u64'}],
            'args':[last,'cast'+str(i)],'attrs':{}});last=following
    functions.append(function('mixed',mixed,['u64'],ops,[last]))
    return {'schema':'hepta.hia.program.v8','module':'export_library',
        'exports':[f['name'] for f in reversed(functions) if f['name']!='private_value'],
        'functions':functions}


def allocated_document():
    ops=[{'op':'buffer.new','out':[{'name':'owner','type':'buffer'}],'args':['p0'],'attrs':{}},
        {'op':'borrow.read','out':[{'name':'view','type':'readbuf'}],'args':['owner'],'attrs':{}},
        {'op':'buffer.len','out':[{'name':'size','type':'usize'}],'args':['view'],'attrs':{}},
        {'op':'loan.end','out':[],'args':['view'],'attrs':{}},
        {'op':'owner.drop','out':[],'args':['owner'],'attrs':{}}]
    return {'schema':'hepta.hia.program.v8','module':'allocator_exports',
        'exports':['allocated_size','second'],
        'functions':[function('allocated_size',['usize'],['usize'],ops,['size'],('alloc','read','trap')),
            constant('second',2)]}


def dense_document(count=128):
    functions=[constant('export_'+str(i),i) for i in range(count)]
    return {'schema':'hepta.hia.program.v8','module':'dense_exports',
        'exports':[f['name'] for f in functions],'functions':functions}


def assembly(value):
    return render_assembly(value).encode()


def refusals():
    base=document();wire=assembly(base)
    result={}
    result.update({
        'empty':wire[:wire.index(b'exports(')]+b'exports()\n'+wire[wire.index(b'\nfn ')+1:],
        'duplicate':wire.replace(b'exports(',b'exports(identity_u8,identity_u8,',1),
        'missing':wire.replace(b'exports(',b'exports(missing,',1),
        'trailing-comma':wire.replace(b')\nfn ',b',)\nfn ',1),
        'repeated-list':wire.replace(b'\nfn ',b'\nexports(identity_u8)\nfn ',1),
        'quoted-name':wire.replace(b'exports(',b'exports("identity_u8",',1),
        'oversize-list':wire.replace(b'exports(',b'exports('+b','.join(b'export_'+str(i).encode() for i in range(129))+b',',1),
        'executable-profile':wire.replace(b' export_library\n',b' selfhost_exec\n',1),
    })
    for name in ('abort','calloc','malloc','free','memset','memcpy','memmove','_init','_fini','__gmon_start__','__cxa_finalize','__dso_handle',
                 '_ITM_registerTMCloneTable','_ITM_deregisterTMCloneTable'):
        value={'schema':'hepta.hia.program.v8','module':'loader_hook',
            'exports':['reserved_native'],'functions':[constant('reserved_native',0)]}
        result['loader-hook-'+name]=assembly(value).replace(b'reserved_native',name.encode())
    # Independently valid Core signatures outside the scalar C export ABI.
    value={'schema':'hepta.hia.program.v8','module':'tuple_export','exports':['pair'],
        'functions':[function('pair',['u64'],['u64','u64'],[],['p0','p0'])]}
    result['multiple-results']=assembly(value)
    value={'schema':'hepta.hia.program.v8','module':'unit_parameter','exports':['unit_param'],
        'functions':[function('unit_param',['unit'],['unit'],[],['p0'])]}
    result['unit-parameter']=assembly(value)
    start=wire.index(b'fn private_value(')
    end=wire.index(b'\nend\n',start)
    result['invalid-private-body']=wire[:start]+wire[start:end].replace(b'ret(result)',b'ret(missing)')+wire[end:]
    result['129-defined-exports']=assembly(dense_document(129))
    # Resource exports violate Core itself and must not reach a native wrapper.
    ordinary=b'''hia-asm.v1 hepta.hia.program.v8 resource_export
exports(resource)
fn resource(data:readbuf) -> (usize) effects(read) entry(start)
block start(data:readbuf)
  result:usize = buffer.len(data)
  ret(result)
end
'''
    result['resource']=ordinary
    return result


def compiler_word_cases():
    """Exercise the actual authored word helpers, including ordered partial writes.

    Not a separately reimplemented optimized algorithm: helper bodies below are
    selected from the exact compiler document before any successor is executed.
    """
    from tools.generate_hia_selfhost import document as compiler_document
    compiler,names=compiler_document()
    helpers=[copy.deepcopy(f) for f in compiler['functions'] if f['name'] in (names['get'],names['put'])]
    helper_wire=assembly({'schema':'hepta.hia.program.v8','module':'selfhost','functions':helpers})
    helper_wire=helper_wire[helper_wire.index(b'fn '):]
    header=b'''hia-asm.v1 hepta.hia.program.v8 selfhost
fn f0(s:readbuf,o:mutbuf,w:mutbuf) -> (u32) effects(read,write,trap) entry(start)
block start(s:readbuf,o:mutbuf,w:mutbuf)
'''
    layouts=[(0,n) for n in range(9)]+[(1,8),(1,9),(8,15),(8,16),((1<<64)-1,8)]
    value=0x0123456789abcdef;rows=[]
    for kind in ('get','put'):
        for at,size in layouts:
            initial=bytes((17*i+3)&255 for i in range(size));expected=bytearray(initial)
            body=f'  offset:u64 = const() {{"value":{at}}}\n'
            trapped=at+8>size
            if kind=='put':
                body+=f'  value:u64 = const() {{"value":{value}}}\n  ignored:u64 = call(o,offset,value) {{"function":"{names["put"]}"}}\n'
                body+='  result:u32 = const() {"value":7}\n  ret(result)\nend\n'
                for i in range(8):
                    position=(at+i)&((1<<64)-1)
                    if position>=size:break
                    expected[position]=(value>>(8*i))&255
            else:
                wanted=int.from_bytes(initial[at:at+8],'little') if not trapped else 0
                body+=f'  value:u64 = call(o,offset) {{"function":"{names["get"]}"}}\n  expected:u64 = const() {{"value":{wanted}}}\n'
                body+='  equal:bool = compare.eq(value,expected)\n  yes:u32 = const() {"value":7}\n  no:u32 = const() {"value":0}\n  result:u32 = select(equal,yes,no)\n  ret(result)\nend\n'
            row={'id':f'compiler-word-{kind}-{at}-{size}','source':(header+body.encode()+helper_wire).decode(),
                'source_hex':'','initial_hex':initial.hex(),'expected_hex':expected.hex(),'owned_elf_only':False}
            row['expected_trap' if trapped else 'expected_result']='bounds' if trapped else 7
            rows.append(row)
    return rows
