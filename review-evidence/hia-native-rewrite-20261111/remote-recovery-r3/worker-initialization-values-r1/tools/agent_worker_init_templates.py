"""Compile immutable literals for complete Worker initialization values.

Development-time source authoring only. The executable projection owns every
runtime substitution. No JSON parser or Python dictionary construction runs in
the application. Templates are exact source-bound read-only program data, not
caller-provided authority or a runtime plan interpreted by the carrier.

This does not replace catalog(), installation_manifest(), namespace effects or
the independent complete verify/render/assemble witnesses in _examples().
"""
from __future__ import annotations
import ast,copy,inspect,json,struct,sys
from hashlib import sha1,sha256
from pathlib import Path

SERVICE_SHA='684caf496de7e3e7c8db1fd80ef616139cf13717aa5879bbd2d6ebf834df9330'
MACRO_SHA='3ee3f31f21719d0eee7414d8bee8ccb046d213ea44310764c21b727eac3c9951'
MAGIC=int.from_bytes(b'HIAWVT01','little')
GRAPH=int.from_bytes(b'HIAGRF01','little')
TEMPLATE_LEASE=0x57565401
MODES={1:'profile_bodies',2:'diagnostics',3:'manifest',
       4:'example_program',5:'example_result',6:'macro_guidance'}
DYNAMIC={1:'identities',2:'catalog_digest',3:'resolved_root_count',
         4:'resolved_roots_digest',5:'profiles',6:'profile_artifacts',
         7:'resources',8:'example_core',9:'example_assembly'}
SERVICE_ATTRIBUTES={'identities':1,'catalog_sha256':2,'profiles':5,
                    'profile_artifacts':6,'resources':7}

class Marker:
    def __init__(self,code):self.code=code
    def __deepcopy__(self,memo):return self

MARKERS={code:Marker(code) for code in DYNAMIC}
def source_blob(raw):
    return dict(bytes=len(raw),sha256=sha256(raw).hexdigest(),
        gitsha=sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest())

def method(tree,name):
    cls=next(node for node in tree.body if isinstance(node,ast.ClassDef)
             and node.name=='HIAAgentService')
    return next(node for node in cls.body if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef))
                and node.name==name)

def is_attr(node,name):
    return (isinstance(node,ast.Attribute) and isinstance(node.value,ast.Name)
            and node.value.id=='self' and node.attr==name)

class DynamicValues(ast.NodeTransformer):
    def __init__(self):self.used=[]
    def marker(self,original,code):
        self.used.append(code)
        return ast.copy_location(ast.Name(id='__dynamic_'+str(code),ctx=ast.Load()),original)
    def visit_Attribute(self,node):
        if isinstance(node.value,ast.Name) and node.value.id=='self':
            assert node.attr in SERVICE_ATTRIBUTES,ast.dump(node)
            return self.marker(node,SERVICE_ATTRIBUTES[node.attr])
        return self.generic_visit(node)
    def visit_Call(self,node):
        if isinstance(node.func,ast.Name) and node.func.id=='len':
            if len(node.args)==1 and is_attr(node.args[0],'artifact_roots') and not node.keywords:
                return self.marker(node,3)
        if isinstance(node.func,ast.Name) and node.func.id=='digest':
            expected=ast.parse('digest([str(root) for root in self.artifact_roots])',mode='eval').body
            assert ast.dump(node)==ast.dump(expected),ast.dump(node)
            return self.marker(node,4)
        if isinstance(node.func,ast.Attribute) and isinstance(node.func.value,ast.Name):
            if node.func.value.id=='program' and node.func.attr=='as_dict':
                assert not node.args and not node.keywords
                return self.marker(node,8)
        if isinstance(node.func,ast.Name) and node.func.id=='deepcopy':
            assert len(node.args)==1 and isinstance(node.args[0],ast.Name)
            assert node.args[0].id=='installation' and not node.keywords
            return self.marker(node,1)
        return self.generic_visit(node)
    def visit_Name(self,node):
        if node.id=='assembly':return self.marker(node,9)
        return node

def expression(node,namespace):
    transformer=DynamicValues()
    tree=ast.Expression(body=transformer.visit(copy.deepcopy(node)))
    tree=ast.fix_missing_locations(tree)
    env=dict(namespace)
    env.update({'__dynamic_'+str(code):value for code,value in MARKERS.items()})
    # This evaluation compiles static source literals only, before HIA generation.
    # Runtime identities and references are Marker nodes, never fabricated values.
    value=eval(compile(tree,'<exact-worker-initialization-literals>','eval'),env,{})
    return value,transformer.used,ast.unparse(tree)+'\n'

def source_values(reference):
    reference=Path(reference).resolve()
    service_path=reference/'hepta/hia_agent_service.py'
    macro_path=reference/'hepta/hia_agent_macro_discovery.py'
    raw=service_path.read_bytes();macro_raw=macro_path.read_bytes()
    assert sha256(raw).hexdigest()==SERVICE_SHA
    assert sha256(macro_raw).hexdigest()==MACRO_SHA
    sys.path.insert(0,str(reference))
    from hepta import hia_agent_service as service
    from hepta import hia_program_native as program_native
    from hepta import hia_safe_core as safe_core
    from hepta import hia_agent_macro_discovery as macro
    assert Path(service.__file__).resolve()==service_path
    assert Path(macro.__file__).resolve()==macro_path
    namespace=dict(vars(service))
    for key in ('TARGET','PROFILE','SUPPORTED_OPCODES','CORE_SCHEMAS','IMPORTS'):
        namespace[key]=getattr(program_native,key)
    for key in ('ARTIFACT_PROFILE','LIMITS'):
        namespace[key]=getattr(safe_core,key)
    namespace['common']={'implementation':MARKERS[1],'catalog_sha256':MARKERS[2]}
    tree=ast.parse(raw)
    profiles=method(tree,'_profiles')
    expressions={}
    bodies=next(stmt.value for stmt in profiles.body
        if isinstance(stmt,ast.Assign) and len(stmt.targets)==1
        and isinstance(stmt.targets[0],ast.Name) and stmt.targets[0].id=='bodies')
    expressions[1]=(bodies,namespace)
    for stmt in profiles.body:
        if not isinstance(stmt,ast.Assign) or len(stmt.targets)!=1:continue
        target=stmt.targets[0]
        if is_attr(target,'manifest'):
            assert isinstance(stmt.value,ast.Call) and len(stmt.value.args)==2
            expressions[3]=(stmt.value.args[0],namespace)
        elif isinstance(target,ast.Subscript) and is_attr(target.value,'resources'):
            if isinstance(target.slice,ast.Constant) and target.slice.value=='diagnostics':
                assert isinstance(stmt.value,ast.Call) and len(stmt.value.args)==2
                expressions[2]=(stmt.value.args[0],namespace)
    example=method(tree,'_examples')
    example_env=dict(namespace)
    params=next(stmt.value for stmt in example.body
        if isinstance(stmt,ast.Assign) and isinstance(stmt.targets[0],ast.Name)
        and stmt.targets[0].id=='params')
    example_env['params']=ast.literal_eval(params)
    document=next(stmt.value for stmt in example.body
        if isinstance(stmt,ast.Assign) and isinstance(stmt.targets[0],ast.Name)
        and stmt.targets[0].id=='document')
    expressions[4]=(document,example_env)
    result=next(stmt.value for stmt in example.body if isinstance(stmt,ast.Return))
    expressions[5]=(result,example_env)
    macro_tree=ast.parse(macro_raw)
    macro_function=next(node for node in macro_tree.body
        if isinstance(node,ast.FunctionDef) and node.name=='macro_policy_guidance')
    macro_result=next(stmt.value for stmt in macro_function.body if isinstance(stmt,ast.Return))
    expressions[6]=(macro_result,vars(macro))
    assert set(expressions)==set(MODES)
    values={};origins={}
    for mode,(node,env) in expressions.items():
        value,used,authored=expression(node,env)
        values[mode]=value
        origins[mode]=dict(mode=mode,name=MODES[mode],dynamic_marker_occurrences=used,
            expression_sha256=sha256(authored.encode()).hexdigest(),expression=authored)
    assert list(values[1])==['compiler','target','backend','artifact','validation','lowering','plan']
    assert origins[1]['dynamic_marker_occurrences'].count(3)==1
    assert origins[1]['dynamic_marker_occurrences'].count(4)==1
    assert values[4]['schema']=='hepta.hia.program.v6'
    assert values[4]['functions'][0]['params'] is values[4]['functions'][0]['blocks'][0]['params']
    assert type(values[5]['objective']['min_improvement_ratio']) is float
    assert values[5]['objective']['min_improvement_ratio']==0.0
    dependencies=[]
    for module in tuple(sys.modules.values()):
        file=getattr(module,'__file__',None)
        if not file:continue
        path=Path(file).resolve()
        if path.suffix=='.py' and path.is_relative_to(reference):
            payload=path.read_bytes()
            dependencies.append(dict(path=str(path),relative=path.relative_to(reference).as_posix(),
                **source_blob(payload),mode=path.stat().st_mode & 0o777))
    assert service_path.read_bytes()==raw and macro_path.read_bytes()==macro_raw
    return values,origins,sorted(dependencies,key=lambda row:row['relative'])

def graph(value,lease):
    """Exact immutable constant encoding. Runtime substitutions happen in HIA."""
    nodes=[];edges=[];pool=bytearray();seen={};markers={}
    def walk(value):
        container=type(value) in (list,tuple,dict)
        marker=isinstance(value,Marker)
        if container or marker:
            key=id(value)
            if key in seen:return seen[key]
        identifier=len(nodes)+1;nodes.append(None)
        if container or marker:seen[id(value)]=identifier
        kind=0;at=0;size=0;first=0;count=0;identity=0;aux=0
        if value is None:pass
        elif type(value) is bool:kind=1;aux=int(value)
        elif type(value) is int:
            kind=2;aux=int(value<0);magnitude=abs(value)
            raw=magnitude.to_bytes((magnitude.bit_length()+7)//8,'little')
            at=len(pool);size=len(raw);pool.extend(raw)
        elif type(value) is float:
            kind=3;at=len(pool);size=8;pool.extend(struct.pack('<d',value))
        elif type(value) is str:
            kind=4;raw=value.encode('utf-8','surrogatepass')
            at=len(pool);size=len(raw);aux=len(value);pool.extend(raw)
        elif container:
            kind={list:5,dict:6,tuple:7}[type(value)]
            identity=identifier;count=len(value);first=len(edges)
            length=count*(2 if kind==6 else 1)
            edges.extend([0]*length)
            iterable=[part for item in value.items() for part in item] if kind==6 else value
            for index,part in enumerate(iterable):edges[first+index]=walk(part)
        elif marker:
            kind=8;assert value.code in DYNAMIC
            assert value.code not in markers;markers[value.code]=identifier
        else:raise TypeError(type(value))
        nodes[identifier-1]=[kind,at,size,first,count,identity,aux,0]
        return identifier
    root=walk(value);database=64+len(nodes)*64+len(edges)*8
    for row in nodes:
        if row[0] in (2,3,4,9):row[1]+=database
    raw=struct.pack('<8Q',GRAPH,lease,len(nodes),root,len(edges),len(pool),database+len(pool),0)
    raw+=b''.join(struct.pack('<8Q',*row) for row in nodes)
    raw+=b''.join(struct.pack('<Q',identifier) for identifier in edges)+pool
    return raw,markers

def build(reference,output):
    output=Path(output);output.mkdir(parents=True,exist_ok=False)
    values,origins,dependencies=source_values(reference)
    size=64+128*len(MODES);packet=bytearray(size);rows=[]
    struct.pack_into('<8Q',packet,0,MAGIC,1,len(MODES),0,128,64,0,0)
    for mode in MODES:
        while len(packet)%8:packet.append(0)
        at=len(packet);payload,markers=graph(values[mode],TEMPLATE_LEASE+mode)
        packet.extend(payload)
        row=[mode,at,len(payload),TEMPLATE_LEASE+mode]
        row.extend(markers.get(code,0) for code in range(1,10));row.extend([0]*3)
        assert len(row)==16
        struct.pack_into('<16Q',packet,64+(mode-1)*128,*row)
        (output/(MODES[mode]+'.graph.bin')).write_bytes(payload)
        rows.append(dict(mode=mode,name=MODES[mode],offset=at,**source_blob(payload),
            placeholders=markers,template_lease=TEMPLATE_LEASE+mode))
    struct.pack_into('<Q',packet,24,len(packet))
    path=output/'initialization-literals.bin';path.write_bytes(packet)
    for row in dependencies:
        raw=Path(row['path']).read_bytes()
        assert source_blob(raw)=={key:row[key] for key in ('bytes','sha256','gitsha')}
        assert Path(row['path']).stat().st_mode & 0o777==row['mode']
    manifest=dict(schema='hia-worker-initialization-constant-templates-v1',
        status='SOURCE_BOUND_STATIC_DATA_NOT_RUNTIME_QUALIFICATION',
        packet=dict(path=str(path),**source_blob(packet)),modes=rows,
        exact_source_expressions=origins,dependencies=dependencies,
        dynamic_values_created_by_HIA=True,runtime_host_template_interpretation=False,
        native_entries=0,whole_worker_closed=False)
    (output/'manifest.json').write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n')
    print(json.dumps({key:manifest[key] for key in ('schema','status','packet','modes','native_entries')},
        sort_keys=True),flush=True)
    return manifest

if __name__=='__main__':
    assert len(sys.argv)==3
    build(Path(sys.argv[1]),Path(sys.argv[2]))
