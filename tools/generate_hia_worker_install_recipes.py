"""Author fixed Worker installation recipes for the native HIA DAG owner."""
from pathlib import Path
import argparse,ast,json,struct
from hashlib import sha256
from tools.generate_hia_release_core_recipe import CoreRecipe
from tools.generate_hia_worker_manifest import model
from tools.generate_hia_worker_install_owner import STAGES
from tools.generate_hia_worker_install_bind import PROFILE_IMAGES,REFERENCES
from tools.generate_hia_worker_capsule_check import KINDS
ROOT=Path(__file__).resolve().parents[1]
BOOT=Path('examples/hia_bootstrap')
class WorkerRecipe(CoreRecipe):
    def node(self,operation,args=(),payload=b''):
        if operation in (20,21,22):
            self.nodes.append((operation,0,tuple(args),bytes(payload)));return 0
        return super().node(operation,args,payload)
    def release_dead_views(self):
        def references(op,args):
            if op in (2,3,4,13,14,15,17,21):return args[:1]
            if op in (8,9):return args
            if op==5:return args[4:]
            if op==6:return (args[0],args[2])
            if op==7:return args[:2]
            if op==10:return args[2:]
            if op in (16,19,22):return args
            if op==20:return (args[0],args[2])
            return ()
        last={identity:i for i,(_,identity,_,_) in enumerate(self.nodes) if identity}
        aliases={identity:args[:1] for op,identity,args,_ in self.nodes if op in (2,3,4,15)}
        for i,(op,_,args,_) in enumerate(self.nodes):
            for handle in references(op,args):
                if handle: last[handle]=max(last[handle],i)
        for handle in sorted(aliases,reverse=True):
            for parent in aliases[handle]:last[parent]=max(last[parent],last[handle])
        expire={}
        for handle,index in last.items():expire.setdefault(index,[]).append(handle)
        nodes=[]
        for i,node in enumerate(self.nodes):
            nodes.append(node)
            dead=sorted(expire.get(i,()),reverse=True)
            for at in range(0,len(dead),128):nodes.append((22,0,tuple(dead[at:at+128]),b''))
        self.nodes=nodes
    def publish(self,name,value,mode=0o400,expected=0):
        self.node(20,(value,mode,expected),name.encode());self.published.append(name)
    def retain(self,name,value):
        self.node(21,(value,),name.encode());self.published.append('@'+name)
    def leaf(self,name):return self.policy(name,'source_build_packer.hepta')
    def lp(self,*parts):return self.concat(*(item for part in parts for item in (self.length(part),part)))
    def wire(self,magic,words,parts):return self.concat(self.literal(magic+struct.pack('<'+'Q'*len(words),*words)),self.lp(*parts))
    def manifest(self,mode,role,*parts):
        if not hasattr(self,'framer'):self.framer=self.leaf('source_worker_manifest.hepta')
        if not hasattr(self,'tables'):self.tables=self.source(str(BOOT/'worker_manifest_tables.hiastd'))
        return self.run(self.framer,self.wire(b'HIAWMF01',(mode,role,len(parts)+1),(*parts,self.tables)))
    def bind(self,mode,role,*parts):
        if not hasattr(self,'binder'):self.binder=self.leaf('source_worker_install_bind.hepta')
        return self.run(self.binder,self.wire(b'HIAWIB01',(mode,role,len(parts)),parts))
    def identity(self,mode,*parts):
        if not hasattr(self,'identity_leaf'):self.identity_leaf=self.leaf('source_worker_install_identity.hepta')
        return self.run(self.identity_leaf,self.wire(b'HIAWID01',(mode,len(parts)),parts))
    def hex(self,view):return self.identity(2,view)
    def hexdigest(self,view):return self.hex(self.digest(view))
    def zjoin(self,parts):
        return self.concat(*(item for i,part in enumerate(parts) for item in ((self.literal(b'\0'),part) if i else (part,))))
    def compiler(self):return self.import_product('selfhost.image.bin')
    def inventory(self):return self.import_product('worker-source-inventory.bin')
    def package(self):return self.import_product('worker-package-pin.bin')
    def authority(self,checker,body,mode,ordinal):
        pin=self.digest(body)
        wire=self.concat(self.literal(struct.pack('<8s2Q',b'HIAWCC01',mode,ordinal)),self.length(body),pin,body)
        response=self.run(checker,wire)
        self.node(8,(response,self.concat(self.literal(b'HIAWCO01'),pin)))
        return pin

def helpers(r,m):
    r.compile_paths([h['source'] for h in m['helpers']]);manifests=[]
    for h in m['helpers']:
        source,image=r.source_views[h['source']],r.compiled[h['source']]
        value=r.manifest(1,h['role'],source,image,r.compiler());manifests.append(value)
        if h['installed']:
            r.node(8,(image,r.import_product(h['image_path'])))
            r.node(8,(value,r.import_product(h['name']+'-manifest.json')))
        else:
            r.publish(h['name']+'/'+h['image_path'],image)
            r.publish(h['name']+'/manifest.json',value)
    r.publish('helpers.json',r.manifest(2,0,r.package(),*manifests))

def report(r,m):
    source_paths=['examples/hia_bootstrap/worker_report.hepta','examples/hia_bootstrap/json_wire.hepta'];r.compile_paths(source_paths);manifests=[]
    for i,(name,protocol,path) in enumerate(zip(('policy','wire'),('worker-report','json-wire'),source_paths),1):
        image=r.compiled[path];manifest=r.manifest(3,i,r.source_views[path],image,r.compiler());manifests.append(manifest)
        r.publish('report/'+name+'/'+protocol+'.image.bin',image);r.publish('report/'+name+'/manifest.json',manifest)
    bundle=r.manifest(4,0,*manifests);r.publish('report/manifest.json',bundle)
    r.publish('report.json',r.manifest(5,0,r.import_product('helpers.json'),bundle))
    from tools.hia_artifact_page_worker_recipe import publish_page
    publish_page(r)

def scheduler(r,family):
    paths=[u['source'] for u in family['units']];r.compile_paths(paths+['examples/hia_bootstrap/continuation_policy.hepta']);manifests=[];images=[]
    for unit in family['units']:
        source,image=r.source_views[unit['source']],r.compiled[unit['source']];images.append(image)
        manifest=r.manifest(6,unit['role'],source,image,r.compiler());manifests.append(manifest)
        base=family['name']+'/policy/'+unit['name']+'/'
        r.publish(base+unit['image_path'],image);r.publish(base+'manifest.json',manifest)
    abi=r.source(family['abi_source']);bundle=r.manifest(7,family['role'],abi,r.compiler(),*manifests)
    r.publish(family['name']+'/policy/manifest.json',bundle)
    frame=r.manifest(10,family['role'],abi,r.compiled['examples/hia_bootstrap/continuation_policy.hepta'],*images)
    packer_source=r.source('examples/hia_bootstrap/continuation_inprocess_packer.hepta')
    wire=r.concat(r.literal(b'HIAWCP01'),r.length(packer_source),packer_source,frame)
    aggregate=r.run(r.leaf('source_worker_continuation_pack.hepta'),wire)
    r.publish(family['name']+'/continuation.image.bin',aggregate)
    manifest=r.manifest(8,family['role'],bundle,r.compiler(),aggregate,r.inventory())
    r.publish(family['name']+'/inprocess-manifest.json',manifest)

def profile(r,m):
    scheduler_manifests=[r.import_product(f['name']+'/inprocess-manifest.json') for f in m['families']]
    scheduling=r.manifest(9,0,r.import_product('report.json'),*scheduler_manifests,r.inventory());r.publish('schedulers.json',scheduling)
    refs=[]
    for name,path in REFERENCES:
        product=Path(path).name;raw=r.import_product(product);refs.append(raw)
        if name!='journal_cost':r.publish(path,raw,0o500)
    from tools.hia_artifact_page_worker_recipe import wrap_page
    page=wrap_page(r,scheduling)
    value=r.bind(1,0,r.package(),page,*(r.import_product(name) for _,name,_ in PROFILE_IMAGES),*refs)
    r.publish('worker.json',value)

def backend_sources():
    tree=ast.parse((ROOT/'hepta/hia_program_native.py').read_text())
    fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='_implementation_hash')
    loop=next(n for n in fn.body if isinstance(n,ast.For))
    return ast.literal_eval(loop.iter)

def identity(r,m):
    identity_table=r.source('examples/hia_bootstrap/worker_install_identity_paths.hiastd')
    worker_pin=r.identity(1,r.inventory(),identity_table)
    parts=[]
    if 'native_source_authority' in m:
        from tools.hia_native_worker_source_authority import BACKEND_DOMAIN
        # The complete admitted source map binds every native source byte via
        # its captured digest; do not retain a parallel host-language source hash.
        # The existing machine-plan, ABI, unit source/image and continuation
        # binding terms below are intentionally preserved.
        parts.extend((r.literal(BACKEND_DOMAIN),worker_pin,r.literal(b'\0')))
    else:
        for name in backend_sources():parts.extend((r.literal(name.encode()+b'\0'),r.source('hepta/'+name),r.literal(b'\0')))
    # The complete 37-helper profile deliberately has no machine-encoding selector.
    parts.append(r.literal(b'native-machine-encoding\0\0'))
    plan=r.concat(r.hexdigest(r.source('examples/hia_bootstrap/machine_plan.hepta')),r.literal(b':'),r.hexdigest(r.import_product('machine-plan/machine-plan.image.bin')))
    parts.extend((r.literal(b'native-machine-plan\0'),plan,r.literal(b'\0')))
    continuation_sources=m['continuation_resources']+m['continuation_runtime']
    continuation_pins=[r.hexdigest(r.source(p)) for p in continuation_sources]
    for family in m['families'][1:]:
        kind=family['name'];abi=r.source(family['abi_source'])
        parts.extend((r.literal((kind+'-abi').encode()+b'\0'),abi,r.literal(b'\0')))
        values=[r.literal(('native-'+kind+'-v1').encode()),r.hexdigest(abi),r.hexdigest(r.import_product(kind+'/policy/manifest.json'))]
        for unit in family['units']:
            values.extend((r.literal(unit['source'].encode()),r.hexdigest(r.source(unit['source'])),r.hexdigest(r.import_product(kind+'/policy/'+unit['name']+'/'+unit['image_path']))))
        continuation=r.zjoin([r.literal(b'hepta.hia.native-continuation-inprocess.v1'),r.hexdigest(r.import_product(kind+'/inprocess-manifest.json')),r.hexdigest(r.import_product(kind+'/continuation.image.bin')),*continuation_pins])
        values.append(r.hex(continuation))
        parts.extend((r.literal(('native-'+kind).encode()+b'\0'),r.zjoin(values),r.literal(b'\0')))
    backend=r.digest(r.concat(*parts));catalog=r.digest(r.source('docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json'));profile=r.digest(r.import_product('worker.json'))
    pins=r.concat(catalog,backend,worker_pin,profile);r.retain('worker-identity-pins.bin',pins)

def roles(kind):
    from tools.generate_hia_read_capsule import ROLES as READ
    from tools.generate_hia_readonly_worker_capsule import ROLES,NATIVE_ROLES,replay_inventory
    from tools.generate_hia_worker_evaluate_launcher import inventory
    return READ if kind=='read' else ROLES if kind=='readonly' else NATIVE_ROLES if kind=='native' else inventory() if kind=='evaluate-full' else replay_inventory(intake=kind=='evaluate-intake')

def capsule(r,kind):
    ordinal=KINDS.index(kind)+1;checker=r.leaf('source_worker_capsule_check_'+kind.replace('-','_')+'.hepta');rows=[]
    for i,name in enumerate(roles(kind),1):
        body=r.import_product(name);pin=r.authority(checker,body,2,i)
        rows.append(r.concat(r.q(i),r.length(body),pin))
    row_data=r.concat(*rows);pins=r.import_product('worker-identity-pins.bin');catalog=r.source('docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json')
    roots=r.q(0) if ordinal<=2 else r.import_product('worker-roots.bin');docs=r.empty;artifact=r.empty;compat=r.empty
    if ordinal>1:
        from tools.generate_hia_discovery_bootstrap_plan import BOOTSTRAP_FILES
        docparts=[r.literal(struct.pack('<8sQ',b'HIADBF01',len(BOOTSTRAP_FILES)))]
        for _,name in BOOTSTRAP_FILES:
            source=r.source('docs/'+name);docparts.extend((r.q(len(name)),r.length(source),r.literal(name.encode()),source))
        docs=r.concat(*docparts)
    if ordinal>2:
        compat=r.source('examples/hia_bootstrap/worker_verifier_compat.json')
        request=r.bind(6,0,pins,roots);artifact=r.run(r.import_product('hia-agent-discovery'),request,0)
    raw=r.bind(5,ordinal,pins,catalog,roots,compat,docs,artifact,row_data);r.authority(checker,raw,1,0)
    r.publish(kind+'-worker-capsule.bin',raw)
    r.publish(kind+'-worker.json',r.bind(7,ordinal,raw,r.import_product('hia-agent-'+kind+'-launcher'),r.package()))

def entry(r,m):
    policy='examples/hia_bootstrap/installed_worker_entry.hepta';r.compile_paths([policy])
    config=r.bind(3,0,r.import_product('worker.json'),r.import_product('evaluate-full-worker-capsule.bin'),r.import_product('hia-agent-evaluate-full-launcher'),r.import_product('worker-identity-pins.bin'),r.import_product('worker-roots.bin'),r.package())
    code=r.concat(r.compiled[policy],config,r.length(config));wire=r.concat(r.literal(b'HIAWEP01'),r.length(code),code)
    elf=r.run(r.import_product('hia-installed-worker-entry-pack'),wire,0)
    packer=r.source('examples/hia_bootstrap/installed_worker_entry_packer.hepta');adapter=r.source('tools/hia_installed_worker_entry.S')
    instructions=r.literal((struct.pack('<Q',1)+b'\xe8')*3)
    r.node(10,(2,3,elf,code,packer,adapter,r.q(0,0,0),instructions))
    r.publish('hia-agent-worker',elf,0o500)

def recipes(native_source_authority=None):
    m=model(ROOT,native_source_authority);result={}
    for kind in STAGES:
        r=WorkerRecipe()
        if kind=='helpers':helpers(r,m)
        elif kind=='report':report(r,m)
        elif kind=='profile':profile(r,m)
        elif kind=='identity':identity(r,m)
        elif kind=='entry':entry(r,m)
        elif kind=='configuration':continue
        elif kind.replace('_','-') in KINDS:capsule(r,kind.replace('_','-'))
        else:scheduler(r,next(f for f in m['families'] if f['module']==kind))
        r.release_dead_views()
        result[kind]=r
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--check',action='store_true');p.add_argument('--native-source-authority',type=Path);a=p.parse_args();records=[]
    for kind,r in recipes(a.native_source_authority).items():
        raw=r.binary();target=ROOT/BOOT/('worker_install_'+kind+'.hiastd')
        if a.check:
            if target.read_bytes()!=raw:raise SystemExit(kind+' differs')
        else:target.write_bytes(raw)
        records.append({'kind':kind,'nodes':len(r.nodes),'handles':r.next_handle-1,'published':len(r.published),'bytes':len(raw),'sha256':sha256(raw).hexdigest(),'outputs':r.published})
    print(json.dumps(records,indent=2))
if __name__=='__main__':main()
