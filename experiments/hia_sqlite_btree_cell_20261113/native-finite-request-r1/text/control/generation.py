"""Same-owner new BTREE_CELL source generation. No existing Source12 VM result is replayed."""
from pathlib import Path
import ast,importlib,json,sys,time,traceback
import common,support
ROOT=support.ROOT
def generate(request):
    output=Path(request['output'])/'source-generation';output.mkdir(mode=0o700)
    report={'schema':'hia.sqlite.btree.cell.source-generation.v1','status':'HOLD','exception':None,
            'denied_effects':[],'VM_executed':False,'native_executed':False,
            'new_authoring_in_current_owner':True,'old_cloud_actual_reconstructed':False}
    started=time.monotonic_ns();active=[True]
    import ctypes,mmap,socket,subprocess
    def audit(event,args):
        if active[0] and any(event==x or event.startswith(x) for x in
            ('subprocess.Popen','os.system','os.exec','os.posix_spawn','os.fork','os.forkpty',
             'pty.spawn','mmap.__new__','socket.','sqlite3.connect','ctypes.dlopen','ctypes.dlsym')):
            report['denied_effects'].append(event);raise RuntimeError('source generation forbidden effect: '+event)
    sys.addaudithook(audit)
    try:
        sys.path.insert(0,request['source_root'])
        import hepta,tools
        hepta.__path__.insert(0,str(ROOT/'candidate/inputs/hepta'))
        tools.__path__=[str(ROOT/'candidate/inputs/tools'),*list(tools.__path__)]
        runtime=importlib.import_module('hepta.hia_program_runtime')
        def forbidden_VM(*args,**kwargs):
            report['denied_effects'].append('hepta.hia_program_runtime._Machine')
            raise RuntimeError('source generation must not execute VM')
        runtime._Machine=forbidden_VM
        author=importlib.import_module('tools.generate_hia_sqlite_btree_cell')
        assembly=importlib.import_module('hepta.hia_agent_assembly')
        program_module=importlib.import_module('hepta.hia_program')
        report['inputs']={'author':common.read(ROOT/'candidate/inputs/tools/generate_hia_sqlite_btree_cell.py')[0],
            'test':common.read(ROOT/'candidate/inputs/tests/test_hia_sqlite_btree_cell_source.py')[0]}
        document=author.document();program=program_module.verify_program(document)
        text=assembly.render_assembly(document);raw=text.encode()
        common.require(assembly.assemble_program(text).as_dict()==program.as_dict(),'new Core/render roundtrip')
        common.require(len(raw)<=1<<20 and len(text.split('\n'))<=16384,'original full source caps')
        funcs=document['functions'];blocks=[b for f in funcs for b in f['blocks']]
        ops=sum(len(b['ops']) for b in blocks);ssa=[]
        common.require(len(funcs)==10<=128 and len(blocks)<=1536 and ops<=8192,'original Core total caps')
        def walk(v):
            if isinstance(v,dict):
                for key,item in v.items():
                    if key in ('args','params') and isinstance(item,list):common.require(len(item)<=16,'original arg/edge cap')
                    walk(item)
            elif isinstance(v,list):
                for item in v:walk(item)
            elif isinstance(v,str) and v.startswith('v') and v[1:].isdigit():ssa.append(int(v[1:]))
        walk(document);common.require(ssa and max(ssa)<=2047,'original SSA cap')
        for f in funcs:
            common.require(len(f['blocks'])<=256 and len(f['returns'])<=3,'original per-function caps')
            for block in f['blocks']:
                for op in block['ops']:common.require(len(op.get('out',[]))<=3,'original result cap')
        report['outputs']={'CORE.json':common.create(output/'CORE.json',document),
            'PROGRAM.json':common.create(output/'PROGRAM.json',program.as_dict()),
            'sqlite_btree_cell.hiaasm':common.create(output/'sqlite_btree_cell.hiaasm',raw,raw=True)}
        report['caps']={'functions':len(funcs),'blocks':len(blocks),'operations':ops,
                       'ssa_max':max(ssa),'lines':len(text.split('\n'))}
        common.require(report['denied_effects']==[] and runtime._Machine is forbidden_VM,'new generation guard')
        actual_source=common.read(ROOT/'reference/source12-actual/tests/sqlite_btree_cell.hiaasm',1<<20)
        common.require(raw==actual_source[1] and actual_source[0]['bytes']==40803
            and actual_source[0]['sha256']=='86776116010d389bf65c453917fda929627f3ee564330e56a3e33af32726a6b7',
            'new generation differs from retained actual Source12 assembly')
        report['source12_actual_assembly']=actual_source[0]
        report['roundtrip_equal']=True;report['status']='SOURCE_GENERATION_ONLY'
    except BaseException as exc:
        report['status']='HOLD';report['exception']=type(exc).__module__+'.'+type(exc).__qualname__+': '+str(exc)[:1024]
        report['traceback']=traceback.format_exc();raise
    finally:
        active[0]=False;report['elapsed_ns']=time.monotonic_ns()-started
        if report['exception'] is not None or report['denied_effects']:report['status']='HOLD'
        common.create(output/'GENERATION.json',report)
    return support.inspect_source_generation(request)
