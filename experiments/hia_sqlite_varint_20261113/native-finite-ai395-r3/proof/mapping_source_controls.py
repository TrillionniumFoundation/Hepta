"""Sixteen pure mapping-observer controls. No real mmap, ctypes, compiler or native call."""
from pathlib import Path
import ast,hashlib,json,os,stat,sys,time,traceback,types
ROOT=Path(__file__).resolve().parent.parent
SUPPORT_SHA='7c0c6df7ceae7b877ef5c3be42f5ce96617618c04d3e09613f5c2eb7b824630b'
NAMES=('named_current_image','unnamed_current_image','wrong_entry_address','wrong_object_length',
       'writable_bound_segment','oversized_span','gapped_segment','nonzero_offset',
       'wrong_deleted_backing','unbound_deleted_file','unbound_exec_anon','backing_alias',
       'image_object_bytes_mismatch','entry_address_bytes_mismatch','entry_changed_after_read',
       'wrapper_changed_after_read')
EXPECTED=(None,None,'original entry equals','image mmap length','shared RX segment','page-rounded',
          'one exact exclusive segment','shared RX segment','anonymous backing representation',
          'unbound deleted mapping','unbound executable','additional mapped alias',
          'complete logical image bytes','complete logical image bytes','identity changed','identity changed')
def identity(s):return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def read(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        s=os.fstat(fd);assert stat.S_ISREG(s.st_mode) and s.st_nlink==1
        b=os.read(fd,s.st_size+1)
        assert len(b)==s.st_size and identity(s)==identity(os.fstat(fd))==identity(Path(path).lstat())
    finally:os.close(fd)
    return b,identity(s)
def wire(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def main():
    assert len(sys.argv)==2
    output=Path(sys.argv[1])
    assert output==ROOT.parent/'varint-native-r3-mapping-controls-actual-r1' and not output.exists()
    output.mkdir(mode=0o700)
    report={'schema':'hia.sqlite.varint.bound-map-pure-controls.v1','status':'HOLD','expected_ids':list(NAMES),
        'loaded_ids':[],'actual_ids':[],'success_ids':[],'rows':[],'exception':None,'denied_effects':[],
        'native_calls':0,'real_maps_or_native_images_created':0,'source8_reexecuted':False}
    started=time.monotonic_ns()
    try:
        raw,before=read(ROOT/'control/support.py')
        assert hashlib.sha256(raw).hexdigest()==SUPPORT_SHA
        assert sys.version_info[:3]==(3,14,4) and sys.flags.isolated==1 and sys.flags.no_site==1 and sys.dont_write_bytecode
        module=ast.parse(raw);functions=[n for n in module.body if isinstance(n,ast.FunctionDef) and n.name=='loaded_file_maps']
        assert len(functions)==1
        code=compile(ast.fix_missing_locations(ast.Module(body=functions,type_ignores=[])),'<frozen-loaded_file_maps-only>','exec')
        def audit(event,args):
            if event in ('subprocess.Popen','os.system','os.exec','os.posix_spawn','os.fork','os.forkpty','pty.spawn','mmap.__new__','sqlite3.connect','ctypes.dlopen','ctypes.dlsym') or event.startswith('socket.'):
                report['denied_effects'].append(event);raise RuntimeError('pure controls denied effect '+event)
        sys.addaudithook(audit)
        report['loaded_ids']=list(NAMES)
        for name,want in zip(NAMES,EXPECTED):
            row={'id':name,'status':'HOLD','expected_refusal':want,'error':None}
            report['rows'].append(row);report['actual_ids'].append(name)
            image=bytes(range(17));state={'maps':'10000-11000 r-xs 00000000 00:01 123 /dev/zero (deleted)\n',
                'creates':{},'address':0x10000,'object_bytes':image,'address_bytes':image,'logical_size':len(image),'reads':0}
            class Pointer:pass
            entry=Pointer();entry.address=0x10000
            installed=object()
            codec=types.SimpleNamespace(_entry=installed,image_sha256=hashlib.sha256(image).hexdigest())
            class Map:
                closed=False
                def __len__(self):return state['logical_size']
                def __getitem__(self,key):
                    assert key==slice(None,None,None)
                    if name=='entry_changed_after_read':entry.address+=4096
                    if name=='wrapper_changed_after_read':codec._entry=object()
                    return state['object_bytes']
            mapped=Map();codec._mapping=mapped
            class FakePath:
                def __init__(self,p):self.p=p.p if isinstance(p,FakePath) else str(p)
                def __str__(self):return self.p
                def __truediv__(self,x):return FakePath(self.p+'/'+str(x))
                def resolve(self,strict=False):return self
                def with_suffix(self,s):return FakePath(self.p+s)
                def read_bytes(self):assert self.p=='/proc/self/maps';return state['maps'].encode()
            imagepin={'path':'/fixed/current-image.bin','bytes':len(image),'sha256':hashlib.sha256(image).hexdigest(),
                      'git_blob':hashlib.sha1(b'blob 17\0'+image).hexdigest(),'identity':[1,2,33152,1000,1000,1,17,3,3]}
            def require(ok,message):
                if not ok:raise RuntimeError(message)
            def image_read(path,maximum):
                assert str(path)==imagepin['path'] and maximum==1<<20
                return dict(imagepin),image
            def create(path,value,raw=False):
                key=str(path);assert key not in state['creates'];state['creates'][key]=value
                return {'path':key,'bytes':len(value) if raw else len(wire(value)),'sha256':hashlib.sha256(value if raw else wire(value)).hexdigest()}
            def string_at(address,n):
                assert address==0x10000 and n==len(image)
                state['reads']+=1;return state['address_bytes']
            cchar=types.SimpleNamespace(from_buffer=lambda m:types.SimpleNamespace(address=state['address']))
            fake_ctypes=types.SimpleNamespace(_CFuncPtr=Pointer,c_void_p=object(),c_char=cchar,
                addressof=lambda x:x.address,cast=lambda e,t:types.SimpleNamespace(value=e.address),string_at=string_at)
            ns={'Path':FakePath,'ROOT':FakePath('/frozen'),'read_json':lambda p:(None,{'files':[]}),
                'common':types.SimpleNamespace(require=require,read=image_read,create=create),
                'mmap':types.SimpleNamespace(mmap=Map,PAGESIZE=4096),'ctypes':fake_ctypes,
                'os':types.SimpleNamespace(sysconf=lambda k:4096,major=os.major,minor=os.minor),
                'hashlib':hashlib,'system_read':lambda p:(_ for _ in ()).throw(AssertionError('unexpected real-file branch'))}
            exec(code,ns)
            if name=='unnamed_current_image':state['maps']='10000-11000 r-xs 00000000 00:00 0\n'
            elif name=='wrong_entry_address':entry.address+=1
            elif name=='wrong_object_length':state['logical_size']+=1
            elif name=='writable_bound_segment':state['maps']=state['maps'].replace('r-xs','rwxs')
            elif name=='oversized_span':state['maps']=state['maps'].replace('10000-11000','10000-12000')
            elif name=='gapped_segment':state['maps']='10000-10800 r-xs 00000000 00:01 123 /dev/zero (deleted)\n10900-11000 r-xs 00000900 00:01 123 /dev/zero (deleted)\n'
            elif name=='nonzero_offset':state['maps']=state['maps'].replace('00000000','00001000')
            elif name=='wrong_deleted_backing':state['maps']=state['maps'].replace('/dev/zero','/other/deleted-image')
            elif name=='unbound_deleted_file':state['maps']+='20000-21000 r-xp 00000000 00:01 124 /other/library (deleted)\n'
            elif name=='unbound_exec_anon':state['maps']+='20000-21000 r-xp 00000000 00:00 0\n'
            elif name=='backing_alias':state['maps']+='20000-21000 r--s 00000000 00:01 123 /dev/zero (deleted)\n'
            elif name=='image_object_bytes_mismatch':state['object_bytes']=b'X'+image[1:]
            elif name=='entry_address_bytes_mismatch':state['address_bytes']=b'X'+image[1:]
            try:
                result=ns['loaded_file_maps']({'system_map':'system.json'},{},codec,entry,installed,imagepin,FakePath('/evidence/'+name))
                if want is not None:raise AssertionError('expected mapping refusal did not occur')
                assert result['image_binding']['logical_bytes']==17 and result['image_binding']['page_rounding_tail_not_hashed_as_image']==4079
                assert result['image_binding']['complete_image_sha256']==imagepin['sha256'] and result['all_executable_mappings_classified'] is True
                assert state['reads']==1
                row['accepted_binding']=result['image_binding']
            except RuntimeError as e:
                if want is None or want not in str(e):raise
                row['observed_refusal']=str(e)
            if name not in ('wrong_entry_address','wrong_object_length'):
                assert state['creates']['/evidence/'+name+'.maps.original']==state['maps'].encode()
                assert '/evidence/'+name+'.binding-start.json' in state['creates']
            row['raw_maps_retained_before_classification']=name not in ('wrong_entry_address','wrong_object_length')
            row['whole_image_address_reads']=state['reads'];row['status']='PASS';report['success_ids'].append(name)
        after,after_id=read(ROOT/'control/support.py')
        assert after==raw and after_id==before
        assert report['expected_ids']==report['loaded_ids']==report['actual_ids']==report['success_ids']
        assert len(report['rows'])==16 and all(x['status']=='PASS' and x['error'] is None for x in report['rows'])
        assert report['denied_effects']==[]
        report['status']='PURE_MAPPING_CONTROLS_16_PASS_ONLY'
    except BaseException as e:
        report['status']='HOLD';report['exception']=type(e).__module__+'.'+type(e).__qualname__+': '+str(e)
        report['traceback']=traceback.format_exc()
    finally:
        report['elapsed_ns']=time.monotonic_ns()-started
        if report['exception'] is not None or report['denied_effects']:report['status']='HOLD'
        with (output/'REPORT.json').open('xb') as f:f.write(wire(report));f.flush();os.fsync(f.fileno())
        print(json.dumps({'status':report['status'],'expected':len(NAMES),'actual':len(report['actual_ids']),
                          'success':len(report['success_ids']),'exception':report['exception']}))
    return 0 if report['status']=='PURE_MAPPING_CONTROLS_16_PASS_ONLY' and report['exception'] is None and report['denied_effects']==[] else 1
if __name__=='__main__':raise SystemExit(main())
