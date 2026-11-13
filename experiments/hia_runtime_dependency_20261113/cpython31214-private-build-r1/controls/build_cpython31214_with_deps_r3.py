"""Private CPython dependency build; no HIA product qualification or activation."""
import hashlib,json,os,shutil,subprocess,sys,time,traceback
from pathlib import Path
ROOT=Path('/home/qq/hia-rewrite-20261113-e26e-r1/cpython31214-r2')
ORIGIN=Path('/home/qq/hia-rewrite-20261113-e26e-r1/cpython31214-r1')
DEPS=ORIGIN/'development-packages-r1/extracted'
LINKS=ROOT/'dependency-links'
SOURCE=ORIGIN/'Python-3.12.14'
BUILD=ROOT/'build'
PREFIX=ROOT/'prefix'
def write(name,value):
    raw=(json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
    with (ROOT/name).open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    return {'path':str(ROOT/name),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def pin(p):
    p=Path(p).resolve(strict=True);b=p.read_bytes();s=p.stat()
    return {'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),
        'mode':s.st_mode,'dev':s.st_dev,'ino':s.st_ino,'mtime_ns':s.st_mtime_ns,'ctime_ns':s.st_ctime_ns}
def main():
    os.umask(0o077)
    ROOT.mkdir(mode=0o700)
    LINKS.mkdir(mode=0o700)
    libraries={}
    for label,soname in (('ffi','libffi.so.8'),('bz2','libbz2.so.1.0'),('lzma','liblzma.so.5'),('sqlite3','libsqlite3.so.0')):
        target=(Path('/usr/lib/x86_64-linux-gnu')/soname).resolve(strict=True)
        libraries[label]=pin(target)
        os.symlink(str(target),LINKS/('lib'+label+'.so'))
    for relative in ('usr/include/x86_64-linux-gnu/ffi.h','usr/include/x86_64-linux-gnu/ffitarget.h','usr/include/bzlib.h','usr/include/lzma.h','usr/include/sqlite3.h'):
        assert (DEPS/relative).is_file(),relative
    write('PRIVATE-DEPENDENCY-INPUTS.json',{'libraries':libraries,'development_packages':json.loads((ORIGIN/'development-packages-r1/EXTRACT-RETURN.json').read_bytes()),'links':str(LINKS),'headers':str(DEPS/'usr/include'),'system_install':False})
    assert hashlib.sha256((ORIGIN/'Python-3.12.14.tar.xz').read_bytes()).hexdigest()=='5c8462af5790baf43a321a1559dbe0db06d1be4300fb85fb53c40060668e548a'
    inventory_raw=(ORIGIN/'SOURCE-INVENTORY.json').read_bytes()
    assert hashlib.sha256(inventory_raw).hexdigest()=='7dd68c668c108b14146bf22c1f486ea38da09b17198b21c71c940bb8c1760092'
    inventory=json.loads(inventory_raw)
    before={}
    for row in inventory['members']:
        if 'sha256' not in row:continue
        p=ORIGIN/row['name'];b=p.read_bytes()
        assert len(b)==row['size'] and hashlib.sha256(b).hexdigest()==row['sha256'],row['name']
        before[row['name']]=row['sha256']
    BUILD.mkdir(mode=0o700);(BUILD/'tmp').mkdir(mode=0o700)
    tools={}
    for name in ('gcc','make','ar','ranlib','ld','nm','readelf','pkg-config','bash'):
        found=shutil.which(name,path='/usr/bin:/bin')
        assert found,name
        tools[name]=pin(found)
    env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','LC_ALL':'C.UTF-8','TZ':'UTC',
        'TMPDIR':str(BUILD/'tmp'),'PYTHONDONTWRITEBYTECODE':'1','PYTHONHASHSEED':'0',
        'CONFIG_SITE':'/dev/null','CC':tools['gcc']['path'],
        'CFLAGS':'-O2 -g -fwrapv -fno-omit-frame-pointer -fkeep-static-functions',
        'AR':tools['ar']['path'],'RANLIB':tools['ranlib']['path'],'SOURCE_DATE_EPOCH':'1786543074',
        'LDFLAGS':'-L'+str(LINKS),
        'LIBFFI_CFLAGS':'-I'+str(DEPS/'usr/include/x86_64-linux-gnu'),'LIBFFI_LIBS':'-L'+str(LINKS)+' -lffi',
        'BZIP2_CFLAGS':'-I'+str(DEPS/'usr/include'),'BZIP2_LIBS':'-L'+str(LINKS)+' -lbz2',
        'LIBLZMA_CFLAGS':'-I'+str(DEPS/'usr/include'),'LIBLZMA_LIBS':'-L'+str(LINKS)+' -llzma',
        'LIBSQLITE3_CFLAGS':'-I'+str(DEPS/'usr/include'),'LIBSQLITE3_LIBS':'-L'+str(LINKS)+' -lsqlite3'}
    steps=[
      ('configure',[tools['bash']['path'],str(SOURCE/'configure'),'--prefix='+str(PREFIX),
        '--disable-shared','--without-pydebug','--disable-optimizations','--without-lto','--without-ensurepip'],180),
      ('make',[tools['make']['path'],'-j4'],600),
      ('altinstall',[tools['make']['path'],'-j4','altinstall','COMPILEALL_OPTS=-j4'],300)]
    intent={'schema':'hia.private-cpython-build.v1','status':'DEPENDENCY_BUILD_ONLY',
        'source_sha256':inventory['archive_sha256'],'source_inventory_sha256':hashlib.sha256(inventory_raw).hexdigest(),
        'source':str(SOURCE),'build':str(BUILD),'prefix':str(PREFIX),'environment':env,
        'tools':tools,'steps':steps,'durable_job_timeout_seconds':1200,'stage_process_group_cleanup':True,
        'earlier_369_launch_rejected_before_worker_execution':True,
        'HIA_qualification_seconds_unchanged':180,'source_files':len(before),'source_bytes':sum(r['size'] for r in inventory['members']),
        'system_install':False,'HIA_product_execution':False}
    write('BUILD-INTENT.json',intent)
    result={'schema':'hia.private-cpython-build-result.v1','status':'HOLD','steps':[],
        'exception':None,'HIA_product_execution':False,'inherited_binary_qualification':False}
    started=time.monotonic_ns()
    try:
        for label,argv,limit in steps:
            step={'label':label,'argv':argv,'cwd':str(BUILD),'timeout_seconds':limit,'start_mono_ns':time.monotonic_ns()}
            write(label.upper()+'-INTENT.json',step)
            with (ROOT/(label+'.stdout')).open('xb') as out,(ROOT/(label+'.stderr')).open('xb') as err:
                process=subprocess.Popen(argv,cwd=BUILD,env=env,stdin=subprocess.DEVNULL,stdout=out,stderr=err,start_new_session=True,close_fds=True)
                try:
                    returncode=process.wait(timeout=limit)
                except BaseException:
                    try:os.killpg(process.pid,9)
                    except ProcessLookupError:pass
                    process.wait(timeout=10)
                    raise
                completed=subprocess.CompletedProcess(argv,returncode)
                out.flush();os.fsync(out.fileno());err.flush();os.fsync(err.fileno())
            step.update(returncode=completed.returncode,elapsed_ns=time.monotonic_ns()-step['start_mono_ns'],
                stdout=pin(ROOT/(label+'.stdout')),stderr=pin(ROOT/(label+'.stderr')))
            write(label.upper()+'-RETURN.json',step);result['steps'].append(step)
            assert completed.returncode==0,step
        executable=PREFIX/'bin/python3.12'
        probe="import ctypes,mmap,sys,sysconfig,struct,hashlib,json,ssl,zlib,bz2,lzma,resource,sqlite3;assert sys.version_info[:3]==(3,12,14);assert struct.calcsize('P')==8;assert not sysconfig.get_config_var('Py_DEBUG');assert not sysconfig.get_config_var('Py_TRACE_REFS');assert not sysconfig.get_config_var('Py_GIL_DISABLED');print(json.dumps({'version':sys.version,'executable':sys.executable,'prefix':sys.prefix,'include':sysconfig.get_path('include'),'config_header':sysconfig.get_config_h_filename(),'SOABI':sysconfig.get_config_var('SOABI'),'CONFIG_ARGS':sysconfig.get_config_var('CONFIG_ARGS'),'CFLAGS':sysconfig.get_config_var('CFLAGS'),'Py_DEBUG':sysconfig.get_config_var('Py_DEBUG'),'Py_GIL_DISABLED':sysconfig.get_config_var('Py_GIL_DISABLED'),'Py_ENABLE_SHARED':sysconfig.get_config_var('Py_ENABLE_SHARED'),'ctypes':ctypes.__file__},sort_keys=True))"
        checks=[('runtime-probe',[str(executable),'-I','-S','-B','-c',probe]),
                ('elf-sections',[tools['readelf']['path'],'-S','-W',str(executable)]),
                ('elf-symbols',[tools['readelf']['path'],'-s','-W',str(executable)])]
        for label,argv in checks:
            with (ROOT/(label+'.stdout')).open('xb') as out,(ROOT/(label+'.stderr')).open('xb') as err:
                p=subprocess.run(argv,cwd=BUILD,env=env,stdin=subprocess.DEVNULL,stdout=out,stderr=err,timeout=30,check=False)
                out.flush();os.fsync(out.fileno());err.flush();os.fsync(err.fileno())
            assert p.returncode==0,(label,p.returncode)
        assert 'SYMTAB' in (ROOT/'elf-sections.stdout').read_text()
        source_changes=[]
        for name,sha in before.items():
            if hashlib.sha256((ORIGIN/name).read_bytes()).hexdigest()!=sha:source_changes.append(name)
        assert not source_changes,source_changes
        prefix_files=[]
        for p in sorted(PREFIX.rglob('*')):
            if p.is_symlink():
                prefix_files.append({'path':str(p),'symlink':os.readlink(p),'resolved':str(p.resolve(strict=True))})
            elif p.is_file():prefix_files.append(pin(p))
        result.update(status='PRIVATE_CPYTHON_31214_BUILT_UNQUALIFIED_FOR_HIA',runtime=pin(executable),
            runtime_probe=json.loads((ROOT/'runtime-probe.stdout').read_bytes()),
            full_original_source_bytes_unchanged=True,prefix_files=len(prefix_files),
            prefix_inventory=write('PREFIX-INVENTORY.json',prefix_files),
            source_internal_headers=str(SOURCE/'Include/internal'),installed_internal_headers=str(PREFIX/'include/python3.12/internal'),
            build_config_header=pin(BUILD/'pyconfig.h'),installed_config_header=pin(PREFIX/'include/python3.12/pyconfig.h'),
            Makefile=pin(BUILD/'Makefile'),config_status=pin(BUILD/'config.status'),
            full_symtab_retained=True,driver_symbols_and_code_mappings_still_require_fresh_admission=True)
    except BaseException as e:
        result['exception']={'type':type(e).__name__,'message':str(e),'traceback':traceback.format_exc()}
    finally:
        result['elapsed_ns']=time.monotonic_ns()-started
        write('BUILD-RETURN.json',result)
    print(json.dumps({'status':result['status'],'elapsed_ns':result['elapsed_ns'],'exception':result['exception'],
        'runtime':result.get('runtime')},sort_keys=True))
    return 0 if result['exception'] is None else 1
if __name__=='__main__':raise SystemExit(main())
