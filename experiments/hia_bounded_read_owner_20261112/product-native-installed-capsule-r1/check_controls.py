"""Finite local control-only checks. No product import, compiler or native call."""
import ast
from hashlib import sha1, sha256
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import time

ROOT=Path(__file__).resolve().parent
CONTROL=ROOT/'control'
OUTPUT=ROOT/'static-checks-r1'
OUTPUT.mkdir(mode=0o700)
sys.dont_write_bytecode=True
sys.path.insert(0,str(CONTROL))

def pin(raw):
    return {'bytes':len(raw),'sha256':sha256(raw).hexdigest(),
            'git_blob_sha1':sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}

def save(name,value):
    with (OUTPUT/name).open('x') as f:
        json.dump(value,f,sort_keys=True,indent=2);f.write('\n')

report={'schema':'hepta.hia.bounded-read-capsule-local-control-checks.v1',
        'status':'HOLD','scope':'LOCAL_PYTHON_STATIC_AND_FINITE_FILESYSTEM_CONTROLS_ONLY',
        'python':sys.version,'product_imported':False,'native_executed':False,
        'compiler_executed':False,'package_built':False,'checks':[],'errors':[],'source_pins':{}}
def check(name,condition):
    report['checks'].append({'id':name,'status':'PASS' if condition else 'FAIL'})
    if not condition:raise AssertionError(name)

try:
    trees={}
    for p in sorted(CONTROL.glob('*.py')):
        raw=p.read_bytes();trees[p.name]=ast.parse(raw,filename=str(p))
        report['source_pins'][p.name]=pin(raw)
    check('all_thirteen_control_Python_parse',len(trees)==13)
    reference=ast.parse((ROOT/'references/controller.py').read_bytes())
    reference_functions={n.name:n for n in reference.body if isinstance(n,ast.FunctionDef)}
    io_names=('_directory_identity','_checked_parent','_read_extent','_create_bytes','_create_directory','read','identity','create')
    for name in ('controller.py','diagnostics.py','source_common.py','package_helper.py','installed_cases.py'):
        functions={n.name:n for n in trees[name].body if isinstance(n,ast.FunctionDef)}
        for method in io_names:
            # Signature includes decorators and default expression syntax.
            check(name+':'+method+':exact_original_AST',
                  ast.dump(functions[method],include_attributes=False)==ast.dump(reference_functions[method],include_attributes=False))
    modules={}
    for name in ('controller','diagnostics','source_common','package_helper','installed_cases'):
        spec=importlib.util.spec_from_file_location('bounded_capsule_local_'+name,CONTROL/(name+'.py'))
        module=importlib.util.module_from_spec(spec)
        sys.modules[spec.name]=module;spec.loader.exec_module(module);modules[name]=module
    check('no_product_import_during_control_loading',not any(n=='hepta' or n.startswith('hepta.') for n in sys.modules))
    for name,module in modules.items():
        base=OUTPUT/name;base.mkdir(mode=0o700)
        regular=base/'original.bin';raw=b'control\0source\xff'
        record=module.create(regular,raw)
        check(name+':real_create_read',module.read(regular,100)[0]==raw and record['bytes']==len(raw))
        def refused(label,fn):
            before=len(list(Path('/proc/self/fd').iterdir()))
            try:fn()
            except (OSError,RuntimeError,AssertionError):pass
            else:raise AssertionError(label+' unexpectedly admitted')
            check(name+':'+label,len(list(Path('/proc/self/fd').iterdir()))==before)
        refused('existing_destination_refused',lambda:module.create(regular,b'overwritten'))
        check(name+':original_after_refusal',module.read(regular,100)[0]==raw)
        refused('bounded_extent_refused',lambda:module.read(regular,1))
        link=base/'leaf-link';link.symlink_to(regular.name)
        refused('leaf_symlink_refused',lambda:module.read(link,100))
        real=base/'real';real.mkdir(mode=0o700);module.create(real/'inside',raw)
        parent_link=base/'parent-link';parent_link.symlink_to(real.name,target_is_directory=True)
        refused('parent_symlink_refused',lambda:module.read(parent_link/'inside',100))
        hard=base/'hard';os.link(regular,hard)
        refused('hardlink_refused',lambda:module.read(regular,100));hard.unlink()
        fifo=base/'fifo';os.mkfifo(fifo,0o600)
        start=time.monotonic();refused('FIFO_refused',lambda:module.read(fifo,100))
        check(name+':FIFO_nonblocking',time.monotonic()-start<1)
        writable=base/'mutable-tool';writable.write_bytes(raw);writable.chmod(0o666)
        refused('writable_system_binary_refused',lambda:module.read(writable,100,system_binary=True))
        writable.chmod(0o444)
        check(name+':immutable_owned_system_binary',module.read(writable,100,system_binary=True)[0]==raw)
        before=len(list(Path('/proc/self/fd').iterdir()))
        for _ in range(16):
            try:module.read(parent_link/'inside',100)
            except (OSError,RuntimeError,AssertionError):pass
            else:raise AssertionError('unexpected parent symlink read')
        check(name+':repeated_failure_no_fd_leak',len(list(Path('/proc/self/fd').iterdir()))==before)
    from native_support import source_manifest
    rows,raw,record=source_manifest(CONTROL/'source-manifest.json')
    check('fixed_manifest_actual_4051',len(rows)==4051)
    inputs,source_rows,declarations,resources=modules['package_helper'].source_inputs(
        Path('/workspace/scratch/hia-bounded-product-v80-20261112-r2/checkout'))
    save('actual-package-inputs.json',{'rows':source_rows,'resource_declarations':declarations,
        'resources':resources,'scope':'READ_ONLY_SOURCE_INPUTS_NO_PACKAGE_BUILD'})
    check('actual_source_170_Python_105_resources',sum(n.startswith('hepta/') and n.endswith('.py') for n in inputs)==170 and len(resources)==105)
    check('helper_child_nine_exact_IDs',modules['package_helper'].IDS==modules['installed_cases'].IDS
          and len(modules['package_helper'].IDS)==9)
    targets=json.loads((CONTROL/'diagnostic-targets.json').read_bytes())['targets']
    records=[{'name':r['name'],'status':'OMITTED_WHOLE_FILE_BUDGET','bytes':16777216,
              'sha256':'f'*64,'git_blob_sha1':'f'*40} for r in targets]
    index={'schema':'hepta.hia.bounded-read-small-channel-index.v1','fixed_targets':len(targets),
        'selected_files':20,'selected_raw_bytes':524288,'raw_limit':524288,'stdout_limit':1048576,
        'observation_raw_bytes':167772160,'boundary':{'current_operation_bound':True,'closed_ECHILD':True,
        'guardian_sha256':'f'*64,'original_product_status_not_changed':True},
        'complete_original_artifact_transport_claimed':False,'product_status_changed':False,'records':records}
    compact=(json.dumps(index,sort_keys=True,separators=(',',':'))+'\n').encode()
    report['complete_compact_index_bytes']=len(compact)
    check('complete_219_ledger_fits_unchanged_64KiB',len(targets)==219 and len(compact)<=65536)
    check('no_product_import_at_end',not any(n=='hepta' or n.startswith('hepta.') for n in sys.modules))
    report['status']='FINITE_CONTROL_CHECKS_PASS_NOT_PRODUCT_OR_INSTALLATION'
except BaseException as error:
    import traceback
    report['errors'].append({'type':type(error).__name__,'traceback':traceback.format_exc()})
finally:
    save('REPORT.json',report)
print(json.dumps({'status':report['status'],'checks':len(report['checks']),'errors':report['errors']}))
raise SystemExit(0 if report['status']=='FINITE_CONTROL_CHECKS_PASS_NOT_PRODUCT_OR_INSTALLATION' else 1)
