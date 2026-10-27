#!/usr/bin/env python3
"""Capture retained HIA data; never execute native or qualification programs."""
import ast
import base64
from datetime import datetime, timezone
import hashlib
import importlib.util
import io
import json
import lzma
from pathlib import Path
import stat
import subprocess
import sys
import tarfile

ROOT = Path('/workspace/scratch/c7c6ee414a6c/hepta-research')
OUT = Path('/workspace/scratch/c7c6ee414a6c/hepta-cpp/evidence/resource_composition_20261026/hia_candidate')
sys.path.insert(0, str(OUT))
import audit

def sha(data): return hashlib.sha256(data).hexdigest()
def wire(data): return json.dumps(data, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
def emit(name, data):
    raw = (json.dumps(data, indent=2, sort_keys=True, allow_nan=False)+'\n').encode() if not isinstance(data, bytes) else data
    with (OUT/name).open('xb') as stream: stream.write(raw)
    return {'bytes':len(raw), 'sha256':sha(raw)}
def git(*args): return subprocess.check_output(['git','-C',str(ROOT),*args], timeout=30)
def stable(path):
    first = path.lstat()
    assert stat.S_ISREG(first.st_mode)
    data = path.read_bytes()
    after = path.lstat()
    fields=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_mode)
    assert fields(first)==fields(after) and len(data)==first.st_size
    return data, stat.S_IMODE(first.st_mode)

assert git('rev-parse','HEAD').decode().strip()==audit.COMMIT
members, metadata = {}, []
def add(name,path):
    assert name not in members
    raw,mode=stable(path)
    members[name]=raw
    metadata.append({'path':name,'bytes':len(raw),'sha256':sha(raw),'mode':mode,'original_path':str(path)})
inventory={}
for label, number in [('attempt1',1),('attempt2',2)]:
    directory=ROOT/f'artifacts/composition-hia-20261026-run{number}'
    found=[]
    for path in sorted(directory.rglob('*')):
        mode=path.lstat().st_mode
        assert not path.is_symlink()
        if stat.S_ISDIR(mode): continue
        assert stat.S_ISREG(mode)
        relative=path.relative_to(directory).as_posix()
        add(label+'/'+relative,path);found.append(relative)
    inventory[label]={'original_directory':str(directory),'files':len(found),
        'bytes':sum(len(data) for name,data in members.items() if name.startswith(label+'/')),
        'relative_paths_sha256':sha(wire(found)),'symlinks_or_special_files':0}
external={
    'attempt1-driver.log':'hepta-composition-hia-20261026-run1.log',
    'attempt2-driver.log':'hepta-composition-hia-20261026-run2.log',
    'attempt2-job.json':'hepta-composition-hia-20261026-run2.job.json',
    'attempt2-spec.json':'hepta-composition-hia-20261026-run2.spec.json',
    'attempt2-supervisor.log':'hepta-composition-hia-20261026-run2.supervisor.log',
    'supervisor.py':'hepta_hia_qualification_job_20261026.py',
}
for name, filename in external.items(): add('runner/'+name,Path('/tmp',filename))
assert inventory['attempt1']['files']==2 and inventory['attempt2']['files']==721 and len(members)==729

review=audit.review(members)
emit('review.json',review)
for output, member in {'qualification.json':'attempt2/qualification.json',
        'performance.json':'attempt2/performance.json',
        'attempt1-interruption-observation.json':'attempt1/interruption-observation.json',
        **{name:'runner/'+name for name in external if name!='supervisor.py'}}.items():
    emit(output,members[member])

# Pure AST/source comparison against the preserved parent protocol. Production
# qualifiers are neither imported nor executed. The earlier independent review
# supplies only its read-only Git/AST helper.
previous=OUT.parents[1]/'composition_performance_review_20261027/review.py'
spec=importlib.util.spec_from_file_location('earlier_independent_review',previous)
helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
frozen=helper.FrozenSources(ROOT)
baseline=git('rev-parse','bdb8690').decode().strip()
path='tools/qualify_hia_program_perf.py'
def constant(node, context):
    if isinstance(node, ast.Constant):return node.value
    if isinstance(node,ast.Name):return context[node.id]
    if isinstance(node,(ast.List,ast.Tuple)):
        result=[constant(value,context) for value in node.elts]
        return tuple(result) if isinstance(node,ast.Tuple) else result
    if isinstance(node,ast.Dict):
        result={}
        for key,value in zip(node.keys,node.values):
            if key is None:result.update(constant(value,context))
            else:result[constant(key,context)]=constant(value,context)
        return result
    if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=='str' and len(node.args)==1 and not node.keywords:
        return str(constant(node.args[0],context))
    raise ValueError(ast.dump(node))
def protocol(revision):
    definitions=frozen.definitions(revision,path)
    context={'BUILD_ROOT':'/tmp','ORIGINAL_PROTOCOL':frozen.protocol(revision,'owned')}
    for name in ('BUILD_PREFIX','BUILD_SUFFIX_CHARACTERS','BUILD_LAYOUT'):
        context[name]=constant(definitions[name][0],context)
    return constant(definitions['PROTOCOL'][0],context)
current,old=protocol(audit.COMMIT),protocol(baseline)
assert wire(current)==wire(old)==wire(audit.parse(members['attempt2/performance.json'])['protocol'])
assert sha(wire(current))==audit.PROTOCOL_SHA
comparisons={'files':{},'definitions':{}}
for name in ('tools/qualify_hia_unified.py','tools/qualify_hia_program_perf.py',
             'examples/hia_program/benchmarks.hepta','examples/hia_program/perf_driver.c',
             'examples/llvm_owned/reference.rs','examples/llvm_owned/observe.c'):
    older,newer=frozen.read(baseline,name),frozen.read(audit.COMMIT,name)
    assert older==newer
    comparisons['files'][name]={'candidate_sha256':sha(newer),'baseline_sha256':sha(older),'exact_bytes_equal':True}
for name in ('PROTOCOL','KERNELS','BACKENDS','CALLS','SIZES','evaluate_samples','sample_order',
             'oracle','correctness_cases','timed_checksum','execute','driver_commands'):
    older=frozen.definitions(baseline,'tools/qualify_llvm_owned.py')[name][1].encode()
    newer=frozen.definitions(audit.COMMIT,'tools/qualify_llvm_owned.py')[name][1].encode()
    assert older==newer
    comparisons['definitions']['tools/qualify_llvm_owned.py:'+name]={
        'candidate_sha256':sha(newer),'baseline_sha256':sha(older),'exact_bytes_equal':True}
emit('protocol-review.json',{'schema':'hepta.hia-candidate.protocol-review.v1',
    'baseline_commit':baseline,'candidate_commit':audit.COMMIT,
    'expanded_protocol_sha256':audit.PROTOCOL_SHA,'expanded_protocol_equal':True,
    'comparisons':comparisons,
    'scope':'read-only Git-object/AST comparison; HIA v3 stable original-kernel-index ordering remains distinct from historical source-owned ordering',
    'production_sources_imported':False,'production_evaluate_samples_called':False})

# Recheck the complete input inventories before sealing. Directory traversal is
# read-only and all members are ordinary files; no temporary native rebuilds.
for row in metadata:
    raw, mode=stable(Path(row['original_path']))
    assert len(raw)==row['bytes'] and sha(raw)==row['sha256'] and mode==row['mode']
for label,number in [('attempt1',1),('attempt2',2)]:
    directory=ROOT/f'artifacts/composition-hia-20261026-run{number}'
    current_paths=sorted(p.relative_to(directory).as_posix() for p in directory.rglob('*') if p.is_file())
    assert sha(wire(current_paths))==inventory[label]['relative_paths_sha256']

buffer=io.BytesIO()
with tarfile.open(fileobj=buffer,mode='w',format=tarfile.USTAR_FORMAT) as archive:
    for row in sorted(metadata,key=lambda value:value['path']):
        header=tarfile.TarInfo(row['path']);header.size=row['bytes'];header.mode=row['mode']
        header.mtime=header.uid=header.gid=0;header.uname=header.gname=''
        archive.addfile(header,io.BytesIO(members[row['path']]))
tar_bytes=buffer.getvalue()
print(json.dumps({'phase':'compressing','members':len(members),'member_bytes':sum(map(len,members.values())),
                  'tar_bytes':len(tar_bytes),'compression':'xz-preset-6-dict-64MiB'}),flush=True)
packed=lzma.compress(tar_bytes,format=lzma.FORMAT_XZ,check=lzma.CHECK_CRC64,
                     filters=[{'id':lzma.FILTER_LZMA2,'preset':6,'dict_size':64*1024*1024}])
encoded=base64.b64encode(packed)
chunk_size=3_499_996
parts=[]
count=(len(encoded)+chunk_size-1)//chunk_size
for index in range(count):
    name='run-artifacts.tar.xz.b64'+('' if count==1 else '.part%02d'%(index+1))
    data=encoded[index*chunk_size:(index+1)*chunk_size]+b'\n'
    parts.append({'path':name,**emit(name,data)})
combined=b''.join((OUT/part['path']).read_bytes() for part in parts)
manifest={'schema':'hepta.hia-candidate.archive.v1','archive':'run-artifacts.tar.xz.b64',
    'encoding':'base64','compression':'xz-preset-6-dict-64MiB','parts':parts,
    'encoded_bytes':len(combined),'encoded_sha256':sha(combined),'decoded_bytes':len(packed),'decoded_sha256':sha(packed),
    'tar_bytes':len(tar_bytes),'tar_sha256':sha(tar_bytes),'member_count':len(members),
    'uncompressed_bytes':sum(map(len,members.values())),'members':sorted(metadata,key=lambda value:value['path'])}
emit('run-artifacts.manifest.json',manifest)
emit('archive-scope.json',{'schema':'hepta.hia-candidate.archive-scope.v1',
    'captured_utc':datetime.now(timezone.utc).isoformat(),'tested_source_commit':audit.COMMIT,
    'source_snapshot_sha256':audit.SNAPSHOT,'directories':inventory,
    'external_files':{'runner/'+name:str(Path('/tmp',filename)) for name,filename in external.items()},
    'all_present_regular_files_captured':True,'unchanged_during_capture':True,'archive_members':len(members),
    'compression':{'format':'xz','preset':6,'dictionary_bytes':64*1024*1024,'compression_runs':1,
                   'base64_part_maximum_bytes':3_500_000,'root_performance_running':False,
                   'scope':'root-authorized compression window after HIA run2 completion'},
    'source_bundle_reference':'../source_candidate/','complete_temporary_or_toolchain_copy':False,
    'scope':'all extant files from both requested output directories and six runner files; deleted temporary workspaces and host/toolchain installations are not reconstructed'})
print(json.dumps({'status':'captured','review_status':review['attempt2']['status'],
                  'members':len(members),'compressed_bytes':len(packed),'parts':parts}),flush=True)
