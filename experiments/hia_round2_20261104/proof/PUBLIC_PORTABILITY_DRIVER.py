import json,os,pathlib,runpy,sys,time,traceback
package=pathlib.Path(sys.argv[1]); destination=pathlib.Path(sys.argv[2]); original=pathlib.Path(sys.argv[3])
forbidden=str(original)+os.sep
denied=[]; canaries=[str(original/'proof-review-archive-v7-v12-r1/proof-review.tar.gz.part0001'),str(original/'proof-review-archive-v7-v12-r1/INVENTORY.json')]
def guard(event,args):
 if event=='open' and args and isinstance(args[0],(str,bytes,os.PathLike)):
  path=os.path.abspath(os.fsdecode(os.fspath(args[0])))
  if path==str(original) or path.startswith(forbidden):
   denied.append(path); raise PermissionError('original evidence read forbidden in relocated restore')
sys.addaudithook(guard)
result={'schema':'hepta.proof.public_restore_path_control.v1','status':'failed','original_prefix_forbidden':str(original),'mechanism':'Python audit open guard with explicit negative canaries; no claim of OS sandboxing','original_proof_qualification_passed':False,'new_lean_invocations':0,'canaries':canaries,'denied':denied}
entered=time.monotonic_ns()
try:
 for path in canaries:
  try:
   with open(path,'rb') as stream:stream.read(1)
  except PermissionError:pass
  else:raise ValueError('original-path negative canary did not reject')
 if denied!=canaries:raise ValueError('canary denial record differs')
 sys.argv=[str(package/'RESTORE.py'),'restore',str(package/'PARTS.json'),str(destination)]
 try:runpy.run_path(str(package/'RESTORE.py'),run_name='__main__')
 except SystemExit as exc:
  if exc.code not in (0,None):raise
 actual=json.loads((destination/'RESULT.json').read_bytes())
 if denied!=canaries:raise ValueError('restorer attempted an original evidence path')
 if actual['status']!='restored_bytes_verified' or actual['restored_files']!=1076 or actual['restored_bytes']!=180913620 or actual['archive']['sha256']!='7e6158c32a31f86fd5ed86fcb0250f1e26c7c03f7de968c9350252139891e3fa':raise ValueError('restored payload differs')
 result.update(status='relocated_public_restore_passed',restore=actual,restorer_attempts_to_open_original_evidence=0)
except BaseException as exc:
 result['error']={'type':type(exc).__name__,'message':str(exc),'traceback':traceback.format_exc()}
result['elapsed_ns']=str(time.monotonic_ns()-entered)
with (package.parent/'GUARDED_RESULT.json').open('xb') as stream:stream.write((json.dumps(result,sort_keys=True,indent=2)+'\n').encode())
print(json.dumps(result,sort_keys=True),flush=True)
raise SystemExit(0 if result['status']=='relocated_public_restore_passed' else 1)
