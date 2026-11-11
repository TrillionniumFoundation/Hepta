"""Portable AST/source inventory, optional host HIA static verify. Never native."""
from pathlib import Path
from hashlib import sha256,sha1
import argparse,ast,json,os,sys
HERE=Path(__file__).resolve().parent

def main():
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--hia-static-verify',action='store_true');a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
 manifest=json.loads((HERE/'SOURCE_FREEZE.json').read_text());overlay=HERE/'source';rows=[]
 for name,digest in manifest['files'].items():
  raw=(overlay/name).read_bytes();assert sha256(raw).hexdigest()==digest
  if name.endswith('.py'):ast.parse(raw.decode());kind='Python AST only'
  else:
   kind='HIA source text only';assert raw.startswith(b'hia-asm.v1 ')
  rows.append({'file':name,'sha256':digest,'check':kind})
 verified=[]
 if a.hia_static_verify:
  # Restore only trusted archived source, no build artifacts. No Linux native dependency.
  source=HERE/'source';base=json.loads((HERE/'BASE_SOURCE_BLOBS.json').read_text())
  for name,expected in base['entries'].items():
   raw=(source/name).read_bytes();assert sha256(raw).hexdigest()==expected['sha256'];assert sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==expected['git_blob_oid']
  # Explicit host/static seed only. This is not required-mode or native evidence.
  for key in ('HIA_NATIVE_JSON_MANIFEST_SHA256','HIA_NATIVE_JSON_SCAN_ARTIFACT_DIR','HIA_NATIVE_NUMERIC_ARTIFACT_DIR'):os.environ.pop(key,None)
  os.environ['HIA_NATIVE_JSON_SCAN']='legacy';os.environ['HIA_NATIVE_NUMERIC']='legacy';os.environ['PYTHONDONTWRITEBYTECODE']='1';sys.dont_write_bytecode=True;sys.path.insert(0,str(source))
  from hepta.hia_agent_assembly import assemble_program
  for row in rows:
   if row['file'].endswith('.hiaasm'):
    checked=assemble_program((overlay/row['file']).read_bytes());verified.append({'file':row['file'],'canonical_bytes':len(checked.canonical_bytes),'scope':'host static grammar/type/effect verification only'})
 report={'status':'STATIC_REVIEW_COMPLETE','checks':rows,'optional_HIA_static_checks':verified,'native_compilation':False,'native_execution':False,'Worker_or_guest_execution':False,'management_keys_or_paid_model':False,'native77_256_72_180_all_still_NOT_RUN':True,'seed_if_optional':'HIA_NATIVE_JSON_SCAN=legacy,HIA_NATIVE_NUMERIC=legacy explicitly for host-only static parsing; no ambient manifest/artifacts trusted'}
 (a.output/'STATIC_REPORT.json').write_text(json.dumps(report,indent=2)+'\n');print('Static source review completed; this is NOT native or normal-path acceptance')
if __name__=='__main__':main()
