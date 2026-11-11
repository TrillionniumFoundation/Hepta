import collections,hashlib,json,pathlib,os,sys
p=pathlib.Path('/home/qian-qi/hia-native-closure-evidence/4161e8d12d87906fde144f039da07908ad52d98a/ci-pr-invocation-cost-r2/analysis.json')
raw=p.read_bytes();assert hashlib.sha256(raw).hexdigest()=='ea5be7d1dd8839ff90a781df9051c0d1d99d31faccf03e4dacc472fb02841a09'
data=json.loads(raw);summary={}
for r in data['receipt_observations']:
 kind=r['kind']
 if kind not in ('linked-selfhost','seed-shared','specialized-allocator-child'):continue
 s=summary.setdefault(kind,{'known_native_count':0,'known_native_wall_ns':0,'known_native_ns':0,'missing_native_count':0,'missing_native_wall_ns':0,'missing_status':{}})
 if r['native_ns'] is not None:
  s['known_native_count']+=1;s['known_native_wall_ns']+=r['wall_ns'];s['known_native_ns']+=r['native_ns']
 else:
  s['missing_native_count']+=1;s['missing_native_wall_ns']+=r['wall_ns']
  k=str(r['status'])+':'+str(r['returncode']);s['missing_status'][k]=s['missing_status'].get(k,0)+1
for row in summary.values():row['known_wall_minus_native_ns']=row['known_native_wall_ns']-row['known_native_ns']
report={'schema':'hia.original-cold-known-native-cost-subtotals.v1','analysis_sha256':hashlib.sha256(raw).hexdigest(),'source_archive_sha256':data['original_archive']['sha256'],'subtotals':summary,'scope':'Measured return rows only. Residual includes loader, input/output, parent bookkeeping and scheduler time; no pure-startup or elapsed critical-path saving claim.'}
b=(json.dumps(report,indent=2,sort_keys=True)+'\n').encode();out=p.parent/'known-native-subtotals.json'
with out.open('xb') as stream:stream.write(b);stream.flush();os.fsync(stream.fileno())
print(json.dumps(report,separators=(',',':')),flush=True)
