import sys,json,hashlib,time,os,base64
from pathlib import Path
client_root=Path('/Users/qianqi/work/hia-release-faa85-v4-c81-r1/http-v4-lifecycle-r2')
if hashlib.sha256((client_root/'http_qualification.py').read_bytes()).hexdigest()!='e1c26fcac54d6825d0123ba53cee2690d0bf7e54a5f81c6955c78430127a5073':raise RuntimeError('transport source changed')
sys.path.insert(0,str(client_root));import http_qualification as h
h.verify_source();os.umask(0o077)
output=Path('/Users/qianqi/work/hia-closure-aa68-20261107-costs-recovery-r1');output.mkdir(mode=0o700)
refs=json.loads("{\"measurements\":{\"id\":\"a-ffcfbbb440b94c9d85455df886b0abad\",\"sha256\":\"3aa2efc39be073ce8f8e0a383a3297a00b24115f415328f544311af5f08244eb\",\"uri\":\"hia://artifacts/03466a6ee74e4c06b097b62695bae472\"}}")
h.dump(output/'registration.json',{'original_job_id':'1a1b59f7d31-12894-7d','original_request_sha256':'c752a30e7565b3bf10bd210354088605d2c529923e2802dd646ac72ce89c2a0c','artifacts':refs,'allowed_domain_tools':['hia_read'],'new_evaluation':False,'predecessor_readback_job':'1a1b5b8534d-12894-be','predecessor_state':'timed_out','predecessor_budget_seconds':300,'new_observation_budget_seconds':600})
client=h.MCPHTTP('http://127.0.0.1:8790/mcp',h.token_bytes(Path('/Users/qianqi/.config/hepta-runtime-mac/token')),output)
started=time.monotonic_ns();summary={'status':'failed','artifacts':{},'new_evaluation':False}
try:
 for name,ref in refs.items():
  raw=bytearray();cursor=None;seen=set()
  old=Path('/Users/qianqi/work/hia-closure-aa68-20261107-costs-r1')
  captures=json.loads("[{\"body\":\"http-body-00005.bin\",\"body_sha256\":\"aae884ceef40a30d0a0d004068cb83f04448ebef1c613b549af699b5e71df34b\",\"body_bytes\":172253,\"request\":{\"id\":4,\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"arguments\":{\"artifact\":{\"id\":\"a-ffcfbbb440b94c9d85455df886b0abad\",\"sha256\":\"3aa2efc39be073ce8f8e0a383a3297a00b24115f415328f544311af5f08244eb\",\"uri\":\"hia://artifacts/03466a6ee74e4c06b097b62695bae472\"},\"catalog_sha256\":\"8b880cc02efc93e10d920bf812bccbb33197aa00f6b92282536a000238ba5e9e\",\"max_bytes\":65536},\"name\":\"hia_read\"}}},{\"body\":\"http-body-00006.bin\",\"body_sha256\":\"d2b5704a8a430142a1e3b4942d07b752ff2622b6cb55bd71afa281f59fd49ef3\",\"body_bytes\":163582,\"request\":{\"id\":5,\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"arguments\":{\"artifact\":{\"id\":\"a-ffcfbbb440b94c9d85455df886b0abad\",\"sha256\":\"3aa2efc39be073ce8f8e0a383a3297a00b24115f415328f544311af5f08244eb\",\"uri\":\"hia://artifacts/03466a6ee74e4c06b097b62695bae472\"},\"catalog_sha256\":\"8b880cc02efc93e10d920bf812bccbb33197aa00f6b92282536a000238ba5e9e\",\"cursor\":\"page-7f6e091deec212fa8aaeffaaa9fdc7d643e3de8d49ca0803f7fd7b0574751b23\",\"max_bytes\":65536},\"name\":\"hia_read\"}}},{\"body\":\"http-body-00007.bin\",\"body_sha256\":\"625092861cab041334e913e624a307da26811b512ad870f38ab55dfd66a62bcd\",\"body_bytes\":160873,\"request\":{\"id\":6,\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"arguments\":{\"artifact\":{\"id\":\"a-ffcfbbb440b94c9d85455df886b0abad\",\"sha256\":\"3aa2efc39be073ce8f8e0a383a3297a00b24115f415328f544311af5f08244eb\",\"uri\":\"hia://artifacts/03466a6ee74e4c06b097b62695bae472\"},\"catalog_sha256\":\"8b880cc02efc93e10d920bf812bccbb33197aa00f6b92282536a000238ba5e9e\",\"cursor\":\"page-2b62b67e946bbff218641d7d36b156e9e3ee51d1c09f3ac9ffb75a6aea8a4752\",\"max_bytes\":65536},\"name\":\"hia_read\"}}},{\"body\":\"http-body-00008.bin\",\"body_sha256\":\"916a028242edb7e48005af0fa2b1e42ce99ec3bf23a6a19c15a27b96b583826f\",\"body_bytes\":160726,\"request\":{\"id\":7,\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"arguments\":{\"artifact\":{\"id\":\"a-ffcfbbb440b94c9d85455df886b0abad\",\"sha256\":\"3aa2efc39be073ce8f8e0a383a3297a00b24115f415328f544311af5f08244eb\",\"uri\":\"hia://artifacts/03466a6ee74e4c06b097b62695bae472\"},\"catalog_sha256\":\"8b880cc02efc93e10d920bf812bccbb33197aa00f6b92282536a000238ba5e9e\",\"cursor\":\"page-3514d66749454119d48c11e156adb9d87b1b32457e309d5635f6dc2ac79eb4f8\",\"max_bytes\":65536},\"name\":\"hia_read\"}}}]")
  for capture in captures:
   body=(old/capture['body']).read_bytes()
   h.require(len(body)==capture['body_bytes'] and hashlib.sha256(body).hexdigest()==capture['body_sha256'],'original wire bytes differ')
   request=capture['request'];h.require(request['params']['arguments'].get('cursor')==cursor,'original cursor chain differs')
   matches=[m for m in h.response_messages(body) if m.get('id')==request['id']]
   h.require(len(matches)==1,'original response identity differs')
   previous=h.MCPHTTP._domain_result(matches[0]['result']);h.require(previous['status']=='completed','original page incomplete')
   page=previous['result'];h.require(page['artifact']==ref,'original artifact identity differs')
   raw.extend(page['content'].encode() if page['encoding']=='utf8' else base64.b64decode(page['content'],validate=True))
   cursor=page['next_cursor'];h.require(cursor not in seen,'original cursor repeated');seen.add(cursor)
  h.require(len(raw)==262144 and cursor is not None,'retained prefix differs')
  summary['reused_prefix_bytes']=len(raw)
  for i in range(8):
   args={'catalog_sha256':h.PINS['catalog_sha256'],'artifact':ref,'max_bytes':65536}
   if cursor is not None:args['cursor']=cursor
   response=client.call('hia_read',args)
   h.require(response.get('status')=='completed','read original artifact did not complete')
   page=response['result'];h.require(page['artifact']==ref,'artifact reference changed')
   part=page['content'].encode() if page['encoding']=='utf8' else base64.b64decode(page['content'],validate=True)
   raw.extend(part);h.require(len(raw)<=8*1024*1024,'artifact bound exceeded')
   cursor=page['next_cursor']
   if cursor is None:break
   h.require(cursor not in seen,'artifact cursor repeated');seen.add(cursor)
  else:raise RuntimeError('artifact page bound exceeded')
  h.require(hashlib.sha256(raw).hexdigest()==ref['sha256'],'original artifact digest differs')
  h.write_new(output/(name+'.json'),bytes(raw));v=json.loads(raw)
  summary['artifacts'][name]={'path':str(output/(name+'.json')),'bytes':len(raw),'sha256':ref['sha256'],'top_level_keys':list(v) if isinstance(v,dict) else None}
 summary['status']='passed'
except BaseException as e:
 summary['error']={'type':type(e).__name__,'message':str(e)};raise
finally:
 summary['elapsed_ns']=time.monotonic_ns()-started;summary['connection']=client.connection_receipt();client.close();h.dump(output/'result.json',summary);print(json.dumps(summary),flush=True)
