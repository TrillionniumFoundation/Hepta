import ast,hashlib,json,stat,struct,zlib
from pathlib import Path
r=Path('/tmp/hia-op13-session-fixture-author-r1-dda7')
s=Path('/tmp/hia-op13-execution-r2-dda7/source')
out=Path('/tmp/hia-progress-v149-20261114-dda7/OP13-FIXTURE-ROOT-REVIEW.json')
def pin(b):
 return {'bytes':len(b),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest(),'sha256':hashlib.sha256(b).hexdigest()}
def read(p):
 a=p.stat();b=p.read_bytes();assert a==p.stat() and stat.S_ISREG(a.st_mode) and a.st_nlink==1;return b
before=read(s/'tests/hia_patch_cli_support.py')
after=read(r/'source/tests/hia_patch_cli_support.py')
assert pin(before)['git_blob']=='c835daf2d2e780dc2041e50ef0a012a3b7e3009c'
assert pin(after)['git_blob']=='5249f7ef07956a72bca6735a50d3a9e1b419a27b'
old=b'        if imports:\n            session._effect(35, 0, 0, 0, 0)\n        return session\n'
new=b"        if imports:\n            require(session.step() == 1\n                    and session.command == (35, 1, 1, 0, 0, 0, 0)\n                    and session.consume_mask == 0,\n                    'real patch import initialization command differs')\n            session.observe()\n        return session\n"
assert before.count(old)==after.count(new)==1 and after.replace(new,old)==before
assert ast.dump(ast.parse(after.replace(new,old)))==ast.dump(ast.parse(before))
tests={}
for name,sha in [('test_hia_patch_cli_native.py','5cf933ab65749b3a5cde3a2d493e01f2a3734749'),('test_hia_patch_cli_source.py','30c6956078698f13cb06532190d1e6e0fbde7727')]:
 b=read(s/'tests'/name);assert pin(b)['git_blob']==sha;tests[name]=pin(b)
proof=json.loads(read(r/'ACTUAL-INITIAL-COMMAND-READBACK.json'))
frames=[]
for row,wanted in zip(proof['observations'],(1,3),strict=True):
 raw=read(Path(row['actual_frame']['path']));assert pin(raw)==row['actual_frame']['pin'];frame=json.loads(raw)
 compressed=read(Path(row['actual_compressed_output']['path']));assert pin(compressed)==row['actual_compressed_output']['pin']
 d=zlib.decompressobj();b=d.decompress(compressed,129);assert d.eof and not d.unused_data and not d.unconsumed_tail
 assert len(b)==128 and pin(b)['sha256']==frame['output_after']['sha256'] and pin(b)['git_blob']==frame['output_after']['git_blob']
 command=struct.unpack('<16Q',b)
 assert frame['result']==wanted and command==(3766220139776459592,35,1,1,0,0,0,0,0,0,0,0,0,0,0,0)
 assert b==read(Path(row['output_copy']['path']));frames.append({'frame':pin(raw),'return':wanted,'output':pin(b)})
result={'status':'PASS_INDEPENDENT_FIXTURE_STATIC_REVIEW','before':pin(before),'after':pin(after),'whole_byte_and_AST_inverse':True,'unchanged_tests':tests,'actual_initial_command_frames':frames,'imports_false_unchanged':True,'new_state_assignment':False,'actual_step_and_observe_required':True,'active_partial_sessions_retired_claim':False,'old_failure_retained':True,'product_execution':0}
with out.open('x') as f:json.dump(result,f,sort_keys=True,indent=2);f.write('\n')
print(json.dumps({'result':pin(out.read_bytes()),'status':result['status']}))
