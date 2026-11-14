import ast,hashlib,json
from pathlib import Path
base=Path('/tmp/hia-r8-fuel-successor-analysis-r1-dda7')
r=base/'candidate-r2';old=(base/'inputs/generate_hia_file_render_checker_v4.before.py').read_bytes()
new=(r/'overlay/tools/generate_hia_file_render_checker_word64.py').read_bytes()
def pin(b):return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
assert pin(old)['git_blob']=='562627ae360c496b2b88477667d616e975d252f8'
assert pin(new)['git_blob']=='8dde3a64f7388f81f8996888c97d43def2b336db'
s=new.decode();start=s.index('# R9-private representation successor.')
end=s.index('def document():\n',start);added=s[start:end]
s=s[:start]+s[end:]
pairs=[("SOURCE = 'examples/hia_bootstrap/file_render_checker_word64.hepta'","SOURCE = 'examples/hia_bootstrap/file_render_checker_v4.hepta'"),("    return doc, dict(counts, word64_projection=word64_proof)","    return doc, counts")]
for x,y in pairs:assert s.count(x)==1;s=s.replace(x,y)
gate="""    baseline = render_assembly(doc).encode()
    if (len(baseline) != WORD64_BASE_SOURCE_BYTES
            or sha256(baseline).hexdigest() != WORD64_BASE_SOURCE_SHA256):
        raise ValueError('word64 original rendered R8 bytes differ')
    doc, word64_proof = _word64_core_document(doc)
"""
assert s.count(gate)==1;s=s.replace(gate,'')
assert s.encode()==old and ast.dump(ast.parse(s))==ast.dump(ast.parse(old))
assert "WIDTHS['u64'] != 64 or WIDTHS['usize'] != 64" in added
assert 'verify_program(after)' in added and "restored != before" in added
a={x.name:ast.dump(x) for x in ast.parse(old).body if isinstance(x,(ast.FunctionDef,ast.ClassDef))}
b={x.name:ast.dump(x) for x in ast.parse(new).body if isinstance(x,(ast.FunctionDef,ast.ClassDef))}
assert set(b)-set(a)=={'_word64_core_document'} and all(a[k]==b[k] for k in a if k!='document')
hia=(base/'inputs/R8-before.hepta').read_bytes()
assert pin(hia)['sha256']=='83953e66677fa0cd7f63f3b1742276d954537df71487c3cd4a6eef9486e3e4de' and len(hia)==395910
sem=json.loads((r/'SEMANTIC-REVIEW.json').read_bytes());authorities=[]
for row in sem['primary_sources']:
 orig=Path(row['source_path']).read_bytes();copy=(r/row['copy_path']).read_bytes()
 assert orig==copy and all(pin(orig)[k]==row[k] for k in ('bytes','sha256','git_blob'));authorities.append(pin(orig))
result={'status':'PASS_ROOT_STATIC_AUTHOR_REVIEW_ONLY','before':pin(old),'after':pin(new),'baseline_HIA':pin(hia),'whole_byte_AST_inverse':True,'all_existing_definitions_except_document_unchanged':True,'semantic_authorities_full_bytes':authorities,'exact_baseline_and_original_verifier_required':True,'generated_source_exists':False,'generation_compile_Native_VM_calls':0,'candidate_size_fuel_PASS':False,'original_limits_and_failures_retained':True}
out=Path('/tmp/hia-progress-v149-20261114-dda7/R9-WORD64-ROOT-REVIEW.json')
with out.open('x') as f:json.dump(result,f,sort_keys=True,indent=2);f.write('\n')
print(json.dumps({'result':pin(out.read_bytes()),'status':result['status']}))
