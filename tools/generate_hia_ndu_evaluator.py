"""Author the complete fixed-policy NDU evaluation leaf in executable HIA."""
from pathlib import Path
import ast,re,json
from tools.generate_hia_worker_config_json import ConfigBuilder
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_ndu_evaluator_common import COMMON,hash_source
from tools.generate_hia_ndu_evaluator_parse import PARSE,helpers
from tools.generate_hia_ndu_evaluator_semantics import SEMANTICS

class NduBuilder(ConfigBuilder):
    def expr(self,node):
        if isinstance(node,ast.BinOp) and isinstance(node.op,(ast.Mod,ast.FloorDiv)):
            left=self.cast(self.expr(node.left),'u64');right=self.cast(self.expr(node.right),'u64')
            return self.op('int.rem.checked' if isinstance(node.op,ast.Mod) else 'int.div.checked',[left,right],'u64')
        return super().expr(node)

def document(source,module):
    nodes=ast.parse(source).body
    names={n.name:'f'+str(i) for i,n in enumerate(nodes)}
    signatures={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        b=NduBuilder(node,names,signatures,total)
        try:b.statements(node.body)
        except BaseException:
            print('AUTHOR_FAILED_FUNCTION',node.name);raise
        functions.append({'name':names[node.name],'params':[b.param(v) for v in b.params],'returns':[b.returns],'effects':['read','write','trap'],'entry':'b0','blocks':b.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v9','module':module,'functions':functions})

ROOT=Path(__file__).resolve().parents[1]
LITERALS={
'L_DISPOSITION_0':'InfeasibleExplicitAbstain',
'L_DISPOSITION_1':'UniqueParetoRecommendation',
'L_DISPOSITION_2':'ParetoSetRequiresSlowPath',
'L_TRUE':'true','L_FALSE':'false','L_NULL':'null',
'L_REQUEST_SCHEMA':'hepta.hia.ndu-request.v1','L_ABSTAIN':'abstain',
'L_AXIS_REGISTRY':'total-ms:minimize;search-ms:ceiling',
'L_NORMALIZATION':'nanoseconds-to-ms-q32;nearest-ties-even;no-clipping',
'L_PROFILE_DOMAIN':'hepta.ndu.utility-profile.v1','L_PROFILE_ID':'hia-total-cost-ms-v1',
'L_TOTAL_MS':'total-ms','L_SEARCH_MS':'search-ms','L_ORGAN':'hia-compiler',
'L_POLICY_DOMAIN':'hepta.ndu.evaluation-policy.v2','L_POLICY_ID':'hia-single-owner-no-shared-cost-v1',
'L_CONTRIBUTION_DOMAIN':'hepta.ndu.contribution.v1','L_EVALUATION_DOMAIN':'hepta.ndu.evaluation.v1','L_EVALUATION_V2_DOMAIN':'hepta.ndu.evaluation.v2',
'L_SUCCESS_OPEN':'{"advisory_recommendation":',
'L_SUCCESS_DISPOSITION':',"authority":"ADVISORY_ONLY","disposition":',
'L_SUCCESS_EVALUATION':',"entry_point":"hepta.hia.ndu_evaluator.v1","evaluation_digest_v2":',
'L_SUCCESS_POLICY':',"evaluation_policy_digest":','L_SUCCESS_GENERATION':',"generation":',
'L_SUCCESS_OBJECTIVE':',"global_optimality_established":false,"objective_sha256":',
'L_SUCCESS_FRONTIER':',"pareto_frontier":[',
'L_SUCCESS_REJECTED':'],"proves_program_safety":false,"reference_entry_point":"codex_hepta_ndu::evaluate_candidates_with_policy","rejected":[',
'L_SUCCESS_REQUEST':'],"request_sha256":',
'L_SUCCESS_PROFILE':',"schema":"hepta.hia.ndu-native-response.v1","upstream_commit":"d3c2d760eca5065fc966820379c35c6e8d56e855","utility_profile_digest":',
'L_REJECT_ID':'{"id":','L_REJECT_REASONS':',"reasons":',
'L_REASON_HARD':'[HardConstraintViolation]','L_REASON_RESOURCE':'[ResourceCeilingExceeded]','L_REASON_BOTH':'[HardConstraintViolation, ResourceCeilingExceeded]',
'L_ERROR_OPEN':'{"authority":"NONE","error":','L_ERROR_END':',"schema":"hepta.hia.ndu-error.v1"}\n',
'L_INVALID_SCHEMA':'invalid schema, candidate count or resource cap',
'L_GENERATION_ZERO':'monotonic identity must be non-zero',
'L_DIGEST_LENGTH':'digest length must be 64, found ',
'L_DIGEST_CHAR':'invalid lowercase hex at byte ',
'L_DUP_NEGATIVE':'duplicate candidate or negative cost',
'L_ABSTAIN_REQUIRED':'baseline abstain candidate is required',
'L_EMPTY_ID':'bounded value must not be empty',
'L_LONG_ID_A':'bounded value has ',
'L_LONG_ID_B':' bytes; maximum is 128',
'L_NUL_ID':'bounded text must not contain NUL',
'L_INVALID_ID':'identifier contains an invalid character',
'L_ZERO_OBJECTIVE':'objective digest must not be zero',
'L_EMPTY_SUPPORT_A':'candidate ','L_EMPTY_SUPPORT_B':' contribution from organ hia-compiler has an empty support digest',
'L_ABSTAIN_INFEASIBLE':'explicit abstain must remain feasible after hard, risk and resource filtering',
'L_REQUEST_OVERSIZE':'request exceeds byte limit',
'L_EXPECTED_VALUE':'expected value','L_EOF_VALUE':'EOF while parsing a value','L_INVALID_NUMBER':'invalid number',
'L_NUMBER_RANGE':'number out of range',
'L_EXPECTED_IDENT':'expected ident','L_UNEXPECTED_HEX':'unexpected end of hex escape',
'L_EOF_LIST':'EOF while parsing a list','L_EOF_OBJECT':'EOF while parsing an object',
'L_EXPECTED_ARRAY_COMMA':"expected \u0060,\u0060 or \u0060]\u0060",'L_EXPECTED_OBJECT_COMMA':"expected \u0060,\u0060 or \u0060}\u0060",
'L_TRAILING_COMMA':'trailing comma','L_KEY_STRING':'key must be a string','L_EXPECTED_COLON':'expected \u0060:\u0060',
'L_CONTROL_STRING':'control character (\\u0000-\\u001F) found while parsing a string',
'L_EOF_STRING':'EOF while parsing a string','L_INVALID_ESCAPE':'invalid escape',
'L_INVALID_HEX':'invalid escape','L_INVALID_SURROGATE':'lone leading surrogate in hex escape','L_INVALID_UNICODE':'invalid unicode code point',
'L_UNKNOWN_A':'unknown field \u0060',
'L_UNKNOWN_REQUEST':'\u0060, expected one of \u0060schema\u0060, \u0060objective_sha256\u0060, \u0060generation\u0060, \u0060resource_cap_q32\u0060, \u0060candidates\u0060',
'L_UNKNOWN_CANDIDATE':'\u0060, expected one of \u0060id\u0060, \u0060cost_q32\u0060, \u0060uncertainty_q32\u0060, \u0060resource_q32\u0060, \u0060hard_violation\u0060, \u0060support_sha256\u0060',
'L_DUPLICATE_FIELD':'duplicate field \u0060','L_MISSING_FIELD':'missing field \u0060',
'L_INVALID_LENGTH':'invalid length ','L_REQUEST_LENGTH':', expected struct Request with 5 elements','L_CANDIDATE_LENGTH':', expected struct Candidate with 6 elements',
'L_TRAILING_CHARACTERS':'trailing characters',
'L_INVALID_TYPE':'invalid type: ','L_INVALID_VALUE':'invalid value: ',
'L_BOOL_TYPE':'boolean \u0060','L_INTEGER_TYPE':'integer \u0060','L_FLOAT_TYPE':'floating point \u0060','L_STRING_TYPE':'string ',
'L_SEQUENCE_TYPE':'sequence','L_MAP_TYPE':'map','L_EXPECTED':', expected ',
'L_EXPECT_STRING':'a string','L_EXPECT_U64':'u64','L_EXPECT_I64':'i64','L_EXPECT_BOOL':'a boolean',
'L_EXPECT_SEQUENCE':'a sequence','L_EXPECT_REQUEST':'struct Request','L_EXPECT_CANDIDATE':'struct Candidate',
'L_LINE':' at line ','L_COLUMN':' column ',
}
ROOT_FIELDS=['schema','objective_sha256','generation','resource_cap_q32','candidates']
CAND_FIELDS=['id','cost_q32','uncertainty_q32','resource_q32','hard_violation','support_sha256']
for i,name in enumerate(ROOT_FIELDS):LITERALS['L_ROOT_FIELD_'+str(i)]=name
for i,name in enumerate(CAND_FIELDS):LITERALS['L_CAND_FIELD_'+str(i)]=name
ENTRY=r'''
def ndu_evaluator(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 25165824 or length(o) < 8388608:
        return 4294967293
    if get(w, 128) == 2:
        if get(w, 16) == 4:
            size = get(w, 120)
            if size < 2 or size > 8388608:
                return 4294967294
            put(w, 96, 16777216)
            put(w, 104, size)
        else:
            if get(w, 120) < 32 or get(w, 120) > 96:
                return 4294967294
            status = get(w, 1572864)
            if status > 2:
                return 4294967294
            if status == 0:
                size = get(w, 1572888)
                if size > 64 or get(w, 120) != size + 32:
                    return 4294967294
                put(w, 96, 1572896)
                put(w, 104, size)
            else:
                put(w, 0, choose(status == 1, 19, 3))
                put(w, 8, get(w, 136) + get(w, 1572872))
        error_json(s, w)
        return finish_output(o, w, 2147483648)
    put(w, 128, 0)
    put(w, 152, 2097152)
    put(w, 0, 0)
    put(w, 48, 65536)
    put(w, 56, 0)
    if length(s) > 1048576:
        error(w, 1030, 0, 0, 0)
    else:
        if parse_request(s, w) == 1:
            if admit(w) == 1:
                input_copy(s, w, 2097152, 0, length(s))
                hash_segment(w, 2097152, length(s), 512)
                if evaluate(w) == 1:
                    evaluation_digest(w)
                    success_json(w)
    failure = choose(get(w, 0) == 0, 0, 2147483648)
    if failure != 0:
        if (get(w, 0) == 120 or get(w, 0) == 121) and get(w, 16) == 4:
            put(w, 128, 1)
            return 4294967287
        if (get(w, 0) == 120 or get(w, 0) == 121) and get(w, 16) == 3:
            put(w, 128, 1)
            return 4294967288
        error_json(s, w)
    return finish_output(o, w, failure)

def finish_output(o:mutbuf, w:mutbuf, failure:u64) -> u32:
    size = get(w, 64) - get(w, 152)
    if size > length(o):
        return 4294967294
    i = 0
    while i < size:
        store(o, i, byte(w, get(w, 152) + i))
        i = i + 1
    return size | failure

def semantic_message(w:mutbuf, code:u64) -> u64:
    if code == 1010:
        return text(w, L_INVALID_SCHEMA)
    if code == 1011:
        return text(w, L_GENERATION_ZERO)
    if code == 1012:
        text(w, L_DIGEST_LENGTH)
        return decimal(w, get(w, 16))
    if code == 1013:
        text(w, L_DIGEST_CHAR)
        return decimal(w, get(w, 16))
    if code == 1014:
        return text(w, L_DUP_NEGATIVE)
    if code == 1015:
        return text(w, L_ABSTAIN_REQUIRED)
    if code == 1016:
        return text(w, L_EMPTY_ID)
    if code == 1017:
        text(w, L_LONG_ID_A)
        decimal(w, get(w, 16))
        return text(w, L_LONG_ID_B)
    if code == 1018:
        return text(w, L_NUL_ID)
    if code == 1019:
        return text(w, L_INVALID_ID)
    if code == 1020:
        return text(w, L_ZERO_OBJECTIVE)
    if code == 1021:
        text(w, L_EMPTY_SUPPORT_A)
        text_copy(w, get(w, 16), get(w, 24))
        return text(w, L_EMPTY_SUPPORT_B)
    if code == 1022:
        return text(w, L_ABSTAIN_INFEASIBLE)
    return text(w, L_REQUEST_OVERSIZE)

def syntax_message(w:mutbuf, code:u64) -> u64:
    if code == 20:
        return text(w, L_EXPECTED_IDENT)
    if code == 18:
        return text(w, L_UNEXPECTED_HEX)
    if code == 19:
        return text(w, L_NUMBER_RANGE)
    if code == 1:
        return text(w, L_EXPECTED_VALUE)
    if code == 2:
        return text(w, L_EOF_VALUE)
    if code == 3:
        return text(w, L_INVALID_NUMBER)
    if code == 4:
        return text(w, L_EOF_LIST)
    if code == 5:
        return text(w, L_EOF_OBJECT)
    if code == 6:
        return text(w, L_EXPECTED_ARRAY_COMMA)
    if code == 7:
        return text(w, L_EXPECTED_OBJECT_COMMA)
    if code == 8:
        return text(w, L_TRAILING_COMMA)
    if code == 9:
        return text(w, L_KEY_STRING)
    if code == 11:
        return text(w, L_EXPECTED_COLON)
    if code == 12:
        return text(w, L_CONTROL_STRING)
    if code == 13:
        return text(w, L_EOF_STRING)
    if code == 14 or code == 15:
        return text(w, L_INVALID_ESCAPE)
    if code == 16:
        return text(w, L_INVALID_SURROGATE)
    return text(w, L_INVALID_UNICODE)

def type_message(w:mutbuf, code:u64) -> u64:
    text(w, choose(code == 120, L_INVALID_TYPE, L_INVALID_VALUE))
    kind = get(w, 16)
    if kind == 0:
        text(w, L_NULL)
    if kind == 1:
        text(w, L_BOOL_TYPE)
        text(w, choose(get(w, 72) == 1, L_TRUE, L_FALSE))
        text_byte(w, 96)
    if kind == 2:
        text(w, L_INTEGER_TYPE)
        if get(w, 80) == 1:
            text_byte(w, 45)
        decimal(w, get(w, 72))
        text_byte(w, 96)
    if kind == 3:
        text(w, L_FLOAT_TYPE)
        text_copy(w, get(w, 96), get(w, 104))
        text_byte(w, 96)
    if kind == 4:
        text(w, L_STRING_TYPE)
        text_copy(w, get(w, 96), get(w, 104))
    if kind == 5:
        text(w, L_SEQUENCE_TYPE)
    if kind == 6:
        text(w, L_MAP_TYPE)
    text(w, L_EXPECTED)
    expected = get(w, 24)
    if expected == 1:
        return text(w, L_EXPECT_STRING)
    if expected == 2:
        return text(w, L_EXPECT_U64)
    if expected == 3:
        return text(w, L_EXPECT_I64)
    if expected == 4:
        return text(w, L_EXPECT_BOOL)
    if expected == 5:
        return text(w, L_EXPECT_SEQUENCE)
    if expected == 6:
        return text(w, L_EXPECT_REQUEST)
    return text(w, L_EXPECT_CANDIDATE)

def serde_message(w:mutbuf, code:u64) -> u64:
    if code == 100 or code == 101:
        text(w, L_UNKNOWN_A)
        text_copy(w, get(w, 16), get(w, 24))
        return text(w, choose(code == 100, L_UNKNOWN_REQUEST, L_UNKNOWN_CANDIDATE))
    if code == 102 or code == 103:
        text(w, choose(code == 102, L_DUPLICATE_FIELD, L_MISSING_FIELD))
        text(w, choose(get(w, 24) == 0, L_ROOT_FIELD_0, L_CAND_FIELD_0) + get(w, 16))
        return text_byte(w, 96)
    if code == 104:
        text(w, L_INVALID_LENGTH)
        decimal(w, get(w, 16))
        return text(w, choose(get(w, 24) == 0, L_REQUEST_LENGTH, L_CANDIDATE_LENGTH))
    if code == 105:
        return text(w, L_TRAILING_CHARACTERS)
    return type_message(w, code)

def error_json(s:readbuf, w:mutbuf) -> u64:
    put(w, 64, 8388608)
    code = get(w, 0)
    if code >= 1000:
        semantic_message(w, code)
    else:
        if code < 100:
            syntax_message(w, code)
        else:
            serde_message(w, code)
        position = get(w, 8)
        if position > length(s):
            position = length(s)
        line = 1
        column = 0
        i = 0
        while i < position:
            if byte(s, i) == 10:
                line = line + 1
                column = 0
            else:
                column = column + 1
            i = i + 1
        text(w, L_LINE)
        decimal(w, line)
        text(w, L_COLUMN)
        decimal(w, column)
    size = get(w, 64) - 8388608
    put(w, 160, size)
    put(w, 152, 16777216)
    put(w, 64, 16777216)
    text(w, L_ERROR_OPEN)
    quote(w, 8388608, size)
    return text(w, L_ERROR_END)
'''
def literal_source():
    items=list(LITERALS.items());pieces=[]
    for group in range((len(items)+9)//10):
        fn=[f'def literals_{group}(w:mutbuf, at:u64, which:u64) -> u64:']
        for index,(name,value) in enumerate(items[group*10:(group+1)*10],group*10):
            raw=value.encode('utf-8');fn.append(f'    if which == {index+1}:')
            for k in range(0,len(raw)//8*8,8):fn.append(f'        put(w, at + {k}, {int.from_bytes(raw[k:k+8],"little")})')
            for k in range(len(raw)//8*8,len(raw)):fn.append(f'        store(w, at + {k}, {raw[k]})')
            fn.append(f'        return at + {len(raw)}')
        fn.append('    return at');pieces.append('\n'.join(fn))
    main=['def literal(w:mutbuf, at:u64, which:u64) -> u64:']
    for g in range((len(items)+9)//10):
        main.append(f'    if which <= {(g+1)*10}:');main.append(f'        return literals_{g}(w, at, which)')
    main.append('    return at')
    return '\n\n'.join(['\n'.join(main),*pieces])
def key_source():
    lines=['def key_field(w:mutbuf, at:u64, size:u64, candidate:u64) -> u64:','    if candidate == 0:']
    for i in range(5):lines+=['        if match_literal(w, at, size, L_ROOT_FIELD_'+str(i)+') == 1:',f'            return {i}']
    lines+=['    else:']
    for i in range(6):lines+=['        if match_literal(w, at, size, L_CAND_FIELD_'+str(i)+') == 1:',f'            return {i}']
    lines+=['    return 255'];return '\n'.join(lines)
def program():
    text='\n\n'.join([ENTRY,COMMON,PARSE,SEMANTICS,hash_source(),helpers(),key_source(),literal_source()])
    for i,name in enumerate(LITERALS,1):text=re.sub(r'\b'+name+r'\b',str(i),text)
    return text
def render():return render_assembly(document(program(),'ndu_evaluator'))
if __name__=='__main__':
    source=program();doc=document(source,'ndu_evaluator')
    path=ROOT/'examples/hia_bootstrap/ndu_evaluator.hepta';path.write_text(render_assembly(doc))
    stats={'source_bytes':path.stat().st_size,'functions':len(doc['functions']),'blocks':sum(len(f['blocks']) for f in doc['functions']),'ops':sum(len(b['ops']) for f in doc['functions'] for b in f['blocks']),'max_blocks':max(len(f['blocks']) for f in doc['functions'])}
    print(json.dumps(stats))
