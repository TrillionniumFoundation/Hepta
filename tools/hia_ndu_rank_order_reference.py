"""QA-only order oracle derived from the original Python constructors.

It never supplies a product proof or identity. Existing native result values
are retained; only the common dictionary construction order is reconstructed
from original source and the original scalar-proof formatter.
"""
import ast,copy,inspect
import hepta.hia_ndu_optimizer as original
import hepta.hia_translation_validation as translation
import hepta.hia_scalar_proof_contract as contract
import hepta.hia_optimization as optimization

def tree(fn):return ast.parse(inspect.getsource(fn)).body[0]
def literal_keys(node):
 assert isinstance(node,ast.Dict)
 return [key.value for key in node.keys if isinstance(key,ast.Constant)and type(key.value)is str]
def first_dict(fn,required):
 for node in ast.walk(tree(fn)):
  if isinstance(node,ast.Dict)and set(required)<=set(literal_keys(node)):return node
 raise AssertionError((fn.__name__,required))
def key_proto(keys):return dict.fromkeys(keys)
def shape(value,proto):
 if type(value)is dict and type(proto)is dict:
  return {key:shape(value[key],proto.get(key))for key in list(proto)+[k for k in value if k not in proto]if key in value}
 if type(value)is list and type(proto)is list and proto:return [shape(x,proto[0])for x in value]
 return copy.deepcopy(value)

TOP=next(n.value for n in reversed(tree(original.rank_candidates).body)if isinstance(n,ast.Return))
TOP_KEYS=literal_keys(TOP)
TOP_VALUES={k.value:v for k,v in zip(TOP.keys,TOP.values)if isinstance(k,ast.Constant)}
CANDIDATE_KEYS=literal_keys(first_dict(original.rank_candidates,{'core_verified','equivalence_proved','observation'}))
ROW_KEYS=literal_keys(first_dict(original.rank_candidates,{'cost_q32','uncertainty_q32','support_sha256'}))
REQUEST_KEYS=literal_keys(first_dict(original.rank_candidates,{'schema','objective_sha256','generation','resource_cap_q32','candidates'}))
NATIVE_ADMISSION_KEYS=literal_keys(first_dict(original.rank_candidates,{'invoked','remaining_budget_ns','timeout_s','reason'}))
FINAL_ADMISSION_KEYS=literal_keys(first_dict(original.rank_candidates,{'candidate_id','spent_search_ns','solver_started'}))
BRIDGE_KEYS=literal_keys(first_dict(original._bridge_identity,{'upstream_commit','binary_sha256','source_attestation'}))
IDENTITY_KEYS=literal_keys(first_dict(optimization._solver_identity,{'name','version','binding_sha256','library_path','library_sha256'}))
DISCHARGE_KEYS=literal_keys(first_dict(optimization._native_circuit_result,{'method','image_sha256','formula_sha256','variables','clauses','steps'}))
for key in literal_keys(first_dict(optimization._native_word_table_decision,{'method','assignments_checked'})):
 if key not in DISCHARGE_KEYS:DISCHARGE_KEYS.append(key)
PREPROCESS_KEYS=literal_keys(first_dict(translation._partition_entry_equality,{'strategy','parameter_index'}))
COUNTEREXAMPLE_KEYS=literal_keys(first_dict(translation.validate_translation,{'arguments','parameter_types'}))+['before','after']
OBS_RETURN_KEYS=literal_keys(first_dict(translation._execute_observation,{'status','values'}))
OBS_TRAP_KEYS=literal_keys(first_dict(translation._execute_observation,{'status','code'}))

def proof_order(value):
 if type(value)is not dict:return copy.deepcopy(value)
 proto=translation._receipt(value.get('function'),value.get('solver',{}).get('timeout_ms'))
 for key in ('validation_error','error_type','wall_ns'):
  if key in value:proto[key]= {'code':None,'message':None}if key=='validation_error'else None
 # Unknown status prevents this QA-only formatter from granting proof authority.
 proto=contract.finish_scalar_proof(proto,{'name':'validate_translation','source_identity':{}})
 proto['solver'].update(identity=key_proto(IDENTITY_KEYS),discharge=key_proto(DISCHARGE_KEYS),
                        query_preprocessing=key_proto(PREPROCESS_KEYS),reason_unknown=None,error=None)
 proto['checker']['solver']=key_proto(IDENTITY_KEYS)
 proto['counterexample']=key_proto(COUNTEREXAMPLE_KEYS)
 proto['counterexample']['before']=key_proto(OBS_RETURN_KEYS+OBS_TRAP_KEYS[1:])
 proto['counterexample']['after']=key_proto(OBS_RETURN_KEYS+OBS_TRAP_KEYS[1:])
 return shape(value,proto)

def bridge_order(value):return shape(value,key_proto(BRIDGE_KEYS))
def result_order(value,args):
 if type(value)is not dict or 'candidate_reports'not in value:return copy.deepcopy(value)
 out=shape(value,key_proto(TOP_KEYS))
 out['costs']=shape(value['costs'],key_proto(literal_keys(TOP_VALUES['costs'])))
 out['claims']=shape(value['claims'],key_proto(literal_keys(TOP_VALUES['claims'])))
 reports=[]
 for row in value['candidate_reports']:
  proto=key_proto(CANDIDATE_KEYS)
  if 'preproof_cost_lower_bound_ns'in row:proto.update(preproof_cost_lower_bound_ns=None,proof_remaining_budget_ns=None,proof_remaining_margin_ns=None)
  if 'proof_timeout_ms'in row:proto.update(proof_timeout_ms=None,proof_wall_ns=None)
  proto['reason']=None
  if 'detail'in row:proto['detail']=None
  r=shape(row,proto);r['observation']=shape(row['observation'],args['observations'][row['id']])
  r['proof']=proof_order(row['proof']);reports.append(r)
 out['candidate_reports']=reports
 out['selected_fresh_proof']=proof_order(value['selected_fresh_proof'])
 out['selected_proof_admission']=shape(value['selected_proof_admission'],key_proto(FINAL_ADMISSION_KEYS+['timeout_ms','wall_ns']))
 out['native_rank_admission']=shape(value['native_rank_admission'],key_proto(NATIVE_ADMISSION_KEYS))
 out['native_request']=shape(value['native_request'],key_proto(REQUEST_KEYS))
 out['native_request']['candidates']=[shape(row,key_proto(ROW_KEYS))for row in value['native_request']['candidates']]
 out['bridge']=bridge_order(value['bridge'])
 if value['selection_resolution']is not None:
  fresh=original.resolve_scalar_selection(out['native_request'],value['native_response'])
  assert fresh==value['selection_resolution']
  out['selection_resolution']=fresh
 return out

def assert_order(actual,expected,path='$'):
 if type(actual)is dict and type(expected)is dict:
  assert list(actual)==list(expected),(path,'key order',list(actual),list(expected))
  for key in actual:assert_order(actual[key],expected[key],path+'.'+key)
 elif type(actual)is list and type(expected)is list:
  assert len(actual)==len(expected),(path,'list length')
  for i,(a,e)in enumerate(zip(actual,expected)):assert_order(a,e,path+'['+str(i)+']')
 else:assert type(actual)is type(expected)and actual==expected,(path,'value',actual,expected)
