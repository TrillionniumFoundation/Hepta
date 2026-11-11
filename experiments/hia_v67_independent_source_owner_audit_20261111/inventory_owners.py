#!/usr/bin/env python3
"""Read every selected canonical file; emit static owners, never qualification."""
from pathlib import Path
import ast,collections,hashlib,json,re
ROOT=Path('/tmp/hia-e26e-v67-independent-audit-r1')
SRC=Path('/workspace/scratch/hia-v67-exact-git-20261111/source-608-r1')
COMMIT='608157e52b0b94e0d294f6b99c4e809869f183aa'
TREE='e7c29a60796a1a78946a2c667aa80df86529e532'
leaves=json.loads((ROOT/'audit-r1/all-3925-leaf-bytes-and-modes.json').read_bytes())['leaves']
by_path={x['path']:x for x in leaves}
backend=set('hia_machine_elf hia_machine_x64 hia_program_native hia_program_llvm hia_program_aarch64 hia_native_byte_abi hia_linux_kernel hia_aarch64_elf object_structure object_symbols elf_shared_abi hia_byte_sum hia_entry_layout'.split())
core=set('hia_program hia_program_runtime hia_program_composite hia_agent_assembly hia_core_api hia_core_upgrade hia_schema hia_opcodes hia_capability_flow hia_bounded_memory hia_json_decode hia_json_preflight hia_program_tools hia_edit_query hia_edit_batch hia_patch_impact hia_routes'.split())
agent=set('hia_agent_service hia_agent_store hia_agent_contract hia_agent_buffers hia_agent_macro_discovery hia_agent_macro_policy'.split())
entry=set('cli __main__ hia_agent_worker hia_agent_runner hia_agent_exec'.split())
transport=set('artifact_publication clang_capture darwin_capture windows_capture native_mapping_identity native_tool_identity hia_native_byte_runner hia_native_differential hia_native_paired_replay hia_native_retirement hia_bounded_wire'.split())
state=set('hia_adaptive hia_artifact_session hia_background_optimizer hia_continuation hia_durable_queue hia_finite_context hia_guarded_batch hia_host_region hia_multiversion hia_prepared hia_queue_commit hia_result_cache hia_result_cache_audit hia_scalar_state hia_stateful'.split())
static=set('__init__ hia_oracle hia_composite_constructor_errors hia_composite_functions_errors'.split())
notes={
 'cli':'Default hia_main uses _reference_hia_main when HEPTA_HIA_CLI_MANIFEST is absent. Selected HIA continuation still invokes the ordinary verifier/build/edit/publish Python bodies.',
 'hia_agent_worker':'Default argparse and _reference_run remain. Native report/request are separately selected; Python creates service, owns I/O/foreign objects and source custody. Deployed Rust MCP owner is external.',
 'hia_machine_x64':'37-command selected HIA instruction bytes do not replace mutable data/labels/fixups/relocations, validation, snapshots and finalize bookkeeping. Public attributes are observable and mutable.',
 'hia_machine_encoding_native':'HIA executes 37 instruction encodings. NativeEncodedCode inherits hosted Code state and emit/label; branch/call/finalize sequencing and foreign operands still traverse Python.',
 'hia_machine_elf':'Full general deterministic ELF64 ET_REL policy, sorting, relocation validation, layout and output bytes are still Python. This whole API is the next independent migration slice.',
 'hia_program_native':'A native-code backend implemented in Python. _Function/_Emitter perform lowering, frame/register/CFG choices, ABI wrappers; ordinary ELF writer and compile/link/inspection remain Python. No class named _Backend exists in this exact tree.',
 'hia_program':'verify_program retains bounded decode/snapshot, ordinary structure/interfaces and _BlockCheck resource/call/borrow/CFG validation; selected kernels cover explicit portions. Full ordinary function still runs Python.',
 'hia_program_composite':'Native type/constructor/helper/function/outer continuations are selectable. Hosted _Types/_Elaborator references, object materialization and fresh primitive checking remain; selected ownership is not default deletion permission.',
 'hia_program_runtime':'Full finite standalone VM remains Python; native execution elsewhere and Rust shadow comparison do not remove this explicit public interpreter route.',
 'hia_agent_store':'Persistent identities, profiles/refs/URI authority, file custody and SQLite schema/reads/transactions/leases remain hosted. Selected journal/artifact/identity kernels do not replace complete Store.',
 'hia_agent_service':'Eleven domain tool methods and control/durable effects remain hosted; journal selection owns explicit transitions, not all tool bodies. _hia_read page candidate is unfinished experimental evidence, not this frozen ordinary path.',
 'hia_agent_journal_native':'HIA owns selected transition decisions/JSON handling; sqlite3 Connection/cursor/commit/rollback and Python exception/object transport remain a declared foreign bridge.',
 'hia_json_wire_native':'HIA policy owns selected complete JSON traversal/output. ForeignGraphObserver uses Python/ctypes object facts, identity/callbacks and buffers; these are live foreign requirements, not a Python-free process.',
 'hia_cli_native':'HIA owns argv/control/presentation for 15 actions. _effect dispatches ordinary verify, assembly, build, edit, inspect and publication Python APIs; Python argparse compatibility and output/syscall bridges remain.',
 'hia_worker_report_native':'HIA controls selected worker continuation/report graph. Hosted callbacks preserve active exceptions and manipulate Python objects/service I/O; default request/service paths remain independently selected.',
 'hia_machine_plan_native':'HIA validates complete selected plan/witness policy with precisely ordered Python foreign dictionary and verified-program observations; it does not lower instructions or emit ELF.',
 'artifact_publication_native':'Explicit code/source admission and syscall execution bridge; the fixed native adapter/policy do not replace ordinary durable activation/recovery or every publication route.',
 'hia_safe_core':'SMT translation validation remains Python/Z3 with explicit finite profile. HIA byte emission is not a replacement proof checker.',
 'hia_routes':'Explicit machine/LLVM/reference routes remain supported. Removing LLVM/interpreter to shrink the surface would not preserve current public behavior.',
}
def category(stem):
 if stem in static:return 'schema-data-or-entry-metadata'
 if stem in backend:return 'machine-lowering-object-and-abi'
 if stem in entry:return 'ordinary-entry-and-dispatch'
 if stem in core:return 'core-admission-normalization-edit-runtime'
 if stem in agent:return 'agent-service-persistence-authority'
 if stem in transport:return 'foreign-process-file-custody'
 if stem in state:return 'native-lifecycle-stateful-runtime'
 if stem.endswith('_native'):return 'explicit-hia-kernel-hosted-bridge'
 if stem.startswith('hia_ndu') or stem in {'hia_planning','hia_full_cost_gate','hia_economic_search','hia_invocation_bank','hia_paired_holdout'}:return 'advisory-ndu-hosted-model-and-transport'
 if stem.startswith('hia_rust'):return 'rust-shadow-or-explicit-rust-profile-bridge'
 return 'proof-resource-analysis-optimization'

def checked(path):
 meta=by_path[path]; p=SRC/path; raw=p.read_bytes()
 assert len(raw)==meta['size'] and hashlib.sha256(raw).hexdigest()==meta['sha256']
 assert hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==meta['oid']
 return raw,meta

def pyrow(path):
 raw,meta=checked(path); t=ast.parse(raw.decode('utf-8'),filename=path)
 defs=[{'name':n.name,'kind':type(n).__name__,'line':n.lineno,'end_line':n.end_lineno,
        **({'methods':[{'name':a.name,'line':a.lineno,'end_line':a.end_lineno} for a in n.body if isinstance(a,(ast.FunctionDef,ast.AsyncFunctionDef))]} if isinstance(n,ast.ClassDef) else {})}
       for n in t.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef))]
 selectors=sorted({n.value for n in ast.walk(t) if isinstance(n,ast.Constant) and type(n.value)is str and re.fullmatch(r'HEPTA_HIA_[A-Z0-9_]+_MANIFEST',n.value)})
 refs=[]
 for n in ast.walk(t):
  if isinstance(n,ast.Call):
   name=ast.unparse(n.func)
   if ('installed_' in name or 'selected_' in name or name.startswith(('subprocess.','os.exec','ctypes.','sqlite3.','json.'))):
    refs.append({'line':n.lineno,'call':name})
 row={'path':path,'bytes':len(raw),'sha256':meta['sha256'],'git_blob_sha1':meta['oid'],'lines':len(raw.splitlines()),
      'full_bytes_read':True,'python_ast_parsed':True,'docstring':ast.get_docstring(t),'declarations':defs,
      'explicit_manifest_literals':selectors,'selected_or_foreign_calls':refs,
      'imported_modules':sorted({n.module or '' for n in ast.walk(t) if isinstance(n,ast.ImportFrom)}|{a.name for n in ast.walk(t) if isinstance(n,ast.Import) for a in n.names})}
 if path.startswith('hepta/'):
  stem=Path(path).stem; cat=category(stem)
  row.update(owner_category=cat,semantic_replacement_proved=False,
     deletion_ready=False,
     review_note=notes.get(stem,('A live hosted native-image admission/foreign-object/buffer bridge remains. Component-native execution is not Python-free application ownership.' if cat=='explicit-hia-kernel-hosted-bridge' else 'The listed Python declarations remain part of the installed supported API/implementation. This static inventory does not establish a complete HIA replacement or authorize deletion.')))
 return row
py_paths=[x['path'] for x in leaves if x['path'].endswith('.py') and not x['path'].startswith(('experiments/','review-evidence/','benchmarks/','tests/'))]
py=[pyrow(p) for p in py_paths]
installed=[x for x in py if x['path'].startswith('hepta/')]
assert len(installed)==161
rust=[]
for meta in leaves:
 if not meta['path'].endswith('.rs'): continue
 raw,_=checked(meta['path']);text=raw.decode('utf-8')
 rust.append({'path':meta['path'],'bytes':len(raw),'sha256':meta['sha256'],'git_blob_sha1':meta['oid'],
   'lines':len(raw.splitlines()),'full_bytes_read':True,
   'module_documentation':'\n'.join(x[3:].lstrip() for x in text.splitlines() if x.startswith('//!')),
   'declared_functions':re.findall(r'(?m)^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+(\w+)',text),
   'scope':('finite Rust raw-Core/shadow verifier or VM; separate source semantics retained' if '/hia-core-shadow/' in meta['path'] else 'advisory Rust NDU adapter/model/planner' if '/hia-ndu-' in meta['path'] else 'reference or fixture Rust source'),
   'hia_replacement_proved':False,'deletion_ready':False})
report={'schema':'hia.canonical-remaining-owner-static-audit.v1','commit':COMMIT,'tree':TREE,
'qualification_executed':False,'whole_native_delivery_qualified':False,'all_old_owners_deletable':False,
'coverage':{'installed_python_modules':len(installed),'non_experiment_python_including_tools_formal_examples_setup':len(py),'all_repository_rust_files':len(rust),
'exclusions_from_python_semantic_inventory':['experiments','review-evidence','benchmarks','tests'],
'complete_repository_bytes_were_already_audited':'audit-r1/all-3925-leaf-bytes-and-modes.json',
'method':'All inventoried UTF-8 bytes were read and checked against independently audited canonical blob SHA1/SHA256. Python AST was parsed; Rust declarations/documentation are static text observations, not compilation or a semantic equivalence proof.',
'focused_semantic_traces':['ordinary CLI and worker selection','Core verification/nominal lowering/normalization','direct machine _Function/_Emitter, mutable Code and full ELF writer','Agent service/store/journal boundary','build/install/foreign runtime and proof/advisory dependencies']},
'owner_category_counts':dict(sorted(collections.Counter(x['owner_category'] for x in installed).items())),
'python_modules':py,'rust_files':rust,
'external_runtime':{'repository_is_not_part_of_this_git_tree':True,'pinned_in_tools_generate_hia_agent_native_contract':'02c390876d4681ddfb90bb9dd6269bbf4e6f6419','crate':'hepta-runtime',
'implemented_runtime_source_audited_here':False,'live_deployment_or_cutover_observed':False,
'retained_boundary_from_worker_and_contract':['MCP/rmcp negotiation','caller authorization','durable process/job identities','cancellation and original-operation observation','terminal worker report verification'],
'conclusion':'Separate Rust process/MCP owner remains a deletion and deployment blocker. Local .rs counts do not audit or replace the external runtime.'}}
(ROOT/'remaining-owners.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
(ROOT/'installed-161-owner-index.tsv').write_text('path\tcategory\tsha256\tlines\tmanifest_literals\n'+''.join(f"{x['path']}\t{x['owner_category']}\t{x['sha256']}\t{x['lines']}\t{','.join(x['explicit_manifest_literals'])}\n" for x in installed))
print(json.dumps({'python':len(py),'installed':len(installed),'rust':len(rust),'categories':report['owner_category_counts'],'report_sha256':hashlib.sha256((ROOT/'remaining-owners.json').read_bytes()).hexdigest()},sort_keys=True))
