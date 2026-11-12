"""Freeze current local controls and policy; does not create a Git ref or run."""
import ast
from hashlib import sha1,sha256
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parent
OUT=ROOT/'control'
def wire(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
def pin(raw):return {'bytes':len(raw),'sha256':sha256(raw).hexdigest(),
    'git_blob_sha1':sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}
candidate={'commit':'ba714f34b8dcb248c779bb5fc0b9538d9151c685',
           'tree':'3489d2047956c1481b2e0593e2fbd32cf273cc70','leaves':4051}
names=next(ast.literal_eval(n.value.args[0]) for n in ast.parse((OUT/'controller.py').read_bytes()).body
    if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='CONTROL_NAMES' for t in n.targets))
inputs={name:pin((OUT/name).read_bytes()) for name in names if name!='control-manifest.json'}
manifest={'schema':'hepta.hia.bounded-read-product-capsule-controls.v1',
    'candidate_commit':candidate['commit'],'candidate_tree':candidate['tree'],
    'outer_qualification_seconds':180,'outer_cleanup_seconds':3,
    'dispatch_authorized_by_this_file':False,'files':inputs}
(OUT/'control-manifest.json').write_bytes(wire(manifest))
inputs['control-manifest.json']=pin((OUT/'control-manifest.json').read_bytes())
policy={'schema':'hia.bounded-read-product-install-actions-policy.v1','candidate':candidate,
    'controls':inputs,'controller_seconds':180,'cleanup_seconds':3,
    'compile_wall_seconds':20,'compile_CPU_seconds':10,'HIA_function_count':14,
    'fresh_B0_B1_B2':True,'cold_qualification':False,'finite_cases':55,'original_methods':8,
    'original_CLI_children':7,'original_CLI_timeout_seconds':20,'exact_group_populations':[12,24,10,9,8],
    'installed_cases':9,'installed_native_reads':7,'installed_child_seconds':5,
    'source_resources':105,'source_Python_modules':170,'native_source_resources':90,
    'trigger_branch':'codex/hia-bounded-read-v80-native-installed-r1-run-20261112-e26e',
    'runtime_root_basename':'hia-bounded-read-v80-native-installed-r1',
    'initial_free_bytes':8<<30,'initial_free_inodes':100000,
    'small_raw_bytes':512<<10,'small_stdout_bytes':1<<20,'small_index_bytes':64<<10,
    'small_channel_schema':'hepta.hia.bounded-read-small-stream.v2',
    'small_index_serialization':'sorted-compact-json-utf8-lf',
    'diagnostic_targets':219,'small_channel_is_complete_artifact_transport':False,
    'full_original_custody':'closed-current-ECHILD typed tar: all regular bytes; directory/symlink/FIFO metadata; no automatic extraction',
    'original_guardian_sha256':'d0b56d24905895ad59120f401d006badfdb1df5b3e0ab17a80e8414da78a1023',
    'original_owner_sha256':'36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2',
    'whole_native_delivery_qualification':False,'public_default_activation_changed':False,
    'existing_general_installed_resource_suite_executed':False,
    'current_support_and_coverage_runtime_check':'fresh in-memory regeneration and exact bytes; no source writes',
    'scope':'FINITE_PRODUCT_NATIVE_AND_ACTUAL_OFFLINE_INSTALLATION_DEVELOPMENT_NOT_COLD'}
(OUT/'policy.json').write_bytes(wire(policy))
design={'schema':'hepta.hia.bounded-read-product-install-capsule-design.v1','status':'STATIC_FROZEN_NOT_EXECUTED',
    'candidate':candidate,'base_product_parent':'d0e110e19f9433baaf202a0f605671c7205b4cff',
    'original_native_run_not_inherited':43175489773,
    'old_601B_ABI_and_new_1153B_ABI':'Native HIA source is the same 59728 bytes. The source-owned descriptor now participates in generator/builder/package controls; runtime adapter does not consume it. The prior native run did not execute this descriptor/build/install capsule.',
    'single_outer_gate':{'guardian':'d0b56d','owner':'369460','seconds':180,'cleanup_seconds':3,
        'fresh_compiler_inner_seconds':60,'qualifier_inner_seconds':180,
        'packaging_tools_seconds':15,'sdist_seconds':120,'wheel_seconds':120,'install_seconds':120,
        'installed_child_seconds':5,'note':'All inner limits are additionally constrained by this one original outer 180-second owner.'},
    'original_product_gate':{'build':'tools/build_hia_bounded_read.py --development',
        'qualifier':'tools/qualify_hia_bounded_read.py --development',
        'groups':[12,24,10,9,8],'finite_cases':55,'original_test_methods':8,'CLI_children':7,
        'unchanged_CLI_timeout':20,'original_cli_source_commands_retained':True,
        'compiler_limits':{'wall_seconds':20,'CPU_seconds':10,'address_bytes':256<<20,'stack_bytes':8<<20,
            'workspace_bytes':1<<20,'output_capacity':1<<20}},
    'installation':{'source_python':170,'hepta_files':172,'resources':105,'native_resources':90,
        'method_ids_source':'control/installed_cases.py:IDS','method_count':9,'successful_public_native_reads':7,
        'input_boundary_bytes':8<<20,'process':'stdlib -I -S -B, empty PATH, new target/consumer directory',
        'packaging':'actual setup.py sdist, no-index/no-build-isolation wheel, no-index --target --no-compile install',
        'original_inputs_and_archives':'all current declared inputs, every tar/wheel member and installed file reread',
        'intentional_warm_changes':'restore byte/mode projection; compare current after identities, not before inode equality',
        'ABI_resource':'source descriptor is checked as a resource; no fabricated hia_hia_bounded_read_abi_native module'},
    'independent_join':'B0 receipt plus actual artifact; B1/B2/component original child stdout projection, full request, input, full 1MiB output and produced image; seven nested qualifier owners, 55 case details, exact seven CLI start/completion pairs; five packaging owners and full installed source/resource originals.',
    'failure_preservation':'Any original failure/partial run remains HOLD. No live child output read before exact outer ECHILD. All closed regular originals retained in typed tar; symlink and FIFO never opened or traversed. Missing fixed names and whole-file omissions explicitly recorded.',
    'small_channel':{'fixed_targets':219,'raw_bytes':512<<10,'stdout_bytes':1<<20,'index_bytes':64<<10,
        'schema':'hepta.hia.bounded-read-small-stream.v2','index_encoding':'sorted compact JSON UTF-8 LF',
        'priority':'actual generated full HIA and source-owned ABI, guardian, final/report, then fixed originals',
        'not_full_artifact_transport':True,'decoder':'decode_small.py'},
    'explicit_open_scope':['OS/path/context/foreign operations remain hosted Python observations',
        'No arbitrary foreign-object, cyclic GC, reflection or asynchronous all-input equivalence claim',
        'No default native activation or prior cold/full result inherited',
        'Current general installed-resource test has parent-owned stale Core range and ABI-stem assumptions; this capsule does not run or repair that separate suite',
        'Unrelated existing UNKNOWN operations are not retried'],
    'local_checks':'107 finite control-only checks with real temporary filesystem observations and AST parity; no product import, native/compile, package build or new qualification.',
    'static_drafts_retained':['first deterministic derivation assertion (diagnostics has no candidate_leaves literal)',
        '219-row pretty index 66272-byte counterexample; compact protocol v2 retains every row below original 64KiB bound']}
(ROOT/'DESIGN.json').write_bytes(wire(design))
pins={p.name:pin(p.read_bytes()) for p in sorted(OUT.iterdir()) if p.is_file()}
(ROOT/'FROZEN-CONTROLS.json').write_bytes(wire({'candidate':candidate,'control_prefix':'experiments/hia_bounded_read_owner_20261112/product-native-installed-capsule-r1',
    'files':pins,'policy':pins['policy.json'],'control_manifest':pins['control-manifest.json'],
    'total_files':len(pins),'total_bytes':sum(r['bytes'] for r in pins.values()),
    'native_executed':False,'triggered':False}))
print(json.dumps({'controls':len(pins),'policy':pins['policy.json'],'manifest':pins['control-manifest.json']}))
