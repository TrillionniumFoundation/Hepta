"""Actual immutable-source request owner gates, with separate interpreter scopes."""
from __future__ import annotations
import argparse
import base64
from hashlib import sha1, sha256
import importlib.metadata
import io
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time
import traceback
import zipfile
import zlib

from source_custody import digest, wire, write, safe, metadata, files, admit_git_snapshot
from workflow_process import run_workflow_step

BASE = '65ceb711e47548f85ecf6b2ec2ae90f11dd50743'
TREE = '49a48cef565b78d0a353822026ec525789768840'
PARENT = '64f67ae897c3cb49d45a1e1a4622db974812e3fe'
COMPILER = '81b6fad94493546b5bf3f858248f25b19aded88bf8f3aaad18140aa317dac109'
COMPILER_PACKET = 'df542582525e52f7855f2746ae9dc7501f6835e41aa46b209e59f2e121177b8b'
NEW_SELECTORS = ('tests.test_hia_service_artifacts_native.ServiceArtifactsSourceTests', 'tests.test_hia_service_artifacts_builder', 'tests.test_hia_service_artifacts_qualifier', 'tests.test_hia_proof_contract_native.ProofContractSourceTests.test_core_and_mechanism_roles_have_exact_provider_edges', 'tests.test_hia_service_context_builder.ServiceContextAdapterTests.test_held_service_selection_does_not_change_default_core_checker_scope', 'tests.test_hia_service_emission_builder.ServiceEmissionAdapterTests.test_held_service_selection_does_not_change_default_core_checker_scope', 'tests.test_hia_service_verification_builder.ServiceVerificationAdapterTests.test_held_service_selection_does_not_change_default_core_checker_scope', 'tests.test_hia_joint_owner_integration.JointOwnerIntegrationSourceTests', 'tests.test_hia_proof_contract_builder.ProofContractAdapterTests.test_held_service_selection_does_not_change_default_core_checker_scope', 'tests.test_hia_service_requests_builder.ServiceRequestsAdapterTests.test_held_service_selection_does_not_change_default_core_checker_scope', 'tests.test_hia_service_emission_native.ServiceEmissionSourceTests')
COMPATIBILITY_SELECTORS = (
    'tests.test_hia_native_build_native.NativeBuildSourceTests',
    'tests.test_hia_native_byte_abi_native.NativeByteABISourceTests',
    'tests.test_hia_proof_contract_native.ProofContractSourceTests',
    'tests.test_hia_service_verification_native.ServiceVerificationSourceTests')
GENERATED = frozenset(('examples/hia_bootstrap/service_artifacts.hiaasm',
    'hepta/hia_service_artifacts_foreign.py','docs/HIA_SELFHOST_LANGUAGE_COVERAGE.json',
    'docs/HIA_SELFHOST_CORE_SUPPORT.json'))
FULL_GENERATORS = ('core_workspace_pipeline', 'core_workspace_facts', 'core_workspace_facts_cli', 'core_workspace_materialize', 'core_workspace_cli', 'capability_renaming', 'core_module_graph', 'core_workspace_json', 'core_workspace_json_cli', 'agent_identity', 'agent_slice', 'elf_linker', 'native_filter', 'core_json_cli', 'agent_stdio', 'agent_snapshot', 'agent_snapshot_json', 'agent_snapshot_json_cli', 'sha256_stream', 'native_observer', 'sha256', 'json_preflight', 'json_decode', 'json_canonical', 'core_json_frontend', 'selfhost', 'agent_binary64', 'agent_data_json', 'instruction_policy', 'program_shape', 'function_shape', 'artifact_publication', 'core_admission_cli', 'core_admission', 'agent_binary64_format', 'core_patch', 'core_patch_cli', 'core_patch_result_cli', 'composite_types', 'task_helpers', 'worker_request', 'release_install', 'enum_match', 'release_selection', 'enum_operations', 'record_operations', 'record_transitions', 'retirement_state', 'task_operations', 'composite_functions', 'composite_constructor', 'composite_outer', 'call_primitive', 'nominal_terminators', 'nominal_module', 'nominal_admission', 'execution_budget', 'request_journal', 'task_helper_cache', 'artifact_namespace', 'slot_ledger', 'program_execution', 'static_budget', 'heap_bound', 'heap_kernels', 'core_json_bytes', 'nominal_json', 'cpython_note_packer', 'program_normalization', 'linked_observer', 'source_build', 'source_admission', 'cli_control', 'cli_format', 'machine_encoding', 'machine_state', 'machine_instructions', 'machine_elf', 'machine_plan', 'service_context', 'core_lowering', 'service_emission', 'core_emitter', 'native_byte_abi', 'native_build_foreign', 'native_build', 'service_verification_foreign', 'service_verification', 'proof_contract', 'service_requests', 'service_requests_foreign', 'core_verification', 'assembly_front', 'service_artifacts', 'service_artifacts_foreign')
FULL_SELECTORS = ('tests.test_hia_core_only', 'tests.test_hia_evidence_archive', 'tests.test_hia_core_workspace_facts_native.CoreWorkspaceFactsSourceTests', 'tests.test_hia_core_workspace_materialize_native.CoreWorkspaceMaterializerSourceTests', 'tests.test_hia_core_string_accounting', 'tests.test_hia_structure_traversal', 'tests.test_hia_capability_renaming_native.CapabilityRenamingSourceTests', 'tests.test_hia_core_module_graph_native.CoreModuleGraphSourceTests', 'tests.test_hia_source_head_identity', 'tests.test_hia_integrated_workflow', 'tests.test_hia_core_workspace_json_native.CoreWorkspaceJsonSourceTests', 'tests.test_hia_core_workspace_json_cli.CoreWorkspaceJsonCliSourceTests', 'tests.test_hia_core_workspace_pipeline.CoreWorkspacePipelineSourceTests', 'tests.test_hia_agent_identity_native.AgentIdentitySourceTests', 'tests.test_hia_agent_slice_native.AgentSliceSourceTests', 'tests.test_hia_agent_installed_resources.AgentInstalledResourceSourceTests', 'tests.test_hia_agent_stdio.AgentStdioSourceTests', 'tests.test_hia_agent_snapshot_native.AgentSnapshotSourceTests', 'tests.test_hia_agent_snapshot_json_native.AgentSnapshotJsonSourceTests', 'tests.test_hia_agent_entry', 'tests.test_hia_elf_linker.ElfLinkerSourceTests', 'tests.test_hia_core_json_cli.CoreJsonCliSourceTests', 'tests.test_hia_selfhost_word_io.WordIOSourceTests', 'tests.test_hia_selfhost_emitter_words.EmitterSourceTests', 'tests.test_hia_sha256_stream_native.Sha256StreamSourceTests', 'tests.test_hia_sha256_native.Sha256HiaSourceTests', 'tests.test_hia_json_preflight', 'tests.test_hia_json_preflight_native.JsonPreflightHiaSourceTests', 'tests.test_hia_json_decode_native.JsonDecodeHiaSourceTests', 'tests.test_hia_json_canonical_native.JsonCanonicalHiaSourceTests', 'tests.test_hia_selfhost_exports.ExportSourceTests', 'tests.test_hia_core_json_frontend_native.CoreJsonFrontendHiaSourceTests', 'tests.test_hia_selfhost.SelfhostSourceTests', 'tests.test_hia_selfhost_contract.SelfhostContractTests', 'tests.test_hia_selfhost_cli', 'tests.test_hia_selfhost_names', 'tests.test_hia_reference_fixture_efficiency', 'tests.test_hia_selfhost_returned_loans', 'tests.test_hia_selfhost_multi_results.SelfhostMultiResultSourceTests', 'tests.test_hia_selfhost_keywords.SelfhostKeywordTests', 'tests.test_hia_selfhost_signed.SelfhostSignedTests', 'tests.test_hia_selfhost_traps.SelfhostExplicitTrapTests', 'tests.test_hia_selfhost_language_coverage.SelfhostLanguageSourceTests', 'tests.test_hia_agent_data_json_native.AgentDataJsonSourceTests', 'tests.test_hia_agent_binary64_native.AgentBinary64SourceTests', 'tests.test_hia_instruction_policy_native.InstructionPolicySourceTests', 'tests.test_hia_program_shape_native.ProgramShapeSourceTests', 'tests.test_hia_function_shape_native.FunctionShapeSourceTests', 'tests.test_hia_artifact_publication_native.ArtifactPublicationPolicyTests', 'tests.test_hia_artifact_publication_route.PublicationRouteSourceTests', 'tests.test_hia_core_admission_native.CoreAdmissionSourceTests', 'tests.test_hia_core_admission_cli.CoreAdmissionCliSourceTests', 'tests.test_hia_core_patch_native.CorePatchSourceTests', 'tests.test_hia_core_patch_cli.CorePatchCliSourceTests', 'tests.test_hia_core_patch_result_cli.CorePatchResultCliSourceTests', 'tests.test_hia_core_patch_result_cli.CorePatchResultCliAdapterTests', 'tests.test_hia_composite_types_native.CompositeTypesSourceTests', 'tests.test_hia_composite_types_native.CompositeTypesAdapterTests', 'tests.test_hia_composite_origins_native.CompositeOriginsAdapterTests', 'tests.test_hia_composite_signatures_native.CompositeSignaturesAdapterTests', 'tests.test_hia_task_helpers_native.TaskHelpersSourceTests', 'tests.test_hia_task_helpers_native.TaskHelpersAdapterTests', 'tests.test_hia_composite_native_composition.SourceTests', 'tests.test_hia_composite_functions_native.FunctionSourceTests', 'tests.test_hia_composite_function_tokens.TokenCodecTests', 'tests.test_hia_composite_function_protocol_audit.FunctionTokenProtocolAuditTests', 'tests.test_hia_composite_constructor_source.ConstructorSourceTests', 'tests.test_hia_composite_constructor_native.ConstructorFrameTests', 'tests.test_hia_composite_outer_source.OuterSourceTests', 'tests.test_hia_composite_outer_native.OuterFrameTests', 'tests.test_hia_native_builder_source_binding', 'tests.test_hia_standalone_builder_source_binding', 'tests.test_hia_enum_match_native.EnumMatchSourceTests', 'tests.test_hia_enum_match_native.EnumMatchAdapterTests', 'tests.test_hia_enum_operations_native.EnumOperationsSourceTests', 'tests.test_hia_enum_operations_native.EnumOperationsAdapterTests', 'tests.test_hia_record_operations_native.RecordOperationsSourceTests', 'tests.test_hia_record_operations_native.RecordOperationsAdapterTests', 'tests.test_hia_record_transitions_native.RecordTransitionsSourceTests', 'tests.test_hia_record_transitions_native.RecordTransitionsAdapterTests', 'tests.test_hia_retirement_state_native.RetirementStateSourceTests', 'tests.test_hia_task_operations_native.TaskOperationsSourceTests', 'tests.test_hia_task_operations_native.TaskOperationsAdapterTests', 'tests.test_hia_agent_binary64_format_native.AgentBinary64FormatSourceTests', 'tests.test_hia_agent_artifact_store_native.AgentArtifactStorePolicyTests', 'tests.test_hia_worker_request_native.WorkerRequestSourceTests', 'tests.test_hia_release_install.ReleaseInstallerSourceTests', 'tests.test_hia_release_selection.ReleaseSelectionSourceTests', 'tests.test_hia_native_value_graph', 'tests.test_hia_nominal_owner_routes', 'tests.test_hia_call_primitive_native.CallPrimitiveSourceTests', 'tests.test_hia_call_primitive_native.CallPrimitiveAdapterTests', 'tests.test_hia_nominal_terminators_native.NominalTerminatorsSourceTests', 'tests.test_hia_nominal_terminators_native.NominalTerminatorsAdapterTests', 'tests.test_hia_nominal_module_native.NominalModuleSourceTests', 'tests.test_hia_nominal_module_native.NominalModuleAdapterTests', 'tests.test_hia_nominal_admission_native.NominalAdmissionSourceTests', 'tests.test_hia_nominal_admission_native.NominalAdmissionAdapterTests', 'tests.test_hia_nominal_function_native.NominalFunctionSourceTests', 'tests.test_hia_nominal_function_native.NominalFunctionAdapterTests', 'tests.test_hia_task_helper_cache_native.TaskHelperCacheSourceTests', 'tests.test_hia_task_helper_cache_native.TaskHelperCacheAdapterTests', 'tests.test_hia_execution_budget_native.ExecutionBudgetSourceTests', 'tests.test_hia_request_journal_native.RequestJournalSourceTests', 'tests.test_hia_artifact_namespace_native.ArtifactNamespaceSourceTests', 'tests.test_hia_slot_ledger_native.SlotLedgerSourceTests', 'tests.test_hia_program_execution_native.ProgramExecutionSourceTests', 'tests.test_hia_program_execution_native.ProgramExecutionAdapterTests', 'tests.test_hia_program_execution_scalars.ProgramExecutionScalarsSourceTests', 'tests.test_hia_program_execution_integration.ExecutionIntegrationSourceTests', 'tests.test_hia_static_budget_native.StaticBudgetSourceTests', 'tests.test_hia_static_budget_native.StaticBudgetAdapterTests', 'tests.test_hia_static_budget_integration.StaticBudgetIntegrationSourceTests', 'tests.test_hia_heap_bound_native.HeapBoundSourceTests', 'tests.test_hia_heap_bound_native.HeapBoundAdapterTests', 'tests.test_hia_heap_live_engine_native.HeapLiveEngineSourceTests', 'tests.test_hia_native_bigints.NativeBigIntSourceTests', 'tests.test_hia_heap_graphs_native.HeapGraphSourceTests', 'tests.test_hia_native_binary_graph', 'tests.test_hia_worker_native_helpers.NativeWorkerHelperFixtureTests', 'tests.test_hia_program_normalization_native.ProgramNormalizationSourceTests', 'tests.test_hia_program_normalization_native.ProgramNormalizationAdapterTests', 'tests.test_hia_cpython_note_packer_native.CPythonNotePackerSourceTests', 'tests.test_hia_core_json_bytes_native.CoreJSONBytesSourceTests', 'tests.test_hia_nominal_json_native.NominalJSONSourceTests', 'tests.test_hia_selfhost_linked_observer.LinkedObserverSourceTests', 'tests.test_hia_agent_identity_source_binding.AgentIdentitySourceBindingTests', 'tests.test_hia_original_select_fragments.OriginalSelectFragmentTests', 'tests.test_hia_checker_identity', 'tests.test_hia_source_build.SourceBuilderSourceTests', 'tests.test_hia_program_selfhost.SelfhostBuildSourceTests', 'tests.test_hia_source_release_integration.SourceReleaseIntegrationSourceTests', 'tests.test_hia_source_release_integration.PublicationUnionCustodyTests', 'tests.test_hia_source_admission_native.SourceAdmissionSourceTests', 'tests.test_hia_cli_native.CliSourceTests', 'tests.test_hia_cli_continuation_native.CliContinuationSourceTests', 'tests.test_hia_machine_encoding_native.MachineEncodingSourceTests', 'tests.test_hia_machine_state_native.MachineStateSourceTests', 'tests.test_hia_machine_instructions_native.MachineInstructionsSourceTests', 'tests.test_hia_machine_code_composition.MachineCodeCompositionSourceTests', 'tests.test_hia_machine_elf_native.MachineElfSourceTests', 'tests.test_hia_machine_plan_native.MachinePlanSourceTests', 'tests.test_hia_service_context_native.ServiceContextSourceTests', 'tests.test_hia_service_context_builder.ServiceContextAdapterTests', 'tests.test_hia_service_context_qualifier.ServiceContextQualifierSourceTests', 'tests.test_hia_macro_campaign.JournalTests', 'tests.test_hia_macro_campaign.NativeObservationTests', 'tests.test_hia_macro_campaign.WorkerSourceInventoryTests', 'tests.test_hia_core_lowering_native.CoreLoweringSourceTests', 'tests.test_hia_machine_frame_shared_native.SharedFrameSourceTests', 'tests.test_hia_service_emission_native.ServiceEmissionSourceTests', 'tests.test_hia_service_emission_builder.ServiceEmissionAdapterTests', 'tests.test_hia_service_emission_qualifier.ServiceEmissionQualifierSourceTests', 'tests.test_hia_service_emission_lifetimes.ServiceEmissionLifetimeSourceTests', 'tests.test_hia_artifact_publication_route.PublicationSealedDescriptorTests', 'tests.test_hia_release_selection_review.ReleaseSelectionReviewPolicyTests', 'tests.test_hia_candidate_evidence', 'tests.test_hia_candidate_preflight', 'tests.test_hia_core_emitter_native.CoreEmitterSourceTests', 'tests.test_hia_native_byte_abi_native.NativeByteABISourceTests', 'tests.test_hia_native_build_native.NativeBuildSourceTests', 'tests.test_hia_native_build_native.NativeBuildCallerSourceTests', 'tests.test_hia_service_verification_native.ServiceVerificationSourceTests', 'tests.test_hia_service_verification_builder.ServiceVerificationAdapterTests', 'tests.test_hia_service_verification_qualifier.ServiceVerificationQualifierSourceTests', 'tests.test_hia_service_verification_default_replay.ServiceVerificationDefaultReplaySourceTests', 'tests.test_hia_call_primitive_native.CallPrimitiveArenaTests', 'tests.test_hia_joint_owner_integration.JointOwnerIntegrationSourceTests', 'tests.test_hia_proof_contract_native.ProofContractSourceTests', 'tests.test_hia_proof_contract_builder.ProofContractAdapterTests', 'tests.test_hia_proof_contract_qualifier.ProofContractQualifierSourceTests', 'tests.test_hia_service_requests_native.ServiceRequestsSourceTests', 'tests.test_hia_service_requests_builder.ServiceRequestsAdapterTests', 'tests.test_hia_service_requests_qualifier.ServiceRequestsQualifierSourceTests', 'tests.test_hia_service_artifacts_native.ServiceArtifactsSourceTests', 'tests.test_hia_service_artifacts_builder.ServiceArtifactsAdapterTests', 'tests.test_hia_service_artifacts_qualifier.ServiceArtifactsQualifierSourceTests', 'tests.test_hia_front_registration.FrontRegistrationSourceTests')
PACKAGES = {'setuptools':'78.1.1','wheel':'0.46.3','z3-solver':'4.15.4.0','jsonschema':'4.26.0'}


def compact(row):
    return {'blob':row['git_blob_sha'],'bytes':row['bytes'],'sha256':row['sha256'],'mode':row['git_mode']}


def unpack(wrapper):
    packed = base64.b64decode(wrapper['payload'],validate=True)
    if len(packed)!=wrapper['compressed']['bytes'] or digest(packed)!=wrapper['compressed']['sha256']:
        raise ValueError('compressed capsule identity differs')
    decode = zlib.decompressobj()
    raw = decode.decompress(packed,wrapper['raw']['bytes']+1)
    if decode.unconsumed_tail:
        raise ValueError('capsule exceeds recorded extent')
    raw += decode.flush()
    if (not decode.eof or decode.unused_data or decode.unconsumed_tail
            or len(raw)!=wrapper['raw']['bytes'] or digest(raw)!=wrapper['raw']['sha256']):
        raise ValueError('complete capsule identity differs')
    return raw


def source_packet(inputs):
    index = json.loads((inputs/'SOURCE-INDEX.json').read_bytes())
    segments = []
    for number,row in enumerate(index['parts']):
        if row['number'] != number:
            raise ValueError('source fragment order differs')
        raw = (inputs/safe(row['path'])).read_bytes()
        if len(raw)!=row['bytes'] or digest(raw)!=row['sha256']:
            raise ValueError('source fragment bytes differ')
        segments.append(raw)
    raw = b''.join(segments)
    if len(raw)!=index['wrapper']['bytes'] or digest(raw)!=index['wrapper']['sha256']:
        raise ValueError('source wrapper differs')
    value = json.loads(unpack(json.loads(raw)))
    if value['base_commit']!=BASE or value['base_tree']!=TREE or len(value['base_manifest'])!=3257:
        raise ValueError('source packet base differs')
    return value


def git(root, *args):
    result = subprocess.run(['git','-C',str(root),*args],capture_output=True,timeout=30)
    if result.returncode:
        raise ValueError('authentic Git read failed: '+args[0])
    return result.stdout


def prepare(checkout, inputs, work, report):
    actual = files(checkout)
    commit = git(checkout,'rev-parse','HEAD').decode().strip()
    tree = git(checkout,'rev-parse','HEAD^{tree}').decode().strip()
    commit_header = git(checkout,'cat-file','commit','HEAD').split(b'\n\n',1)[0]
    parents = [line.removeprefix(b'parent ').decode('ascii') for line in commit_header.splitlines()
               if line.startswith(b'parent ')]
    parent = ' '.join(parents)
    if (commit,tree,parent)!=(BASE,TREE,PARENT):
        raise ValueError('authentic source commit/tree/parent differ')
    records = git(checkout,'ls-tree','-r','-z','HEAD')
    admit_git_snapshot(checkout,actual,records)
    packet = source_packet(inputs)
    if {name:compact(row) for name,row in actual.items()} != packet['base_manifest']:
        raise ValueError('all original Git source bytes differ from frozen base')
    source = work/'source'
    source.mkdir()
    for name,row in actual.items():
        path = source/safe(name)
        path.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(checkout/name,path)
        path.chmod(0o755 if row['git_mode']=='100755' else 0o644)
    for name,pair in packet['files'].items():
        path = source/safe(name)
        if pair['before'] != packet['base_manifest'].get(name):
            raise ValueError('source delta has a different exact predecessor')
        row = pair['after']
        if row is None:
            raise ValueError('development source packet must not delete old production')
        raw = row['content'].encode() if row['encoding']=='utf-8' else base64.b64decode(row['content'],validate=True)
        check = {'bytes':len(raw),'sha256':digest(raw),
                 'blob':sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),'mode':row['mode']}
        if any(check[k]!=row[k] for k in check) or row['mode'] not in ('100644','100755'):
            raise ValueError('source delta content or mode differs')
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(raw)
        path.chmod(0o755 if row['mode']=='100755' else 0o644)
    final = files(source)
    if {name:compact(row) for name,row in final.items()} != packet['source_manifest']:
        raise ValueError('complete new source readback differs')
    compiler_packet = (inputs/'retained-compiler.json').read_bytes()
    if digest(compiler_packet)!=COMPILER_PACKET:
        raise ValueError('exact retained compiler capsule differs')
    saved = json.loads(compiler_packet)
    packed = base64.b64decode(saved['compiler_zlib_base64'],validate=True)
    if digest(packed)!=saved['compressed_sha256'] or len(packed)!=saved['compressed_bytes']:
        raise ValueError('retained compiler compression differs')
    raw = zlib.decompress(packed)
    if len(raw)!=669494 or digest(raw)!=COMPILER:
        raise ValueError('actual retained B3 bytes differ')
    compiler = work/'retained-B3.bin'
    write(compiler,raw); compiler.chmod(0o444)
    receipt = saved['original_receipt_utf8'].encode()
    if digest(receipt)!=saved['original_receipt_sha256']:
        raise ValueError('original retained compiler receipt differs')
    write(work/'retained-B3.original-receipt.json',receipt)
    report.update(base_source_files=len(actual),authored_source_files=len(final),
                  authored_source_tree=packet['source_tree'],deletions=0,
                  actual_base_git_verified=True,compiler_sha256=COMPILER,
                  source_manifest={name:compact(row) for name,row in final.items()})
    return source,compiler,final


def run_group(source, inputs, work, report, label, tail, environment, limit=1800):
    out = work/'commands'/label
    out.mkdir(parents=True)
    command = [sys.executable,'-B',*tail]
    result = run_workflow_step(command,cwd=source,env=environment,
        stdout_path=out/'stdout',stderr_path=out/'stderr',receipt_path=out/'WORKFLOW-OWNER.json',seconds=limit)
    process = dict(result)
    process.update(argv=command,wall_limit_seconds=limit)
    write(out/'PROCESS.json',wire(process))
    report['commands'].append({'label':label,**process})
    write(work/'snapshots'/(label+'.json'),wire(files(source)))
    return (result.get('status')=='WORKFLOW_STEP_COMPLETED' and result.get('returncode')==0
            and result.get('timed_out') is False and result.get('cleanup',{}).get('complete') is True)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--inputs',type=Path,required=True)
    parser.add_argument('--workspace',type=Path,required=True)
    parser.add_argument('--profile',choices=('native314','default311','source314'),required=True)
    args=parser.parse_args()
    checkout,inputs=args.source.resolve(strict=True),args.inputs.resolve(strict=True)
    work=args.workspace.absolute(); work.mkdir(mode=0o700,exist_ok=False)
    (work/'snapshots').mkdir()
    before_inputs=files(inputs)
    report={'schema':'hia.artifacts.actual-interpreter-development.v82.r1','status':'STARTED',
        'python':sys.version,'profile':args.profile,'commands':[],
        'current_source_cold':False,'whole_native':False,'production_activated':False,
        'original_work_limit_seconds':1800,'original_compiler_limit_seconds':20}
    source=compiler=None; final=None
    try:
        if platform.system()!='Linux' or platform.machine()!='x86_64':
            raise ValueError('actual Linux x86-64 required')
        expected=(3,11) if args.profile=='default311' else (3,14,4)
        if sys.version_info[:len(expected)]!=expected:
            raise ValueError('actual interpreter profile differs')
        if {name:importlib.metadata.version(name) for name in PACKAGES}!=PACKAGES:
            raise ValueError('explicit prerequisite versions differ')
        source,compiler,authored=prepare(checkout,inputs,work,report)
        environment=dict(os.environ)
        for name in list(environment):
            if name.startswith('HEPTA_'):
                del environment[name]
        environment.update(PYTHONPATH=str(source),PYTHONDONTWRITEBYTECODE='1',PYTHONUNBUFFERED='1')
        if args.profile=='source314':
            groups=[]
            for number,name in enumerate(FULL_GENERATORS):
                groups.append(run_group(source,inputs,work,report,'full-generate-'+str(number),
                    ['-m','tools.generate_hia_'+name],environment))
                if not groups[-1]:
                    raise ValueError('complete source generator failed')
            if files(source)!=authored:
                raise ValueError('complete checked-in generation was not byte/mode reproducible')
            for number,command in enumerate((['tools/check_hia_core_only.py'],
                    ['tools/generate_hia_selfhost_contract.py','--check'],
                    ['tests/test_hia_selfhost_language_coverage.py','--generate-inventory'])):
                groups.append(run_group(source,inputs,work,report,'full-contract-'+str(number),command,environment))
            if files(source)!=authored:
                raise ValueError('complete source contract or inventory drifted')
            groups.append(run_group(source,inputs,work,report,'full-source-controls',
                [str(inputs/'run_controls.py'),'--source',str(source),
                 '--output',str(work/'full-source-observations'),'--expected','930',*FULL_SELECTORS],environment))
            final=authored
            report['status']='PASS' if all(groups) else 'FAIL'
        elif args.profile=='native314':
            commands=[['-m','tools.generate_hia_service_artifacts'],
                ['-m','tools.generate_hia_service_artifacts_foreign'],
                ['tests/test_hia_selfhost_language_coverage.py','--generate-inventory'],
                ['tools/generate_hia_selfhost_contract.py'],
                ['tools/generate_hia_selfhost_contract.py','--check'],['tools/check_hia_core_only.py']]
            for number,command in enumerate(commands):
                if not run_group(source,inputs,work,report,'generate-'+str(number),command,environment):
                    raise ValueError('actual source generation failed')
            final=files(source)
            changed={name for name in set(authored)|set(final) if authored.get(name)!=final.get(name)}
            if not changed<=GENERATED:
                raise ValueError('generation changed an unadmitted source path')
            report['generated_paths']=sorted(changed)
            report['generated_source_manifest']={name:compact(row) for name,row in final.items()}
            groups=[]
            groups.append(run_group(source,inputs,work,report,'source-controls',
                [str(inputs/'run_controls.py'),'--source',str(source),
                 '--output',str(work/'source-control-observations'),'--expected','45',*NEW_SELECTORS],environment))
            groups.append(run_group(source,inputs,work,report,'changed-compatibility-source-controls',
                [str(inputs/'run_controls.py'),'--source',str(source),
                 '--output',str(work/'changed-compatibility-source-observations'),'--expected','27',
                 *COMPATIBILITY_SELECTORS],environment))
            built=run_group(source,inputs,work,report,'actual-build',
                ['tools/build_hia_service_artifacts.py','--compiler',str(compiler),
                 '--output',str(work/'image'),'--development'],environment)
            groups.append(built)
            if built:
                manifest=work/'image/development-manifest.json'
                native_env=dict(environment,HEPTA_HIA_SERVICE_ARTIFACTS_DEVELOPMENT_MANIFEST=str(manifest),
                    HEPTA_HIA_SERVICE_ARTIFACTS_EVIDENCE=str(work/'component-evidence'))
                groups.append(run_group(source,inputs,work,report,'native-controls',
                    [str(inputs/'run_controls.py'),'--source',str(source),
                     '--output',str(work/'native-control-observations'),'--expected','12',
                     'tests.test_hia_service_artifacts_native.ServiceArtifactsNativeTests'],native_env))
                for group in ('agent','namespace','ledger'):
                    groups.append(run_group(source,inputs,work,report,'original-'+group,
                        ['tools/qualify_hia_service_artifacts.py','--development-compiler',str(compiler),
                         '--caller-group',group,'--evidence',str(work/('callers-'+group))],environment))
            report['status']='PASS' if all(groups) else 'FAIL'
        else:
            final=authored
            imported=run_group(source,inputs,work,report,'default-import-and-abi-refusal',
                [str(inputs/'default311.py'),str(source),str(inputs/'local-image.json'),str(work/'compatibility')],environment)
            callers=run_group(source,inputs,work,report,'original-default-artifact-8',
                [str(inputs/'run_controls.py'),'--source',str(source),
                 '--output',str(work/'default-control-observations'),'--expected','8',
                 'tests.test_hia_agent_native_tools.ArtifactContractTests'],environment)
            report['status']='PASS' if imported and callers else 'FAIL'
        if files(source)!=final or files(inputs)!=before_inputs or digest(compiler.read_bytes())!=COMPILER:
            raise ValueError('frozen source, harness inputs or compiler changed')
        report['final_inputs_and_source_unchanged']=True
    except BaseException:
        report.update(status='FAIL',traceback=traceback.format_exc())
    finally:
        report['harness_inputs_unchanged']=files(inputs)==before_inputs
        if source is not None:
            observed=files(source)
            write(work/'FINAL-SOURCE.json',wire(observed))
            report['final_source_files']=len(observed)
        write(work/'REPORT.json',wire(report))
        evidence=work/'COMPLETE-RAW.zip'
        with zipfile.ZipFile(evidence,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as archive:
            for path in sorted(work.rglob('*')):
                if path.is_file() and path!=evidence and 'source' not in path.relative_to(work).parts:
                    archive.write(path,path.relative_to(work).as_posix())
        with zipfile.ZipFile(evidence) as archive:
            if archive.testzip() is not None:
                raise ValueError('complete raw evidence CRC differs')
        print(json.dumps({'status':report['status'],'profile':args.profile,
            'actual_commands':len(report['commands']),'evidence_bytes':evidence.stat().st_size,
            'whole_native':False,'current_source_cold':False},sort_keys=True))
    return 0 if report['status']=='PASS' else 1


if __name__=='__main__':
    raise SystemExit(main())
