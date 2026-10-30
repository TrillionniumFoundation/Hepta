#!/usr/bin/env python3
"""Read-only stdlib audit of an existing run, then lossless safe-path archival."""
import copy
import gzip
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import random
import re
import stat
import subprocess
import tarfile
import time
import zlib
from collections import Counter

REPO = Path('/workspace/scratch/cd43ab608057/hepta-hia')
RAW = Path('/tmp/hepta-six-track-legacy-irpgo-20261030-01')
OUT = Path('/workspace/scratch/cd43ab608057/hia-run-evidence')
AUDIT = OUT / 'legacy-irpgo-arithmetic-audit.json'
MANIFEST = OUT / 'legacy-irpgo-raw-manifest.json'
ARCHIVE = OUT / 'legacy-irpgo-raw.tar.gz'
for destination in (AUDIT, MANIFEST, ARCHIVE):
    if destination.exists():
        raise SystemExit('Refusing to replace existing evidence: ' + str(destination))
started = time.monotonic_ns()
checks = []

def check(name, passed, details=None):
    item = {'name': name, 'passed': bool(passed)}
    if details is not None:
        item['details'] = details
    checks.append(item)

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()

def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def identity(path):
    path = Path(path).resolve(strict=True)
    return {'path': str(path), 'bytes': path.stat().st_size, 'sha256': sha(path)}

def matches(record):
    try:
        found = identity(record['path'])
        return all(found[key] == record[key] for key in ('path', 'bytes', 'sha256'))
    except (OSError, KeyError):
        return False

def git(*args):
    return subprocess.check_output(['git', *args], cwd=REPO, text=True).strip()

def read_json(path):
    return json.loads(Path(path).read_text())

def close(a, b):
    return math.isclose(a, b, rel_tol=1e-12, abs_tol=1e-12)

q = read_json(RAW / 'qualification.json')
processes = [json.loads(row) for row in (RAW / 'processes.jsonl').read_text().splitlines()]
differential = [json.loads(row) for row in (RAW / 'differential.jsonl').read_text().splitlines()]
protocol_path = REPO / 'experiments/hia_legacy_queue/IRPGO_PROTOCOL_20261029.json'
protocol = read_json(protocol_path)
base_protocol = read_json(REPO / 'experiments/hia_filecheck/PROTOCOL_20261028.json')
arms, algorithms = protocol['arms'], protocol['algorithms']
source_commit, source_tree = q['git'], git('rev-parse', q['git'] + '^{tree}')
review_commit, review_tree = git('rev-parse', 'HEAD'), git('rev-parse', 'HEAD^{tree}')
check('complete_qualification_status', q['ok'] is True and q['status'] == 'completed' and q['prepare_only'] is False)
check('recorded_clean_source', q['git_status'] == '' and q['source_files_tracked'] is True)
check('review_tree_equals_measured_tree', source_tree == review_tree, {'measured_commit':source_commit, 'review_commit':review_commit, 'tree':source_tree})
check('review_worktree_clean', git('status', '--porcelain') == '')
check('frozen_protocol_identity_and_value', q['protocol'] == protocol and q['protocol_sha256'] == sha(protocol_path))
source_failures = []
for name, digest in q['source_bindings'].items():
    path = PurePosixPath(name)
    if path.is_absolute() or '..' in path.parts or sha(REPO / name) != digest:
        source_failures.append(name)
check('all_recorded_source_bindings_match_current_equal_tree', not source_failures, {'files':len(q['source_bindings']), 'mismatches':source_failures})
check('tool_and_python_identities_still_match', all(matches(item) for item in [*q['tools'].values(), q['python']]))
check('process_ledger_identity', matches(q['process_ledger']))
check('process_ledger_equals_all_recorded_commands', len(processes) == len(q['commands']) and all({k:v for k,v in row.items() if k not in ('stdout','stderr')} == record for row,record in zip(processes,q['commands'])))
check('every_recorded_command_successful', all(row.get('returncode') == 0 and not row.get('timed_out') and not row.get('signal') for row in processes), {'commands':len(processes)})
stage_counts = dict(sorted(Counter(row['stage'] for row in processes).items()))

# Independent integer CRC recurrence and table, not the experiment helpers.
def crc_table(polynomial):
    table = []
    for byte in range(256):
        value = byte
        for _ in range(8):
            value = (value >> 1) ^ (polynomial if value & 1 else 0)
        table.append(value)
    return table

def crc_update(state, data, polynomial):
    table = crc_table(polynomial)
    for byte in data:
        state = (state >> 8) ^ table[(state ^ byte) & 255]
    return state

check('independent_crc_known_vectors', crc_update(0xffffffff,b'123456789',0x82f63b78)^0xffffffff == 0xe3069283 and crc_update(0xffffffff,b'123456789',0xedb88320)^0xffffffff == 0xcbf43926)

def generated_corpus(seed, size):
    value = seed & 0xffffffff
    text = b'Hepta file checksum application: ownership, ABI, migration.\n'
    result = bytearray(size)
    for index in range(size):
        value ^= (value << 13) & 0xffffffff
        value ^= value >> 17
        value ^= (value << 5) & 0xffffffff
        region = (index // 4096) % 3
        result[index] = 0 if region == 0 else text[index % len(text)] if region == 1 else value & 255
    return bytes(result)

input_audit = {}
for name, spec in [('training.bin',protocol['training']),('held-out.bin',protocol['held_out'])]:
    data = (RAW / name).read_bytes()
    expected_data = generated_corpus(spec['seed'],spec['bytes'])
    sums = {name:crc_update(0xffffffff,data,polynomial)^0xffffffff for name,polynomial in algorithms.items()}
    check(name + '_fixed_bytes_and_checksums', matches(q['inputs'][name]) and data == expected_data and sums == q['inputs'][name]['checksums'] and sums['ieee'] == zlib.crc32(data)&0xffffffff)
    input_audit[name] = {'seed':spec['seed'], 'identity':identity(RAW/name), 'independently_computed_checksums':sums, 'calls_per_application':(len(data)+7)//8, 'batches_per_application':(len(data)+4095)//4096}

# Reconstruct the registered scalar cases in their original shared-helper order.
rng = random.Random(20261028)
expected_cases = []
for index in range(protocol['differential_cases']):
    count = index % 12
    packed, state = rng.getrandbits(64), rng.getrandbits(32)
    polynomial = list(base_protocol['algorithms'].values())[index % 2]
    answer = (1 << 32) if count > 8 else crc_update(state,packed.to_bytes(8,'little')[:count],polynomial)
    expected_cases.append({'arguments':[count,packed,state,polynomial], 'expected':answer})
check('differential_ledger_identity', matches(q['differential']['ledger']))
check('all_96_registered_differential_inputs_and_independent_results', len(differential) == 96 and all({k:row[k] for k in ('arguments','expected')} == expected for row,expected in zip(differential,expected_cases)))
check('all_1056_native_differential_values', all(set(row['observed']) == set(arms) and all(value == row['expected'] for value in row['observed'].values()) for row in differential))
check('differential_metadata_counts', q['differential']['cases'] == 96 and q['differential']['routes'] == 11 and q['differential']['native_calls'] == 1056)

# Bind every application row to its original raw process stdout and RSS receipt.
def application_matches(record, input_name, algorithm, stage):
    command = processes[record['command_index']]
    argv = command['argv']
    expected = input_audit[input_name]
    observed = record['observation']
    memory = record['memory']
    return (command['stage'] == stage and command['wall_ns'] == record['process_wall_ns']
            and json.loads(command['stdout']) == observed
            and Path(argv[1]) == Path(record['memory_receipt']['path'])
            and Path(argv[5]) == RAW / input_name and int(argv[6]) == algorithms[algorithm]
            and argv[4] == 'legacy_checksum_chunk'
            and observed['checksum'] == expected['independently_computed_checksums'][algorithm]
            and observed['bytes'] == expected['identity']['bytes']
            and observed['calls'] == expected['calls_per_application']
            and observed['batches'] == len(observed['batch_ns']) == expected['batches_per_application']
            and all(type(value) is int and value > 0 for value in observed['batch_ns'])
            and matches(record['memory_receipt'])
            and read_json(record['memory_receipt']['path']) == memory
            and memory['child_exit_code'] == 0 and memory['child_signal'] == 0
            and memory['child_wait4_ru_maxrss_kib'] > 0)

samples = q['samples']
expected_order = []
for group in range(protocol['paired_groups']):
    for index, algorithm in enumerate(algorithms):
        shift = (group+index) % len(arms)
        rotated = arms[shift:]+arms[:shift]
        if group % 2:
            rotated = list(reversed(rotated))
        expected_order.extend((group,algorithm,arm) for arm in rotated)
actual_order = [(row['group'],row['algorithm'],row['arm']) for row in samples]
check('complete_154_samples_in_exact_registered_order', actual_order == expected_order and len(samples) == 154 and len(set(actual_order)) == 154)
measured_indices = [index for index,row in enumerate(processes) if row['stage'] == 'measured_application']
check('no_omitted_or_duplicate_measured_process_records', [row['command_index'] for row in samples] == measured_indices and len(measured_indices) == 154 and q['samples_excluded'] == 0)
check('all_measured_stdout_rss_work_and_library_bindings', all(application_matches(row,'held-out.bin',row['algorithm'],'measured_application') and Path(processes[row['command_index']]['argv'][3]) == RAW/(row['arm']+'.so') for row in samples))

training_records = []
for arm, build in q['builds'].items():
    if 'training' not in build:
        continue
    stage = 'ir_profile_training' if arm.endswith('_irpgo') else 'profile_training'
    valid = len(build['training']) == 2
    for algorithm, row in zip(algorithms,build['training']):
        valid &= application_matches(row,'training.bin',algorithm,stage)
        training_records.append(row['command_index'])
    check(arm+'_training_and_profiles', valid and len(build['profiles']) == 2 and all(matches(profile) and profile['bytes'] > 0 for profile in build['profiles']) and matches(build['merged_profile']))
check('all_12_and_only_registered_training_processes', sorted(training_records) == [index for index,row in enumerate(processes) if row['stage'] in ('profile_training','ir_profile_training')] and len(training_records) == 12)

# Pure arithmetic recomputation from the raw per-process times and batch samples.
def median7(values):
    values = sorted(values)
    assert len(values) == 7
    return values[3]

def percentile(values, integer_percent):
    values = sorted(values)
    return values[(integer_percent*len(values)+99)//100-1]

recomputed = {}
summary_matches = True
for algorithm in algorithms:
    table = {}
    for arm in arms:
        rows = [row for row in samples if row['algorithm'] == algorithm and row['arm'] == arm]
        batches = [value for row in rows for value in row['observation']['batch_ns']]
        wall = median7([row['process_wall_ns'] for row in rows])
        computed = {'samples':len(rows), 'median_process_wall_ns':wall,
                    'mib_per_second':protocol['held_out']['bytes']*1e9/wall/2**20,
                    'batch_p95_ns':percentile(batches,95), 'batch_p99_ns':percentile(batches,99),
                    'child_wait4_peak_rss_kib_median':median7([row['memory']['child_wait4_ru_maxrss_kib'] for row in rows])}
        stored = q['summary'][algorithm]['arms'][arm]
        summary_matches &= set(stored) == set(computed) and all(close(computed[key],stored[key]) for key in computed)
        table[arm] = computed
    reference = min((arm for arm in arms if not arm.startswith('hia')),key=lambda arm:table[arm]['median_process_wall_ns'])
    hia, strong = table['hia_native_irpgo'], table[reference]
    ratios = {'hia_runtime_ratio':hia['median_process_wall_ns']/strong['median_process_wall_ns'],
              'hia_p99_ratio':hia['batch_p99_ns']/strong['batch_p99_ns'],
              'hia_rss_ratio':hia['child_wait4_peak_rss_kib_median']/strong['child_wait4_peak_rss_kib_median']}
    stored = q['summary'][algorithm]
    summary_matches &= stored['fastest_strong_reference'] == reference and all(close(stored[key],value) for key,value in ratios.items())
    recomputed[algorithm] = {'arms':table, 'fastest_strong_reference':reference,
                            'selected_hia_arm':'hia_native_irpgo', **ratios,
                            'hia_process_time_increase_percent':100*(ratios['hia_runtime_ratio']-1),
                            'hia_p99_increase_percent':100*(ratios['hia_p99_ratio']-1),
                            'hia_rss_change_percent':100*(ratios['hia_rss_ratio']-1),
                            'latency_gate':ratios['hia_runtime_ratio'] <= 1 and ratios['hia_p99_ratio'] <= 1,
                            'rss_gate':ratios['hia_rss_ratio'] <= 1,
                            'pooled_batches_per_arm':7*((protocol['held_out']['bytes']+4095)//4096)}
check('all_22_arm_summaries_and_reference_ratios_recompute',summary_matches)
performance_gate = all(row['latency_gate'] for row in recomputed.values())
combined_gate = performance_gate and all(row['rss_gate'] for row in recomputed.values())
check('preselected_hia_arm_and_both_gates_recompute', q['selected_hia_arm'] == protocol['selected_hia_arm'] == 'hia_native_irpgo' and q['performance_advantage_gate'] is performance_gate and q['performance_and_rss_gate'] is combined_gate)

# Resource expected values derive from the explicit three-allocation client,
# independently of the VM's recorded counters.
resources = q['resource_cases']
resource_processes = {}
for index, row in enumerate(processes):
    if row['stage'] not in ('resource_execution','ir_pgo_resource_execution'):
        continue
    key = (Path(row['argv'][0]).name, tuple(map(int,row['argv'][1:])))
    resource_processes.setdefault(key,[]).append((index,json.loads(row['stdout'])))
resource_order = [(row['arguments'],refuse) for row in expected_cases[:24] for refuse in protocol['allocation_refusal_indices']]
check('all_96_resource_rows_in_registered_order', [(row['arguments'],row['refuse_at']) for row in resources] == resource_order and len(resources) == 96)
resource_values_ok, resource_process_bindings_ok = True, True
resource_command_indices = []
for row in resources:
    count,packed,state,polynomial = row['arguments']
    refuse = row['refuse_at']
    if count == 0 or count > 8:
        result = state if count == 0 else 1 << 32
        attempts = allocations = peak = 0
    elif refuse:
        result, attempts, allocations = 1 << 33, refuse, refuse-1
        peak = (0,16,24)[refuse-1]
    else:
        result = crc_update(state,packed.to_bytes(8,'little')[:count],polynomial)
        attempts = allocations = 3
        peak = 32
    expected = {'result':result,'attempts':attempts,'allocations':allocations,'frees':allocations,'live':0}
    vm, stats = row['vm'], row['vm']['resources']
    resource_values_ok &= (set(row['native']) == {'c','hia','hia_irpgo'}
        and all(value == expected for value in row['native'].values())
        and vm['status'] == 'returned' and vm['result'] == result
        and vm['program_sha256'] == q['migration']['program_sha256']
        and stats['allocation_attempts'] == attempts
        and stats['allocations'] == stats['frees'] == allocations
        and stats['owners_created'] == stats['owners_dropped'] == allocations
        and stats['live_owners'] == stats['live_bytes'] == stats['live_local_loans'] == 0
        and stats['loans_started'] == stats['loans_ended'] and stats['peak_bytes'] == peak)
    for route in ('c','hia','hia_irpgo'):
        key = ('resource_'+route,tuple([*row['arguments'],refuse]))
        records = resource_processes.get(key,[])
        resource_process_bindings_ok &= len(records) == 1 and records[0][1] == row['native'][route]
        resource_command_indices.extend(index for index,_ in records)
check('all_resource_values_match_independent_client_expectations',resource_values_ok)
check('all_288_native_resource_outputs_bound_to_process_ledger',resource_process_bindings_ok and len(resource_command_indices) == len(set(resource_command_indices)) == 288 and len(resource_processes) == 288)
resource_builds = [row for row in processes if row['stage'] in ('ir_pgo_resource_object','ir_pgo_resource_link')]
check('irpgo_observer_is_separate_and_retains_registered_optimization',len(resource_builds) == 2 and all(all(flag in row['argv'] for flag in ('-O3','-flto=full','-march=native')) for row in resource_builds) and q['irpgo_resource_scope']['performance_dso_injected'] is False)

maintenance = q['maintenance']
maintenance_rows = maintenance['cases']
expected_maintenance = []
for algorithm in (0,1,2,3):
    for state,byte in ((0,0),(0xffffffff,255),(12345,49)):
        result = state if algorithm not in (1,2) else crc_update(state,bytes([byte]),algorithms['ieee' if algorithm == 1 else 'castagnoli'])
        expected_maintenance.append({'arguments':[state,byte,algorithm],'expected':result,'values':{'c':result,'hia':result}})
check('12_maintenance_cases_recompute_by_named_algorithm',maintenance_rows == expected_maintenance and read_json(RAW/'maintenance-cases.json') == expected_maintenance)
check('human_labor_not_claimed_zero',q['migration']['human_effort_measured'] is False and maintenance['human_effort_measured'] is False and q['claims']['human_labor_saving_measured'] is False)
check('whole_qualification_cost_arithmetic',q['whole_qualification_wall_ns'] == q['initialization_wall_ns']+q['run_wall_ns'])

# Verify retained capture/configuration/contract identities, without invoking Clang.
captures = {}
for label in ('migration','maintenance'):
    report = q['migration'] if label == 'migration' else maintenance['migration']
    captured = read_json(RAW/label/'capture.json')
    migration = read_json(RAW/label/'migration.json')
    database = read_json(RAW/label/'compile_commands.json')
    generated = report['generated_program']
    check(label+'_retained_files_and_capture_digest', all(matches(record) for record in [report['capture'],report['migration'],*report['asts'],*generated.values()])
          and captured == migration['capture']
          and hashlib.sha256(canonical({k:v for k,v in captured.items() if k != 'sha256'})).hexdigest() == captured['sha256']
          and sha(captured['database']['path']) == captured['database']['sha256'])
    check(label+'_all_captured_dependency_bytes_match',all(matches(record) for record in captured['dependencies']))
    expected_tus = 4 if label == 'migration' else 5
    check(label+'_explicit_configurations_and_scalar_abi_model',len(database) == len(captured['configurations']) == report['source_tus'] == expected_tus
          and all(config['model'] == {'char_unsigned':True,'long_bits':64,'pointer_bits':64} for config in captured['configurations'])
          and all(all(flag in entry['arguments'] for flag in ('-std=c11','-DNDEBUG','-funsigned-char','-fno-builtin','-O3')) for entry in database))
    contracts = migration['contracts']
    contract_bytes = canonical(contracts)
    contract_identity = migration['contract_identity']
    check(label+'_caller_declared_contract_identity',contract_identity['origin'] == 'caller_declared_not_inferred_or_proved'
          and len(contract_bytes) == contract_identity['canonical_bytes']
          and hashlib.sha256(contract_bytes).hexdigest() == contract_identity['canonical_sha256'])
    check(label+'_retained_hepta_and_client_exact',migration['source'] == (RAW/label/'source.hepta').read_text()
          and migration['client_source'] == (RAW/label/'client.hepta').read_text())
    captures[label] = {'source_tus':report['source_tus'], 'translated_implementation_bodies':report['translated_implementation_bodies'],
                      'upstream_function_bodies':report['upstream_function_bodies'], 'authored_migrated_function_bodies':report['authored_migrated_function_bodies'],
                      'authored_client_function_bodies':report['authored_client_function_bodies'], 'capture_identity':report['capture'],
                      'program_sha256':report['program_sha256'], 'generated_program':generated,
                      'captured_dependencies':len(captured['dependencies']), 'contract_identity':contract_identity,
                      'contract_function_count':len(contracts['functions']), 'manual_migrated_body_edits_recorded':report['manual_migrated_body_edits'],
                      'human_effort_measured':report['human_effort_measured'], 'wall_ns':report['wall_ns'],
                      'fresh_admission_wall_ns':report['fresh_admission_wall_ns']}

original_contracts = copy.deepcopy(read_json(RAW/'project/ring/contracts.json'))
original_contracts['functions'].update(read_json(RAW/'project/compare/contracts.json')['functions'])
original_contracts['functions']['checksum_byte'] = {'records':{},'slices':{}}
check('initial_contracts_exact_explicit_component_merge',original_contracts == read_json(RAW/'project/contracts.json') == read_json(RAW/'migration/migration.json')['contracts'])
upstream_bad = []
upstream_checked = 0
for dirname, record_key in [('ring','upstream_ring'),('compare','upstream_compare')]:
    for record in q['migration'][record_key]['files']:
        for project in ('project','maintained-project'):
            path = RAW/project/dirname/record['local_path']
            upstream_checked += 1
            if path.stat().st_size != record['bytes'] or sha(path) != record['sha256']:
                upstream_bad.append(str(path))
check('all_upstream_bytes_unchanged_in_original_and_maintenance_projects',not upstream_bad,{'file_observations':upstream_checked,'mismatches':upstream_bad})
for receipt_name, receipt, core_sha in [('hia_default',q['builds']['hia_default']['receipt'],q['migration']['program_sha256']),
                                       ('resource_native',q['resource_native_build'],q['migration']['program_sha256']),
                                       ('maintenance',maintenance['build'],maintenance['migration']['program_sha256'])]:
    artifact = identity(receipt['output'])
    check(receipt_name+'_native_receipt_and_retained_image',receipt['ok'] is True and receipt['core_sha256'] == core_sha
          and artifact['sha256'] == receipt['artifact_sha256'] and artifact['bytes'] == receipt['artifact_bytes'])
check('all_final_native_artifact_identities',all(matches(record) for record in [*q['artifacts'].values(),q['supervisor'],*q['irpgo_resource_artifacts']]))
for arm in ('hia_native_lto','hia_native_irpgo'):
    build = q['builds'][arm]
    outputs = [row for row in processes if '-o' in row['argv'] and row['argv'][-1] == str(RAW/(arm+'.so'))]
    check(arm+'_same_core_llvm_and_no_original_c_link_input',build['generated_program'] == q['migration']['generated_program']
          and len(outputs) == 1 and str(RAW/'migration/program.ll') in outputs[0]['argv']
          and not any(argument.endswith(('.c','.cpp','.rs')) for argument in outputs[0]['argv']))

counter_audit = {}
for arm in ('hia_native_irpgo','c_native_irpgo','cpp_native_irpgo'):
    build = q['builds'][arm]
    shown = Path(build['counter_inspection']['path']).read_text()
    segments = re.findall(r'^  legacy_checksum_chunk:\n(.*?)(?=^  \S|^Instrumentation level:|\Z)',shown,re.M|re.S)
    valid = len(segments) == 1
    counters = []
    if valid:
        declared = re.findall(r'^    Counters: ([0-9]+)$',segments[0],re.M)
        lists = re.findall(r'^    Block counts: (\[[^\n]+\])$',segments[0],re.M)
        valid &= len(declared) == len(lists) == 1
        if valid:
            counters = json.loads(lists[0])
            valid &= len(counters) == int(declared[0]) and all(type(value) is int and 0 <= value < 2**64 for value in counters) and any(counters)
    check(arm+'_positive_exact_target_ir_counter_list',valid and counters == build['entry_function_block_counts']
          and len(counters) == build['entry_function_counters'] and sum(counters) == build['entry_function_block_count_sum']
          and matches(build['counter_inspection']) and matches(build['instrumented_image']))
    counter_audit[arm] = {'target':'legacy_checksum_chunk','block_counter_count':len(counters), 'block_counts':counters,
                          'interpretation':'stored block counters; neither first counter nor sum is entry invocation count',
                          'counter_text_identity':build['counter_inspection']}
for name, record in q['switch_recovery'].items():
    expected_switch = name == 'successful_switch'
    check(name+'_raw_output_and_expected_switch_behavior',application_matches(record,'held-out.bin','ieee',name)
          and record['observation']['switches'] == int(expected_switch)
          and record['observation']['refused_switches'] == int(not expected_switch))

# Inventory exactly the original output directory, without adding or removing data.
files, directories = [], []
unsafe = []
for path in sorted(RAW.rglob('*')):
    relative = path.relative_to(RAW).as_posix()
    mode = path.lstat().st_mode
    safe_name = not PurePosixPath(relative).is_absolute() and '..' not in PurePosixPath(relative).parts
    if not safe_name or path.is_symlink() or not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)) or mode & 0o6000:
        unsafe.append(relative)
    elif path.is_dir():
        directories.append(relative)
    else:
        files.append({'path':relative,'bytes':path.stat().st_size,'sha256':sha(path),'mode_octal':oct(stat.S_IMODE(mode))})
check('raw_archive_input_paths_safe',not unsafe,{'unsafe_entries':unsafe})
if unsafe:
    raise RuntimeError('Unsafe raw archive path; original data retained')
manifest = {'schema':'hepta.hia.legacy-irpgo.exact-raw-manifest.v1','source_commit':source_commit,'source_tree':source_tree,
            'original_directory':str(RAW),'archive_top_directory':RAW.name,'file_count':len(files),
            'total_file_bytes':sum(row['bytes'] for row in files),'directory_count':len(directories)+1,
            'directories':['.',*directories],'files':files,
            'all_original_regular_files_retained':True,'symlinks_or_special_files':False,
            'native_binaries_and_fixed_corpora_included':True,'original_directory_modified':False}
with MANIFEST.open('x') as stream:
    json.dump(manifest,stream,sort_keys=True,indent=2,allow_nan=False)
    stream.write('\n')
with ARCHIVE.open('xb') as target:
    with gzip.GzipFile(filename='',mode='wb',fileobj=target,mtime=0,compresslevel=6) as zipped:
        with tarfile.open(fileobj=zipped,mode='w',format=tarfile.PAX_FORMAT,dereference=True) as archive:
            archive.add(RAW,arcname=RAW.name,recursive=False)
            for relative in directories:
                archive.add(RAW/relative,arcname=RAW.name+'/'+relative,recursive=False)
            for row in files:
                archive.add(RAW/row['path'],arcname=RAW.name+'/'+row['path'],recursive=False)
expected_members = {RAW.name+'/'+row['path']:row for row in files}
seen, archive_safe, archive_equal = set(), True, True
with tarfile.open(ARCHIVE,'r:gz') as archive:
    for member in archive:
        parsed = PurePosixPath(member.name)
        archive_safe &= not parsed.is_absolute() and '..' not in parsed.parts and bool(parsed.parts) and parsed.parts[0] == RAW.name and (member.isdir() or member.isreg())
        if member.isreg():
            archive_equal &= member.name not in seen and member.name in expected_members
            seen.add(member.name)
            wanted = expected_members.get(member.name)
            if wanted:
                with archive.extractfile(member) as stream:
                    actual_digest = hashlib.file_digest(stream,'sha256').hexdigest()
                archive_equal &= member.size == wanted['bytes'] and actual_digest == wanted['sha256']
check('archive_readback_safe_and_byte_exact',archive_safe and archive_equal and seen == set(expected_members),{'regular_file_count':len(seen),'extraction_performed':False})
check('original_raw_directory_files_unchanged_after_archive',all((RAW/row['path']).stat().st_size == row['bytes'] and sha(RAW/row['path']) == row['sha256'] for row in files) and sorted(path.relative_to(RAW).as_posix() for path in RAW.rglob('*') if path.is_file()) == [row['path'] for row in files])
check('source_still_clean_after_readonly_audit',git('status','--porcelain') == '' and git('rev-parse','HEAD^{tree}') == source_tree)

result = {'schema':'hepta.hia.legacy-irpgo.independent-arithmetic-audit.v1','audit_date_utc':'2026-10-30',
          'audit_ok':all(row['passed'] for row in checks),'audit_scope':'Existing raw evidence only; independent Python standard-library arithmetic and identity checks; no compiler, model, native artifact execution or new performance sampling.',
          'new_native_runs':0,'new_performance_samples':0,'source_commit':source_commit,'source_tree':source_tree,
          'review_commit_same_tree':review_commit,'qualification_identity':identity(RAW/'qualification.json'),
          'process_ledger_identity':identity(RAW/'processes.jsonl'),'differential_ledger_identity':identity(RAW/'differential.jsonl'),
          'protocol_identity':identity(protocol_path),'checks':checks,
          'counts':{'recorded_processes':len(processes),'process_stages':stage_counts,'native_routes':len(arms),
                    'differential_cases':len(differential),'native_differential_calls':sum(len(row['observed']) for row in differential),
                    'resource_rows':len(resources),'native_resource_processes':len(resource_command_indices),
                    'maintenance_cases':len(maintenance_rows),'maintenance_native_result_values':2*len(maintenance_rows),
                    'training_application_processes':len(training_records),'measured_application_processes':len(samples),
                    'measured_groups':protocol['paired_groups'],'samples_per_algorithm_and_arm':7,'samples_excluded':q['samples_excluded'],
                    'switch_observations':len(q['switch_recovery'])},
          'input_domain':{'abi':'Linux x86-64 LP64 scalar entry: usize count, u64 packed, u32 state, u32 polynomial -> u64',
                          'capture_configuration':['C11','NDEBUG','unsigned char','no builtin during capture','64-bit long and pointer'],
                          'ordinary_chunk_count':'1 through 8 bytes; count 0 returns the input state without allocating',
                          'checked_invalid_counts':'9,10,11 in the finite differential domain return 2^32; this is not exhaustive validation of all usize inputs',
                          'allocation_failure_sentinel':1<<33,'buffer_lengths_bytes':[16,8,8],
                          'ring_capacity':'fixed 16-byte power-of-two storage in the authored client',
                          'polynomials':algorithms,'corpus_regions':'zero runs, repeating public text, seeded xorshift32 bytes, final partial chunk',
                          'contracts':'Caller-supplied record/slice access and length declarations, retained and hash-bound; not inferred or proved from arbitrary C pointers.',
                          'foreign_pointer_or_original_record_layout_abi_claimed':False,'inputs':input_audit},
          'capture_and_migration':captures,'ir_profile_counter_audit':counter_audit,
          'summary_recomputed':recomputed,'performance_advantage_gate_recomputed':performance_gate,'performance_and_rss_gate_recomputed':combined_gate,
          'arithmetic_rules':{'median':'4th sorted observation of exactly 7 process samples',
                              'batch_percentiles':'nearest-rank ceil(percent*n/100), pooled 7*513 batch durations per arm and algorithm',
                              'strong_reference':'minimum median process wall time over all seven non-HIA C/C++/Rust arms, separately for each algorithm',
                              'hia_candidate':'hia_native_irpgo fixed by the protocol before sampling',
                              'float_summary_comparison_tolerance':{'relative':1e-12,'absolute':1e-12}},
          'cost_scope':{'initialization_wall_ns':q['initialization_wall_ns'],'run_wall_ns':q['run_wall_ns'],
                        'whole_qualification_wall_ns':q['whole_qualification_wall_ns'],
                        'whole_qualification_seconds':q['whole_qualification_wall_ns']/1e9,
                        'migration_wall_ns':q['migration']['wall_ns'],'maintenance_wall_ns':maintenance['wall_ns'],
                        'build_preparation_wall_ns':{arm:value['wall_ns'] for arm,value in q['builds'].items()},
                        'human_effort_measured':False,'human_hours':None,'human_labor_saving_measured':False,
                        'manual_migrated_body_edits_recorded':{'initial':q['migration']['manual_migrated_body_edits'],'maintenance':maintenance['manual_migrated_body_edits']},
                        'manual_edit_counter_is_total_labor_cost':False,
                        'unmeasured':['authoring contracts, clients, harness and migration implementation','historical toolchain acquisition','outer Python startup/import','final report write','archiving','human engineering labor'],
                        'cost_interval_warning':'Build/migration subtimers are inside whole_qualification; do not add them again. Audit/archive time is separate.'},
          'limitations':['Finite shared-host observation; no statistical or universal performance advantage claim.',
                         'Lower RSS medians do not establish a whole-process resource upper bound or a language safety proof.',
                         'Resource refusal is observed in a separate O3/full-LTO/native-CPU observer, not injected into the timed IRPGO DSO.',
                         'Native differential and maintenance observations are not source/native refinement proofs.',
                         '11 upstream C function bodies plus authored integration are not a full C++ library migration.',
                         'No evidence of total human labor being zero; zero recorded manual edits to migrated bodies has a narrower meaning.',
                         'File hashes and mutually consistent retained logs are trusted-host evidence, not hardware attestation or proof against fabricated records.'],
          'archive':{'identity':identity(ARCHIVE),'manifest_identity':identity(MANIFEST),
                     'raw_file_count':len(files),'raw_total_file_bytes':manifest['total_file_bytes'],
                     'all_original_files_included':True,'safe_relative_paths_verified':archive_safe,
                     'per_file_decompressed_sha256_verified':archive_equal and seen == set(expected_members),
                     'original_directory_retained':str(RAW),'public_native_binaries_and_fixed_inputs_retained':True,
                     'exceeds_4_000_000_bytes':ARCHIVE.stat().st_size > 4_000_000,
                     'git_publication_performed':False},
          'auditor_script_identity':identity(Path(__file__)),
          'audit_and_archive_wall_ns':time.monotonic_ns()-started}
with AUDIT.open('x') as stream:
    json.dump(result,stream,sort_keys=True,indent=2,allow_nan=False)
    stream.write('\n')
print(json.dumps({'audit_ok':result['audit_ok'],'checks':len(checks),'failed_checks':[row for row in checks if not row['passed']],
                  'audit':identity(AUDIT),'archive':result['archive'],
                  'ratios':{key:{name:row[name] for name in ('fastest_strong_reference','hia_runtime_ratio','hia_p99_ratio','hia_rss_ratio')} for key,row in recomputed.items()},
                  'wall_seconds':result['audit_and_archive_wall_ns']/1e9},sort_keys=True))
