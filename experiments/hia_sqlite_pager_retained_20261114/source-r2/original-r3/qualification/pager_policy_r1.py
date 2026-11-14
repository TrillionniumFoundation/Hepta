"""Exact finite Pager request policy; no product execution at import."""
from pathlib import Path
import os
import sys
import pager_common_r1 as common
from pager_generation_r1 import CAPS
from pager_interop_cases_r3 import CASE_IDS
from pager_ipc_session_r2 import NATIVE_RAW_MAX, NATIVE_RECORD_MAX, C_COMMAND_RAW
from pager_link_buffer_trace_r1 import MAX_EXPANDED as LINK_EXPANDED

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = 'hia.sqlite-pager.first-native-interoperability-request.v1'
STATUS = 'FOUR_SCENARIOS_UNEXECUTED'
ACTUAL_NAME = 'sqlite-pager-read-owner-native-r3-actual'
PROFILE = {
    'case_ids': list(CASE_IDS), 'native_processes': 8, 'C_processes': 16,
    'native_client_commands': 40, 'automatic_page_releases': 24,
    'C_commands': 98, 'C_commands_each_version': 49,
    'HIA_B3_compiles': 2, 'bootstrap_assembly_objects': 3,
    'HIA_ELF_linker_calls': 1, 'reference_compiles_in_qualification': 0,
}
TRACE = {
    'physical_bytes_shared_including_indexes': 256 << 20,
    'part_bytes': 4 << 20, 'decode_piece_bytes': 65536,
    'ipc_row_bytes': 1 << 20, 'index_reserve_bytes_inside_total': 65536,
    'native_raw_each': NATIVE_RAW_MAX,
    'native_records_each': NATIVE_RECORD_MAX,
    'C_raw_each_command': C_COMMAND_RAW,
    'native_plus_C_expanded_bound': 8*NATIVE_RAW_MAX+98*C_COMMAND_RAW,
    'one_linker_six_buffers_expanded_bound': LINK_EXPANDED,
    'combined_expanded_bound': 8*NATIVE_RAW_MAX+98*C_COMMAND_RAW+LINK_EXPANDED,
    'extra_physical_budget_for_linker': 0,
}
LIMITS = {
    'qualification_seconds': 180, 'cleanup_seconds': 3,
    'compiler_wall_seconds': 20, 'compiler_cpu_seconds': 10,
    'compiler_input_bytes': 1 << 20, 'compiler_output_bytes': 1 << 20,
    'compiler_workspace_bytes': 1 << 20,
    'object_wall_seconds': 20, 'object_cpu_seconds': 10,
    'object_file_bytes': 1 << 20, 'native_file_bytes': 4 << 20,
    'native_address_bytes': 256 << 20, 'native_stack_bytes': 8 << 20,
    'output_files_limit': 192, 'output_bytes_limit': 384 << 20,
    'initial_free_bytes': 1 << 30, 'reserve_free_bytes': 512 << 20,
    'free_inodes': 4096,
}

def validate(request, request_pin, *, new_output):
    common.require(request['schema'] == SCHEMA and request['status'] == STATUS,
                   'exact one finite request profile')
    common.require(common.wire(request['population']) == common.wire(PROFILE)
        and common.wire(request['trace_limits']) == common.wire(TRACE)
        and common.wire(request['limits']) == common.wire(LIMITS)
        and common.wire(request['original_caps']) == common.wire(CAPS),
        'all original compiler/resource/case populations preserved')
    common.require(request['qualification_seconds'] == 180 and
                   request['cleanup_seconds'] == 3, 'original owner budget')
    common.require(request['root'] == str(ROOT)
        and request_pin['path'] == str(ROOT/'REQUEST.json')
        and Path(request['output']) == ROOT.parent/ACTUAL_NAME
        and dict(os.environ) == request['environment'], 'exact root/output/environment')
    common.require(request['command'] == [sys.executable, '-I', '-S', '-B',
        str(ROOT/'qualification/pager_worker_r1.py'), str(ROOT/'REQUEST.json'),
        '@REQUEST_SHA256@'], 'exact sole finite worker command')
    common.require(request['environment'] == {
        'LANG': 'C', 'LC_ALL': 'C', 'PATH': '/usr/bin:/bin',
        'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONHASHSEED': '0', 'TZ': 'UTC',
        'TMPDIR': str(Path(request['output'])/'tmp')}, 'exact original clean environment')
    common.require(request['inputs']['qualification/process_owner_impl.py']['sha256'] ==
        '36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2',
        'original unchanged process owner implementation')
    common.require(type(request['trace_budget_token']) is str
                   and request['trace_budget_token'], 'one aggregate token')
    common.require(request['matching_current_cold_compiler'] is False
        and request['full_SQLite_or_AgentStore_qualification'] is False
        and request['assembly_transport_is_bootstrap'] is True,
        'explicit development and bootstrap boundaries')
    if new_output:
        common.require(not os.path.lexists(request['output']),
                       'new exact disjoint output namespace')
    return request
