"""Exact two-author generation request; no native or interop entry at import."""
from pathlib import Path
import os
import sys
import pager_common_r1 as common
from pager_generation_r1 import CAPS, PARTS, AUTHORS

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = 'hia.sqlite-pager.retained-generation-only-request.v1'
STATUS = 'TWO_AUTHORS_UNEXECUTED'
ACTUAL_NAME = 'pager-retained-generation-r1-actual'
PROFILE = {
    'authors': [list(value) for value in AUTHORS],
    'source_parts': list(PARTS),
    'author_document_calls': 2,
    'core_documents': 2, 'assembly_documents': 2,
    'Core_assembly_roundtrip_pairs': 2,
    'B3_calls': 0, 'GAS_calls': 0, 'VM_calls': 0,
    'HIA_native_entries': 0, 'SQLite_processes': 0, 'interop_cases': 0,
}
LIMITS = {
    'qualification_seconds': 180, 'cleanup_seconds': 3,
    'cpu_seconds': 180, 'file_bytes': 4 << 20,
    'address_bytes': 256 << 20, 'stack_bytes': 8 << 20,
    'output_files_limit': 192, 'output_bytes_limit': 384 << 20,
    'initial_free_bytes': 1 << 30, 'reserve_free_bytes': 512 << 20,
    'free_inodes': 4096,
}
QUALIFICATION = tuple('qualification/'+name for name in (
    'pager_common_r1.py', 'pager_support_r1.py', 'pager_policy_r1.py',
    'pager_generation_r1.py', 'pager_worker_r1.py', 'pager_launch_r1.py',
    'pager_clean_exec_r1.py', 'process_owner_impl.py'))
AUTHOR_PINS = {
    'inputs/tools/generate_hia_sqlite_pager_retained_owner_r1.py':
        (4813, '5db58dff51acc4ce63f6a899c31e58011762711418d1adb529bd57655f115b6c'),
    'inputs/tools/generate_hia_pager_elf_linker.py':
        (3979, '25fe26191fc58965a4346f49cc39fd1d4d8f8b322fd818c7c7ad10f5e742c029'),
    'inputs/tools/pager_owner_lock_source_r3.py':
        (15651, '49e5c19a3d00b6e40ade3b632c1739433a647afafbed690163cacc3b6eb4fb4c'),
    'inputs/tools/pager_owner_page_source.py':
        (4797, 'ab2b5080b3aa8480a7d500e16185ffae8cda6060a025d5eef3074e3edfbc8aa9'),
    'inputs/tools/pager_owner_common_source_r2.py':
        (7069, 'da2df5548aaf1497db907f6d18bb7f9508c01991699c3b88713a07b03f2b8eaa'),
    'inputs/tools/sqlite_pager_retained_owner.hia':
        (6115, '60129d48d1bb4144a01ef80d8763aae97f894c70f2576dc645022d7ec43f76e6'),
}

def validate(request, request_pin, *, new_output):
    common.require(request['schema'] == SCHEMA and request['status'] == STATUS,
                   'exact two-author generation-only request')
    common.require(common.wire(request['population']) == common.wire(PROFILE)
        and common.wire(request['limits']) == common.wire(LIMITS)
        and common.wire(request['original_caps']) == common.wire(CAPS),
        'same owner, physical limits, and original nine compiler caps')
    common.require(type(request['qualification_seconds']) is int
        and request['qualification_seconds'] == 180
        and type(request['cleanup_seconds']) is int
        and request['cleanup_seconds'] == 3, 'one original owner budget')
    common.require(request['root'] == str(ROOT)
        and ROOT.name == 'pager-retained-generation-r1'
        and request_pin['path'] == str(ROOT/'REQUEST.json')
        and Path(request['output']) == ROOT.parent/ACTUAL_NAME
        and dict(os.environ) == request['environment'], 'exact root/output/environment')
    common.require(request['command'] == [sys.executable, '-I', '-S', '-B',
        str(ROOT/'qualification/pager_worker_r1.py'), str(ROOT/'REQUEST.json'),
        '@REQUEST_SHA256@'], 'exact original worker basename and sole command')
    common.require(request['environment'] == {
        'LANG': 'C', 'LC_ALL': 'C', 'PATH': '',
        'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONHASHSEED': '0', 'TZ': 'UTC',
        'TMPDIR': str(Path(request['output'])/'tmp')}, 'exact generation-only environment')
    common.require(request['source_root'] ==
        '/home/qq/hia-rewrite-20261113-e26e-r1/core-put-mask-elision-derive8-r1/source'
        and request['source_tree'] == 'a5d9ce2d6fdff616bf91611c650e0fd3dc1786f2'
        and type(request['source_commit']) is str and len(request['source_commit']) == 40
        and all(value in '0123456789abcdef' for value in request['source_commit'])
        and type(request['source_count']) is int and request['source_count'] == 4136
        and type(request['source_bytes']) is int and request['source_bytes'] == 412713085
        and type(request['source_map_count']) is int and request['source_map_count'] == 901
        and request['source_map_sha256'] ==
            '28348495a949b9c94ffafcfb14a79b93f4bf7e1e4a8dbb435d0da376ee73c843',
        'fixed current 4136-file and 901-entry source')
    common.require(request['system_map'] == 'SYSTEM-INPUTS.json'
        and type(request['system_count']) is int and request['system_count'] == 4815
        and type(request['system_bytes']) is int and request['system_bytes'] == 181643507,
        'full retained system profile must be revalidated before this request')
    common.require(type(request['inputs']) is dict
        and set(QUALIFICATION)|set(AUTHOR_PINS)|
            {'SOURCE-BASE.json', 'SOURCE-MAP.json', 'SYSTEM-INPUTS.json'}
            <= set(request['inputs'])
        and sorted(request['qualification_namespace']) == sorted(QUALIFICATION),
        'complete generation-only required input roles')
    for name, pin in request['inputs'].items():
        common.require(type(name) is str and name and not name.startswith('/')
            and str(Path(name)) == name and '..' not in Path(name).parts
            and set(pin) == {'path','bytes','sha256','git_blob','identity'}
            and pin['path'] == str(ROOT/name)
            and type(pin['bytes']) is int and pin['bytes'] >= 0
            and type(pin['identity']) is list and len(pin['identity']) == 9
            and all(type(value) is int for value in pin['identity'])
            and pin['identity'][6] == pin['bytes'],
            'complete local input pin and exact nine integer fields')
    for name, (size, digest) in AUTHOR_PINS.items():
        common.require(request['inputs'][name]['bytes'] == size
            and request['inputs'][name]['sha256'] == digest,
            'exact fixed original source/author body: '+name)
    common.require(request['inputs']['SYSTEM-INPUTS.json']['bytes'] == 2048191
        and request['inputs']['SYSTEM-INPUTS.json']['sha256'] ==
            'f6dea8875c638cfaf79f8e9af1e109df3d114ec150d65482215692423fccee09',
        'same entire selected system-map body, newly verified physical inputs')
    common.require(request['inputs']['qualification/process_owner_impl.py']['sha256'] ==
        '36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2',
        'original unchanged process owner implementation')
    common.require(request['source_immutable'] is True
        and request['CPython_author_tooling'] is True
        and request['native_execution_authorized'] is False
        and request['VM_execution_authorized'] is False
        and request['interop_qualification'] is False
        and request['matching_current_cold_compiler'] is False
        and request['full_SQLite_or_AgentStore_qualification'] is False,
        'explicit generation-only scope; original four-case qualification not replaced')
    if new_output:
        common.require(not os.path.lexists(request['output']),
                       'new exact disjoint output namespace')
    return request
