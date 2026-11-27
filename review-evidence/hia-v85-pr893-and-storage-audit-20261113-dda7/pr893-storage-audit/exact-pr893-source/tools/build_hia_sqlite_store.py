"""Build the development HIA-owned SQLite store and closed system-ABI bridge.

Compilation/custody and GNU assembly/linking remain hosted. The produced ELF
runs HIA decisions and SQLite engine calls without Python, a SQL script driver
or a child process. A development compiler is never current-source qualification.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))
from tools.build_hia_json_preflight import admit_cold_build, current_sources
from tools.qualify_hia_selfhost import compile_stage

SCHEMA = 'hepta.hia.sqlite-platform-build.v5'
SOURCES = (
    'tools/generate_hia_sqlite_store.py',
    'examples/hia_bootstrap/sqlite_store.hepta',
    'examples/hia_bootstrap/sqlite_agent_transaction.hepta',
    'examples/hia_bootstrap/sqlite_rollback_policy.hepta',
    'tools/generate_hia_agent_data_json.py',
    'tools/generate_hia_worker_request.py',
    'tools/generate_hia_json_preflight.py',
    'docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json',
    'examples/hia_bootstrap/agent_journal.hepta',
    'tools/generate_hia_agent_journal.py',
    'tools/hia_sqlite_platform.S',
    'tools/build_hia_sqlite_store.py',
    'hepta/hia_sqlite_store_native.py',
    'tests/test_hia_sqlite_store.py',
    'tests/test_hia_sqlite_store_integration.py',
    'docs/HIA_SQLITE_PLATFORM.md',
    'examples/hia_bootstrap/json_canonical.hepta',
    'tools/generate_hia_json_canonical.py',
    'tools/generate_hia_json_decode.py',
    'examples/hia_bootstrap/sha256_stream.hepta',
    'tools/generate_hia_sha256_stream.py',
    'tools/generate_hia_sha256.py',
    'examples/hia_bootstrap/json_preflight.hepta',
    'examples/hia_bootstrap/agent_data_json.hepta',
    'examples/hia_bootstrap/agent_binary64.hepta',
    'tools/generate_hia_agent_binary64.py',
)
SQLITE_SYMBOLS = frozenset((
    'sqlite3_open_v2', 'sqlite3_close', 'sqlite3_busy_timeout', 'sqlite3_prepare_v2',
    'sqlite3_bind_null', 'sqlite3_bind_int64', 'sqlite3_bind_double',
    'sqlite3_bind_text64', 'sqlite3_bind_blob64', 'sqlite3_step',
    'sqlite3_column_count', 'sqlite3_column_type', 'sqlite3_column_int64',
    'sqlite3_column_double', 'sqlite3_column_text', 'sqlite3_column_blob',
    'sqlite3_column_bytes', 'sqlite3_finalize', 'sqlite3_get_autocommit',
))
FOREIGN_SYMBOLS = SQLITE_SYMBOLS | {'__libc_start_main'}


def _digest(raw):
    return sha256(raw).hexdigest()


def _file(path):
    path = Path(path).resolve(strict=True)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022:
        raise ValueError('build input must be a non-writable-by-others regular file')
    raw = path.read_bytes()
    return {'path': str(path), 'bytes': len(raw), 'sha256': _digest(raw),
            'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid}, raw


def _run(output, label, argv, timeout=120):
    completed = subprocess.run(argv, cwd=output, capture_output=True, timeout=timeout,
                               env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
    (output/(label+'.stdout')).write_bytes(completed.stdout)
    (output/(label+'.stderr')).write_bytes(completed.stderr)
    record = {'argv': list(map(str, argv)), 'returncode': completed.returncode,
              'timeout_seconds': timeout, 'stdout_sha256': _digest(completed.stdout),
              'stderr_sha256': _digest(completed.stderr)}
    if completed.returncode:
        raise ValueError(label + ' failed; original streams retained')
    return completed.stdout, record



def _source_snapshot(*,development):
    if not development:
        return current_sources()
    # A development component has not been registered/rebound into the frozen
    # release contract. Capture its complete declared-source and Python closure
    # plus every component input without claiming that contract validates it.
    from tools.hia_selfhost_contract import CONTRACT_PATH,file_digests
    actual=file_digests(ROOT)
    actual[CONTRACT_PATH]=_digest((ROOT/CONTRACT_PATH).read_bytes())
    for name in SOURCES:
        actual[name]=_digest((ROOT/name).read_bytes())
    return dict(sorted(actual.items()))


def _cold(compiler_bytes, cold_bytes, *, development, compiler_source, python):
    if not development:
        if compiler_source is not None:
            raise ValueError('compiler-source applies only to explicit development')
        return admit_cold_build(compiler_bytes, cold_bytes), None
    if compiler_source is None:
        raise ValueError('development requires an explicit frozen compiler source')
    source = Path(compiler_source).resolve(strict=True)
    # The separate admitted source is never imported over the new development
    # module graph. The actual compiler/report bytes travel as captured input.
    script = (
        "import base64,json,sys\n"
        "sys.path.insert(0,sys.argv[1])\n"
        "from tools.build_hia_json_preflight import admit_cold_build\n"
        "r=json.load(sys.stdin)\n"
        "print(json.dumps(admit_cold_build(base64.b64decode(r['compiler'],validate=True),"
        "base64.b64decode(r['cold'],validate=True)),sort_keys=True))\n")
    import base64
    payload = json.dumps({'compiler': base64.b64encode(compiler_bytes).decode(),
                          'cold': base64.b64encode(cold_bytes).decode()}).encode()
    done = subprocess.run([str(python), '-I', '-B', '-c', script, str(source)],
                          input=payload, capture_output=True, timeout=30)
    if done.returncode:
        raise ValueError('explicit compiler provenance refused: ' +
                         done.stderr.decode(errors='replace'))
    admitted = json.loads(done.stdout)
    if type(admitted) is not dict or not admitted:
        raise ValueError('compiler provenance returned no exact source map')
    return admitted, {'source': str(source), 'stdout_sha256': _digest(done.stdout),
                      'stderr_sha256': _digest(done.stderr), 'returncode': 0}


def _inspect(output, executable, readelf):
    dynamic, dyn_receipt = _run(output, 'elf-dynamic', [str(readelf), '-dW', str(executable)])
    symbols, sym_receipt = _run(output, 'elf-symbols', [str(readelf), '-WsW', str(executable)])
    program, prog_receipt = _run(output, 'elf-program', [str(readelf), '-lW', str(executable)])
    text = dynamic.decode()
    if any(marker in text for marker in ('(RPATH)', '(RUNPATH)', '(TEXTREL)')):
        raise ValueError('platform ELF has an ambient or writable-code loader route')
    needed = re.findall(r'\(NEEDED\).*\[([^]]+)\]', text)
    if set(needed) != {'libsqlite3.so.0', 'libc.so.6'} or len(needed) != 2:
        raise ValueError('closed first-level platform dependencies changed')
    undefined = set()
    for row in symbols.decode().splitlines():
        parts = row.split()
        if len(parts) >= 8 and parts[6] == 'UND' and parts[7]:
            undefined.add(parts[7].split('@', 1)[0])
    if undefined != FOREIGN_SYMBOLS:
        raise ValueError('platform external function inventory differs: ' +
                         repr(sorted(undefined ^ FOREIGN_SYMBOLS)))
    interpreter = re.findall(r'Requesting program interpreter: ([^]]+)', program.decode())
    if len(interpreter) != 1:
        raise ValueError('platform ELF interpreter was not uniquely observed')
    for row in program.decode().splitlines():
        if row.lstrip().startswith('LOAD') and 'RWE' in row.replace(' ', ''):
            raise ValueError('writable executable segment')
    return {'needed': needed, 'undefined_symbols': sorted(undefined),
            'interpreter': interpreter[0], 'dynamic_receipt': dyn_receipt,
            'symbol_receipt': sym_receipt, 'program_receipt': prog_receipt}


def _dependencies(output, executable, sqlite_library, readelf, ldconfig):
    raw, _ = _run(output, 'system-library-cache', [str(ldconfig), '-p'])
    cache = {}
    for row in raw.decode().splitlines():
        match = re.match(r'\s*(\S+).*\(([^)]*)\)\s*=>\s*(\S+)$', row)
        if match and 'x86-64' in match[2]:
            cache.setdefault(match[1], match[3])
    cache['libsqlite3.so.0'] = str(sqlite_library)
    pending = [str(executable)]
    seen, records = set(), {}
    while pending:
        path = Path(pending.pop()).resolve(strict=True)
        if path in seen:
            continue
        seen.add(path)
        if path != executable:
            item, _ = _file(path)
            records[str(path)] = item
        data, _ = _run(output, 'dependency-%03d' % len(seen),
                       [str(readelf), '-dW', str(path)])
        for name in re.findall(r'\(NEEDED\).*\[([^]]+)\]', data.decode()):
            if name not in cache:
                raise ValueError('unresolved explicit system dependency: '+name)
            pending.append(cache[name])
    return records


def build(output: Path, compiler: Path, cold_report: Path, *,
          sqlite_library: Path, cc: Path = Path('/usr/bin/cc'),
          readelf: Path = Path('/usr/bin/readelf'),
          ldconfig: Path = Path('/usr/sbin/ldconfig'),
          development=False, compiler_source: Path | None = None,
          python: Path = Path(sys.executable)):
    # Admission is before output creation or compiler/native/linker execution.
    compiler_bytes, cold_bytes = compiler.read_bytes(), cold_report.read_bytes()
    source_bytes = {name: (ROOT/name).read_bytes() for name in SOURCES}
    full_sources = _source_snapshot(development=development)
    admitted, provenance = _cold(compiler_bytes, cold_bytes, development=development,
                                compiler_source=compiler_source, python=python)
    if not development and any(admitted.get(name) != _digest(raw)
                               for name, raw in source_bytes.items()):
        raise ValueError('platform source not in current matching cold source map')
    dependency, sqlite_bytes = _file(sqlite_library)
    sqlite_library = Path(dependency['path'])
    tools = {}
    for name, path in (('cc', cc), ('readelf', readelf), ('ldconfig', ldconfig)):
        item, _ = _file(path)
        tools[name] = item
    cc,readelf,ldconfig=(Path(tools[key]['path']) for key in ('cc','readelf','ldconfig'))
    output = output.absolute()
    output.mkdir(mode=0o700)
    commands, images, image_bytes, compile_receipts = [], {}, {}, {}
    for label, source in (('driver', 'examples/hia_bootstrap/sqlite_store.hepta'),
                          ('canonical', 'examples/hia_bootstrap/json_canonical.hepta'),
                          ('agent', 'examples/hia_bootstrap/sqlite_agent_transaction.hepta'),
                          ('policy', 'examples/hia_bootstrap/sqlite_rollback_policy.hepta'),
                          ('journal', 'examples/hia_bootstrap/agent_journal.hepta'),
                          ('sha-stream', 'examples/hia_bootstrap/sha256_stream.hepta'),
                          ('preflight', 'examples/hia_bootstrap/json_preflight.hepta'),
                          ('data-json', 'examples/hia_bootstrap/agent_data_json.hepta'),
                          ('binary64', 'examples/hia_bootstrap/agent_binary64.hepta')):
        image, receipt = compile_stage(output, label, compiler, source_bytes[source])
        raw = image.read_bytes()
        with (output/(label+'.image')).open('xb') as stream:
            stream.write(raw)
        images[label], image_bytes[label], compile_receipts[label] = image, raw, receipt
    assembly = output/'bridge.S'
    assembly.write_bytes(source_bytes['tools/hia_sqlite_platform.S'])
    _, record = _run(output, 'assemble', [str(cc), '-c', '-x', 'assembler',
                         '-Wa,--fatal-warnings', '-o', 'bridge.o', str(assembly)])
    commands.append(record)
    executable = output/'hia-sqlite-store'
    _, record = _run(output, 'link', [str(cc), '-nostartfiles', '-no-pie',
                         '-Wl,--no-as-needed', '-Wl,-z,now', '-Wl,-z,relro',
                         '-Wl,-z,noexecstack', '-Wl,--fatal-warnings',
                         '-Wl,-e,_start', 'bridge.o', str(sqlite_library), '-lc',
                         '-o', str(executable)])
    commands.append(record)
    executable.chmod(0o500)
    raw = executable.read_bytes()
    inspection = _inspect(output, executable, readelf)
    dependencies = _dependencies(output, executable, sqlite_library, readelf, ldconfig)
    loader, _ = _file(Path(inspection['interpreter']))
    dependencies[loader['path']] = loader
    version, version_receipt = _run(output, 'compiler-version', [str(cc), '--version'])
    # A standalone -c/-link result is not enough: all source/compiler/report,
    # compiled images and actual ELF/library/tool bytes are re-read.
    if compiler.read_bytes()!=compiler_bytes or cold_report.read_bytes()!=cold_bytes:
        raise ValueError('compiler or cold report changed before publication')
    again, _ = _cold(compiler_bytes, cold_bytes, development=development,
                     compiler_source=compiler_source, python=python)
    if again != admitted or _source_snapshot(development=development)!=full_sources:
        raise ValueError('source/cold admission changed before publication')
    if any((ROOT/name).read_bytes()!=data for name,data in source_bytes.items()):
        raise ValueError('platform source changed before publication')
    if any(images[name].read_bytes()!=data or (output/(name+'.image')).read_bytes()!=data
           for name,data in image_bytes.items()):
        raise ValueError('compiled HIA image changed before publication')
    if executable.read_bytes()!=raw or sqlite_library.read_bytes()!=sqlite_bytes:
        raise ValueError('platform ELF or SQLite dependency changed')
    for item in [*dependencies.values(), *tools.values()]:
        if _file(item['path'])[0] != item:
            raise ValueError('build tool/dependency custody changed')
    record = {
        'schema': SCHEMA, 'closed_platform_effect_abi': 5,
        'agent_transaction_internal_stages_only': True,
        'rollback_schema_and_terminal_sql_owner': 'HIA',
        'rollback_policy_scope': 'actual bound rollback input schema and catalog; continuation under development',
        'ordinary_rollback_core_dependency_closed': False,
        'ordinary_call_adapter_exposed': False,
        'artifact_read_prefix_owner': 'HIA SQL identity/kind, Linux fd identity and 64-MiB incremental SHA',
        'artifact_metadata_core_request_contains_real_raw_bytes': True,
        'artifact_metadata_decode_and_whole_core_dependency_closed': False,
        'artifact_metadata_default_bytes_json_admission': 'HIA complete UTF8, transformed preflight, actual arena and source-order numeric conversions',
        'artifact_metadata_internal_operation': 6,
        'artifact_metadata_wire_and_whole_core_closed': False,
        'installation_recursive_enumeration_policy_closed': False,
        'status': 'DEVELOPMENT_NATIVE_SQLITE_STORE_BUILT' if development else
                  'SOURCE_QUALIFIED_NATIVE_SQLITE_STORE_BUILT',
        'current_source_cold_qualified': not development,
        'compiler_source_provenance': provenance,
        'compiler_source_manifest': admitted,
        'current_source_manifest': full_sources,
        'current_source_contract_validated': not development,
        'source_manifest': {name:_digest(raw) for name,raw in source_bytes.items()},
        'runtime_source_sha256': {
            name: _digest(source_bytes[name]) for name in
            ('examples/hia_bootstrap/sqlite_store.hepta',
             'examples/hia_bootstrap/json_canonical.hepta',
             'examples/hia_bootstrap/sqlite_agent_transaction.hepta',
             'examples/hia_bootstrap/sqlite_rollback_policy.hepta',
             'examples/hia_bootstrap/agent_journal.hepta',
             'examples/hia_bootstrap/sha256_stream.hepta',
             'examples/hia_bootstrap/json_preflight.hepta',
             'examples/hia_bootstrap/agent_data_json.hepta',
             'examples/hia_bootstrap/agent_binary64.hepta')},
        'compiler_sha256':_digest(compiler_bytes), 'cold_report_sha256':_digest(cold_bytes),
        'images': {name:{'path':name+'.image','sha256':_digest(data),'bytes':len(data)}
                   for name,data in image_bytes.items()},
        'compile_receipts':compile_receipts, 'executable_path':executable.name,
        'executable_sha256':_digest(raw), 'executable_bytes':len(raw),
        'inspection':inspection, 'system_dependencies':dependencies,
        'tool_files':tools, 'cc_version':version.decode(), 'cc_version_receipt':version_receipt,
        'commands':commands,
        'runtime_python_sql_decisions':False,
        'system_sqlite_external_dependency':True,
        'host_build_code_custody_and_object_transport':True,
        'ordinary_core_platform_effects_enabled':False,
        'existing_private_database_release_slot_prototype':True,
        'request_journal_slot_atomic_transaction_complete':False,
        'budget_business_transaction_complete':False,
        'ordinary_default_service_cutover':False, 'whole_native_delivery_qualified':False,
    }
    manifest=output/'build.json'
    with manifest.open('x') as stream:
        json.dump(record,stream,indent=2,sort_keys=True)
        stream.write('\n')
    return manifest


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('output','compiler','cold-report','sqlite-library'):
        parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--compiler-source',type=Path)
    parser.add_argument('--development',action='store_true')
    parser.add_argument('--cc',type=Path,default=Path('/usr/bin/cc'))
    args=parser.parse_args()
    print(build(args.output,args.compiler,args.cold_report,sqlite_library=args.sqlite_library,
                cc=args.cc,development=args.development,compiler_source=args.compiler_source))


if __name__=='__main__':
    main()
