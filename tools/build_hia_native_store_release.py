"""Build and verify a flat native Store release from a matching HIA cold qualification."""
from __future__ import annotations

import argparse
import gzip
import io
from hashlib import file_digest, sha256
from importlib import import_module
import json
import os
import stat
from pathlib import Path
import subprocess
import tarfile
from tempfile import NamedTemporaryFile, TemporaryDirectory

from tools.build_hia_core_edit import PROGRAMS as CORE_EDIT_PROGRAMS
from tools.build_hia_source_build import _compiled_sources, _run_captured
from tools.build_hia_json_preflight import ROOT, admit_cold_build, build_batch, current_sources
from tools.build_hia_sqlite_components import PROJECTION, UNITS
from tools.build_hia_worker_release import AGENT_STDIO_ROLES, INSTALLED_HELPERS


# These are release entry points. Other stdio variants have independent build contracts.
STDIO_ROLES = tuple(sorted(AGENT_STDIO_ROLES.keys() - {
    'borrowed-wrapper', 'context-cost-diagnostic', 'worker-describe-reactor',
}))
FLOW_ROLES = ('describe', 'input', 'artifact', 'discovery', 'context', 'inspection',
              'candidate', 'rollback', 'emit', 'adopt', 'verify', 'discovery-bootstrap',
              'evaluate-replay', 'evaluate-intake', 'evaluate-claim', 'evaluate-run-input', 'evaluate-run', 'evaluate-proof', 'evaluate-document', 'evaluate-closeout', 'evaluate-unkeyed')
LAUNCHERS = ('read', 'context-control', 'native', 'readonly', 'evaluate-replay', 'evaluate-intake', 'evaluate-full')
RESOURCES = ('examples/hia_bootstrap/selfhost.hepta', 'examples/hia_bootstrap/source_build_packer.hepta',
             'examples/hia_bootstrap/source_filter_member.hepta',
             'examples/hia_bootstrap/source_build_policy.hepta', 'examples/hia_bootstrap/core_json_cli_packer.hepta',
             'examples/hia_bootstrap/core_json_frontend.hepta', 'docs/HIA_SELFHOST_CORE_SUPPORT.json',
             'docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json')


def _compile(work, component, compiler, cold_report, *args, label=None, **options):
    builder = import_module('tools.build_hia_' + component).build
    directory = work / (label or component)
    return builder(directory, compiler, cold_report, *args, **options)


def _stage_component_outputs(work, compiler, cold_report, publish):
    def component(name, *args, **options):
        with TemporaryDirectory(prefix=name + '-', dir=work) as tmp:
            result = _compile(Path(tmp), name, compiler, cold_report, *args, **options)
            publish(result)

    with TemporaryDirectory(prefix='core-edit-', dir=work) as tmp:
        output = _compile(Path(tmp), 'core_edit', compiler, cold_report)
        for name, _ in CORE_EDIT_PROGRAMS.values():
            publish(output / name)
        publish(output / 'hia-worker-scalar-implementation')

    for kind in ('suite', 'totality', 'proof_wire'):
        component('core_admission_cli', **{kind: True})
    for kind in ('installer', 'directory'):
        component('release_install', kind=kind)
    for name in ('agent_artifact_capture', 'worker_read_release', 'core_patch_result_cli',
                 'core_workspace_pipeline', 'source_build',
                 'release_selection', 'supplied_safe_core_proof',
                 'owned_reference_cli', 'nominal_constructor'):
        component(name)
    component('agent_stdio', output_profile='elf')

    with TemporaryDirectory(prefix='standalone-', dir=work) as tmp:
        directory = Path(tmp)
        core = _compile(directory, 'core_json_cli', compiler, cold_report, output_profile='elf')
        publish(core)
        publish(core.parent / 'compiler-manifest.json')
        manifest = _compile(directory, 'nominal_json', compiler, cold_report, standalone=True)
        publish(manifest.parent / 'hia-nominal-packet')
        admit = _compile(directory, 'worker_request_cli', compiler, cold_report)
        publish(admit)
        for name in ('terminal', 'data', 'response', 'journal-call', 'port'):
            publish(admit.parent / ('hia-worker-' + name))
        owner = _compile(directory, 'agent_store', compiler, cold_report)
        publish(owner)
        metadata = json.loads((owner.parent / 'build.json').read_bytes())
        for name, digest in metadata['module_sha256'].items():
            publish(owner.parent / metadata['module_root'] / name, expected=digest)


def _stage_sqlite(work, compiler, cold_report, publish):
    def component(name, *args, **options):
        path = _compile(work, name, compiler, cold_report, *args, **options)
        publish(path)
        return path.parent

    artifacts = component('artifact_publication')
    batches = {}
    for kind in ('batch', 'sealed', 'initialize'):
        batches[kind] = component('agent_batch_commit', label='commit-' + kind, kind=kind)
    pager = component('sqlite_pager')
    components = _compile(work, 'sqlite_components', compiler, cold_report)
    for unit in (*UNITS, PROJECTION):
        publish(components / ('hia-' + unit))
    publisher = component('sqlite_migration_publish', artifacts, batches['batch'])
    component('sqlite_migrate', {'pager': pager, 'staging': components, 'initializer': batches['initialize'],
                                 'publisher': publisher})


def _stage_helper_images(work, compiler, cold_report, publish):
    images = build_batch(work / 'images', compiler, cold_report, candidates=INSTALLED_HELPERS)
    for kind in INSTALLED_HELPERS:
        manifest = images[kind]
        record = json.loads(manifest.read_bytes())
        image_name = record['image_path']
        if Path(image_name).name != image_name:
            raise ValueError('sealed Store helper has a nonlocal image name')
        publish(manifest, kind + '-manifest.json')
        publish(manifest.parent / image_name, expected=record['image_sha256'])


def _source_worker_recipes():
    from tools.build_hia_read_launcher import LAUNCHERS as READ_PROGRAMS
    from tools.generate_hia_readonly_worker_capsule import FULL_SOURCE, INTAKE_SOURCE, NATIVE_SOURCE, REPLAY_SOURCE
    from tools.generate_hia_worker_flow_packer import PROGRAMS, SECTIONS

    authorities = {'native': NATIVE_SOURCE, 'evaluate-intake': INTAKE_SOURCE,
                   'evaluate-replay': REPLAY_SOURCE, 'evaluate-full': FULL_SOURCE}
    for kind in FLOW_ROLES:
        suffix = '' if kind in ('input', 'discovery', 'discovery-bootstrap') else '-worker'
        name = f'hia-agent-{kind}{suffix}-carrier'
        primary, packer = PROGRAMS[kind]
        sources = {name + '.hepta': Path(primary).name}
        for part in SECTIONS.get(kind, ()):
            sources[Path(part).name] = Path(part).name
        yield name, Path(packer).name, sources

    for kind in LAUNCHERS:
        name = f'hia-agent-{kind}-launcher'
        if kind in authorities:
            primary, packer = PROGRAMS[kind + '-launcher']
            authority = Path(authorities[kind]).name
            sources = {name + '.hepta': Path(primary).name, authority: authority}
        else:
            launcher = READ_PROGRAMS[kind]
            packer = launcher.source
            sources = {name + '.hepta': Path(launcher.authority).name}
        yield name, Path(packer).name, sources


def _source_tool_recipes():
    from tools.build_hia_direct_call import ROLES
    from tools.build_hia_elf_linker import LINKERS
    from tools.build_hia_json_preflight import CANDIDATES
    from tools.generate_hia_native_filter import REFERENCE_CLI_PACKER

    for application, name in (('worker-prepare', 'hia-worker-prepare'), ('cnf', 'hia-proof-cnf')):
        yield name, 'native_filter_packer.hepta', {name + '.hepta': CANDIDATES[application][0] + '.hepta'}
    for application, packer, _magic, name, _inputs in LINKERS.values():
        yield name, CANDIDATES[packer][0] + '.hepta', {name + '.hepta': CANDIDATES[application][0] + '.hepta'}
    for role, (source, packer, _adapter, _magic, _label) in ROLES.items():
        name = 'hia-' + role
        yield name, Path(packer).name, {name + '.hepta': Path(source).name}
    yield 'hia-reference-wire', Path(REFERENCE_CLI_PACKER).name, {'hia-reference-wire.hepta': 'scalar_reference.hepta'}


def _source_member_recipes():
    """Map published names to checked-in HIA inputs. Framing and modes belong to HIA."""
    for role in STDIO_ROLES:
        name = 'hia-agent-' + role
        sources = {name + '.hepta': AGENT_STDIO_ROLES[role][0] + '.hepta'}
        if role == 'journal':
            sources['agent_journal_transport.hepta'] = 'agent_journal_transport.hepta'
            yield name, 'agent_journal_stdio_packer.hepta', sources
        else:
            yield name, 'mcp_stdio_packer.hepta', sources

    for role in ('budget-observation', 'budget-store', 'cost-ledger', 'cost-ledger-flow',
                 'measurements', 'native-report', 'paired-batch', 'publication', 'reference-batch',
                 'reference-report', 'report-flow', 'run-plan', 'settlement'):
        stem = 'evaluate_' + role.replace('-', '_')
        sources = {stem + '.hepta': stem + '.hepta'}
        if role in ('cost-ledger', 'run-plan'):
            sources['worker_request.hepta'] = 'worker_request.hepta'
        yield 'hia-evaluate-' + role, stem + '_packer.hepta', sources
    for name, stem, packer in (
            ('hia-evaluate-projector', 'evaluate_reference_wire', 'evaluate_reference_wire_filter_packer'),
            ('hia-execution-budget-session', 'execution_budget', 'execution_budget_session_packer'),
            ('hia-safe-core-loader', 'safe_core_elf_inventory', 'safe_core_loader_filter_packer')):
        yield name, packer + '.hepta', {stem + '.hepta': stem + '.hepta'}

    yield from _source_worker_recipes()
    yield from _source_tool_recipes()


def _stage_source_members(work, stage, admitted, members, publish):
    """Compile and pack release members with the captured native seed and HIA policy."""
    def captured(role):
        data = (stage / role).read_bytes()
        if sha256(data).hexdigest() != members[role]:
            raise ValueError('native release tool differs from its staged identity: ' + role)
        return data

    seed = captured('hia-source-build')
    pack_directory = captured('hia-directory-package-build')
    builders = {}

    # These products bind their non-relocated syscall adapter and image entry
    # separately as part of the original build contract.
    from tools.build_hia_direct_call import ROLES as direct_roles
    from tools.generate_hia_native_filter import REFERENCE_CLI_ADAPTER, read_adapter_binding, verify_adapter
    adapter_files = {'hia-' + role: info[2] for role, info in direct_roles.items()}
    adapter_files['hia-reference-wire'] = REFERENCE_CLI_ADAPTER

    def call(program, operation, wire):
        result = _run_captured(program, operation, wire, work)
        if result.returncode or result.stderr or not result.stdout:
            raise ValueError(f'native release member {operation} failed ({result.returncode})')
        return result.stdout

    def compile_sources(named):
        pinned = {}
        with TemporaryDirectory(prefix='member-sources-', dir=work) as staging:
            directory = Path(staging)
            for name, source in named.items():
                relative = 'examples/hia_bootstrap/' + source
                data = (ROOT / relative).read_bytes()
                if admitted.get(relative) != sha256(data).hexdigest():
                    raise ValueError('release member source differs from cold admission: ' + relative)
                pinned[name] = data
                with (directory / name).open('xb') as stream:
                    stream.write(data)
                    os.fchmod(stream.fileno(), 0o400)
            packed = _run_captured(pack_directory, directory, b'', work)
            if packed.returncode or packed.stderr != (sha256(packed.stdout).hexdigest() + '\n').encode():
                raise ValueError('native source directory receipt differs from its bytes')
        compiled = call(seed, 'build', packed.stdout)
        # Authenticate the actual source copies read by both native programs.
        return compiled, _compiled_sources(compiled, pinned)

    for name, packer, sources in _source_member_recipes():
        if packer not in builders:
            kit, _ = compile_sources({'source_build_policy.hepta': 'source_filter_member.hepta',
                                      'selfhost.hepta': 'selfhost.hepta', 'source_build_packer.hepta': packer})
            builders[packer] = call(seed, 'pack', kit)
        group, images = compile_sources(sources)
        product = call(builders[packer], 'build', group)
        if name in adapter_files:
            adapter_file = adapter_files[name]
            packer_file = 'examples/hia_bootstrap/' + packer
            adapter_source = (ROOT / adapter_file).read_bytes()
            packer_source = (ROOT / packer_file).read_bytes()
            if (sha256(adapter_source).hexdigest() != admitted.get(adapter_file) or
                    sha256(packer_source).hexdigest() != admitted.get(packer_file)):
                raise ValueError('release tool adapter differs from the cold source: ' + name)
            binding = read_adapter_binding(packer_source, adapter_source, calls=1)
            verify_adapter(product, images[name + '.hepta'], binding, entries=(0,))
        if not product.startswith(b'\x7fELF'):
            raise ValueError('native source member returned an invalid release program: ' + name)
        with NamedTemporaryFile(dir=work, prefix='native-member-') as stream:
            stream.write(product)
            stream.flush()
            publish(Path(stream.name), name, expected=sha256(product).hexdigest())


def _pack_and_verify(work, stage, members):
    package = work / 'store.hiapack'
    with package.open('xb') as result:
        pack = subprocess.run([stage / 'hia-directory-package-build', stage], stdout=result, stderr=subprocess.PIPE,
                              env={'PATH': ''}, check=True, timeout=180)
    with package.open('rb') as stream:
        digest = file_digest(stream, 'sha256').hexdigest()
    if pack.stderr != (digest + '\n').encode():
        raise ValueError('native directory package digest differs from its output')
    depot = work / 'verified'
    depot.mkdir(mode=0o700)
    for action in ('install', 'verify'):
        with package.open('rb') as stream:
            checked = subprocess.run([stage / 'hia-release', action, depot, digest], stdin=stream,
                                     capture_output=True, env={'PATH': ''}, check=True, timeout=180)
        receipt = json.loads(checked.stdout)
        if checked.stderr or receipt['sha256'] != digest or receipt['files'] != len(members):
            raise ValueError('native Store installation receipt differs from its built inventory')
    installed = depot / digest
    actual = {path.name: sha256(path.read_bytes()).hexdigest() for path in installed.iterdir()}
    if actual != members:
        raise ValueError('installed native Store files differ from their source-built members')
    return package


def build(output, compiler, cold_report):
    """Publish one verified package. All compiler receipts and component scratch are private."""
    output = Path(output).absolute()
    compiler, cold_report = Path(compiler).resolve(), Path(cold_report).resolve()
    if output.is_symlink() or (output.exists() and (not output.is_dir() or any(output.iterdir()))):
        raise FileExistsError('expected a new or empty release output directory: ' + str(output))
    compiler_bytes, report_bytes = compiler.read_bytes(), cold_report.read_bytes()
    admitted = admit_cold_build(compiler_bytes, report_bytes)
    with TemporaryDirectory(prefix='hia-native-store-release-', dir=output.parent) as tmp:
        work = Path(tmp)
        stage = work / 'stage'
        stage.mkdir(mode=0o700)
        members = {}

        def publish(path, name=None, *, expected=None):
            name = path.name if name is None else name
            if Path(name).name != name or name in members or path.is_symlink() or not path.is_file():
                raise ValueError('invalid or duplicate Store release member: ' + name)
            raw = path.read_bytes()
            digest = sha256(raw).hexdigest()
            if expected is not None and digest != expected:
                raise ValueError('Store release member differs from its declared source: ' + name)
            target = stage / name
            with target.open('xb') as stream:
                stream.write(raw)
                os.fchmod(stream.fileno(), 0o500 if raw.startswith(b'\x7fELF') else 0o400)
            members[name] = digest

        for name in RESOURCES:
            publish(ROOT / name, expected=admitted[name])
        _stage_component_outputs(work, compiler, cold_report, publish)
        _stage_sqlite(work, compiler, cold_report, publish)
        _stage_helper_images(work, compiler, cold_report, publish)
        _stage_source_members(work, stage, admitted, members, publish)
        package = _pack_and_verify(work, stage, members)
        if current_sources() != admitted or compiler.read_bytes() != compiler_bytes or cold_report.read_bytes() != report_bytes:
            raise ValueError('native Store cold inputs changed before publication')
        created = not output.exists()
        if created:
            output.mkdir(mode=0o700)
        elif output.is_symlink() or any(output.iterdir()):
            raise FileExistsError('release output changed during the build')
        target = output / package.name
        try:
            package.chmod(0o400)
            os.link(package, target)
        except BaseException:
            if created:
                output.rmdir()
            raise
    return target


def _read_regular_cold_source(relative):
    """Pin cold source descriptors and reject links/devices before reading any bytes.

    The checked-in inventory is not permission to traverse a symlink, including
    a parent directory symlink, or to block indefinitely on a FIFO.
    """
    opened = []
    try:
        directory = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        opened.append(directory)
        for component in relative.parts[:-1]:
            directory = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=directory)
            opened.append(directory)
        file = os.open(relative.parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                       dir_fd=directory)
        opened.append(file)
        if not stat.S_ISREG(os.fstat(file).st_mode):
            raise ValueError('cold source is not a regular file: ' + str(relative))
        with os.fdopen(os.dup(file), 'rb') as stream:
            return stream.read()
    except OSError as error:
        raise ValueError('cold source is a symlink or not a regular file: ' + str(relative)) from error
    finally:
        for descriptor in reversed(opened):
            os.close(descriptor)


def write_source_archive(output):
    """Archive precisely the files exported by the cold replay, including its support contract."""
    output = Path(output).absolute()
    if output.exists() or output.is_symlink():
        raise FileExistsError(output)
    sources = current_sources()
    with NamedTemporaryFile(dir=output.parent, prefix='.hia-native-source-') as temporary:
        with gzip.GzipFile(fileobj=temporary, filename='', mode='wb', mtime=0, compresslevel=6) as compressed:
            with tarfile.open(fileobj=compressed, mode='w|', format=tarfile.PAX_FORMAT) as archive:
                for name, expected in sorted(sources.items()):
                    path = Path(name)
                    if path.is_absolute() or path.as_posix() != name or '..' in path.parts:
                        raise ValueError('invalid cold source path: ' + name)
                    data = _read_regular_cold_source(path)
                    if sha256(data).hexdigest() != expected:
                        raise ValueError('cold source changed during export: ' + name)
                    entry = tarfile.TarInfo('hia-core-source/' + name)
                    entry.mode = 0o644
                    entry.size = len(data)
                    archive.addfile(entry, io.BytesIO(data))
        temporary.flush()
        if current_sources() != sources:
            raise ValueError('cold source inventory changed before publication')
        os.fchmod(temporary.fileno(), 0o400)
        os.link(temporary.name, output)
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='From an extracted hia-core-source directory:\n'
               '  python -m tools.replay_hia_selfhost_cold --output ../cold.json\n'
               '  python -m tools.build_hia_native_store_release --output ../release '
               '--compiler ../cold.cold/qualification.evidence/B3.image.bin --cold-report ../cold.json')
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--output', type=Path, help='new or empty directory for the native store.hiapack')
    action.add_argument('--source-archive', type=Path, help='new .tar.gz path for all source inputs to cold replay')
    parser.add_argument('--compiler', type=Path, help='B3 compiler image from the matching cold replay')
    parser.add_argument('--cold-report', type=Path, help='matching source-qualified cold replay JSON')
    args = parser.parse_args()
    if args.source_archive is not None:
        if args.compiler is not None or args.cold_report is not None:
            parser.error('--source-archive takes only the complete checked-in sources')
        print(write_source_archive(args.source_archive))
    else:
        if args.compiler is None or args.cold_report is None:
            parser.error('--output requires --compiler and --cold-report')
        print(build(args.output, args.compiler, args.cold_report))


if __name__ == '__main__':
    main()
