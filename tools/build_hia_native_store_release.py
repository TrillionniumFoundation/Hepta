"""Build and verify a flat native Store release from a matching HIA cold qualification."""
from __future__ import annotations

import argparse
import gzip
import io
from hashlib import file_digest, sha256
from importlib import import_module
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
from tempfile import NamedTemporaryFile, TemporaryDirectory

from tools.build_hia_core_edit import PROGRAMS as CORE_EDIT_PROGRAMS
from tools.build_hia_json_preflight import ROOT, admit_cold_build, build_batch, current_sources
from tools.build_hia_native_filter import (
    SAFE_CORE_LOADER_FILTER_MAGIC, build_evaluate_paired_batch, build_evaluate_projector,
    build_evaluate_budget_store, build_evaluate_native_report, build_evaluate_reference_batch, build_evaluate_reference_report,
    build_evaluate_settlement,
    build_execution_budget_session, build_filter,
)
from tools.build_hia_sqlite_components import PROJECTION, UNITS
from tools.build_hia_worker_release import AGENT_STDIO_ROLES, INSTALLED_HELPERS, build_packaged_stdio_roles


# These are release entry points. Other stdio variants have independent build contracts.
STDIO_ROLES = tuple(sorted(AGENT_STDIO_ROLES.keys() - {
    'borrowed-wrapper', 'context-cost-diagnostic', 'worker-describe-reactor',
}))
FLOW_ROLES = ('describe', 'input', 'artifact', 'discovery', 'context', 'inspection',
              'candidate', 'rollback', 'emit', 'adopt', 'verify', 'discovery-bootstrap',
              'evaluate-replay', 'evaluate-intake', 'evaluate-claim', 'evaluate-proof', 'evaluate-document')
LAUNCHERS = ('read', 'context-control', 'native', 'readonly', 'evaluate-replay', 'evaluate-intake')
RESOURCES = ('examples/hia_bootstrap/selfhost.hepta', 'examples/hia_bootstrap/source_build_packer.hepta',
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
    for kind in ('static', 'verified-shared', 'direct-shared'):
        component('elf_linker', kind=kind)
    for kind in LAUNCHERS:
        component('read_launcher', kind=kind)
    for kind in FLOW_ROLES:
        component('worker_flow', kind=kind)
    for name in ('agent_artifact_capture', 'worker_read_release', 'core_patch_result_cli',
                 'core_workspace_pipeline', 'source_build', 'worker_prepare', 'proof_cnf',
                 'release_selection', 'supplied_safe_core_proof', 'scalar_reference_cli',
                 'owned_reference_cli', 'nominal_constructor'):
        component(name)
    component('direct_call', role='job-receipt')
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


def _stage_roles(work, compiler, cold_report, publish):
    images = build_batch(work / 'images', compiler, cold_report, candidates=INSTALLED_HELPERS)
    for kind in INSTALLED_HELPERS:
        manifest = images[kind]
        record = json.loads(manifest.read_bytes())
        image_name = record['image_path']
        if Path(image_name).name != image_name:
            raise ValueError('sealed Store helper has a nonlocal image name')
        publish(manifest, kind + '-manifest.json')
        publish(manifest.parent / image_name, expected=record['image_sha256'])
    for _, executable in build_packaged_stdio_roles(work / 'stdio', compiler, cold_report, STDIO_ROLES, images=images):
        publish(executable)
        shutil.rmtree(executable.parent)
    for builder in (build_evaluate_projector, build_evaluate_paired_batch, build_evaluate_reference_batch,
                    build_evaluate_reference_report, build_evaluate_native_report, build_evaluate_settlement,
                    build_evaluate_budget_store, build_execution_budget_session):
        publish(builder(work / builder.__name__, compiler, cold_report))
    publish(build_filter(work / 'safe-core-loader', compiler, cold_report, application='safe-core-elf-inventory',
                         packer='safe-core-loader-filter', magic=SAFE_CORE_LOADER_FILTER_MAGIC,
                         filename='hia-safe-core-loader', schema='hepta.hia.safe-core-loader-filter-build.v1'))


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
        _stage_roles(work, compiler, cold_report, publish)
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
                    data = (ROOT / path).read_bytes()
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
