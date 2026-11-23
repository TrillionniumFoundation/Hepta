"""Authenticated ordinary distribution inputs for packaging and installed-API tests."""
from __future__ import annotations

import atexit
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from threading import Lock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
_cache = {}
_lock = Lock()


def _sources():
    from tools.build_hia_json_preflight import current_sources

    return current_sources()


def stage_cold_sources(directory):
    """Fill the fixture's source tree with the exact admitted sdist inputs."""
    directory = Path(directory)
    for name, digest in _sources().items():
        path = directory / name
        if path.exists():
            if not path.is_file() or path.is_symlink() or sha256(path.read_bytes()).hexdigest() != digest:
                raise ValueError('packaging fixture changed a cold input: ' + name)
            continue
        raw = (ROOT / name).read_bytes()
        if sha256(raw).hexdigest() != digest:
            raise ValueError('cold input changed during fixture staging: ' + name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)


def installed_wheel_path(directory, member):
    """Resolve an archive member after pip --target installs a platform wheel."""
    parts = Path(member).parts
    if len(parts) == 3 and parts[0].endswith('.data') and parts[1] == 'scripts':
        return Path(directory) / 'bin' / parts[2]
    return Path(directory) / member


def derived_python_pin(archive):
    """Reconstruct the one generated Python module from the actual wheel inputs."""
    from hepta.hia_default_native import (
        BINDER_RESOURCE, BUNDLE_RESOURCE, CLI_BUNDLE_RESOURCE, PIN_SCHEMA,
        PROOF_BUNDLE_RESOURCE, SCOPES, TARGET, render_pin,
    )
    from tools.build_hia_default_release import PACKAGE_DIRECTORY, PIN_FILE, source_identity

    provenance = json.loads(archive.read(PACKAGE_DIRECTORY + '/provenance.json'))
    def digest(name):
        return sha256(archive.read(name)).hexdigest()
    values = (
        PIN_SCHEMA, TARGET, BUNDLE_RESOURCE, digest('hepta/' + BUNDLE_RESOURCE), SCOPES[0],
        digest(PACKAGE_DIRECTORY + '/cold-report.json'), source_identity(provenance['source_manifest']),
        digest('hepta/' + PROOF_BUNDLE_RESOURCE), digest('hepta/' + CLI_BUNDLE_RESOURCE),
        digest('hepta/' + BINDER_RESOURCE),
    )
    from hepta.hia_default_native import INTEGER_BUNDLE_RESOURCE, LEDGER_BUNDLE_RESOURCE, GRAPH_BUNDLE_RESOURCE, OWNED_VM_RESOURCE
    integer_bundle = 'hepta/' + INTEGER_BUNDLE_RESOURCE
    if integer_bundle in archive.namelist():
        values += (digest(integer_bundle),)
    ledger_bundle = 'hepta/' + LEDGER_BUNDLE_RESOURCE
    if ledger_bundle in archive.namelist():
        if integer_bundle not in archive.namelist():
            raise ValueError('the installed ledger bundle has no scalar predecessor')
        values += (digest(ledger_bundle),)
    graph_bundle, owned = 'hepta/' + GRAPH_BUNDLE_RESOURCE, 'hepta/' + OWNED_VM_RESOURCE
    if graph_bundle in archive.namelist() or owned in archive.namelist():
        if ledger_bundle not in archive.namelist():
            raise ValueError('the installed graph owners have no execution-ledger predecessor')
        values += (digest(graph_bundle), digest(owned))
    if provenance.get('derived_pin_resource') is not None:
        resource = PACKAGE_DIRECTORY + '/pin.json'
        data = (json.dumps(values, ensure_ascii=True, separators=(',', ':')) + '\n').encode('ascii')
        if (provenance['derived_pin_resource'] != resource or provenance['runtime_source_transformations'] != {}
                or archive.read(resource) != data or sha256(data).hexdigest() != provenance['derived_pin_sha256']):
            raise ValueError('installed pin data differs from its actual cold wheel inputs')
        expected = render_pin(None)
    else:
        expected = render_pin(values)
        if sha256(expected).hexdigest() != provenance['derived_pin_sha256']:
            raise ValueError('installed derived Python pin differs from its actual cold wheel inputs')
    if (sha256((ROOT / PIN_FILE).read_bytes()).hexdigest() != provenance['pin_template_sha256']
            or archive.read(PIN_FILE) != expected):
        raise ValueError('installed Python pin differs from its declared distribution profile')
    return sha256(expected).hexdigest()


def _check_wheel(path, sources):
    from hepta.hia_default_native import SCOPES
    from tools.build_hia_default_release import PACKAGE_DIRECTORY, source_identity

    with zipfile.ZipFile(path) as wheel:
        provenance = json.loads(wheel.read(PACKAGE_DIRECTORY + '/provenance.json'))
        derived_python_pin(wheel)
        scripts = [name for name in wheel.namelist() if name.endswith('.data/scripts/hia')]
        if (provenance['scope'] != SCOPES[0] or not provenance['cold_report_sha256']
                or provenance['source_manifest'] != sources
                or provenance['source_identity_sha256'] != source_identity(sources)
                or len(scripts) != 1 or not wheel.read(scripts[0]).startswith(b'\x7fELF')):
            raise ValueError('installed fixture wheel differs from the current cold distribution')
    return path


def ordinary_wheel(source, python=None):
    """Use one real offline pip build per source identity and packaging interpreter."""
    source = Path(source)
    python = python or os.environ.get('HEPTA_HIA_TEST_PACKAGING_PYTHON', sys.executable)
    sources = _sources()
    # Partial fixture trees deliberately contain the resources exercised by each
    # caller. A conflicting staged input must fail even if the wheel already exists.
    if source != ROOT:
        for name, digest in sources.items():
            path = source / name
            if path.exists() and (not path.is_file() or path.is_symlink() or sha256(path.read_bytes()).hexdigest() != digest):
                raise ValueError('installed fixture staged different cold source: ' + name)
    from tools.build_hia_default_release import source_identity

    supplied = os.environ.get('HEPTA_HIA_TEST_DISTRIBUTION_WHEEL')
    pin = os.environ.get('HEPTA_HIA_TEST_DISTRIBUTION_SHA256')
    if (supplied is None) != (pin is None):
        raise ValueError('an external test wheel requires its path and SHA-256 together')
    key = (str(python), source_identity(sources), supplied, pin)
    with _lock:
        if key in _cache:
            path, digest = _cache[key]
            if sha256(path.read_bytes()).hexdigest() != digest:
                raise ValueError('the verified fixture wheel changed')
            return path
        directory = TemporaryDirectory(prefix='hia-installed-distribution-')
        atexit.register(directory.cleanup)
        work = Path(directory.name)
        if supplied is not None:
            original = Path(supplied).resolve(strict=True)
            raw = original.read_bytes()
            if sha256(raw).hexdigest() != pin:
                raise ValueError('the supplied distribution wheel has the wrong SHA-256')
            path = work / original.name
            path.write_bytes(raw)
            path.chmod(0o400)
        else:
            stage = work / 'source'
            stage.mkdir()
            stage_cold_sources(stage)
            wheels = work / 'wheels'
            wheels.mkdir()
            command = [str(python), '-B', '-m', 'pip', 'wheel', '--no-index', '--no-deps',
                       '--no-build-isolation', '--wheel-dir', str(wheels), str(stage)]
            result = subprocess.run(command, cwd=work, capture_output=True)
            if result.returncode:
                raise RuntimeError('ordinary offline wheel build failed:\n'
                                   + (result.stdout + result.stderr).decode(errors='replace'))
            path, = wheels.glob('*.whl')
        _check_wheel(path, sources)
        _cache[key] = (path, sha256(path.read_bytes()).hexdigest())
        return path


# Inject into isolated installed-Python probes, which deliberately have no tests on sys.path.
VM_EXECUTION_ROUTES = """
def compare_vm_routes(collect):
    import os
    from unittest.mock import patch
    from hepta import hia_default_native as default, hia_program_runtime as vm

    factory = getattr(default, 'default_reference_graph', None)
    projector = factory() if factory is not None else None
    if projector is None:
        return collect(True)
    # Observe the unrestricted public call and its existing operation-level route.
    with patch.object(vm._Machine, 'invoke', side_effect=AssertionError('installed graph used host dispatch')):
        graph_reports = collect(False)
    selector, _ = default.GRAPH_OWNER
    manifest = projector._default_package_binding.selections[selector]
    with patch.dict(os.environ, {selector: str(manifest)}):
        operation_reports = collect(True)
    assert operation_reports == graph_reports
    return graph_reports
"""
