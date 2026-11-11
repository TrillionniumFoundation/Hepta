"""One strict, source-bound fixture for every complete-function native test.

Cold builds use the complete matching-source qualification gate. Explicit
development images require the function bundle and both dependency manifests.
With no selection, one real B0/B1/B2 bootstrap supplies a development fixture;
that branch never emits or claims a cold-qualification receipt. All classes in
one process share the same build, while every reuse rechecks its custody pins.
"""
from __future__ import annotations

import atexit
from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import tempfile

from hepta.hia_composite_functions_native import (
    KERNELS, SCHEMA, SELECTOR, SOURCES, installed_composite_functions)
from hepta.hia_composite_types_native import (
    SCHEMA as TYPE_SCHEMA, SELECTOR as TYPE_SELECTOR, SOURCE as TYPE_SOURCE,
    installed_composite_types)
from hepta.hia_task_helpers_native import (
    SCHEMA as HELPER_SCHEMA, SELECTOR as HELPER_SELECTOR, SOURCE as HELPER_SOURCE,
    installed_task_helpers)


DEVELOPMENT_KEYS = (
    'HEPTA_HIA_COMPOSITE_FUNCTIONS_DEVELOPMENT_MANIFEST',
    'HEPTA_HIA_COMPOSITE_TYPES_DEVELOPMENT_MANIFEST',
    'HEPTA_HIA_TASK_HELPERS_DEVELOPMENT_MANIFEST',
)
COLD_KEYS = (
    'HEPTA_HIA_COMPOSITE_FUNCTIONS_COLD_REPORT',
    'HEPTA_HIA_COMPOSITE_TYPES_COLD_REPORT',
    'HEPTA_HIA_TASK_HELPERS_COLD_REPORT',
)
_FIXTURES = {}


def configuration(environ=None):
    """Reject ambiguous provenance before importing a builder or making files."""
    environ = os.environ if environ is None else environ
    development = tuple(environ.get(key, '') for key in DEVELOPMENT_KEYS)
    cold = tuple(environ.get(key, '') for key in COLD_KEYS)
    if any(development) and any(cold):
        raise ValueError('development images cannot override cold qualification')
    if any(development) and not all(development):
        raise ValueError('complete function fixture requires all three development manifests')
    if all(development):
        return 'DEVELOPMENT_ONLY', tuple(str(Path(p).resolve()) for p in development)
    if any(cold):
        reports = {str(Path(p).resolve()) for p in cold if p}
        if len(reports) != 1:
            raise ValueError('complete function fixture requires one identical cold report')
        return 'MATCHING_SOURCE_COLD_BUILD', (reports.pop(),)
    return 'BOOTSTRAP_DEVELOPMENT_ONLY', ()


@dataclass(frozen=True)
class CompositeFunctionFixture:
    scope: str
    manifest: Path
    type_manifest: Path
    helper_manifest: Path
    bundle: object
    types_image: object
    helpers_image: object
    pins: tuple

    @property
    def environment(self):
        return {SELECTOR: str(self.manifest), TYPE_SELECTOR: str(self.type_manifest),
                HELPER_SELECTOR: str(self.helper_manifest)}

    @property
    def reference_environment(self):
        return dict.fromkeys((SELECTOR, TYPE_SELECTOR, HELPER_SELECTOR), '')

    def check_custody(self):
        for path, digest in self.pins:
            if sha256(path.read_bytes()).hexdigest() != digest:
                raise ValueError('shared complete function fixture changed: ' + str(path))


def _bootstrap_development(folder):
    from tools.qualify_hia_selfhost import build_seed, compile_stage
    seed, _ = build_seed(folder)
    source = TYPE_SOURCE.with_name('selfhost.hiaasm').read_bytes()
    first, _ = compile_stage(folder, 'B1', seed, source, image_format='seed-shared')
    compiler, _ = compile_stage(folder, 'B2', first, source)
    if first.read_bytes() != compiler.read_bytes():
        raise AssertionError('development bootstrap did not reach the native fixed point')
    rows = [('types', TYPE_SOURCE, TYPE_SCHEMA), ('helpers', HELPER_SOURCE, HELPER_SCHEMA)]
    rows += [(name, SOURCES[name], 'hepta.hia.composite-function-' + name + '-native.v1')
             for name in KERNELS]
    manifests = {}
    for name, path, schema in rows:
        image, receipt = compile_stage(folder, 'function-fixture-' + name, compiler, path.read_bytes())
        target = folder / (name + '.manifest.json')
        target.write_text(json.dumps(dict(schema=schema,
            source_sha256=sha256(path.read_bytes()).hexdigest(), image_path=image.name,
            image_sha256=sha256(image.read_bytes()).hexdigest(),
            compiler_sha256=sha256(compiler.read_bytes()).hexdigest()), indent=2) + '\n')
        (folder / (name + '.development-compile.json')).write_text(
            json.dumps(receipt, indent=2) + '\n')
        manifests[name] = target
    manifest = folder / 'manifest.json'
    manifest.write_text(json.dumps(dict(schema=SCHEMA,
        kernels={name: manifests[name].name for name in KERNELS},
        types_source_sha256=sha256(TYPE_SOURCE.read_bytes()).hexdigest(),
        helpers_source_sha256=sha256(HELPER_SOURCE.read_bytes()).hexdigest()), indent=2) + '\n')
    return manifest, manifests['types'], manifests['helpers']


def _custody_paths(manifest, type_manifest, helper_manifest):
    paths = {manifest, type_manifest, helper_manifest, TYPE_SOURCE, HELPER_SOURCE, *SOURCES.values()}
    bundle = json.loads(manifest.read_bytes())
    components = [manifest.parent / bundle['kernels'][name] for name in KERNELS]
    for component in (*components, type_manifest, helper_manifest):
        value = json.loads(component.read_bytes())
        paths.add(component)
        paths.add(component.parent / value['image_path'])
    return paths


def _build_fixture(scope, paths):
    temporary = None
    extra_pins = set()
    try:
        if scope == 'DEVELOPMENT_ONLY':
            manifest, type_manifest, helper_manifest = map(Path, paths)
        else:
            temporary = tempfile.TemporaryDirectory(prefix='hia-function-fixture-')
            folder = Path(temporary.name)
            if scope == 'MATCHING_SOURCE_COLD_BUILD':
                from tools.build_hia_composite_functions import build as build_functions
                from tools.build_hia_json_preflight import build
                cold = Path(paths[0])
                report = json.loads(cold.read_bytes())
                nested_path = Path(report['nested_report'])
                nested = json.loads(nested_path.read_bytes())
                compiler = Path(nested['generations'][-1]['produced_image'])
                manifest = build_functions(folder / 'functions', compiler, cold)
                type_manifest = build(folder / 'types', compiler, cold, candidate='composite-types')
                helper_manifest = build(folder / 'helpers', compiler, cold, candidate='task-helpers')
                extra_pins.update((cold, nested_path, compiler))
            else:
                manifest, type_manifest, helper_manifest = _bootstrap_development(folder)
            (folder / 'fixture-scope.json').write_text(json.dumps({
                'schema': 'hepta.hia.complete-function-test-fixture.v1', 'scope': scope,
                'matching_source_cold_build': scope == 'MATCHING_SOURCE_COLD_BUILD',
                'fixture_result_is_whole_stack_qualification': False,
            }, indent=2) + '\n')
        bundle = installed_composite_functions(manifest)
        types_image = installed_composite_types(type_manifest)
        helpers_image = installed_task_helpers(helper_manifest)
        pin_paths = _custody_paths(manifest, type_manifest, helper_manifest) | extra_pins
        pins = tuple((path, sha256(path.read_bytes()).hexdigest())
                     for path in sorted(pin_paths, key=str))
        fixture = CompositeFunctionFixture(scope, manifest, type_manifest, helper_manifest,
                                           bundle, types_image, helpers_image, pins)
        fixture.check_custody()
    except BaseException:
        if temporary is not None:
            temporary.cleanup()
        raise
    if temporary is not None:
        atexit.register(temporary.cleanup)
    return fixture


def composite_function_fixture():
    """Share one real build, with no native-test skips or provenance fallback."""
    key = configuration()
    fixture = _FIXTURES.get(key)
    if fixture is None:
        fixture = _build_fixture(*key)
        _FIXTURES[key] = fixture
    fixture.check_custody()
    return fixture
