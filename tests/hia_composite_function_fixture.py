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
from hepta.hia_json_preflight_native import MAX_IMAGE_BYTES
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


def _compile_bound(folder, label, compiler, source, compiler_sha, **options):
    from tools.qualify_hia_selfhost import compile_stage
    compiler_bytes = compiler.read_bytes()
    if sha256(compiler_bytes).hexdigest() != compiler_sha:
        raise ValueError('development fixture compiler changed before compilation')
    image, receipt = compile_stage(folder, label, compiler, source, **options)
    source_sha = sha256(source).hexdigest()
    if (compiler.read_bytes() != compiler_bytes
            or receipt.get('input_sha256') != source_sha
            or receipt.get('source_sha256') != source_sha
            or receipt.get('source_unchanged') is not True
            or receipt.get('artifact_sha256') != compiler_sha
            or receipt.get('produced_sha256') != sha256(image.read_bytes()).hexdigest()):
        raise ValueError('development fixture compile receipt differs from frozen inputs or output')
    return image, receipt


def _bootstrap_development(folder):
    from tools.qualify_hia_selfhost import build_seed
    rows = [('types', TYPE_SOURCE, TYPE_SCHEMA), ('helpers', HELPER_SOURCE, HELPER_SCHEMA)]
    rows += [(name, SOURCES[name], 'hepta.hia.composite-function-' + name + '-native.v1')
             for name in KERNELS]
    compiler_source = TYPE_SOURCE.with_name('selfhost.hiaasm')
    frozen = {path: path.read_bytes() for path in (compiler_source, *(p for _, p, _ in rows))}
    source = frozen[compiler_source]
    seed, seed_receipt = build_seed(folder, source=source)
    if seed_receipt.get('source_sha256') != sha256(source).hexdigest():
        raise ValueError('development seed source differs from the frozen compiler source')
    seed_bytes = seed.read_bytes()
    if (seed_receipt.get('artifact_sha256') != sha256(seed_bytes).hexdigest()
            or type(seed_receipt.get('artifact_bytes')) is not int
            or seed_receipt['artifact_bytes'] != len(seed_bytes)):
        raise ValueError('development seed image differs from its publication receipt')
    first, first_receipt = _compile_bound(folder, 'B1', seed, source,
        seed_receipt['artifact_sha256'], image_format='seed-shared')
    compiler, second_receipt = _compile_bound(folder, 'B2', first, source,
                                            first_receipt['produced_sha256'])
    if first.read_bytes() != compiler.read_bytes():
        raise AssertionError('development bootstrap did not reach the native fixed point')
    compiler_sha = second_receipt['produced_sha256']
    manifests = {}
    for name, path, schema in rows:
        raw = frozen[path]
        image, receipt = _compile_bound(folder, 'function-fixture-' + name, compiler, raw, compiler_sha)
        if path.read_bytes() != raw:
            raise ValueError('development fixture source changed during compilation')
        target = folder / (name + '.manifest.json')
        target.write_text(json.dumps(dict(schema=schema,
            source_sha256=sha256(raw).hexdigest(), image_path=image.name,
            image_sha256=receipt['produced_sha256'], compiler_sha256=compiler_sha), indent=2) + '\n')
        (folder / (name + '.development-compile.json')).write_text(
            json.dumps(receipt, indent=2) + '\n')
        manifests[name] = target
    if (any(path.read_bytes() != raw for path, raw in frozen.items())
            or sha256(compiler.read_bytes()).hexdigest() != compiler_sha):
        raise ValueError('development fixture inputs changed before bundle publication')
    manifest = folder / 'manifest.json'
    manifest.write_text(json.dumps(dict(schema=SCHEMA,
        kernels={name: manifests[name].name for name in KERNELS},
        types_source_sha256=sha256(frozen[TYPE_SOURCE]).hexdigest(),
        helpers_source_sha256=sha256(frozen[HELPER_SOURCE]).hexdigest()), indent=2) + '\n')
    return manifest, manifests['types'], manifests['helpers']


def _custody_snapshot(manifest, type_manifest, helper_manifest):
    """Pin disk bytes before a possibly warm immutable-image loader is used."""
    pins = {}

    def read(path, capacity):
        with path.open('rb') as handle:
            raw = handle.read(capacity + 1)
        if len(raw) > capacity:
            raise ValueError('complete function fixture file exceeds its declared capacity')
        pins[path] = sha256(raw).hexdigest()
        return raw

    bundle = json.loads(read(manifest, 16384))
    rows = [(name, manifest.parent / bundle['kernels'][name], SOURCES[name]) for name in KERNELS]
    rows += [('types', type_manifest, TYPE_SOURCE), ('helpers', helper_manifest, HELPER_SOURCE)]
    images = {}
    for name, component, source in rows:
        value = json.loads(read(component, 16384))
        if sha256(read(source, 1 << 20)).hexdigest() != value['source_sha256']:
            raise ValueError('complete function fixture source differs from its manifest')
        image = component.parent / value['image_path']
        if sha256(read(image, MAX_IMAGE_BYTES)).hexdigest() != value['image_sha256']:
            raise ValueError('complete function fixture image differs from its manifest')
        images[name] = value['image_sha256']
    if (bundle['types_source_sha256'] != pins[TYPE_SOURCE]
            or bundle['helpers_source_sha256'] != pins[HELPER_SOURCE]):
        raise ValueError('complete function fixture dependency source differs from its bundle')
    return pins, images


def _build_fixture(scope, paths):
    temporary = None
    extra_pins = {}
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
                cold_bytes = cold.read_bytes()
                report = json.loads(cold_bytes)
                nested_path = Path(report['nested_report'])
                nested_bytes = nested_path.read_bytes()
                nested = json.loads(nested_bytes)
                compiler = Path(nested['generations'][-1]['produced_image'])
                extra_pins = {cold: sha256(cold_bytes).hexdigest(),
                              nested_path: sha256(nested_bytes).hexdigest(),
                              compiler: sha256(compiler.read_bytes()).hexdigest()}
                manifest = build_functions(folder / 'functions', compiler, cold)
                type_manifest = build(folder / 'types', compiler, cold, candidate='composite-types')
                helper_manifest = build(folder / 'helpers', compiler, cold, candidate='task-helpers')
            else:
                manifest, type_manifest, helper_manifest = _bootstrap_development(folder)
            (folder / 'fixture-scope.json').write_text(json.dumps({
                'schema': 'hepta.hia.complete-function-test-fixture.v1', 'scope': scope,
                'matching_source_cold_build': scope == 'MATCHING_SOURCE_COLD_BUILD',
                'fixture_result_is_whole_stack_qualification': False,
            }, indent=2) + '\n')
        pins, expected_images = _custody_snapshot(manifest, type_manifest, helper_manifest)
        for path, digest in extra_pins.items():
            if path in pins and pins[path] != digest:
                raise ValueError('complete function fixture cold inputs changed')
            pins[path] = digest
        bundle = installed_composite_functions(manifest)
        types_image = installed_composite_types(type_manifest)
        helpers_image = installed_task_helpers(helper_manifest)
        loaded_images = {**bundle.images, 'types': types_image, 'helpers': helpers_image}
        if any(image.image_sha256 != expected_images[name] for name, image in loaded_images.items()):
            raise ValueError('complete function fixture loaded image differs from its manifest')
        pins = tuple(sorted(pins.items(), key=lambda item: str(item[0])))
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
