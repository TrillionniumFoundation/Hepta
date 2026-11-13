"""One fresh-process original/native observation before the service import.

The store's public helper may be replaced before the service module imports it.
This test-only process records that real import and the original evaluation body.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--kind', choices=('original', 'function', 'none', 'object',
                                         'absent', 'object_metadata_error'), required=True)
    parser.add_argument('--selected', choices=('0', '1'), required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    sys.path.insert(0, str(source))
    manifest_raw = args.manifest.read_bytes()
    manifest = json.loads(manifest_raw)
    image_path = args.manifest.parent/manifest['image_path']
    image_raw = image_path.read_bytes()
    assert sha256(image_raw).hexdigest() == manifest['image_sha256']
    before = {name:sha256((source/name).read_bytes()).hexdigest() for name in (
        'hepta/hia_agent_service.py', 'hepta/hia_agent_store.py',
        'hepta/hia_service_evaluation_native.py')}
    from hepta import hia_agent_store as store
    assert 'hepta.hia_agent_service' not in sys.modules
    anchor = store._connection_arguments
    assert store._NATIVE_EVALUATION_CONNECTION_ARGUMENTS is anchor
    events = []
    def replacement(value):
        events.append(['call', '_connection_arguments'])
        return anchor(value)
    class Foreign:
        def __getattribute__(self, name):
            if name == '__module__':
                events.append(['metadata', name])
                if args.kind == 'object_metadata_error':
                    raise LookupError('metadata must not run during helper selection')
                return 'foreign_evaluation_fixture'
            return object.__getattribute__(self, name)
        def __call__(self, value):
            events.append(['call', '_connection_arguments'])
            return anchor(value)
    if args.kind == 'absent':
        del store._connection_arguments
    elif args.kind == 'none':
        store._connection_arguments = None
    elif args.kind == 'function':
        store._connection_arguments = replacement
    elif args.kind in ('object', 'object_metadata_error'):
        store._connection_arguments = Foreign()
    result = {'import_error':None,'admission_error':None,'admission_events':[],
              'business':None,'helper_events':[]}
    image = None
    definition_anchor = False
    try:
        from hepta import hia_agent_service as api
    except BaseException as error:
        result['import_error'] = {'type':type(error).__name__,'args':list(error.args),
                                  'name':getattr(error,'name',None)}
    else:
        definition_anchor = api._NATIVE_EVALUATION_PUBLIC_ENTRIES[0] is anchor
        from hepta import hia_service_evaluation_native as native
        from tests import hia_service_evaluation_fixtures as fixtures
        if args.selected == '1':
            try:
                image = native.NativeEvaluationImage(image_raw, manifest['image_sha256'])
            except BaseException as error:
                result['admission_error'] = {'type':type(error).__name__,'args':list(error.args)}
        result['admission_events'] = list(events)
        events.clear()
        if args.selected == '0' or image is not None:
            initial = 0 if image is None else image.entries
            result['business'] = fixtures.fixture_call('eval-ok', image)
            actual_entries = 0 if image is None else image.entries-initial
        else:
            actual_entries = 0
        result['helper_events'] = list(events)
    finally:
        store._connection_arguments = anchor
    after = {name:sha256((source/name).read_bytes()).hexdigest() for name in before}
    record = {'schema':'hia.evaluation.store-definition-before-service-import.v1',
              'python':sys.version,'selected':args.selected=='1','kind':args.kind,
              'original_definition_anchor':definition_anchor,'observation':result,
              'actual_native_entries':0 if image is None else actual_entries,
              'source_before':before,'source_after':after,
              'inputs_unchanged':before==after and args.manifest.read_bytes()==manifest_raw
                  and image_path.read_bytes()==image_raw,
              'image_sha256':manifest['image_sha256'],'current_cold':False}
    with args.output.open('x') as file:
        file.write(json.dumps(record,indent=2,sort_keys=True)+'\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
