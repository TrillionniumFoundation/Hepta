"""Inputs derived solely from the frozen original methods and object protocols."""
import copy
from hashlib import sha256


class DictSubclass(dict):
    pass


def arrange(f, case):
    if __package__:
        from .hia_native_build_admission_oracle import Compared, ObservedDict, ObservedIterable, ObservedIterator, Program, Truth
    else:
        from hia_native_build_admission_oracle import Compared, ObservedDict, ObservedIterable, ObservedIterator, Program, Truth
    action = case.get('action', 'valid')
    fn = f.functions[0]
    if 'scalar_names' in case:
        f.program.scalar_names = copy.deepcopy(case['scalar_names'])
    if action == 'valid':
        return
    if action == 'edit':
        for edit in case['edits']:
            value = getattr(f, edit['root'])
            for key in edit.get('path', [])[:-1]:
                value = value[key]
            key = edit['path'][-1]
            if edit.get('delete'):
                del value[key]
            else:
                value[key] = copy.deepcopy(edit['value'])
        return
    if action == 'function_types':
        f.functions[:] = [f.function('f', case['params'], case['returns'])]
    elif action == 'empty_functions':
        f.functions.clear()
    elif action == 'not_scalar':
        f.program.scalar_names = []
    elif action == 'duplicate_functions':
        f.functions[:] = [f.function('f'), f.function('f', ('bool',), ('bool',))]
    elif action == 'export_overrides_bad_scalar':
        fn['params'] = [ObservedDict(f.trace, 'bad_parameter', {'type': 'mutbuf'})]
        fn['returns'] = ['unsupported']
        f.set_exports([('f', 1 << 512)])
    elif action == 'exports':
        f.set_exports(case['pairs'])
    elif action == 'native_large_exports':
        f.set_exports([(str(i), 1 << (i % 100)) for i in range(case['size'])])
    elif action == 'context_none':
        f.context_argument = None
        if case.get('drop_context'):
            del f.metadata['context']
    elif action == 'functions_once':
        f.document['functions'] = ObservedIterator(f.trace, 'functions_once', f.functions)
    elif action == 'functions_iterable':
        f.document['functions'] = ObservedIterable(f.trace, 'functions', f.functions)
    elif action in ('params_once', 'params_iterable'):
        values = dict.__getitem__(fn, 'params')
        if case.get('bad_first'):
            values[0]['type'] = 'mutbuf'
            f.set_exports([('f', 7)])
        cls = ObservedIterator if action == 'params_once' else ObservedIterable
        fn['params'] = cls(f.trace, 'params', values)
    elif action in ('returns_iterable', 'returns_once'):
        values = dict.__getitem__(fn, 'returns')
        if action == 'returns_once':
            fn['returns'] = ObservedIterator(f.trace, 'returns', values)
        else:
            fn['returns'] = ObservedIterable(f.trace, 'returns', values, length=case.get('length'))
    elif action == 'scalar_names_once':
        f.functions[:] = [f.function('f'), f.function('g')]
        f.program.scalar_names = ObservedIterator(f.trace, 'scalar_names', ['g', 'f'])
    elif action == 'widths_once':
        f.widths = ObservedIterator(f.trace, 'widths', list(f.widths))
    elif action == 'widths_iterable':
        f.widths = ObservedIterable(f.trace, 'widths', list(f.widths))
    elif action == 'many_params':
        fn['params'] = [ObservedDict(f.trace, 'parameter:f:' + str(i), {'type': 'u64'}) for i in range(case['size'])]
    elif action == 'many_functions':
        f.functions[:] = [f.function('f' + str(i), ('bool',), ('unit',)) for i in range(case['size'])]
        f.program.scalar_names = {str('f' + str(i)) for i in range(case['size'])}
    elif action == 'unhashable_param':
        fn['params'][0]['type'] = []
    elif action == 'unhashable_return':
        fn['returns'] = [[]]
    elif action == 'compared_param':
        fn['params'][0]['type'] = Compared(f.trace, 'parameter_type', 'u32', equal=Truth(f.trace, 'parameter_type_truth', True))
    elif action == 'normalized_iterator':
        f.normalized_exports = ObservedIterator(f.trace, 'normalized_exports', case.get('pairs', [('f', 9)]))
    elif action == 'normalized_mapping':
        f.normalized_exports = ObservedDict(f.trace, 'normalized_mapping', {'f': 9})
    elif action == 'raw_exports_iterable':
        pair = ObservedIterable(f.trace, 'export_pair', ['f', 9], length=case.get('pair_length'))
        exports = ObservedIterable(f.trace, 'raw_exports', [pair])
        f.set_exports([('f', 9)])
        f.context['foreign_buffer_exports'] = exports
    elif action == 'raw_exports_once':
        f.set_exports([('f', 9)])
        f.context['foreign_buffer_exports'] = ObservedIterator(f.trace, 'raw_exports', [('f', 9)])
    else:
        arrange_admission(f, case)


def arrange_admission(f, case):
    if __package__:
        from .hia_native_build_admission_oracle import Compared, ObservedDict, ObservedIterable, Program, Truth
    else:
        from hia_native_build_admission_oracle import Compared, ObservedDict, ObservedIterable, Program, Truth
    action = case['action']
    if action == 'invalid_exports_outer':
        f.context['foreign_buffer_exports'] = None
        f.metadata['core_sha256'] = 'also-wrong-but-later'
    elif action == 'invalid_exports_pair':
        f.context['foreign_buffer_exports'] = [1]
        f.metadata['core_sha256'] = 'also-wrong-but-later'
    elif action == 'compared_installation':
        f.metadata['installation'] = Compared(f.trace, 'installation', f.installation,
            equal=False, unequal=Truth(f.trace, 'installation_truth', False))
    elif action == 'metadata_extra':
        f.metadata['extra'] = case['value']
    elif action == 'metadata_extra_same':
        value = float('nan') if case.get('nan') else case['value']
        f.metadata['extra'] = f.record['extra'] = value
    elif action == 'metadata_items_iterator':
        rows = list(dict.items(f.metadata))
        if case.get('malformed'):
            rows[0] = ('installation',)
        f.metadata.items_override = ObservedIterable(f.trace, 'metadata_items', rows)
    elif action == 'metadata_inequality_truth':
        compared = Compared(f.trace, 'metadata_value', 'ignored', unequal=Truth(f.trace, 'any_truth', False))
        f.record['core_sha256'] = compared
    elif action == 'metadata_inequality_stop':
        f.record['core_sha256'] = Compared(f.trace, 'metadata_value', f.program.core_digest)
    elif action == 'built_type':
        f.record['native_build'] = DictSubclass(f.built) if case['kind'] == 'subclass' else case['value']
    elif action == 'object_ref_type':
        f.record['object_artifact'] = DictSubclass(f.object_ref) if case['kind'] == 'subclass' else case['value']
    elif action == 'native_bytearray':
        f.native_bytes = bytearray(f.native_bytes)
    elif action == 'native_bad_bytes':
        f.native_bytes = 'not-bytes'
        if case.get('early_kind_error'):
            f.built['kind'] = 'different'
    elif action == 'object_bad_bytes':
        f.object_bytes = 'not-bytes'
        if case.get('early_metadata_error'):
            f.object_metadata['schema'] = 'different'
    elif action == 'object_changed_bytes':
        f.object_bytes = b'different-object-bytes'
    elif action == 'missing_optional_exports':
        del f.metadata['foreign_buffer_exports']
        del f.record['foreign_buffer_exports']
    elif action == 'missing_output_kind':
        del f.metadata['output_kind']
        del f.record['output_kind']
        if case.get('early_shape_error'):
            f.record['native_build'] = None
    elif action == 'program_none':
        f.program = None
    elif action == 'context_none_result':
        f.context = None
        f.metadata['core_sha256'] = 'also-wrong-but-later'
    elif action == 'provider_pair':
        kind = case['kind']
        pairs = {'native': [f.native_bytes, f.metadata], 'build-object': [f.object_bytes, f.object_metadata],
                 'build-receipt': [f.record, f.record_metadata]}
        value = pairs[kind]
        shape = case['shape']
        if shape == 'none':
            value = None
        elif shape == 'one':
            value = value[:1]
        elif shape == 'three':
            value = value + [None]
        elif shape == 'iterable':
            value = ObservedIterable(f.trace, 'provider_pair', value)
        f.store_results[kind] = value
    elif action == 'object_output':
        f.metadata['output_kind'] = f.record['output_kind'] = f.built['kind'] = 'object'
        if case.get('same_bytes'):
            f.native_bytes = f.object_bytes
            f.built['artifact_sha256'] = sha256(f.native_bytes).hexdigest()
    elif action == 'object_ref_sha_missing':
        del f.object_ref['sha256']
    elif action == 'object_ref_sha_wrong':
        f.object_ref['sha256'] = 'different'
    elif action == 'behavior':
        revised_functions = [f.function('f')]
        revised_document = ObservedDict(f.trace, 'revised_document', {'functions': revised_functions})
        f.revised = Program(f, 'revised', revised_document, ['f'], canonical=b'revised-core')
        if case.get('same_core'):
            f.revised.canonical = f.program.canonical
        f.timeout_ms = case.get('timeout_ms', 1000)
        if case.get('empty_signatures'):
            f.program.scalar_names = f.revised.scalar_names = []
    else:
        raise AssertionError('unrecognized original input fixture: ' + action)


def scenarios():
    cases = []

    def add(name, mode=1, **options):
        cases.append({'name': name, 'mode': mode, **options})

    def edit(root, path, value=None, *, delete=False):
        return {'root': root, 'path': path, 'delete': delete, 'value': value}

    add('signatures_scalar')
    for action in ('empty_functions', 'not_scalar', 'duplicate_functions', 'export_overrides_bad_scalar',
                   'functions_once', 'functions_iterable', 'params_once', 'params_iterable',
                   'returns_iterable', 'returns_once', 'scalar_names_once', 'widths_once',
                   'widths_iterable', 'unhashable_param', 'unhashable_return', 'compared_param',
                   'normalized_iterator', 'normalized_mapping'):
        add('signatures_' + action, action=action)
    for params, returns, name in (
            ([], [], 'empty_signature'), (['bool'], ['unit'], 'bool_to_unit'),
            (['isize', 'usize', 'i8', 'u8', 'i16', 'u16', 'i32', 'u32', 'i64', 'u64'], [], 'every_width'),
            (['unit'], [], 'unit_parameter'), (['mutbuf'], ['u64'], 'buffer_parameter'),
            (['u64'], ['buffer'], 'buffer_return'), (['u64'], ['u64', 'bool'], 'multiple_returns')):
        add('signatures_' + name, action='function_types', params=params, returns=returns)
    add('signatures_export_unknown_name', action='exports', pairs=[['absent', 42]])
    add('signatures_export_huge_extent', action='exports', pairs=[['f', 1 << 512]])
    add('signatures_export_duplicate_last_wins', action='exports', pairs=[['f', 1], ['f', 2]])
    add('signatures_consumed_params_then_export_tail', action='params_once', bad_first=True)
    for length, name in ((-1, 'negative'), (1 << 256, 'huge'), (0, 'misleading_zero')):
        add('signatures_returns_len_' + name, action='returns_iterable', length=length)
    add('signatures_4097_params_no_added_limit', action='many_params', size=4097)
    add('signatures_1025_functions_no_added_limit', action='many_functions', size=1025)
    add('signatures_not_scalar_never_reads_missing_params', action='edit', scalar_names=[],
        edits=[edit('functions', [0, 'params'], delete=True), edit('functions', [0, 'returns'], delete=True)])
    add('signatures_bad_param_precedes_missing_returns', action='edit',
        edits=[edit('functions', [0, 'params', 0, 'type'], 'mutbuf'), edit('functions', [0, 'returns'], delete=True)])
    add('signatures_two_returns_precede_unhashable_element', action='edit',
        edits=[edit('functions', [0, 'returns'], [[], []])])
    add('signatures_normalized_bad_pair', action='normalized_iterator', pairs=[['f']])
    add('signatures_normalized_unhashable_key', action='normalized_iterator', pairs=[[[], 1]])
    for action, event, argument, name in (
            ('valid', 'parameter:f:0.getitem', 'type', 'parameter_get_stop_is_pep479'),
            ('widths_iterable', 'widths.iter', None, 'widths_iter_stop_is_pep479'),
            ('params_iterable', 'params.iter', None, 'params_iter_stop_outside_generator'),
            ('returns_iterable', 'returns.iter', None, 'returns_iter_stop_outside_generator'),
            ('compared_param', 'parameter_type_truth.bool', None, 'membership_truth_stop_is_pep479')):
        fault = {'event': event, 'exception': 'StopIteration'}
        if argument is not None:
            fault['argument0'] = argument
        add('signatures_' + name, action=action, fault=fault)
    for name, action, options in (
            ('ordinary', 'valid', {}), ('context_none', 'context_none', {}),
            ('context_none_missing_binding', 'context_none', {'drop_context': True}),
            ('exports_once', 'raw_exports_once', {}), ('exports_iterable', 'raw_exports_iterable', {}),
            ('exports_pair_negative_hint', 'raw_exports_iterable', {'pair_length': -1}),
            ('exports_pair_huge_hint', 'raw_exports_iterable', {'pair_length': 1 << 256}),
            ('invalid_exports_before_core_outer', 'invalid_exports_outer', {}),
            ('invalid_exports_before_core_pair', 'invalid_exports_pair', {}),
            ('compared_installation_uses_ne', 'compared_installation', {}),
            ('large_exports', 'native_large_exports', {'size': 2049})):
        add('native_' + name, 2, action=action, **options)
    for key in ('installation', 'context', 'core_sha256', 'signatures', 'foreign_buffer_exports'):
        add('native_reject_' + key, 2, action='edit', edits=[edit('metadata', [key], 'different')])
    for key in ('installation', 'context', 'candidate', 'core_sha256', 'signatures'):
        add('native_missing_' + key, 2, action='edit', edits=[edit('metadata', [key], delete=True)])
    add('native_installation_reject_before_missing_candidate', 2, action='edit',
        edits=[edit('metadata', ['installation'], None), edit('metadata', ['candidate'], delete=True)])
    add('native_core_reject_before_signatures_lookup', 2, action='edit',
        edits=[edit('metadata', ['core_sha256'], None), edit('metadata', ['signatures'], delete=True)])
    for mode in (3, 4):
        prefix = 'inputs_' if mode == 3 else 'receipt_'
        add(prefix + 'ordinary', mode)
        for key in ('context', 'native_artifact', 'installation', 'target_profile', 'backend_profile'):
            add(prefix + 'subject_reject_' + key, mode, action='edit', edits=[edit('record', [key], 'different')])
        for key in ('object_artifact', 'object_sha256', 'core_sha256', 'input_sha256',
                    'implementation_sha256', 'kind', 'foreign_buffer_exports', 'artifact_sha256'):
            add(prefix + 'build_reject_' + key, mode, action='edit', edits=[edit('built', [key], 'different')])
        for action in ('metadata_inequality_truth', 'metadata_items_iterator', 'native_bytearray',
                       'native_bad_bytes', 'object_bad_bytes', 'object_ref_sha_missing', 'object_ref_sha_wrong'):
            add(prefix + action, mode, action=action)
        add(prefix + 'items_pair_unpack_error', mode, action='metadata_items_iterator', malformed=True)
        for action in ('built_type', 'object_ref_type'):
            add(prefix + action + '_exact_type_subclass_rejected', mode, action=action, kind='subclass')
            add(prefix + action + '_none', mode, action=action, kind='other', value=None)
        add(prefix + 'absent_record_extra_none_admitted', mode, action='metadata_extra', value=None)
        add(prefix + 'extra_metadata_missing_in_record', mode, action='metadata_extra', value=1)
        add(prefix + 'build_kind_error_precedes_bad_native_bytes', mode, action='native_bad_bytes', early_kind_error=True)
        add(prefix + 'metadata_error_precedes_bad_object_bytes', mode, action='object_bad_bytes', early_metadata_error=True)
        add(prefix + 'object_output_same_bytes', mode, action='object_output', same_bytes=True)
        add(prefix + 'object_output_different_bytes', mode, action='object_output', same_bytes=False)
        for key in ('schema', 'core_sha256', 'machine_plan_sha256', 'installation'):
            add(prefix + 'object_metadata_' + key, mode, action='edit', edits=[edit('object_metadata', [key], 'different')])
        add(prefix + 'object_metadata_extra_field', mode, action='edit', edits=[edit('object_metadata', ['extra'], 1)])
        add(prefix + 'record_get_stop_is_pep479', mode, fault={'event': 'record.get', 'argument0': 'core_sha256', 'exception': 'StopIteration'})
        add(prefix + 'metadata_ne_stop_is_pep479', mode, action='metadata_inequality_stop', fault={'event': 'metadata_value.ne', 'exception': 'StopIteration'})
        add(prefix + 'any_truth_stop_is_not_pep479', mode, action='metadata_inequality_truth', fault={'event': 'any_truth.bool', 'exception': 'StopIteration'})
        add(prefix + 'first_subject_error_precedes_next_missing_key', mode, action='edit',
            edits=[edit('record', ['context'], 'different'), edit('record', ['native_artifact'], delete=True)])
    for mode, events in (
            (1, ['program.as_dict', 'program.scalar_entrypoints', 'normalize_exports']),
            (2, ['store.get:native', 'service._program', 'service._context', 'program.sha256', 'normalize_exports']),
            (3, ['store.get_json:build-receipt', 'store.get:native', 'service._program', 'service._context',
                 'normalize_exports', 'program.input_sha256', 'sha256', 'sha256.hexdigest', 'store.get:build-object']),
            (4, ['store.get_json:build-receipt', 'store.get:build-object'])):
        for event in events:
            for error in ('ValueError', 'OSError', 'KeyboardInterrupt', 'StopIteration'):
                add('mode' + str(mode) + '_foreign_' + event.replace(':', '_').replace('.', '_') + '_' + error,
                    mode, fault={'event': event, 'exception': error})
    for name, options in (
            ('two_signature_calls', {}), ('empty_still_calls_both', {'empty_signatures': True}),
            ('timeout_calls_neither', {'timeout_ms': 0}), ('reflexive_calls_neither', {'same_core': True}),
            ('first_signature_provider_fails', {'fault': {'event': 'normalize_exports', 'exception': 'ValueError'}}),
            ('second_signature_provider_fails', {'fault': {'event': 'normalize_exports', 'occurrence': 2, 'exception': 'OSError'}})):
        add('behavior_' + name, 1, route='behavior', action='behavior', **options)
    for mode in (2, 3, 4):
        add('mode' + str(mode) + '_missing_optional_exports', mode, action='missing_optional_exports')
        add('mode' + str(mode) + '_program_provider_returns_none', mode, action='program_none')
        add('mode' + str(mode) + '_context_none_before_core_mismatch', mode, action='context_none_result')
        kinds = ['native'] if mode == 2 else ['native', 'build-receipt', 'build-object']
        for kind in kinds:
            for shape in ('none', 'one', 'three', 'iterable'):
                add('mode' + str(mode) + '_provider_' + kind + '_pair_' + shape,
                    mode, action='provider_pair', kind=kind, shape=shape)
    for mode in (3, 4):
        add('mode' + str(mode) + '_object_bytes_digest_mismatch', mode, action='object_changed_bytes')
        add('mode' + str(mode) + '_missing_output_kind', mode, action='missing_output_kind')
        add('mode' + str(mode) + '_early_shape_precedes_missing_output_kind', mode,
            action='missing_output_kind', early_shape_error=True)
        add('mode' + str(mode) + '_same_unbounded_positive_integer', mode, action='metadata_extra_same', value=1 << 1024)
        add('mode' + str(mode) + '_same_unbounded_negative_integer', mode, action='metadata_extra_same', value=-(1 << 1024))
        add('mode' + str(mode) + '_same_nan_object_still_ne', mode, action='metadata_extra_same', nan=True)
        add('mode' + str(mode) + '_metadata_items_iter_stop_outside_generator', mode,
            action='metadata_items_iterator', fault={'event': 'metadata_items.iter', 'exception': 'StopIteration'})
        add('mode' + str(mode) + '_metadata_iterator_early_stop_is_EOF', mode,
            action='metadata_items_iterator', fault={'event': 'metadata_items.iterator.next', 'occurrence': 2, 'exception': 'StopIteration'})
        for key in ('context', 'native_artifact', 'installation'):
            add('mode' + str(mode) + '_subject_missing_' + key, mode, action='edit', edits=[edit('record', [key], delete=True)])
        for key in ('target', 'backend'):
            add('mode' + str(mode) + '_profile_missing_' + key, mode, action='edit', edits=[edit('profiles', [key], delete=True)])
    for occurrence in (1, 2, 3):
        add('signatures_key_access_stop_' + str(occurrence),
            fault={'event': 'function:f.getitem', 'argument0': 'name', 'occurrence': occurrence, 'exception': 'StopIteration'})
    for occurrence in (3, 4):
        add('signatures_export_RHS_then_target_key_stop_' + str(occurrence), action='export_overrides_bad_scalar',
            fault={'event': 'function:f.getitem', 'argument0': 'name', 'occurrence': occurrence, 'exception': 'StopIteration'})
    for event in ('export_pair.iter', 'export_pair.len'):
        add('native_map_tuple_transform_stop_is_EOF_' + event.rsplit('.', 1)[-1], 2,
            action='raw_exports_iterable', fault={'event': event, 'exception': 'StopIteration'})
    add('signatures_param_iterator_stop_is_EOF', action='params_iterable',
        fault={'event': 'params.iterator.next', 'occurrence': 2, 'exception': 'StopIteration'})
    assert len({case['name'] for case in cases}) == len(cases)
    return cases
