"""Typed constructor compatibility, real library use, and foreign boundaries."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from hepta.cpp_contracts import bridge_cpp_contracts
from tools.validate_cpp import EXAMPLE as V1_EXAMPLE
from tools.validate_cpp_constructors import (EXAMPLE, NEGATIVE_CONTROLS, _negative_controls,
                                             qualify_cpp_constructors, validate_constructor_qualification)

NATIVE = shutil.which('g++') and shutil.which(os.environ.get('RUSTC', 'rustc'))


def parameter(name, typ, mode='value'):
    value = {'name': name, 'type': typ, 'mode': mode}
    if mode != 'value': value['retention'] = 'call_only'
    return value


def probe_contract(typ, params, *, exception='catch_status', returns='u64'):
    return {'schema': 'hepta.cpp-contract.v2', 'module': 'probe', 'pod_types': [], 'functions': [],
            'handles': [{'name': 'Object', 'cpp_type': 'probe::' + typ, 'template_args': [],
                         'threading': 'serialized', 'reentrancy': 'reject', 'allocator': 'cpp_shared_owner',
                         'destruction': 'nothrow_defer_inflight',
                         'constructors': [{'name': 'new', 'params': params, 'exception': exception}],
                         'methods': [{'name': 'value', 'cpp_method': 'value', 'const': True, 'params': [],
                                      'returns': returns, 'return_mode': 'value', 'exception': 'noexcept'}]}]}


@unittest.skipUnless(NATIVE, 'C++ constructor tests require g++ and pinned rustc; Boost headers are a required dependency')
class CppConstructorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='hepta-constructor-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def probe(self, header, contract, main=None, name='generated'):
        source = self.root / (name + '.hpp')
        source.write_text('#pragma once\n#include <cstdint>\n#include <span>\n#include <stdexcept>\n' + header)
        destination = self.root / name
        report = bridge_cpp_contracts(source, contract, destination, cxx='g++')
        if main is not None:
            self.assertTrue(report['ok'], report)
            caller = self.root / (name + '.cpp')
            caller.write_text('#include "bridge.h"\n#include <cstdlib>\n' + main)
            exe = self.root / (name + '-native')
            built = subprocess.run(['g++', '-std=c++20', '-O2', '-pthread', '-Werror', '-I' + str(destination),
                                    str(destination / 'bridge.cpp'), str(caller), '-o', str(exe)],
                                   capture_output=True, text=True, timeout=90)
            self.assertEqual(built.returncode, 0, built.stderr)
            ran = subprocess.run([str(exe)], capture_output=True, text=True, timeout=15)
            self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)
        return report

    def test_real_nondefault_boost_and_vector_constructor_roundtrips_and_allocation_refusal(self):
        report = qualify_cpp_constructors(self.root, benchmark=False, negative_controls=False)
        self.assertTrue(report['ok'], report)
        self.assertTrue(report['native_link_qualified'])
        execution = report['execution']
        self.assertTrue(execution['boost_nondefault_constructible'])
        self.assertEqual(execution['boost_success_cases'], 5)
        self.assertEqual(execution['boost_domain_failure_cases'], 3)
        self.assertEqual(execution['vector_constructor_cases'], 8)
        self.assertGreaterEqual(execution['allocation_failure_sites'], 4)
        self.assertEqual(execution['allocation_recovery_calls'], execution['allocation_failure_sites'])
        self.assertEqual(execution['warm_registry_live_allocation_delta'], 0)
        self.assertEqual(execution['live_fixture_objects'], 0)
        self.assertTrue(execution['span_copy_observed'])
        self.assertTrue(execution['output_preserved_on_failure'])
        self.assertTrue(report['headers']['unchanged'])
        self.assertTrue(any(name.endswith('/boost/math/distributions/students_t.hpp') for name in report['headers']['before']))
        self.assertFalse(report['exact_constructor_parameter_signature_proved'])
        self.assertFalse(report['borrow_retention_proved'])
        self.assertTrue(validate_constructor_qualification(report, require_benchmark=False, require_controls=False))
        with self.assertRaisesRegex(ValueError, 'rejection controls'):
            validate_constructor_qualification(report, require_benchmark=False)
        with self.assertRaisesRegex(ValueError, 'timing rows'):
            validate_constructor_qualification(report, require_controls=False)
        mutations = {
            'incomplete_allocations': lambda r: r['execution'].update(allocation_failure_sites=3, allocation_recovery_calls=3),
            'missing_recovery': lambda r: r['execution'].update(allocation_recovery_calls=0),
            'live_allocation': lambda r: r['execution'].update(warm_registry_live_allocation_delta=1),
            'native_failed': lambda r: r['execution_process'].update(returncode=11),
            'wrong_boost': lambda r: r['boost'].update(version=1),
            'headers_changed': lambda r: r['headers'].update(after={}),
            'source_changed': lambda r: r.update(inputs={}),
            'output_modified': lambda r: r['execution'].update(output_preserved_on_failure=False),
            'fake_signature_proof': lambda r: r['bridge_generation']['constructor_checks'][0].update(exact_constructor_parameter_signature_proved=True),
            'malformed_execution': lambda r: r.update(execution=None),
            'boolean_exit_status': lambda r: r['execution_process'].update(returncode=False),
            'float_exit_status': lambda r: r['execution_process'].update(returncode=0.0),
            'missing_stdout_identity': lambda r: r['execution_process'].pop('stdout_sha256'),
            'invalid_stderr_identity': lambda r: r['execution_process'].update(stderr_sha256='not-a-hash'),
            'bridge_not_run': lambda r: r['bridge_generation'].update(status='not_run'),
            'bridge_empty_object': lambda r: r['bridge_generation'].update(object_bytes=0),
            'bridge_boolean_object_size': lambda r: r['bridge_generation'].update(object_bytes=True),
            'bridge_missing_object_identity': lambda r: r['bridge_generation'].pop('object_sha256'),
            'bridge_object_mismatch': lambda r: r['bridge_generation'].update(object_sha256='0' * 64),
            'missing_linked_object': lambda r: r['object_sha256'].pop('foreign.o'),
            'invalid_linked_object_identity': lambda r: r['object_sha256'].update({'harness.o': None}),
            'bridge_hepta_source_mismatch': lambda r: r['bridge_generation']['hepta_validation'].update(source_sha256='0' * 64),
            'consumer_source_mismatch': lambda r: r['hepta_consumer'].update(source_sha256='0' * 64),
            'native_not_run': lambda r: r['hepta_native_library'].update(status='not_run'),
            'native_check_only_missing': lambda r: r['hepta_native_library'].pop('check_only'),
            'native_check_only_true': lambda r: r['hepta_native_library'].update(check_only=True),
            'native_wrong_crate_type': lambda r: r['hepta_native_library'].update(crate_type='rlib'),
            'native_wrong_rustc_crate_type': lambda r: r['hepta_native_library'].update(rustc_crate_type='lib'),
            'native_missing_artifact': lambda r: r['hepta_native_library'].pop('artifact'),
            'native_empty_artifact': lambda r: r['hepta_native_library'].update(artifact_bytes=0),
            'native_boolean_artifact_size': lambda r: r['hepta_native_library'].update(artifact_bytes=True),
            'native_missing_artifact_identity': lambda r: r['hepta_native_library'].pop('artifact_sha256'),
            'native_validation_identity_mismatch': lambda r: r['hepta_native_library'].update(validation_artifact_sha256='0' * 64),
            'native_rust_source_mismatch': lambda r: r['hepta_native_library'].update(rust_sha256='0' * 64),
        }

        def change_field(path, key, value):
            def mutate(record):
                for component in path:
                    record = record[component]
                record[key] = value
            return mutate

        for name, path in (('bridge', ('bridge_generation', 'hepta_validation')), ('consumer', ('hepta_consumer',))):
            for label, key, value in (('not_run', 'status', 'not_run'),
                                      ('compiler_mismatch', 'compiler_sha256', '0' * 64),
                                      ('missing_checks', 'checks', {}),
                                      ('missing_external_obligations', 'assumptions', []),
                                      ('missing_rust_source', 'rust_sha256', None)):
                mutations[name + '_frontend_' + label] = change_field(path, key, value)
            for label, key, value in (('not_run', 'status', 'not_run'),
                                      ('missing_check_only', 'check_only', None),
                                      ('not_check_only', 'check_only', False),
                                      ('missing_artifact_identity', 'validation_artifact_sha256', None),
                                      ('rust_source_mismatch', 'rust_sha256', '0' * 64)):
                mutations[name + '_backend_' + label] = change_field((*path, 'backend'), key, value)
            mutations[name + '_foreign_obligation_labeled_proved'] = change_field((*path, 'assumptions', 0), 'status', 'proved')
        for name, mutate in mutations.items():
            with self.subTest(evidence_mutation=name):
                changed = copy.deepcopy(report)
                mutate(changed)
                with self.assertRaises(ValueError):
                    validate_constructor_qualification(changed, require_benchmark=False, require_controls=False)

        # Native compilation/execution is the real in-process result above;
        # only this deliberately malformed timing payload is fabricated.
        # An oversized JSON integer must be rejected as evidence, not escape
        # the public validator as an uncaught arithmetic exception.
        overflow = copy.deepcopy(report)
        overflow['performance'] = {
            'status': 'measured', 'scope': 'lifecycle_pairs_and_separate_steady_state_methods',
            'measurements': [{'case': name, 'iterations': 1, 'checksum': 0,
                              'samples_ns': [10 ** 400] * 7, 'median_ns_per_operation': 1}
                             for name in ('native_vector_create_destroy', 'handle_vector_create_destroy',
                                          'native_student_create_destroy', 'handle_student_create_destroy',
                                          'native_vector_size', 'handle_vector_size',
                                          'native_student_degrees', 'handle_student_degrees')],
        }
        with self.assertRaisesRegex(ValueError, 'malformed nested qualification record'):
            validate_constructor_qualification(overflow, require_controls=False)

    def test_v1_keeps_implicit_default_constructor_and_original_c_abi(self):
        report = bridge_cpp_contracts(V1_EXAMPLE / 'foreign.hpp', V1_EXAMPLE / 'contract.json', self.root / 'v1', cxx='g++')
        self.assertTrue(report['ok'], report)
        self.assertEqual(report['contract_schema'], 'hepta.cpp-contract.v1')
        header = (self.root / 'v1/bridge.h').read_text()
        self.assertIn('hepta_cpp_stdlib_IntVector_new(uint64_t* out)', header)
        self.assertEqual(report['constructor_checks'][0]['argument_types'], [])
        v1 = json.loads((V1_EXAMPLE / 'contract.json').read_text())
        v1['handles'][0]['constructors'] = [{'name': 'new', 'params': [], 'exception': 'catch_status'}]
        rejected = bridge_cpp_contracts(V1_EXAMPLE / 'foreign.hpp', v1, self.root / 'v1-unknown', cxx='g++')
        self.assertFalse(rejected['ok'])
        self.assertEqual(rejected['diagnostics'][0]['code'], 'E_CPP_CONTRACT')

    def test_schema_and_native_constructor_negative_controls_do_not_publish(self):
        controls = _negative_controls(self.root, 'g++', os.environ.get('RUSTC'))
        self.assertEqual([r['id'] for r in controls], list(NEGATIVE_CONTROLS))
        self.assertTrue(all(r['rejected'] for r in controls), controls)
        self.assertTrue(all(not r['output_directory_created'] for r in controls))

    def test_constructor_categories_match_make_shared_forwarding(self):
        header = '''namespace probe { struct Category {
            Category()=delete;
            explicit Category(std::uint64_t&& input) noexcept : stored(input+1) {}
            Category(const std::uint64_t&)=delete;
            std::uint64_t value()const noexcept{return stored;}
            std::uint64_t stored;
        }; }'''
        contract = probe_contract('Category', [parameter('input', 'u64')], exception='noexcept')
        report = self.probe(header, contract, '''int main(){
            uint64_t h=0,out=0;
            if(hepta_cpp_probe_Object_new(7,&h)||hepta_cpp_probe_Object_value(h,&out)||out!=8)return 1;
            return hepta_cpp_probe_Object_destroy(h);
        }''')
        self.assertTrue(report['constructor_checks'][0]['nothrow_object_construction_checked'])
        changed = copy.deepcopy(contract)
        changed['handles'][0]['constructors'][0]['params'] = [parameter('input', 'u64', 'const_ref')]
        rejected = self.probe(header, changed, name='const-ref')
        self.assertFalse(rejected['ok'])
        self.assertEqual(rejected['diagnostics'][0]['code'], 'E_CPP_NATIVE')

    def test_implicit_conversion_is_not_mislabeled_exact_constructor_signature(self):
        report = self.probe('''namespace probe { struct Converting {
            Converting()=delete; explicit Converting(double input) noexcept:stored(input){}
            std::uint64_t value()const noexcept{return static_cast<std::uint64_t>(stored);}
            double stored;
        }; }''', probe_contract('Converting', [parameter('input', 'u64')], exception='noexcept'), '''int main(){
            uint64_t h=0,out=0;
            if(hepta_cpp_probe_Object_new(42,&h)||hepta_cpp_probe_Object_value(h,&out)||out!=42)return 1;
            return hepta_cpp_probe_Object_destroy(h);
        }''')
        self.assertFalse(report['constructor_checks'][0]['exact_constructor_parameter_signature_proved'])
        self.assertEqual(report['constructor_checks'][0]['construction_check'], 'native_constructibility_with_declared_argument_categories')

    def test_private_constructor_and_ambiguous_overloads_are_native_rejections(self):
        fixtures = {
            'Private': 'class Private { Private(std::uint64_t){} public: std::uint64_t value()const noexcept{return 1;} };',
            'Ambiguous': 'struct Ambiguous { Ambiguous(double){} Ambiguous(float){} std::uint64_t value()const noexcept{return 1;} };',
        }
        for typ, source in fixtures.items():
            with self.subTest(typ=typ):
                report = self.probe('namespace probe {' + source + '}', probe_contract(typ, [parameter('input', 'u64')]), name=typ)
                self.assertFalse(report['ok'])
                self.assertEqual(report['diagnostics'][0]['code'], 'E_CPP_NATIVE')
                self.assertFalse((self.root / typ).exists())

    def test_external_retention_obligation_cannot_be_proved_by_json_contract(self):
        # The deliberately bad foreign constructor retains a span despite the
        # descriptor. The backing array stays live: observe retention without
        # invoking undefined behavior or claiming that the wrapper detected it.
        report = self.probe('''namespace probe { struct Retained {
            explicit Retained(std::span<const std::int64_t> values):stored(values){}
            std::int64_t value()const noexcept{return stored.empty()?0:stored[0];}
            std::span<const std::int64_t> stored;
        }; }''', probe_contract('Retained', [parameter('values', 'i64', 'borrow_const')], returns='i64'), '''int main(){
            int64_t values[1]={7},out=0;uint64_t h=0;
            if(hepta_cpp_probe_Object_new(values,1,&h))return 1;
            values[0]=91;
            if(hepta_cpp_probe_Object_value(h,&out)||out!=91)return 2;
            return hepta_cpp_probe_Object_destroy(h);
        }''')
        self.assertFalse(report['borrow_retention_proved'])
        self.assertFalse(report['constructor_checks'][0]['borrow_retention_proved'])
        self.assertTrue(any('call_only' in assumption for assumption in report['assumptions']))

    def test_constructor_exception_preserves_handle_but_does_not_roll_back_borrowed_writes(self):
        self.probe('''namespace probe { struct Mutating {
            explicit Mutating(std::span<std::int64_t> values) {
                if(!values.empty())values[0]=91;
                throw std::runtime_error("constructor failure after write");
            }
            std::uint64_t value()const noexcept{return 1;}
        }; }''', probe_contract('Mutating', [parameter('values', 'i64', 'borrow_mut')]), '''int main(){
            int64_t values[1]={7};uint64_t h=888;
            auto status=hepta_cpp_probe_Object_new(values,1,&h);
            return status==3&&h==888&&values[0]==91?0:1;
        }''')


if __name__ == '__main__':
    unittest.main()
