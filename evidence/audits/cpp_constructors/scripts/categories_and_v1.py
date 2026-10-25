#!/usr/bin/env python3
"""Independently replay constructor categories and legacy v1 ABI observations."""
from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


HEADER = r'''#pragma once
#include <cstdint>
#include <span>
namespace audit {
struct Config { std::uint64_t value; };
struct ScalarR {
    explicit ScalarR(std::uint64_t&& v) noexcept:stored(v+100){}
    ScalarR(const std::uint64_t&)=delete;
    std::uint64_t stored; std::uint64_t value()const noexcept{return stored;}
};
struct ScalarL {
    explicit ScalarL(const std::uint64_t& v) noexcept:stored(v+200){}
    ScalarL(std::uint64_t&&)=delete;
    std::uint64_t stored; std::uint64_t value()const noexcept{return stored;}
};
struct PodR {
    explicit PodR(Config&& v) noexcept:stored(v.value+300){}
    PodR(const Config&)=delete;
    std::uint64_t stored; std::uint64_t value()const noexcept{return stored;}
};
struct PodL {
    explicit PodL(const Config& v) noexcept:stored(v.value+400){}
    PodL(Config&&)=delete;
    std::uint64_t stored; std::uint64_t value()const noexcept{return stored;}
};
struct SpanR {
    explicit SpanR(std::span<const std::int64_t>&& v) noexcept:stored(static_cast<std::uint64_t>(v[0])+500){}
    SpanR(const std::span<const std::int64_t>&)=delete;
    std::uint64_t stored; std::uint64_t value()const noexcept{return stored;}
};
struct MutableSpanR {
    explicit MutableSpanR(std::span<std::int64_t>&& v) noexcept {v[0]+=600;stored=static_cast<std::uint64_t>(v[0]);}
    MutableSpanR(const std::span<std::int64_t>&)=delete;
    std::uint64_t stored; std::uint64_t value()const noexcept{return stored;}
};
struct Choice {
    explicit Choice(std::uint64_t&& v) noexcept(false):stored(v+700){}
    explicit Choice(const std::uint64_t& v) noexcept:stored(v+800){}
    std::uint64_t stored; std::uint64_t value()const noexcept{return stored;}
};
struct SpanChoice {
    explicit SpanChoice(std::span<const std::int64_t>&& v) noexcept(false):stored(static_cast<std::uint64_t>(v[0])){}
    explicit SpanChoice(const std::span<const std::int64_t>& v) noexcept:stored(static_cast<std::uint64_t>(v[0])){}
    std::uint64_t stored; std::uint64_t value()const noexcept{return stored;}
};
}
'''

MAIN = r'''#include "bridge.h"
#include <cstdint>
#include <cstdio>
#include <cstdlib>
static void require(bool value){if(!value)std::abort();}
int main(){
    std::uint64_t h=0,out=0;
    require(hepta_cpp_categories_ScalarR_new(9,&h)==0);
    require(hepta_cpp_categories_ScalarR_value(h,&out)==0&&out==109);
    require(hepta_cpp_categories_ScalarR_destroy(h)==0);
    require(hepta_cpp_categories_ScalarL_new(9,&h)==0);
    require(hepta_cpp_categories_ScalarL_value(h,&out)==0&&out==209);
    require(hepta_cpp_categories_ScalarL_destroy(h)==0);
    hepta_cpp_categories_Config config{9};
    require(hepta_cpp_categories_PodR_new(config,&h)==0);
    require(hepta_cpp_categories_PodR_value(h,&out)==0&&out==309);
    require(hepta_cpp_categories_PodR_destroy(h)==0);
    require(hepta_cpp_categories_PodL_new(config,&h)==0);
    require(hepta_cpp_categories_PodL_value(h,&out)==0&&out==409);
    require(hepta_cpp_categories_PodL_destroy(h)==0);
    std::int64_t input=9;
    require(hepta_cpp_categories_SpanR_new(&input,1,&h)==0);
    require(hepta_cpp_categories_SpanR_value(h,&out)==0&&out==509);
    require(hepta_cpp_categories_SpanR_destroy(h)==0);
    require(hepta_cpp_categories_MutableSpanR_new(&input,1,&h)==0);
    require(input==609);
    require(hepta_cpp_categories_MutableSpanR_value(h,&out)==0&&out==609);
    require(hepta_cpp_categories_MutableSpanR_destroy(h)==0);
    require(hepta_cpp_categories_ChoiceR_new(9,&h)==0);
    require(hepta_cpp_categories_ChoiceR_value(h,&out)==0&&out==709);
    require(hepta_cpp_categories_ChoiceR_destroy(h)==0);
    require(hepta_cpp_categories_ChoiceL_new(9,&h)==0);
    require(hepta_cpp_categories_ChoiceL_value(h,&out)==0&&out==809);
    require(hepta_cpp_categories_ChoiceL_destroy(h)==0);
    std::puts("{\"scalar_rvalue\":109,\"scalar_const_ref\":209,\"pod_rvalue\":309,\"pod_const_ref\":409,"
              "\"const_span_rvalue\":509,\"mutable_span_rvalue\":609,\"choice_throwing_rvalue\":709,\"choice_nothrow_const_ref\":809}");
}
'''

C_CLIENT = r'''#include "bridge.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
static void require(int good){if(!good)abort();}
int main(void){
    uint64_t input=19;
    require(hepta_cpp_stdlib_mix(input)==((input^UINT64_C(0x9e3779b97f4a7c15))*UINT64_C(0xbf58476d1ce4e5b9)));
    require(hepta_cpp_stdlib_twice(42)==84);
    hepta_cpp_stdlib_Pair pair={1,-8};
    pair=hepta_cpp_stdlib_swap_pair(pair);
    require(pair.first==-8&&pair.second==1);
    int64_t values[3]={2,-3,11},sum=0;
    require(hepta_cpp_stdlib_sum(values,3,&sum)==0&&sum==10);
    require(hepta_cpp_stdlib_add(values,3,7)==0&&values[0]==9&&values[1]==4&&values[2]==18);
    uint8_t bytes[3]={'a',0,'b'};size_t length=0;
    require(hepta_cpp_stdlib_text_size(bytes,3,&length)==0&&length==3);
    uint64_t h=0;
    require(hepta_cpp_stdlib_IntVector_new(&h)==0);
    require(hepta_cpp_stdlib_IntVector_push(h,-7)==0);
    require(hepta_cpp_stdlib_IntVector_push(h,100)==0);
    require(hepta_cpp_stdlib_IntVector_size(h,&length)==0&&length==2);
    int64_t value=0;
    require(hepta_cpp_stdlib_IntVector_at(h,0,&value)==0&&value==-7);
    value=777;
    require(hepta_cpp_stdlib_IntVector_at(h,2,&value)==3&&value==777);
    require(hepta_cpp_stdlib_IntVector_destroy(h)==0);
    require(hepta_cpp_stdlib_IntVector_destroy(h)==2);
    require(hepta_cpp_stdlib_IntVector_new(NULL)==1);
    puts("{\"scalar\":true,\"pod\":true,\"span\":true,\"embedded_nul_string\":true,"
         "\"legacy_default_vector_constructor\":true,\"exception_output_preserved\":true,\"duplicate_destroy_rejected\":true}");
}
'''


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(argv, **kwargs):
    result = subprocess.run([str(arg) for arg in argv], capture_output=True, text=True, timeout=90, **kwargs)
    if result.returncode:
        raise RuntimeError(json.dumps({'argv': [str(a) for a in argv], 'returncode': result.returncode,
                                       'stdout': result.stdout, 'stderr': result.stderr}))
    return result


def parameter(typ, mode):
    result = {'name': 'input', 'type': typ, 'mode': mode}
    if mode != 'value':
        result['retention'] = 'call_only'
    return result


def handle(name, typ, param, exception='noexcept'):
    return {'name': name, 'cpp_type': 'audit::' + typ, 'template_args': [], 'threading': 'serialized',
            'reentrancy': 'reject', 'allocator': 'cpp_shared_owner', 'destruction': 'nothrow_defer_inflight',
            'constructors': [{'name': 'new', 'params': [param], 'exception': exception}],
            'methods': [{'name': 'value', 'cpp_method': 'value', 'const': True, 'params': [], 'returns': 'u64',
                         'return_mode': 'value', 'exception': 'noexcept'}]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--rustc', required=True)
    parser.add_argument('--baseline', default='e8a3b4cb6f1b2f31df73a3fdd68fc9878d809697')
    parser.add_argument('--cxx', default='g++')
    parser.add_argument('--cc', default='gcc')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('Refusing to overwrite an earlier observation')
    repo = args.repo.resolve()
    sys.path.insert(0, str(repo))
    os.environ['RUSTC'] = args.rustc
    from hepta.cpp_contracts import bridge_cpp_contracts
    from hepta.pipeline import compiler_hash
    revision = run(['git', 'rev-parse', 'HEAD'], cwd=repo).stdout.strip()
    baseline_revision = run(['git', 'rev-parse', args.baseline], cwd=repo).stdout.strip()
    before = compiler_hash()
    cxx = shutil.which(args.cxx)
    cc = shutil.which(args.cc)
    if not cxx or not cc:
        raise RuntimeError('Native C and C++ compilers required')
    with tempfile.TemporaryDirectory(prefix='hepta-cpp-independent-categories-') as temp:
        root = Path(temp)
        header = root / 'fixture.hpp'
        header.write_text(HEADER)
        contract = {'schema': 'hepta.cpp-contract.v2', 'module': 'categories', 'functions': [],
                    'pod_types': [{'name': 'Config', 'cpp_type': 'audit::Config', 'fields': [{'name': 'value', 'type': 'u64'}]}],
                    'handles': [
                        handle('ScalarR', 'ScalarR', parameter('u64', 'value')),
                        handle('ScalarL', 'ScalarL', parameter('u64', 'const_ref')),
                        handle('PodR', 'PodR', parameter('Config', 'value')),
                        handle('PodL', 'PodL', parameter('Config', 'const_ref')),
                        handle('SpanR', 'SpanR', parameter('i64', 'borrow_const')),
                        handle('MutableSpanR', 'MutableSpanR', parameter('i64', 'borrow_mut')),
                        handle('ChoiceR', 'Choice', parameter('u64', 'value'), 'catch_status'),
                        handle('ChoiceL', 'Choice', parameter('u64', 'const_ref')),
                    ]}
        destination = root / 'categories'
        receipt = bridge_cpp_contracts(header, contract, destination, cxx=cxx, rustc=args.rustc)
        if not receipt['ok']:
            raise RuntimeError(json.dumps(receipt))
        source = root / 'main.cpp'
        source.write_text(MAIN)
        exe = root / 'categories-native'
        flags = ['-std=c++20', '-O2', '-pthread', '-Werror']
        run([cxx, *flags, '-I' + str(destination), destination / 'bridge.cpp', source, '-o', exe])
        category_values = json.loads(run([exe]).stdout)
        negatives = []
        for identifier, candidate in [
            ('scalar_deleted_const_ref', handle('Wrong', 'ScalarR', parameter('u64', 'const_ref'))),
            ('scalar_deleted_rvalue', handle('Wrong', 'ScalarL', parameter('u64', 'value'))),
            ('pod_deleted_const_ref', handle('Wrong', 'PodR', parameter('Config', 'const_ref'))),
            ('pod_deleted_rvalue', handle('Wrong', 'PodL', parameter('Config', 'value'))),
            ('span_wrong_element_type', handle('Wrong', 'SpanR', parameter('i32', 'borrow_const'))),
            ('scalar_wrong_overload_noexcept', handle('Wrong', 'Choice', parameter('u64', 'value'))),
            ('span_wrong_overload_noexcept', handle('Wrong', 'SpanChoice', parameter('i64', 'borrow_const'))),
        ]:
            changed = copy.deepcopy(contract)
            changed['handles'] = [candidate]
            target = root / identifier
            result = bridge_cpp_contracts(header, changed, target, cxx=cxx, rustc=args.rustc)
            codes = [diagnostic['code'] for diagnostic in result.get('diagnostics', [])]
            rejected = not result['ok'] and not target.exists() and codes == ['E_CPP_NATIVE']
            negatives.append({'id': identifier, 'rejected': rejected, 'output_directory_created': target.exists(),
                              'diagnostics': result.get('diagnostics', [])})
            if not rejected:
                raise RuntimeError(json.dumps(negatives[-1]))

        old_source = run(['git', 'show', baseline_revision + ':hepta/cpp_contracts.py'], cwd=repo).stdout
        old_path = root / 'legacy_cpp_contracts.py'
        old_path.write_text(old_source)
        spec = importlib.util.spec_from_file_location('hepta._cpp_legacy_independent_review', old_path)
        old_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(old_module)
        legacy = repo / 'examples/cpp/stdlib'
        legacy_contract = json.loads((legacy / 'contract.json').read_text())
        legacy_rows = []
        for label, generator in [('before', old_module.bridge_cpp_contracts), ('after', bridge_cpp_contracts)]:
            target = root / ('v1-' + label)
            result = generator(legacy / 'foreign.hpp', legacy_contract, target, cxx=cxx, rustc=args.rustc)
            if not result['ok']:
                raise RuntimeError(json.dumps(result))
            client = root / ('client-' + label + '.c')
            client.write_text(C_CLIENT)
            client_object = root / ('client-' + label + '.o')
            run([cc, '-std=c11', '-O2', '-Werror', '-I' + str(target), '-c', client, '-o', client_object])
            client_exe = root / ('client-' + label)
            run([cxx, *flags, target / 'bridge.cpp', legacy / 'foreign.cpp', client_object, '-o', client_exe])
            legacy_rows.append({'version': label, 'c_header_sha256': digest(target / 'bridge.h'),
                                'hepta_externs_sha256': digest(target / 'bridge.hepta'),
                                'native_c_client_sha256': digest(client), 'executable_sha256': digest(client_exe),
                                'execution': json.loads(run([client_exe]).stdout)})
        same_header = legacy_rows[0]['c_header_sha256'] == legacy_rows[1]['c_header_sha256']
        same_externs = legacy_rows[0]['hepta_externs_sha256'] == legacy_rows[1]['hepta_externs_sha256']
        if not same_header or not same_externs:
            raise RuntimeError('Legacy public declarations changed')
        other_compiler_changes = [path for path in run(['git', 'diff', '--name-only', baseline_revision, revision, '--', 'hepta'], cwd=repo).stdout.splitlines()
                                  if path != 'hepta/cpp_contracts.py']
        result = {'schema': 'hepta.cpp-constructors-independent-category-abi-review.v1', 'ok': True,
            'generated_at_utc': datetime.now(timezone.utc).isoformat(), 'commit': revision,
            'baseline_cpp_generator_commit': baseline_revision, 'baseline_cpp_generator_sha256': digest(old_path),
            'other_compiler_paths_changed_since_baseline': other_compiler_changes,
            'compiler_sha256_before': before, 'compiler_sha256_after': compiler_hash(),
            'source_unchanged': before == compiler_hash(), 'cpp_contracts_sha256': digest(repo / 'hepta/cpp_contracts.py'),
            'cxx_version': run([cxx, '--version']).stdout.splitlines()[0],
            'cc_version': run([cc, '--version']).stdout.splitlines()[0],
            'rustc_version': run([args.rustc, '--version']).stdout.strip(),
            'fixture_sha256': digest(header), 'harness_sha256': digest(source),
            'category_contract': contract, 'constructor_checks': receipt['constructor_checks'],
            'category_values': category_values, 'negative_controls': negatives,
            'legacy_v1': {'c_header_identical': same_header, 'hepta_externs_identical': same_externs, 'native_clients': legacy_rows},
            'limitations': [
                'Constructor traits verify constructibility and noexcept of the emitted argument categories; implicit conversions remain allowed.',
                'Exact constructor parameter signatures are not proved. C++ constructors have no function pointer signature comparison here.',
                'Legacy comparison loads only the preceding cpp_contracts.py; the report lists any changed supporting compiler files.',
                'Pure C clients exercise this installed compiler/stdlib host ABI, not every C/C++ ABI or shared-library deployment.',
                'A JSON call_only promise does not prove nonretention, pointer extent, alias validity or foreign thread safety.',
            ]}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x') as stream:
        json.dump(result, stream, sort_keys=True, indent=2)
        stream.write('\n')
    print(json.dumps({'ok': result['ok'], 'output': str(args.output),
                      'native_category_cases': len(category_values), 'negative_controls': len(negatives),
                      'legacy_c_header_identical': same_header, 'legacy_hepta_externs_identical': same_externs}))


if __name__ == '__main__':
    main()
