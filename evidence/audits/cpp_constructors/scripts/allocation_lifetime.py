#!/usr/bin/env python3
"""Replay independent constructor/registry allocation and lifetime observations.

Uses actual replaceable operator new failures in fresh native processes.  The
generated bridge is not modified.  This is a finite host/library observation,
not a proof of arbitrary C++ allocation, lifetime, pointer or library safety.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


HEADER = r'''#pragma once
#include <cstdint>
#include <memory>
namespace audit {
inline std::uint64_t begun=0, completed=0, destroyed=0, members=0, member_drops=0;
inline void (*on_destroy)() noexcept = nullptr;
struct Failure {};
struct Member {
    Member() noexcept { ++members; }
    ~Member() noexcept { ++member_drops; }
};
struct Counted {
    Member member;
    std::unique_ptr<std::uint64_t> payload;
    explicit Counted(std::uint64_t value):payload(new std::uint64_t(value)) {
        ++begun;
        if(value==999) throw Failure{};
        ++completed;
    }
    ~Counted() noexcept { ++destroyed; if(on_destroy)on_destroy(); }
    std::uint64_t value()const noexcept { return *payload; }
};
struct NoThrow {
    Member member;
    std::uint64_t stored;
    explicit NoThrow(std::uint64_t value) noexcept:stored(value) { ++begun; ++completed; }
    ~NoThrow() noexcept { ++destroyed; if(on_destroy)on_destroy(); }
    std::uint64_t value()const noexcept { return stored; }
};
}
'''

HARNESS = r'''#include "bridge.h"
#include "fixture.hpp"
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>

namespace {
std::int64_t live_allocations=0;
bool observing=false;
std::int64_t fail_site=-1;
std::uint64_t attempts=0;
std::size_t sizes[128]{};
using Create = std::int32_t(*)(std::uint64_t,std::uint64_t*) noexcept;
using Destroy = std::int32_t(*)(std::uint64_t) noexcept;
using Read = std::int32_t(*)(std::uint64_t,std::uint64_t*) noexcept;
Read callback_read=nullptr;
std::uint64_t callback_handle=0, callback_expected=0, callbacks=0;
void require(bool condition,const char* message) {
    if(!condition) { std::fprintf(stderr,"%s\n",message); std::exit(1); }
}
void reenter() noexcept {
    std::uint64_t value=0;
    require(callback_read(callback_handle,&value)==0&&value==callback_expected,
            "destructor reentry must observe live peer with registry mutex released");
    ++callbacks;
}
}

void* operator new(std::size_t bytes) {
    if(observing) {
        require(attempts<128,"allocation observation capacity");
        sizes[attempts]=bytes;
        const auto site=attempts++;
        if(static_cast<std::int64_t>(site)==fail_site) {
            observing=false; // one-shot: unwinding and diagnosis may allocate
            throw std::bad_alloc();
        }
    }
    void* value=std::malloc(bytes?bytes:1);
    if(!value)throw std::bad_alloc();
    ++live_allocations;
    return value;
}
void operator delete(void* value) noexcept { if(value){--live_allocations;std::free(value);} }
void* operator new[](std::size_t bytes) { return ::operator new(bytes); }
void operator delete[](void* value) noexcept { ::operator delete(value); }
void operator delete(void* value,std::size_t) noexcept { ::operator delete(value); }
void operator delete[](void* value,std::size_t) noexcept { ::operator delete(value); }

int main(int argc,char**argv) {
    require(argc==5,"need kind prefill failure-site constructor-throws");
    const bool affine=std::strcmp(argv[1],"affine")==0;
    const bool no_throw=std::strcmp(argv[1],"nothrow")==0;
    const int prefill=std::atoi(argv[2]);
    fail_site=std::atoll(argv[3]);
    const bool foreign_throws=std::atoi(argv[4])!=0;
    require(prefill>=-1&&prefill<256,"bounded peer setup");
    require(!no_throw||!foreign_throws,"noexcept fixture must not throw");
    Create create=affine?hepta_cpp_review_Affine_new:no_throw?hepta_cpp_review_NoThrow_new:hepta_cpp_review_Serial_new;
    Destroy destroy=affine?hepta_cpp_review_Affine_destroy:no_throw?hepta_cpp_review_NoThrow_destroy:hepta_cpp_review_Serial_destroy;
    Read read=affine?hepta_cpp_review_Affine_value:no_throw?hepta_cpp_review_NoThrow_value:hepta_cpp_review_Serial_value;
    std::uint64_t peers[256]{};
    if(prefill==-1) {
        std::uint64_t h=0;
        require(create(47,&h)==0&&destroy(h)==0,"warm registry before observation");
    }
    for(int i=0;i<prefill;++i)require(create(static_cast<std::uint64_t>(i+1),&peers[i])==0,"peer creation");
    if(prefill>0) {
        callback_read=read; callback_handle=peers[0]; callback_expected=1;
        audit::on_destroy=reenter;
    }
    const auto baseline_allocations=live_allocations;
    const auto baseline_completed=audit::completed, baseline_destroyed=audit::destroyed;
    const auto baseline_members=audit::members, baseline_member_drops=audit::member_drops;
    const std::uint64_t sentinel=0x123456789abcdef0ULL;
    std::uint64_t handle=sentinel;
    observing=true;
    const auto status=create(foreign_throws?999:91,&handle);
    observing=false;
    const auto returned_handle=handle;
    const auto completed_during_call=audit::completed-baseline_completed;
    const auto destroyed_during_call=audit::destroyed-baseline_destroyed;
    const auto members_during_call=audit::members-baseline_members;
    const auto member_drops_during_call=audit::member_drops-baseline_member_drops;
    const auto allocations_after_call=live_allocations-baseline_allocations;
    const bool expect_failure=foreign_throws||fail_site>=0;
    if(expect_failure) {
        require(status==3&&handle==sentinel,"failure preserves output and returns caught-exception status");
        if(fail_site>=0)require(attempts==static_cast<std::uint64_t>(fail_site+1),"injected allocation site reached exactly");
        require(completed_during_call==destroyed_during_call,"completed failed-call object destroyed exactly once");
        require(members_during_call==member_drops_during_call,"partial object's completed subobject destroyed exactly once");
        require(completed_during_call<=1&&destroyed_during_call<=1,"no duplicate object construction/destruction");
        if(prefill!=0)require(allocations_after_call==0,"warm registry failure retains no allocation");
        require(create(91,&handle)==0,"recovery creation after caught failure");
    } else {
        require(status==0&&handle!=0&&handle!=sentinel,"successful registry publication");
        require(completed_during_call==1&&destroyed_during_call==0,"one live object published");
    }
    std::uint64_t result=0;
    require(read(handle,&result)==0&&result==91,"constructed/recovered value");
    const auto before_destroy=audit::destroyed;
    require(destroy(handle)==0,"explicit cleanup");
    require(audit::destroyed==before_destroy+1,"explicit cleanup destroys object exactly once");
    const auto duplicate_status=destroy(handle);
    require(duplicate_status==2&&audit::destroyed==before_destroy+1,"duplicate cleanup rejected without another destruction");
    audit::on_destroy=nullptr;
    for(int i=0;i<prefill;++i) {
        result=0;
        require(read(peers[i],&result)==0&&result==static_cast<std::uint64_t>(i+1),"preexisting peer unchanged by failure");
        require(destroy(peers[i])==0,"peer cleanup");
    }
    require(audit::completed==audit::destroyed&&audit::members==audit::member_drops,"all objects and subobjects reclaimed");
    std::printf("{\"kind\":\"%s\",\"prefill\":%d,\"failure_site\":%lld,\"constructor_throws\":%s,"
                "\"status\":%d,\"output_before\":%llu,\"output_after\":%llu,\"allocation_attempts\":%llu,"
                "\"completed_during_call\":%llu,\"destroyed_during_call\":%llu,\"members_during_call\":%llu,"
                "\"member_drops_during_call\":%llu,\"allocation_delta_after_call\":%lld,"
                "\"recovery_validated\":%s,\"duplicate_destroy_status\":%d,\"destructor_reentry_checks\":%llu,"
                "\"live_objects_at_end\":0,\"live_subobjects_at_end\":0,\"allocation_sizes\":[",
                argv[1],prefill,static_cast<long long>(fail_site),foreign_throws?"true":"false",status,
                static_cast<unsigned long long>(sentinel),static_cast<unsigned long long>(returned_handle),
                static_cast<unsigned long long>(attempts),static_cast<unsigned long long>(completed_during_call),
                static_cast<unsigned long long>(destroyed_during_call),static_cast<unsigned long long>(members_during_call),
                static_cast<unsigned long long>(member_drops_during_call),static_cast<long long>(allocations_after_call),
                expect_failure?"true":"false",duplicate_status,static_cast<unsigned long long>(callbacks));
    for(std::uint64_t i=0;i<attempts;++i)std::printf("%s%zu",i?",":"",sizes[i]);
    std::puts("]}");
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--rustc', required=True)
    parser.add_argument('--cxx', default='g++')
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
    before = compiler_hash()
    contract = {'schema': 'hepta.cpp-contract.v2', 'module': 'review', 'pod_types': [], 'functions': [], 'handles': []}
    for name, cpp_type, threading, exception in (
        ('Serial', 'Counted', 'serialized', 'catch_status'),
        ('Affine', 'Counted', 'creator_thread', 'catch_status'),
        ('NoThrow', 'NoThrow', 'serialized', 'noexcept'),
    ):
        contract['handles'].append({'name': name, 'cpp_type': 'audit::' + cpp_type, 'template_args': [],
            'threading': threading, 'reentrancy': 'reject', 'allocator': 'cpp_shared_owner',
            'destruction': 'nothrow_defer_inflight',
            'constructors': [{'name': 'new', 'params': [{'name': 'value', 'type': 'u64', 'mode': 'value'}], 'exception': exception}],
            'methods': [{'name': 'value', 'cpp_method': 'value', 'const': True, 'params': [], 'returns': 'u64',
                         'return_mode': 'value', 'exception': 'noexcept'}]})
    compiler = shutil.which(args.cxx)
    if not compiler:
        raise RuntimeError('C++ compiler unavailable')
    with tempfile.TemporaryDirectory(prefix='hepta-cpp-independent-alloc-') as temp:
        root = Path(temp)
        header = root / 'fixture.hpp'
        header.write_text(HEADER)
        generated = root / 'generated'
        receipt = bridge_cpp_contracts(header, contract, generated, cxx=compiler, rustc=args.rustc)
        if not receipt['ok']:
            raise RuntimeError(json.dumps(receipt))
        main_cpp = root / 'main.cpp'
        main_cpp.write_text(HARNESS)
        executable = root / 'audit'
        flags = ['-std=c++20', '-O2', '-pthread', '-Werror', '-I' + str(root), '-I' + str(generated)]
        built = run([compiler, *flags, generated / 'bridge.cpp', main_cpp, '-o', executable])

        def observe(kind, prefill, failure=-1, throws=False):
            result = run([executable, kind, prefill, failure, int(throws)])
            return json.loads(result.stdout)

        rows = []
        scopes = [('serial_cold', 'serial', 0), ('serial_warm', 'serial', -1),
                  ('affine_cold', 'affine', 0), ('affine_warm', 'affine', -1),
                  ('nothrow_cold', 'nothrow', 0)]
        search = []
        warm = observe('serial', -1)
        growth = None
        for count in range(1, 129):
            candidate = observe('serial', count)
            search.append(candidate)
            if candidate['allocation_attempts'] > warm['allocation_attempts']:
                growth = count
                break
        if growth is None:
            raise RuntimeError('No observable registry bucket growth within finite search')
        scopes.append(('serial_growth', 'serial', growth))
        for scope, kind, prefill in scopes:
            baseline = observe(kind, prefill)
            baseline['scope'] = scope
            rows.append(baseline)
            for site in range(baseline['allocation_attempts']):
                trial = observe(kind, prefill, site)
                trial['scope'] = scope
                rows.append(trial)
        for scope, prefill in [('serial_cold', 0), ('serial_warm', -1), ('serial_growth', growth)]:
            trial = observe('serial', prefill, throws=True)
            trial['scope'] = scope
            rows.append(trial)
        result = {'schema': 'hepta.cpp-constructors-independent-allocation-review.v1', 'ok': True,
            'generated_at_utc': datetime.now(timezone.utc).isoformat(), 'commit': revision,
            'compiler_sha256_before': before, 'compiler_sha256_after': compiler_hash(),
            'source_unchanged': before == compiler_hash(), 'cpp_contracts_sha256': digest(repo / 'hepta/cpp_contracts.py'),
            'cxx_version': run([compiler, '--version']).stdout.splitlines()[0],
            'rustc_version': run([args.rustc, '--version']).stdout.strip(),
            'fixture_sha256': digest(header), 'harness_sha256': digest(main_cpp),
            'executable_sha256': digest(executable), 'generated_cpp_sha256': digest(generated / 'bridge.cpp'),
            'flags': flags, 'build_stderr': built.stderr, 'contract': contract,
            'constructor_checks': receipt['constructor_checks'], 'bridge_assumptions': receipt['assumptions'],
            'growth_search': search, 'growth_prefill': growth, 'trials': rows,
            'allocation_failure_trials': sum(row['failure_site'] >= 0 for row in rows),
            'foreign_constructor_failure_trials': sum(row['constructor_throws'] for row in rows),
            'native_process_trials': len(rows) + len(search) + 1,
            'limitations': [
                'Finite observed allocation paths of this C++ compiler, standard library and authored fixture.',
                'Process-lifetime registry, retained bucket capacity and thread token allocations are intentional infrastructure, not foreign-object leaks.',
                'Warm failures additionally require live allocation count to return to baseline; cold paths report retained infrastructure honestly.',
                'The generated bridge is unmodified. Public calls plus replaceable allocation functions perform injection.',
                'No proof of foreign pointer extent, provenance, nonretention, arbitrary destructor behavior or whole-library safety.',
                'Aligned allocation overloads are not intercepted; fixtures and generated types in this observed run use ordinary allocation.',
            ]}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x') as stream:
        json.dump(result, stream, sort_keys=True, indent=2)
        stream.write('\n')
    print(json.dumps({'ok': result['ok'], 'output': str(args.output),
                      'allocation_failure_trials': result['allocation_failure_trials'],
                      'native_process_trials': result['native_process_trials']}))


if __name__ == '__main__':
    main()
