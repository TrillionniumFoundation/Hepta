"""One explicit Source10 group on the exact generated inspect source view.

This is not the complete R1 executor. No preparation copy, generation command,
compiler image invocation, old3/CLI43, Native17, VM12 or cold group is launched.
The frozen Source methods may recompute their generated representation in
memory as part of their existing original assertions.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import stat
import sys
import time
import traceback

HERE = Path(__file__).absolute().parent
GEN = Path('/workspace/scratch/dda74a4fae35/v119-inspect-generation-only-r1')
KIT = Path('/workspace/scratch/dda74a4fae35/v119-inspect-policy-execution-r1')
SOURCE = GEN / 'attempt-r1/source'
BASE = Path('/workspace/scratch/dda74a4fae35/v120-union-r20/source')
SCHEMA = 'hepta.hia.inspect-source10-only.v1'
SECONDS, CLEANUP = 180, 3
MIB = 1048576
_ATTEMPT = None


def require(value, message):
    if not value:
        raise AssertionError(message)


def pin(raw):
    return {'bytes': len(raw), 'mode': '100644', 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def bootstrap(plan_path, plan_sha256):
    raw = Path(plan_path).read_bytes()
    require(hashlib.sha256(raw).hexdigest() == plan_sha256, 'reviewed Source10 plan differs')
    plan = json.loads(raw)
    require(plan['schema'] == SCHEMA + '.plan' and plan['status'] == 'AUTHORED_NOT_EXECUTED'
            and plan['source']['path'] == str(SOURCE)
            and plan['source']['tree'] == '7df49dd24bbba4ba3210168e639d6ea35a76a475'
            and plan['source']['files'] == 3187
            and plan['limits'] == {'qualification_seconds': SECONDS, 'cleanup_seconds': CLEANUP}
            and pin(Path(__file__).read_bytes()) == plan['runner'], 'fixed Source10 runner/contract differs')
    require(pin((HERE / 'SOURCE10-CONTRACT.md').read_bytes()) == plan['contract'],
            'reviewed Source10 contract bytes differ')
    generation_runner = GEN / 'run_generation_only.py'
    require(pin(generation_runner.read_bytes()) == plan['generation_runner'], 'frozen generation guard differs')
    sys.path.insert(0, str(GEN))
    import run_generation_only as guard
    require(Path(guard.__file__).absolute() == generation_runner, 'wrong generation guard import')
    guard.load_plan(GEN / 'GENERATION-ONLY-PLAN.json', plan['generation_plan_sha256'])
    support = guard.helpers()
    captures = {}
    for name, row in plan['inputs'].items():
        value, actual = guard.read_exact(Path(row['path']), maximum=max(row['pin']['bytes'], MIB),
                                        expected=row['pin'])
        require(actual['mode'] == row['posix_mode'], 'captured artifact POSIX mode differs')
        captures[name] = json.loads(value)
    require(captures['generation_result']['status'] == 'GENERATION_ONLY_PASS'
            and captures['generation_result']['owner_launch_attempts'] == 3
            and captures['generation_result']['generation_invocations'] == 2
            and captures['generation_result']['check_invocations'] == 1
            and captures['installation']['source_tree'] == plan['source']['tree']
            and captures['source_final']['files'] == captures['source_map']
            and support.tree_digest(captures['source_map']) == plan['source']['tree'],
            'actual generated source provenance differs')
    original = json.loads((KIT / 'EXECUTION-SPEC.json').read_bytes())
    require(plan['ids'] == original['groups']['source10'] and len(plan['ids']) == 10,
            'exact frozen Source10 methods required')
    return plan, guard, support, captures


def full_guard(output, label, plan, guard, support, captures):
    base_map = json.loads((KIT / 'inputs/R20-SOURCE-MANIFEST.json').read_bytes())
    current_base = guard.capture(BASE, base_map)
    current_source = guard.capture(SOURCE, captures['source_map'])
    record = {'label': label, 'base': guard.cas(output, current_base),
              'source': guard.cas(output, current_source)}
    guard.publish(output / ('GUARD-' + label + '.json'), record)
    guard.assert_capture(current_base, base_map, stable=captures['base_final']['stat'])
    guard.assert_capture(current_source, captures['source_map'], stable=captures['source_final']['stat'])
    support.compiler_bytes()  # Identity check only; no compiler invocation.
    return record


def protected_source_fence(protected_inodes):
    """Cooperative filesystem write protection, not a hostile-code sandbox.

    Temporary Source fixtures and evidence writes remain possible. Any write
    to a frozen source path, its currently held inode alias, or prior evidence
    is refused. The complete before/after byte and stat guards remain required.
    """
    roots = (BASE, SOURCE, KIT, GEN)
    exact = (Path(__file__).absolute(), HERE / 'SOURCE10-PLAN.json',
             HERE / 'SOURCE10-PLAN-R2.json', HERE / 'SOURCE10-CONTRACT.md')

    def check(path, directory_fd=None):
        if type(path) is int:
            current = os.fstat(path)
            require((current.st_dev, current.st_ino) not in protected_inodes,
                    'write to shared/frozen source descriptor refused')
            return
        require(type(path) in (str, bytes), 'exact filesystem argument required')
        named = Path(os.fsdecode(path))
        if named.is_absolute() or directory_fd in (None, -1, -100):
            value = Path(os.path.abspath(named))
        else:
            # rmtree's descriptor-relative removal must be resolved against
            # the actual held directory, never against the source cwd.
            require(type(directory_fd) is int, 'exact directory descriptor required')
            held = os.fstat(directory_fd)
            require(stat.S_ISDIR(held.st_mode), 'directory descriptor is not a directory')
            directory = os.readlink('/proc/self/fd/' + str(directory_fd))
            require(directory.startswith('/') and not directory.endswith(' (deleted)'),
                    'held directory pathname is unavailable')
            bound = Path(directory)
            named_directory = bound.stat()
            require((named_directory.st_dev, named_directory.st_ino) == (held.st_dev, held.st_ino),
                    'held directory and named directory differ')
            value = Path(os.path.abspath(bound / named))
        resolved = value.resolve(strict=False)
        require(value not in exact and resolved not in exact
                and not any(value.is_relative_to(root) or resolved.is_relative_to(root) for root in roots),
                'write or mutation of a frozen source/evidence path refused')
        try:
            current = value.stat()
        except FileNotFoundError:
            return
        require((current.st_dev, current.st_ino) not in protected_inodes,
                'write through an alias of a frozen source inode refused')

    def audit(event, arguments):
        if event == 'open':
            path, mode, flags = arguments
            if (type(flags) is int and flags & (os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND)) or (
                    type(mode) is str and any(c in mode for c in 'wax+')):
                check(path)
        elif event in ('os.remove','os.rmdir'):
            check(arguments[0],arguments[1])
        elif event in ('os.mkdir','os.chmod'):
            check(arguments[0],arguments[2])
        elif event in ('os.chown','os.utime'):
            check(arguments[0],arguments[3])
        elif event == 'os.truncate':
            check(arguments[0])
        elif event in ('os.rename','os.link'):
            check(arguments[0],arguments[2]); check(arguments[1],arguments[3])
        elif event == 'os.symlink':
            check(arguments[1],arguments[2])
        elif event == 'subprocess.Popen' or event in ('os.system','os.exec','os.posix_spawn','os.fork','os.forkpty'):
            raise AssertionError('Source10 child cannot start another product process')
    sys.addaudithook(audit)


def pure_parameter(value):
    # The fixed two Source subTest loops contain only exact built-in values.
    # Do not add repr/equality/attribute calls on arbitrary provider objects.
    if value is None or type(value) in (bool,int,str):
        return value
    if type(value) in (list,tuple):
        return [pure_parameter(item) for item in value]
    require(type(value) is dict and all(type(key) is str for key in value),
            'unexpected foreign subtest parameter protocol')
    return {key:pure_parameter(item) for key,item in dict.items(value)}


def run_source_methods(plan, output, support):
    import unittest
    original_result = unittest.TextTestResult
    rows = []
    class SubtestJournal(original_result):
        def addSubTest(self, test, subtest, error):
            parameters = {key:pure_parameter(value) for key,value in subtest.params.items()}
            rows.append({'ordinal':len(rows)+1, 'method_id':test.id(), 'parameters':parameters,
                         'success':error is None,
                         'exception_type':None if error is None else error[0].__module__+'.'+error[0].__qualname__})
            return super().addSubTest(test, subtest, error)
    # The unchanged R1 exact runner defines its Result subclass at invocation.
    # This adds only successful/failed subtest observations; its count/ID/event
    # and all error/skip/failure admissions are retained in the original code.
    unittest.TextTestResult = SubtestJournal
    try:
        result = support.run_exact_tests(plan['ids'], output / 'TESTS.json')
        require([row['method_id'] for row in rows] == plan['subtest_method_projection']
                and all(row['success'] for row in rows), 'complete successful subtest projection differs')
        return result
    finally:
        unittest.TextTestResult = original_result
        support.publish(output / 'SUBTESTS.json', {'schema':SCHEMA+'.subtests',
            'actual_subtests':rows,'declared_method_projection':plan['subtest_method_projection'],
            'no_foreign_repr_added':True,'ordinary_TextTestResult_restored':True})


def child(request_path, request_sha256):
    raw = Path(request_path).read_bytes()
    require(hashlib.sha256(raw).hexdigest() == request_sha256, 'Source10 child request differs')
    request = json.loads(raw)
    plan, guard, support, captures = bootstrap(request['plan'], request['plan_sha256'])
    require(request['schema'] == SCHEMA+'.request' and request['ids'] == plan['ids'],
            'only the frozen Source10 child request is admitted')
    output = Path(request['output']).absolute()
    require(output == Path(request_path).parent / 'child' and not output.exists(),
            'fresh Source10 child evidence directory required')
    output.mkdir(mode=0o700)
    (output/'maps').mkdir(mode=0o700)
    result = {'schema':SCHEMA+'.child','status':'FAIL','request_pin':pin(raw),
              'scope':'SOURCE10_ONLY','matching_current_cold':False,
              'Native_compilation':0,'VM_group_execution':0,'old3_or_CLI43_executed':False}
    sys.path.insert(0,str(SOURCE))
    from tools.hia_linux_file_roundtrip_cold import guard_runtime_context
    try:
        guard_runtime_context(request['runtime_context'])
        full_guard(output,'before',plan,guard,support,captures)
        protected = {(row['device'],row['inode']) for key in ('base_final','source_final')
                     for row in captures[key]['stat'].values()}
        protected_source_fence(protected)
        result['tests'] = run_source_methods(plan,output,support)
        guard_runtime_context(request['runtime_context'])
        result['status'] = 'PASS'
    except BaseException:
        result['traceback'] = traceback.format_exc()
    finally:
        try:
            full_guard(output,'after',plan,guard,support,captures)
            result['all_original_and_generated_source_bytes_modes_stats_unchanged'] = True
        except BaseException:
            result['source_guard_error'] = traceback.format_exc(); result['status']='FAIL'
        support.publish(output/'RESULT.json',result)
    return 0 if result['status']=='PASS' else 1


def execute(plan_path, plan_sha256, attempt):
    global _ATTEMPT
    plan,guard,support,captures = bootstrap(plan_path,plan_sha256)
    attempt=Path(attempt).absolute()
    require(attempt.parent == HERE and not attempt.exists(), 'new exact Source10 attempt required')
    require(guard.storage(HERE)['available_bytes'] >= 64*MIB, 'Source10 needs64MiB free for complete evidence')
    attempt.mkdir(mode=0o700); _ATTEMPT=attempt
    (attempt/'maps').mkdir(mode=0o700); (attempt/'tmp').mkdir(mode=0o700)
    support.publish(attempt/'PLAN-USED.json',plan)
    report={'schema':SCHEMA+'.result','status':'FAIL','plan_pin':pin(Path(plan_path).read_bytes()),
            'started_ns':time.monotonic_ns(),'owner_launch_attempts':0,
            'scope':'SOURCE10_ONLY','matching_current_cold':False,'Native_compilation':0,
            'VM_group_execution':0,'old3_or_CLI43_executed':False,'whole_cli_native':False}
    returned=None
    try:
        full_guard(attempt,'before',plan,guard,support,captures)
        sys.path.insert(0,str(SOURCE))
        from tools.hia_selfhost_process_owner import run_owned
        from tools.hia_linux_file_roundtrip_cold import (
            capture_runtime_context,guard_runtime_context,runtime_child_environment)
        runtime=capture_runtime_context()
        require(runtime==captures['generation_runtime'], 'actual fixed3.14 runtime changed since generation')
        support.publish(attempt/'RUNTIME.json',runtime)
        environment=runtime_child_environment({'PATH':'/usr/local/bin:/usr/bin:/bin',
            'HOME':str(attempt),'LANG':'C.UTF-8','LC_ALL':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1',
            'TMPDIR':str(attempt/'tmp')},runtime)
        request={'schema':SCHEMA+'.request','plan':str(Path(plan_path).absolute()),
                 'plan_sha256':plan_sha256,'ids':plan['ids'],'runtime_context':runtime,
                 'output':str(attempt/'child')}
        request_path=attempt/'REQUEST.json';support.publish(request_path,request)
        command=[sys.executable,'-I','-B',str(Path(__file__).absolute()),'--child',str(request_path),
                 '--request-sha256',pin(support.encoded(request))['sha256']]
        support.publish(attempt/'COMMAND.json',{'argv':command,'cwd':str(SOURCE),'environment':environment,
            'supervisor_environment':environment,'qualification_seconds':SECONDS,'cleanup_seconds':CLEANUP})
        report['owner_launch_attempts']=1
        returned=run_owned(command,cwd=SOURCE,env=environment,supervisor_env=environment,
            stdout_path=attempt/'stdout.raw',stderr_path=attempt/'stderr.raw',receipt_path=attempt/'OWNER.json',
            qualification_seconds=SECONDS,cleanup_seconds=CLEANUP)
        support.publish(attempt/'OWNER-RETURNED.json',returned)
        support.complete_receipt(returned,attempt/'OWNER.json')
        child_raw=(attempt/'child/RESULT.json').read_bytes(); actual=json.loads(child_raw)
        require(actual['status']=='PASS' and actual['request_pin']==pin(support.encoded(request))
                and actual['all_original_and_generated_source_bytes_modes_stats_unchanged'] is True,
                'actual Source10 child failed or changed its source')
        tests=json.loads((attempt/'child/TESTS.json').read_bytes())
        require(tests==actual['tests'] and tests['status']=='PASS'
                and tests['declared_ids']==tests['loaded_ids']==tests['started_ids']==tests['stopped_ids']==plan['ids']
                and type(tests['tests_run']) is int and tests['tests_run']==10
                and tests['events']==[event for name in plan['ids'] for event in (['start',name],['stop',name])]
                and not any(tests[key] for key in ('loader_errors','failures','errors','skipped','expected_failures','unexpected_successes')),
                'complete original exact test observation differs')
        subtests=json.loads((attempt/'child/SUBTESTS.json').read_bytes())
        require([row['method_id'] for row in subtests['actual_subtests']]==plan['subtest_method_projection']
                and all(row['success'] for row in subtests['actual_subtests']), 'actual subtest projection differs')
        guard_runtime_context(runtime)
        bootstrap(plan_path,plan_sha256)
        report.update(status='SOURCE10_ONLY_PASS',tests=tests,subtests=subtests,
                      source_tree=plan['source']['tree'],source_files=3187)
    except BaseException:
        report['traceback']=traceback.format_exc();report['halted_after_first_failed_group']=True
    finally:
        try:
            full_guard(attempt,'after',plan,guard,support,captures)
            report['complete_source_guard_pass']=True
        except BaseException:
            report['source_guard_error']=traceback.format_exc();report['status']='FAIL'
        report['owner_returned']=returned;report['finished_ns']=time.monotonic_ns()
        support.publish(attempt/'RESULT.json',report)
    return 0 if report['status']=='SOURCE10_ONLY_PASS' else 1


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute-source10-only',action='store_true')
    parser.add_argument('--plan',type=Path);parser.add_argument('--plan-sha256')
    parser.add_argument('--attempt',type=Path);parser.add_argument('--child',type=Path)
    parser.add_argument('--request-sha256')
    args=parser.parse_args(argv)
    if args.child is not None:
        require(not args.execute_source10_only and args.plan is None and args.plan_sha256 is None
                and args.attempt is None and args.request_sha256,'mixed Source10 child/parent invocation')
        return child(args.child,args.request_sha256)
    require(args.execute_source10_only and args.plan is not None and args.plan_sha256
            and args.attempt is not None and args.request_sha256 is None,'explicit reviewed Source10-only invocation required')
    try:
        return execute(args.plan,args.plan_sha256,args.attempt)
    except BaseException:
        error=traceback.format_exc();sys.stderr.write(error)
        if _ATTEMPT is not None and not (_ATTEMPT/'RESULT.json').exists():
            with (_ATTEMPT/'ENTRY-FAILURE.json').open('x') as stream:
                json.dump({'status':'FAIL','traceback':error,'matching_current_cold':False},stream)
        return 1


if __name__=='__main__':
    raise SystemExit(main())
