"""One frozen v86 development request with two separately owned phases.

Each new phase has 180+3. The original publication unittest step had no overall
180-second owner; its four store timeouts stay 60 and generic publish stays 30.
No fresh compiler generations, original39 suite, standard CI or cold claim.
"""
from hashlib import sha256
import argparse
import importlib.util
import json
import os
from pathlib import Path
import struct
import stat
import sys
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import (closed, controls, external_inputs, inventory, join_child,
                    owner_readback, read, require, small_pin, source_snapshot, write)


def suite_ok(value, expected):
    return (value['loaded_ids'] == value['executed_ids'] == expected
            and value['tests_run'] == len(expected) and value['pass'] is True
            and all(value[name] == [] for name in
                    ('errors','failures','skipped','expectedFailures','unexpectedSuccesses')))


def verify_phase_inputs(folder, source, config, report, config_path, config_sha):
    require(report['schema'] == 'hepta.hia.v86-native-development-phase.v1'
            and report['source_candidate'] == config['candidate']
            and report['python'] == config['python']['version']
            and report['fresh_cold'] is False and report['original_39_run'] is False
            and report['source_stable'] is True, 'actual phase scope differs')
    snapshots = []
    for label in ('before', 'after'):
        path = folder / ('source-' + label + '.json'); raw, pin = read(path, 8 << 20)
        require(report['source_' + label] == {k: pin[k] for k in ('path','bytes','sha256')},
                'actual worker source inventory pin differs')
        value = json.loads(raw)
        require(set(value) == set(config['source_pins']), 'worker source namespace differs')
        for name, row in value.items():
            expected = config['source_pins'][name]
            require(row['path'] == str(source / name)
                    and {k: row[k] for k in ('bytes','sha256')} == {k: expected[k] for k in ('bytes','sha256')}
                    and stat.S_IMODE(row['identity'][2]) == int(expected['mode'][-3:], 8),
                    'worker observed noncanonical source: ' + name)
        snapshots.append(value)
    require(snapshots[0] == snapshots[1], 'worker source identities changed')
    require(report['control_before'] == report['control_after'] == controls(config_path, config, config_sha)
            and report['external_before'] == report['external_after'] == external_inputs(config),
            'worker control or external input identity differs')
    modules = report['imported_repository_modules']
    require(type(modules) is dict and bool(modules), 'actual repository import inventory missing')
    for name, row in modules.items():
        expected = config['source_pins'].get(row['path'])
        require(expected is not None and row['path'].endswith('.py')
                and {k: row[k] for k in ('bytes','sha256')} == {k: expected[k] for k in ('bytes','sha256')},
                'actual repository import not bound: ' + name)
    return {'canonical_files': len(snapshots[0]), 'actual_repository_imports': len(modules),
            'source_identity_before_after_equal': True}


def verify_sha(folder, source, config, report):
    require(report['status'] == 'DEVELOPMENT_SHA_12_METHOD_BODIES_PASS'
            and report['original_native_classes_executed'] is False
            and report['original_fresh_setUpClass_executed'] is False
            and report['original_VM_setUpClass_prechecks_executed'] is False,
            'development fixture scope differs')
    built = json.loads(read(folder/'build/BUILD.json', 8 << 20)[0])
    require(built == report['build'] and built['new_compile_transactions'] == 2
            and built['new_pack_transactions'] == 1 and built['fresh_B0_B1_B2_executed'] is False,
            'actual build record differs')
    build = folder/'build'; compiler = build/'existing-v82-B3.image.bin'
    require(small_pin(compiler) == {k:config['inputs']['compiler'][k] for k in ('bytes','sha256')},
            'actual existing compiler bytes differ')
    images = {}
    for label, schema in [('sha256','hepta.hia.sha256-native.v1'),
                          ('sha256_stream','hepta.hia.sha256-stream-native.v1')]:
        item = built['compiled'][label]; image = build/(label+'.image.bin')
        manifest = build/(label+'.manifest.json'); raw = read(source/'examples/hia_bootstrap'/(label+'.hiaasm'))[0]
        require(item['image']==str(image) and item['manifest']==str(manifest), 'actual new image path differs')
        require(item['receipt'] == json.loads(read(build/(label+'.receipt.json'))[0])
                and item['actual_child_join'] == join_child(build,label,compiler,raw,config,image),
                'full compiler child originals differ')
        image_pin = small_pin(image); images[label] = image_pin['sha256']
        actual_manifest = json.loads(read(manifest)[0])
        require(actual_manifest == {'schema':schema,'source_sha256':sha256(raw).hexdigest(),
                    'image_path':image.name,'image_sha256':image_pin['sha256'],
                    'compiler_sha256':small_pin(compiler)['sha256']}, 'actual new manifest differs')
    for label in ('policy','packer'):
        require(small_pin(build/(label+'.retained.image.bin')) ==
                    {k:config['inputs'][label+'_image'][k] for k in ('bytes','sha256')}, 'retained image copy differs')
    packet = read(build/'publication-pack.input.bin')[0]
    policy = read(build/'policy.retained.image.bin')[0]; stream = read(build/'sha256_stream.image.bin')[0]
    require(packet == struct.pack('<3Q',config['publication_magic'],len(policy),len(stream))+policy+stream,
            'actual policy/new stream pack input differs')
    joined = join_child(build,'publication-pack',build/'packer.retained.image.bin',packet,config)
    require(joined==built['pack'] and read(build/'hia-artifact')[0] ==
                read(build/'publication-pack.output.bin')[0][:joined['returned_bytes']], 'native packed executable differs')
    require(built['app']==str(build/'hia-artifact'), 'actual executable path differs')
    for path, expected in built['retained_bundle'].items():
        require(small_pin(path)==expected, 'actual complete image bundle changed')
    mapping = config['development_method_map']; expected = list(mapping)
    suite = json.loads(read(folder/'suite.json')[0])
    require(report['original_to_development_IDs']==mapping and report['suite']==suite
            and suite_ok(suite,expected), 'complete original 7+5 bodies or anomaly populations differ')
    require(report['fixture_events'] == [
        {'class':'DevelopmentOneShotCases','operation':'explicit_existing_compiler_fixture'},
        {'class':'DevelopmentOneShotCases','operation':'retain_complete_fixture'},
        {'class':'DevelopmentStreamCases','operation':'explicit_existing_compiler_fixture'},
        {'class':'DevelopmentStreamCases','operation':'retain_complete_fixture'},
    ], 'explicit development fixture event population differs')
    matrix = json.loads(read(folder/'native-returns.json', 8 << 20)[0])
    require(matrix==report['actual_native_returns'] and {r['test'] for r in matrix}==set(expected),
            'complete actual method return coverage differs')
    keys=set(); statuses={}
    for row in matrix:
        group='sha256_stream' if '.DevelopmentStreamCases.' in row['test'] else 'sha256'
        key=(row['test'],row['image_sha256'],row['flat_C_ABI_argument_count'],row['status'])
        require(set(row)=={'test','original_method','image_sha256','flat_C_ABI_argument_count','status','count'}
                and key not in keys and row['original_method']==mapping[row['test']]
                and row['image_sha256']==images[group]
                and type(row['flat_C_ABI_argument_count']) is int and row['flat_C_ABI_argument_count']==6
                and type(row['status']) is int and row['status'] in (0,32,0xfffffffd)
                and type(row['count']) is int and row['count']>0, 'actual native return row differs')
        keys.add(key);statuses.setdefault(group,set()).add(row['status'])
    require(statuses['sha256']=={32,0xfffffffd} and statuses['sha256_stream']=={0,32,0xfffffffd},
            'actual valid and refusal returns were not observed')
    return {'original_method_bodies':12,'original_native_classes_executed':False,
            'new_compile_count':2,'new_pack_count':1,'actual_native_return_count':sum(r['count'] for r in matrix),
            'image_sha256':images,'app':small_pin(build/'hia-artifact')}


def verify_publication(folder, prior, config, report):
    require(report['status']=='DEVELOPMENT_QUOTA_AND_GENERIC_MEASUREMENT_PASS'
            and report['original_39_run'] is False and report['original_fresh_setUpClass_executed'] is False,
            'quota measurement scope differs')
    previous_raw, previous_pin = read(prior/'REPORT.json',8<<20)
    require(report['prior_sha_report']==previous_pin, 'actual prior SHA report identity differs')
    previous=json.loads(previous_raw);app=prior/'build/hia-artifact'; app_pin=small_pin(app)
    require(report['app']==app_pin and previous['build']['retained_bundle'][str(app)]==app_pin,
            'actual measured executable differs')
    suite=json.loads(read(folder/'suite.json')[0])
    require(report['suite']==suite and suite_ok(suite,config['publication_method_ids']), 'two fixed measurement IDs differ')
    calls=json.loads(read(folder/'application-calls.json',8<<20)[0])
    require(calls==report['calls'] and len(calls)==5, 'all five original runtime calls are required')
    operations=['store-put','store-get','store-hash','store-put','publish']; sizes=[64<<20,0,(64<<20)+1,(64<<20)+1,(64<<20)+1]
    codes=[0,0,17,17,0]; seconds=[60,60,60,60,30]
    store=folder/'fixtures/store-case-1/artifacts'
    stage=folder/'fixtures/case-1/stage'; destination=folder/'fixtures/case-1/destination'
    accepted_digest=sha256(b'x'*(64<<20)).hexdigest()
    commands=[[str(app),'store-put',str(store),'-'],
              [str(app),'store-get',str(store),accepted_digest],
              [str(app),'store-hash',str(store),'-'],
              [str(app),'store-put',str(store),'-'],
              [str(app),'publish',str(stage),str(destination)]]
    actual=[]
    for i,row in enumerate(calls):
        d=folder/('call-%02d'%i);request=json.loads(read(d/'REQUEST.json')[0]);result=json.loads(read(d/'RESULT.json')[0])
        require(result==row and all(request[k]==row[k] for k in request if k!='status') and request['status']=='HOLD',
                'actual call request/result binding differs')
        wire,wire_pin=read(d/'stdin.original.bin');out,out_pin=read(d/'stdout.original.bin');err,err_pin=read(d/'stderr.original.bin')
        require(row['ordinal']==i and row['status']=='RETURNED' and row['returncode']==codes[i]
                and row['command']==commands[i]
                and row['test']==config['publication_method_ids'][0 if i<4 else 1]
                and row['environment']=={'PATH':''} and row['timeout_seconds']==seconds[i]
                and row['offered_input']=={k:wire_pin[k] for k in ('bytes','sha256')}
                and row['stdout']=={k:out_pin[k] for k in ('bytes','sha256')}
                and row['stderr']=={k:err_pin[k] for k in ('bytes','sha256')}
                and wire==b'x'*sizes[i] and err==b'' and row['app_before']==row['app_after']==app_pin
                and type(row['run_elapsed_ns']) is int and row['run_elapsed_ns']>=0,
                'actual command, original bound, bytes or immutable executable differs')
        if i in (0,4):require(json.loads(out)=={'sha256':sha256(wire).hexdigest(),'bytes':len(wire)},'actual publication receipt differs')
        if i==1:require(out==b'x'*(64<<20),'entire original 64 MiB store-get result differs')
        actual.append({'operation':operations[i],'timeout_seconds':seconds[i],'run_elapsed_ns':row['run_elapsed_ns'],
                       'stdin':{k:wire_pin[k] for k in ('bytes','sha256')},'stdout':{k:out_pin[k] for k in ('bytes','sha256')},'returncode':codes[i]})
    require(list(store.iterdir())==[], 'original quota method did not leave the store empty')
    stage_raw,stage_pin=read(stage,independent=False);dest_raw,dest_pin=read(destination,independent=False)
    require(stage_raw==dest_raw==b'x'*((64<<20)+1)
            and stage_pin['identity'][:2]==dest_pin['identity'][:2]
            and stage_pin['identity'][3]==dest_pin['identity'][3]==2,
            'actual generic publication full bytes or hardlink identity differ')
    return {'original_quota_method_bodies':1,'new_generic_measurements':1,'original_39_run':False,'actual_calls':actual}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('config','source','output'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--config-sha256',required=True)
    args=parser.parse_args(); config=json.loads(args.config.read_bytes());source=args.source.resolve();root=args.output.resolve()
    require(config['limits']=={'phase_seconds':180,'cleanup_seconds':3,'compile_wall_seconds':20,'compile_CPU_seconds':10,
                              'compile_capacity':1<<20,'store_call_seconds':60,'generic_call_seconds':30},'frozen bounds differ')
    require(str(root)==config['output_path'] and str(source)==config['source_path'],'fixed request paths differ')
    require(not root.exists(),'single create-only output root already exists');root.mkdir(mode=0o700)
    report={'schema':'hepta.hia.v86-native-development-final.v1','status':'HOLD','candidate':config['candidate'],
            'fresh_B0_B1_B2':False,'fresh_cold':False,'original_39_run':False,'phases':{},
            'original_SHA_class_fixture_run':False,'original_publication_had_no_overall_180_owner':True,
            'new_diagnostic_owners':[{'name':name,'seconds':180,'cleanup':3} for name in ('sha','publication')]}
    all_closed=True
    try:
        report['control_before']=controls(args.config,config,args.config_sha256)
        report['external_before']=external_inputs(config)
        before=source_snapshot(source,config);report['source_before']=write(root/'source-before.json',before)
        spec=importlib.util.spec_from_file_location('_v86_original_process_owner',source/'tools/hia_selfhost_process_owner.py')
        owner=importlib.util.module_from_spec(spec);spec.loader.exec_module(owner)
        env={'PATH':config['environment_PATH'],'LANG':'C.UTF-8','LC_ALL':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1'}
        for phase in ('sha','publication'):
            directory=root/phase;directory.mkdir(mode=0o700)
            command=[sys.executable,'-I','-B',str(args.config.parent/'worker.py'),'--phase',phase,
                     '--config',str(args.config.resolve()),'--config-sha256',args.config_sha256,
                     '--source',str(source),'--output',str(directory/'worker'),'--prior',str(root/'sha/worker')]
            value=report['phases'][phase]={'command':command,'environment':env,'status':'HOLD'}
            # An exception from run_owned must not be interpreted as proof
            # that it did not start an owned process.
            all_closed=False
            value['returned']=owner.run_owned(command,cwd=source,env=env,stdout_path=directory/'stdout.log',
                stderr_path=directory/'stderr.log',receipt_path=directory/'owner.json',qualification_seconds=180,cleanup_seconds=3)
            all_closed=closed(value['returned']);value['closed_before_read']=all_closed
            require(all_closed,'original owner cannot prove this phase closed')
            value['owner']=owner_readback(directory,value['returned'],command,env,source,config)
            value['originals']=write(directory/'closed-originals.json',inventory(directory))
            raw,pin=read(directory/'worker/REPORT.json',16<<20);actual=json.loads(raw)
            value['report_original']=pin;value['actual_report']=actual
            require(value['owner']['natural'] and actual['source_stable'] is True,'phase failed, timed out or source changed')
            value['input_verification']=verify_phase_inputs(directory/'worker',source,config,actual,
                                                           args.config,args.config_sha256)
            value['verification']=(verify_sha(directory/'worker',source,config,actual) if phase=='sha'
                else verify_publication(directory/'worker',root/'sha/worker',config,actual))
            value['status']='DEVELOPMENT_PHASE_PASS'
        report['status']='DEVELOPMENT_SHA12_AND_QUOTA_MEASUREMENTS_PASS'
    except BaseException:
        report['status']='HOLD';report['failure']=traceback.format_exc()
    finally:
        report['all_started_phases_confirmed_closed']=all_closed
        if all_closed:
            try:
                after=source_snapshot(source,config);report['source_after']=write(root/'source-after.json',after)
                require(after==before,'full frozen source identities changed')
                report['control_after']=controls(args.config,config,args.config_sha256);report['external_after']=external_inputs(config)
                require(report['control_after']==report['control_before'] and report['external_after']==report['external_before'],
                        'controller, source or sealed external inputs changed')
                report['source_stable']=True
                report['complete_closed_originals']=write(root/'closed-originals.json',inventory(root))
            except BaseException:
                report['status']='HOLD';report['final_read_error']=traceback.format_exc()
        write(root/'FINAL.json',report)
    print(json.dumps({'status':report['status'],'final':str(root/'FINAL.json'),'fresh_cold':False,'original_39_run':False}))
    return 0 if report['status']=='DEVELOPMENT_SHA12_AND_QUOTA_MEASUREMENTS_PASS' else 1


if __name__=='__main__':
    raise SystemExit(main())
