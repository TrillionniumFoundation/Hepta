#!/usr/bin/env python3
"""Qualify each private task's native feasibility before any learner sees it.

The private teacher is used only by this coordinator control. It is never an
Agent candidate or a starting incumbent in the comparative campaign.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import resource
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.hia_agent_contract import installation_manifest
from hepta.hia_agent_runner import run_native_batch
from hepta.hia_program import verify_program
from hepta.hia_program_native import emit_program_machine, compile_program_machine
from tools.prepare_hia_followup_tasks import mathematical_value
from tools.qualify_hia_macro_campaign import _json, _read_regular, _new_file, _native_result_correct
from hepta.hia_agent_store import wire


def qualify(registration_path, output):
    registration_path = Path(registration_path).absolute()
    output = Path(output).absolute()
    output.mkdir(mode=0o700, exist_ok=False)
    started = time.monotonic_ns()
    before = [resource.getrusage(k) for k in (resource.RUSAGE_SELF,resource.RUSAGE_CHILDREN)]
    installation = installation_manifest()
    raw_registration = _read_regular(registration_path)
    registration = _json(raw_registration)
    if registration.get('schema') != 'hepta.hia.agent.followup-preregistration.v2':
        raise ValueError('unregistered task input')
    rows, files = [], []

    def retain(name, value, *, raw=False):
        content = value if raw else wire(value) + b'\n'
        _new_file(output / name, content)
        row = {'path':name,'sha256':sha256(content).hexdigest(),'bytes':len(content)}
        files.append(row)
        return row

    for item in registration['tasks']:
        task_directory = output / item['id']
        task_directory.mkdir(mode=0o700)
        documents = {}
        for scope in ('public','hidden'):
            raw = _read_regular(registration_path.parent / item[scope]['path'])
            if len(raw) != item[scope]['bytes'] or sha256(raw).hexdigest() != item[scope]['sha256']:
                raise ValueError('registered task changed')
            documents[scope] = _json(raw)
        public, hidden = documents['public'],documents['hidden']
        expected = [mathematical_value(x,hidden['parameters']) for x in range(256)]
        if expected != hidden['oracle'] or hidden['cases'] != [
                {'function':'transform','arguments':[x],'expected':{'status':'returned','values':[y]}}
                for x,y in enumerate(expected)]:
            raise ValueError('independent mathematical oracle differs')
        observed = {}
        for label,document in (('baseline',public['baseline']),('private_feasibility',hidden['feasibility_core'])):
            program = verify_program(document)
            expected_sha = public['baseline_sha256'] if label == 'baseline' else hidden['feasibility_core_sha256']
            if program.sha256 != expected_sha:
                raise ValueError('Core identity changed')
            image = emit_program_machine(program)
            retain(item['id'] + '/' + label + '.o',image.object_bytes,raw=True)
            path = task_directory / (label + '.so')
            commands = []
            build = compile_program_machine(image,program=program,output=path,kind='shared',
                linker='ld',command_log=commands,parent_death_guard=True,timeout_seconds=10)
            binary = _read_regular(path)
            files.append({'path':str(path.relative_to(output)), 'sha256':sha256(binary).hexdigest(),'bytes':len(binary)})
            observation = run_native_batch(binary,{'transform':{'params':['u8'],'returns':['u8']}},
                hidden['cases'],timeout_ms=10000,memory_bytes=536870912)
            correct = _native_result_correct(observation,{'workload':{'cases':hidden['cases']}},sha256(binary).hexdigest())
            record = {'label':label,'build':build,'commands':commands,'native':observation,
                'all_256_correct':correct,'artifact_bytes':len(binary),'core_sha256':program.sha256,
                'artifact_sha256':sha256(binary).hexdigest(),'model_calls':0}
            retain(item['id'] + '/' + label + '.json',record)
            observed[label] = record
        strictly_smaller = observed['private_feasibility']['artifact_bytes'] < observed['baseline']['artifact_bytes']
        passed = strictly_smaller and all(row['all_256_correct'] for row in observed.values())
        rows.append({'task_id':item['id'],'purpose':item['purpose'],'passed':passed,
            'baseline_bytes':observed['baseline']['artifact_bytes'],
            'private_feasibility_bytes':observed['private_feasibility']['artifact_bytes'],
            'strictly_smaller':strictly_smaller,'native_cases':512,
            'public_sha256':item['public']['sha256'],'hidden_sha256':item['hidden']['sha256'],
            'oracle_sha256':sha256(wire(hidden['oracle'])).hexdigest(),
            'namespace':item['namespace']})
        print(json.dumps(rows[-1]),flush=True)
    after = [resource.getrusage(k) for k in (resource.RUSAGE_SELF,resource.RUSAGE_CHILDREN)]
    result = {'schema':'hepta.hia.agent.private-native-feasibility.v2',
        'passed':all(row['passed'] for row in rows) and installation_manifest() == installation,
        'registration_sha256':sha256(raw_registration).hexdigest(),'installation':installation,
        'qualifier_sha256':sha256(Path(__file__).read_bytes()).hexdigest(),
        'generator_sha256':sha256((ROOT/'tools/prepare_hia_followup_tasks.py').read_bytes()).hexdigest(),
        'tasks':rows,'native_executions':len(rows)*2,'native_cases':len(rows)*512,
        'model_calls':0,'formal_mcp_calls':0,'learner_success':False,
        'linkage_profile':'GNU ld, matching HIAAgentService._compile; canonical codegen with no machine plan',
        'private_teacher_is_learner_input':False,'p1_acceptance':'HOLD',
        'economic_benefit_established':False,'wall_ns':time.monotonic_ns()-started,
        'cpu_ns':{name:round((b.ru_utime+b.ru_stime-a.ru_utime-a.ru_stime)*1e9)
            for name,a,b in zip(('parent','children'),before,after)},
        'nested_wall_not_added_again':True,'files':files,
        'scope':'native feasibility of separately generated synthetic tasks on these exact source/host bytes; no model or formal endpoint acceptance'}
    retain('QUALIFICATION.json',result)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--registration',required=True)
    parser.add_argument('--output',required=True)
    arguments = parser.parse_args()
    result = qualify(arguments.registration,arguments.output)
    raise SystemExit(0 if result['passed'] else 2)
