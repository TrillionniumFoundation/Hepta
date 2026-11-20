"""Original-first escaped-generator and dynamic callback controls."""
from __future__ import annotations
import argparse
import contextvars
from hashlib import sha256
import json
from pathlib import Path
import sys
import threading
import traceback
ROOT=Path(__file__).resolve().parents[1]
if __package__ in (None,''):sys.path.insert(0,str(ROOT))
from tests import hia_service_verification_oracle as oracle

CASES=tuple({'id':action+'.outer'+str(outer),'action':action,'outer':bool(outer)}
    for action in ('drain','close-before-start','throw-before-start','send-close',
                   'thread-resume','copied-context-resume') for outer in (0,1))

def write(path,value):
    raw=oracle.canonical(value)+b'\n'
    with Path(path).open('xb') as stream:stream.write(raw)
    return sha256(raw).hexdigest()

def exercise(spec,factory=oracle.original_factory):
    base=json.loads((oracle.ORIGINALS/'cases.json').read_bytes())['base_cases']
    case=dict(next(x for x in base if x['id']=='behavior.finite.outer0'))
    case['outer']=spec['outer'];world=oracle.World(case,factory)
    captured=[];steps=[];errors=[]
    def collector(name,answer):
        def consume(generator):
            captured.append((name,generator,contextvars.copy_context()))
            return answer
        return consume
    world.namespace.update(sum=collector('sum',0),any=collector('any',False),all=collector('all',True))
    def call():
        values={'factory':factory,'world':world,'arguments':world.arguments()}
        return values.pop('factory')(values.pop('world'),'behavior',values.pop('arguments'))
    def outcome(callback):
        try:return {'status':'returned','value':oracle.role(callback())}
        except BaseException as error:
            errors.append({'type':type(error).__module__+'.'+type(error).__qualname__,
                           'traceback':traceback.format_exception(type(error),error,error.__traceback__)})
            return {'status':'raised','error':oracle.error_fields(error,world)}
    def run():
        result=outcome(call)
        for number,(name,generator,copied) in enumerate(captured):
            assert type(generator).__name__=='generator'
            operations=[]
            action=spec['action']
            if action=='close-before-start':
                operations.append(outcome(generator.close))
            elif action=='throw-before-start':
                error=KeyboardInterrupt('declared generator throw');world.fault=error
                operations.append(outcome(lambda:generator.throw(error)))
                world.fault=None
            else:
                first=outcome(lambda:next(generator));operations.append(first)
                if action=='drain':
                    for unused in range(64):
                        item=outcome(lambda:generator.send(None));operations.append(item)
                        if item['status']=='raised':break
                    else:raise AssertionError('bounded original generator did not stop')
                elif action=='send-close':
                    operations.append(outcome(lambda:generator.send(7)))
                    operations.append(outcome(generator.close))
                elif action=='thread-resume':
                    observed=[]
                    thread=threading.Thread(target=lambda:observed.append(outcome(lambda:generator.send(None))))
                    thread.start();thread.join(5)
                    assert not thread.is_alive() and len(observed)==1
                    operations.extend(observed);operations.append(outcome(generator.close))
                else:
                    operations.append(copied.run(lambda:outcome(lambda:generator.send(None))))
                    operations.append(outcome(generator.close))
            steps.append({'index':number,'provider':name,'operations':operations,
                          'closed':generator.gi_frame is None,'running':generator.gi_running})
        return result
    if spec['outer']:
        try:raise KeyError('declared outer')
        except KeyError as outer:
            world.outer=outer
            result=run()
    else:result=run()
    # The same consumer drops retained generator references in both lanes.
    captured.clear()
    row={'id':spec['id'],'result':result,'steps':steps,'events':world.events,
         'alive_at_seal':world.alive()}
    return json.loads(oracle.canonical(row)),errors

def run(manifest,output):
    output=Path(output);output.mkdir(mode=0o700)
    source_paths=[Path(__file__),Path(oracle.__file__),oracle.ORIGINALS/'cases.json']
    source_paths += [oracle.ORIGINALS/name for name in oracle.PINNED]
    before={str(path):path.read_bytes() for path in source_paths}
    write(output/'inputs.json',list(CASES))
    original=[];original_raw=[]
    for spec in CASES:
        row,raw=exercise(spec);original.append(row);original_raw.append({'id':spec['id'],'tracebacks':raw})
    expected_pin=write(output/'original-observations.json',original)
    write(output/'original-tracebacks.json',original_raw)
    # Actual complete original results exist before the optional owner import.
    from tests.hia_service_verification_observer import PublicFactory,differences
    from hepta import hia_native_delivery as delivery
    factory=PublicFactory('native',manifest);actual=[];actual_raw=[]
    try:
        for spec in CASES:
            try:row,raw=exercise(spec,factory)
            finally:factory.restore_case()
            actual.append(row);actual_raw.append({'id':spec['id'],'tracebacks':raw})
        entries=factory.image._entry.calls
        assert entries>0 and factory.retained_calls==0
        assert not delivery.custody_snapshot()
    finally:factory.close()
    actual_pin=write(output/'candidate-observations.json',actual)
    write(output/'candidate-tracebacks.json',actual_raw)
    diffs=differences(original,actual);write(output/'differences.json',diffs)
    assert all(path.read_bytes()==raw for path,raw in ((Path(name),raw) for name,raw in before.items()))
    assert sha256((output/'original-observations.json').read_bytes()).hexdigest()==expected_pin
    report={'schema':'hepta.service-verification.lazy-controls.v1','status':'PASS' if not diffs else 'HOLD',
        'count':len(CASES),'ordered_ids':[x['id'] for x in CASES],'original_sha256':expected_pin,
        'candidate_sha256':actual_pin,'actual_entries':entries,'retained_calls':0,
        'source_pins':{name:sha256(raw).hexdigest() for name,raw in before.items()},
        'differences':len(diffs),'whole_native':False}
    write(output/'report.json',report)
    if diffs:raise AssertionError('escaped generator or callback differs from actual original')
    return report

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--manifest',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args();run(a.manifest,a.output)
