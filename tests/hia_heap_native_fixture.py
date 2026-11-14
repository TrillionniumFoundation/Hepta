"""Explicit native equivalents of retained heap implementation fault fixtures.

Unselected tests keep their original Python injections. Selected tests use the
consumed HIA invocation continuation and the unchanged real work limits; the
independent reference runs in a child with all native selectors absent.
"""
from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
OBSERVATIONS=[]
_REFERENCE_CACHE={}
_REFERENCE_CODE=r"""
import json,os,sys
sys.path.insert(0,sys.argv[1])
assert not any(name.startswith('HEPTA_') for name in os.environ)
from hepta import hia_heap_bound as heap
from hepta.hia_heap_bound_native import selected_heap_bound
from hepta.hia_static_budget_native import selected_static_budget
assert selected_heap_bound() is None and selected_static_budget() is None
request=json.load(sys.stdin)
try:
    value=getattr(heap,request['api'])(request['source'],'entry',[],
                                      max_live_heap_bytes=0)
except Exception as error:
    cause=error.__cause__
    value={'type':type(error).__name__,'code':getattr(error,'code',None),
           'message':str(error),'cause':None if cause is None else {
               'type':type(cause).__name__,'code':getattr(cause,'code',None),'message':str(cause)}}
    result={'error':value}
else:
    result={'returned':value}
print(json.dumps(result,sort_keys=True,separators=(',',':')))
"""


def native_heap_selected():
    return bool(os.environ.get('HEPTA_HIA_HEAP_BOUND_MANIFEST'))


def _wire(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),
                      ensure_ascii=False,allow_nan=False).encode('utf-8')


def _observation(action):
    try:return {'returned':action()}
    except Exception as error:
        cause=error.__cause__
        return {'error':{'type':type(error).__name__,'code':getattr(error,'code',None),
                         'message':str(error),'cause':None if cause is None else {
                             'type':type(cause).__name__,'code':getattr(cause,'code',None),'message':str(cause)}}}


def _reference(api,source):
    raw=_wire({'api':api,'source':source})
    key=sha256(raw).hexdigest()
    if key not in _REFERENCE_CACHE:
        env={key:value for key,value in os.environ.items() if not key.startswith('HEPTA_')}
        result=subprocess.run([sys.executable,'-I','-B','-c',_REFERENCE_CODE,str(ROOT)],
                              cwd=ROOT,env=env,input=raw,stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE,timeout=60)
        assert result.returncode==0 and not result.stderr,(result.returncode,result.stdout,result.stderr)
        report=json.loads(result.stdout)
        _REFERENCE_CACHE[key]=report
        OBSERVATIONS.append({'kind':'unselected_reference','api':api,'request_sha256':key,
                             'stdout':result.stdout.decode('utf-8'),'stdout_sha256':sha256(result.stdout).hexdigest(),
                             'stderr':result.stderr.decode('utf-8'),'returncode':result.returncode})
    return deepcopy(_REFERENCE_CACHE[key])


def assert_native_finite_work_limits(case,api,schema):
    """Real default boundary pairs, with full unmodified-oracle outcomes."""
    assert native_heap_selected()
    from hepta import hia_heap_bound as heap
    from tests.test_hia_rust_finite_heap import context_work,depth_work
    assert (heap._FINITE_MAX_CONTEXTS,heap._FINITE_MAX_ANALYSIS_DEPTH,
            heap._FINITE_MAX_TRANSFER_STEPS)==(1024,64,32768)
    pairs=(('contexts',context_work(1023),context_work(1024),'contexts',1024),
           ('depth',depth_work(64),depth_work(65),'peak_analysis_call_depth',64),
           ('transfers',context_work(32,1000),context_work(33,1000),None,None))
    for kind,positive,negative,counter,expected in pairs:
        for admitted,source in ((True,positive),(False,negative)):
            source['schema']='hepta.hia.program.v'+str(schema)
            with case.subTest(native_work_boundary=kind,admitted=admitted):
                reference=_reference(api,source)
                native=_observation(lambda:getattr(heap,api)(source,'entry',[],max_live_heap_bytes=0))
                OBSERVATIONS.append({'kind':'actual_native_work_boundary','api':api,'boundary':kind,
                                     'admitted':admitted,'source_sha256':sha256(_wire(source)).hexdigest(),
                                     'reference':reference,'native':native})
                case.assertEqual(_wire(native),_wire(reference))
                if admitted:
                    case.assertEqual(native['returned']['peak_bound_bytes'],0)
                    if counter:case.assertEqual(native['returned']['analysis_work'][counter],expected)
                else:
                    case.assertEqual(native['error']['code'],'E_HIA_BUDGET_LIMIT')


@contextmanager
def before_native_finite_invocation(callback):
    """Observe the exact tuple after HIA has consumed the actual query grant."""
    assert native_heap_selected()
    from hepta.hia_heap_bound_native import HeapContext
    original=HeapContext._invoke
    calls=[]
    def invoke(context,frame):
        if frame.request==22:
            mode=struct.unpack_from('<Q',context.workspace,120)[0]
            if mode in (3,4,5):
                assert context.executed==frame.sequence and context.pending is None
                identifier=struct.unpack_from('<Q',context.workspace,208)[0]
                captured=context.pool.get(identifier)
                assert type(captured) is tuple
                assert len(frame.value[3])==len(captured)
                assert all(a is b for a,b in zip(frame.value[3],captured))
                calls.append((mode,frame.sequence))
                OBSERVATIONS.append({'kind':'actual_consumed_native_invocation',
                                     'mode':mode,'sequence':frame.sequence,'captured_arguments':list(captured)})
                callback(captured)
        return original(context,frame)
    with patch.object(HeapContext,'_invoke',invoke):
        yield
    assert len(calls)==1,calls
