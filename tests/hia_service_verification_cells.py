"""Bounded original LOAD_FAST/LOAD_DEREF protocol controls.

This is a separate mechanical-cell domain, not additional expectations for the
185 immutable business cases. It preserves the runtime's raw exception metadata
and records both real tracebacks. It does not inspect or rewrite live frames.
"""
from __future__ import annotations
import json
from pathlib import Path
import traceback


def _original_local():
    marker: object
    return marker


def _original_cell_local():
    def escape():
        return marker
    return marker
    marker = None


def _original_empty_free():
    marker = None
    def read():
        return marker
    del marker
    return read


def _fields(error, outer, seen=None):
    if error is None:
        return None
    if seen is None:
        seen=set()
    if id(error) in seen:
        return {'cycle':True}
    seen.add(id(error))
    obj=getattr(error,'obj',None)
    return {'type':type(error).__module__+'.'+type(error).__qualname__,
        'message':str(error),'name':getattr(error,'name',None),
        'obj':None if obj is None else {'type':type(obj).__module__+'.'+type(obj).__qualname__},
        'outer_identity':error is outer,'suppress_context':error.__suppress_context__,
        'context':_fields(error.__context__,outer,seen),'cause':_fields(error.__cause__,outer,seen)}


def _observe(action, outer_active):
    result=None;raw=None
    def call(outer):
        nonlocal result,raw
        try:
            action()
        except BaseException as error:
            result=_fields(error,outer)
            raw=''.join(traceback.format_exception(type(error),error,error.__traceback__))
        else:
            raise AssertionError('unbound original load unexpectedly returned')
    if outer_active:
        try:
            raise KeyError('declared cell protocol outer')
        except KeyError as outer:
            call(outer)
    else:
        call(None)
    return result,raw


def run(output):
    # Freeze independent original load behavior first. No candidate result is
    # used to create or alter expected metadata.
    output=Path(output);output.mkdir(mode=0o700)
    original=[];original_raw=[]
    modes=('local','cell_local','free')
    for outer in (False,True):
        for mode in modes:
            action=(_original_local if mode=='local' else
                    _original_cell_local if mode=='cell_local' else _original_empty_free())
            fields,raw=_observe(action,outer)
            case_id=mode+'.outer'+str(int(outer))
            original.append({'id':case_id,'exception':fields})
            original_raw.append({'id':case_id,'traceback':raw})
    def write(name,value):
        raw=json.dumps(value,ensure_ascii=True,sort_keys=True,separators=(',',':')).encode()+b'\n'
        with (output/name).open('xb') as stream:stream.write(raw)
        return raw
    expected=write('original-observations.json',original)
    write('original-tracebacks.json',original_raw)
    from hepta import hia_service_verification_native as native
    actual=[];actual_raw=[]
    for outer in (False,True):
        for mode in modes:
            if mode=='free':
                storage=native._CapturedCells({'marker':native._CELL_TYPE()})
            else:
                storage=native._LocalStorage(('marker',),frozenset({'marker'}) if mode=='cell_local' else frozenset())
            fields,raw=_observe(lambda:storage['marker'],outer)
            case_id=mode+'.outer'+str(int(outer))
            actual.append({'id':case_id,'exception':fields})
            actual_raw.append({'id':case_id,'traceback':raw})
    observed=write('candidate-observations.json',actual)
    write('candidate-tracebacks.json',actual_raw)
    bound=[]
    value=object()
    for cell in (False,True):
        storage=native._LocalStorage(('marker',),frozenset({'marker'}) if cell else frozenset())
        storage['marker']=value
        assert storage['marker'] is value
        captured=storage.capture(('marker',))
        assert captured['marker'] is value
        bound.append({'cell_local':cell,'same_value':True})
    assert (output/'original-observations.json').read_bytes()==expected
    report={'schema':'hepta.hia.service-verification-cell-protocol.v1',
        'status':'PASS' if observed==expected else 'HOLD','count':len(original),
        'ordered_ids':[row['id'] for row in original],'bound_controls':bound,
        'same_original_bytes':observed==expected,
        'scope':'actual runtime unbound local/free-variable errors only; no full business or GC equivalence claim'}
    write('report.json',report)
    if observed!=expected:
        raise AssertionError('mechanical cell read changed original unbound-load metadata')
    return report
