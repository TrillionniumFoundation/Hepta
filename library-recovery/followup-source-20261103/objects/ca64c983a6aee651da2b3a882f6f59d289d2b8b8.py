"""Standalone policy regression for Hepta SSA contracts and C ABI flag derivation.

Not a Hepta repo test or compiler proof; the logic below mirrors only the scoped
new guards, without importing the compiler repository.
"""
import json, subprocess, shutil

ALLOWED_EFFECTS={'panic'}
ALLOWED_RESOURCES={'heap_allocations':0,'may_block':False,'may_suspend':False,'may_spawn':False}
def contract(fn):
    declared=fn.get('declared_effects')
    inferred=fn.get('inferred_transitive_effects')
    resources=fn.get('resource_contract')
    if (not isinstance(declared,list) or not isinstance(inferred,list)
        or any(type(effect) is not str for effect in [*declared,*inferred])
        or declared!=sorted(set(declared)) or inferred!=sorted(set(inferred))
        or not set(inferred).issubset(declared)
        or (set(declared)|set(inferred))-ALLOWED_EFFECTS):
        raise ValueError('E_SSA_EFFECT')
    if (not isinstance(resources,dict)
        or any(key not in ALLOWED_RESOURCES or type(value) is not type(ALLOWED_RESOURCES.get(key))
               or value!=ALLOWED_RESOURCES.get(key) for key,value in resources.items())):
        raise ValueError('E_SSA_RESOURCE')
    return declared,inferred,resources

def canon(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)

def model_flags(flags):
    result=[];index=0
    while index < len(flags):
        flag=flags[index]
        if flag in {'-I','-isystem','-iquote','-D','-U'}:
            if index+1>=len(flags):raise ValueError('E_C_BUILD_IDENTITY')
            index+=2
        elif flag.startswith(('-I','-D','-U')) and len(flag)>2:index+=1
        elif flag.startswith('-std=') or flag in {'-funsigned-char','-fsigned-char'}:
            result.append(flag);index+=1
        else:raise ValueError('E_C_BUILD_IDENTITY')
    return result

valid=[{'declared_effects':[],'inferred_transitive_effects':[],'resource_contract':{}},
       {'declared_effects':['panic'],'inferred_transitive_effects':['panic'],
        'resource_contract':{'heap_allocations':0,'may_block':False,'may_suspend':False,'may_spawn':False}}]
invalid=[
 {'declared_effects':['ffi'],'inferred_transitive_effects':[],'resource_contract':{}},
 {'declared_effects':[],'inferred_transitive_effects':['panic'],'resource_contract':{}},
 {'declared_effects':['panic','panic'],'inferred_transitive_effects':[],'resource_contract':{}},
 {'declared_effects':['panic'],'inferred_transitive_effects':[],'resource_contract':{'may_block':0}},
 {'declared_effects':['panic'],'inferred_transitive_effects':[],'resource_contract':{'heap_allocations':False}},
 {'declared_effects':['panic'],'inferred_transitive_effects':[],'resource_contract':{'may_spawn':1}},
 {'declared_effects':['panic'],'inferred_transitive_effects':[],'resource_contract':{'max_heap':0}},
 ]
checks=0
for item in valid:
    contract(item);checks+=1
for item in invalid:
    try:contract(item)
    except ValueError:checks+=1
    else:raise AssertionError(('accepted unsafe contract',item))
for key,a,b in [('may_block',False,0),('heap_allocations',0,False)]:
    assert a == b and canon({key:a}) != canon({key:b});checks+=1
assert model_flags(['-std=c11','-I','include','-DUSER_FLAG=1','-fsigned-char']) == ['-std=c11','-fsigned-char'];checks+=1
assert model_flags(['-std=c17','-U','FOO','-isystem','include','-Iinclude']) == ['-std=c17'];checks+=1
for attack in [['-std=c11','-Xclang','-load','plugin.so'],['-I'],['-std=c11','-include','evil.h']]:
    try:model_flags(attack)
    except ValueError:checks+=1
    else:raise AssertionError(('accepted compiler flag injection',attack))
compiler=shutil.which('clang')
if compiler:
    probe=subprocess.run([compiler,'-std=c11','-fsigned-char','-dM','-E','-x','c','-'],input='',text=True,capture_output=True,check=True,timeout=5)
    assert '#define __SIZEOF_POINTER__' in probe.stdout and '#define __CHAR_BIT__' in probe.stdout
    checks+=1
print(json.dumps({'scope':'standalone_policy_only_not_full_hepta_compiler','passed':checks,
                  'clang_used':bool(compiler),'tests':'contracts, type-confusion, ABI-flag replay, actual Clang macro query',
                  'full_hepta_compiler_tested':False,'production_blockers_closed':False},indent=2))
