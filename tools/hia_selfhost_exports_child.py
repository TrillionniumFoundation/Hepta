"""Disposable stdlib-only observer for verified scalar-export shared objects."""
from __future__ import annotations
import argparse
import ctypes
from hashlib import sha256
import json
from pathlib import Path
import platform
import re
import resource
import sys


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--request',required=True);parser.add_argument('--sha256',required=True)
    args=parser.parse_args();raw=Path(args.request).read_bytes()
    if sha256(raw).hexdigest()!=args.sha256:raise ValueError('export observation request identity')
    request=json.loads(raw)
    if set(request)!={'schema','image','image_sha256','calls'} or request['schema']!='hepta.hia.scalar-export-observation.v1':
        raise ValueError('unknown export observation schema')
    if platform.system()!='Linux' or platform.machine()!='x86_64':raise ValueError('Linux x86-64 required')
    if type(request['calls']) is not list or not 1<=len(request['calls'])<=1024:raise ValueError('bounded calls required')
    image=Path(request['image']).resolve(strict=True);before=image.read_bytes()
    if sha256(before).hexdigest()!=request['image_sha256']:raise ValueError('export image identity')
    resource.setrlimit(resource.RLIMIT_CORE,(0,0));resource.setrlimit(resource.RLIMIT_CPU,(10,10))
    resource.setrlimit(resource.RLIMIT_AS,(256<<20,256<<20))
    lib=ctypes.CDLL(str(image));observations=[]
    allowed={'u8','u16','u32','u64','usize','i8','i16','i32','i64','isize','bool','unit','void'}
    for row in request['calls']:
        if (type(row) is not dict or set(row)!={'function','arguments','return_type'}
                or type(row['function']) is not str or re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]{0,127}',row['function']) is None
                or type(row['arguments']) is not list or len(row['arguments'])>16
                or any(type(v) is not int or not 0<=v<1<<64 for v in row['arguments'])
                or row['return_type'] not in allowed):raise ValueError('unsupported scalar export observation')
        function=getattr(lib,row['function']);function.argtypes=[ctypes.c_uint64]*len(row['arguments'])
        typ=row['return_type'];function.restype=None if typ=='void' else ctypes.c_int64 if typ.startswith('i') else ctypes.c_uint64
        observations.append({'function':row['function'],'value':function(*row['arguments'])})
    if image.read_bytes()!=before or Path(args.request).read_bytes()!=raw:raise ValueError('export input changed')
    forbidden=[name for name in sys.modules if name=='hepta' or name.startswith('hepta.') or name.startswith('tools.')]
    if forbidden:raise ValueError('compiler module reached isolated export observer')
    print(json.dumps({'status':'SCALAR_EXPORT_OBSERVATIONS_RETURNED','observations':observations,
        'image_sha256':request['image_sha256'],'forbidden_compiler_modules_loaded':forbidden},sort_keys=True))


if __name__=='__main__':main()
