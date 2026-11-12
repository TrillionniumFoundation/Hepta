#!/usr/bin/env python3
"""Always export completed text records; full binary inputs stay in the artifact."""
import base64
from hashlib import sha256
import json
from pathlib import Path
import sys
import zlib

workspace=Path(sys.argv[1]).resolve()
files={}
roots={'driver':workspace/'evidence','images':workspace/'development/development-images-r2','controls':workspace/'development/new-controls-r1'}
for label,root in roots.items():
    if not root.exists():continue
    for path in sorted(root.rglob('*')):
        if not path.is_file() or path.is_symlink():continue
        if path.suffix not in ('.json','.log','.stdout','.stderr','.txt') and path.name not in ('stdout','stderr'):continue
        raw=path.read_bytes()
        try:text=raw.decode('utf-8')
        except UnicodeError:continue
        files[label+'/'+path.relative_to(root).as_posix()]={'bytes':len(raw),'sha256':sha256(raw).hexdigest(),'text':text}
packet={'schema':'hia.global-import.development-original-text.v80.r1','scope':'COMPLETE_SELECTED_TEXT_NOT_BINARY_ARTIFACT_CRC','files':files}
raw=(json.dumps(packet,sort_keys=True,separators=(',',':'))+'\n').encode();packed=zlib.compress(raw,9);data=base64.b64encode(packed).decode()
header={'protocol':'HIA_V80_GLOBAL_IMPORT_ZLIB_BASE64','record':'begin','raw_bytes':len(raw),'raw_sha256':sha256(raw).hexdigest(),'compressed_bytes':len(packed),'compressed_sha256':sha256(packed).hexdigest(),'chunks':(len(data)+10999)//11000}
print(json.dumps(header,sort_keys=True))
for index,start in enumerate(range(0,len(data),11000)):
    line=json.dumps({'protocol':header['protocol'],'record':'chunk','index':index,'data':data[start:start+11000]},sort_keys=True)
    assert len(line.encode())<=12288;print(line)
print(json.dumps({'protocol':header['protocol'],'record':'end','raw_sha256':header['raw_sha256']},sort_keys=True))
