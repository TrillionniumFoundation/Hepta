"""Frozen original SDK stdio adversarial corpus, independent of production imports.

Source driver SHA256: 8d3ac6b805c4c4924b417ab9b76d1aca2b7d993c0721d6d39a233ba99a7aadc1
Its original case bodies and ordering are retained below.
"""
from hashlib import sha256
import json

def wire(value):return json.dumps(value,ensure_ascii=True,separators=(',',':')).encode()

def request(method='ping',id='ping',params=None):
    value={'jsonrpc':'2.0','id':id,'method':method}
    if params is not None:value['params']=params
    return wire(value)

INIT=request('initialize','init',{'protocolVersion':'2025-11-25','capabilities':{},'clientInfo':{'name':'native-sdk-differential','version':'1'}})+b'\n'

PING=request()+b'\n'

def digest(raw):return sha256(raw).hexdigest()

def cases():
    yield 'eof-before-initialize',b''
    yield 'ping-only-eof',PING
    yield 'init-without-ready',INIT+PING
    yield 'unterminated-first-frame',PING[:-1]
    yield 'unterminated-final-frame',INIT+PING[:-1]
    yield 'crlf-control',INIT.replace(b'\n',b'\r\n')+PING.replace(b'\n',b'\r\n')
    for raw in [b'',b' ',b'{',b'null',b'[]',b'0',b'false',b'"x"',b'{"jsonrpc":"2.0","id":null,"method":"ping"}',b'{"jsonrpc":"2.0","jsonrpc":"2.0","id":1,"method":"ping"}',b'{"jsonrpc":"2.0","id":1,"method":"ping","params":[]}',b'{"jsonrpc":"2.0","id":1,"method":"ping","extra":1e309}',b'{"jsonrpc":"2.0","id":1,"method":"ping","extra":1e309,"extra":0}',b'{"jsonrpc":"2.0","id":1,"method":"ping","extra":"\xff"}']:
        yield 'malformed-'+digest(raw)[:12],INIT+raw+b'\n'+PING
    yield 'bom-ping',INIT+b'\xef\xbb\xbf'+PING
    yield 'bom-init',b'\xef\xbb\xbf'+INIT+PING
    yield 'unknown-duplicate-control',INIT+b'{"jsonrpc":"2.0","id":7,"method":"ping","extra":1,"extra":2}\n'+PING
    yield 'notification-before-init',b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n'+INIT
    yield 'response-before-init',b'{"jsonrpc":"2.0","id":1,"result":{}}\n'+INIT
    for token in [b'-0',b'0.0',b'1e0',b'1e-9999',b'9007199254740991.0',b'9007199254740992.0',b'-9223372036854775808',b'9223372036854775807',b'18446744073709551615',b'"\\/\\u0061"',b'"\\ud83d\\ude00"']:
        raw=b'{"jsonrpc":"2.0","method":"ping","id":'+token+b'}\n'
        yield 'request-id-'+token.hex(),INIT+raw+PING
    method=b'{"jsonrpc":"2.0","id":"boundary","method":"ping"}'
    for size in [(8<<20),(8<<20)+1,(16<<20)-1,(16<<20),(16<<20)+1]:
        yield 'wire-bytes-'+str(size),INIT+b' '*(size-len(method))+method+b'\n'+PING
    yield 'exact-crlf-wire-bound',INIT+b' '*((16<<20)-2-len(method))+method+b'\r\n'+PING
    yield 'over-crlf-wire-bound',INIT+b' '*((16<<20)-1-len(method))+method+b'\r\n'+PING
    yield 'sdk-large-value-count',INIT+b'{"jsonrpc":"2.0","id":2,"method":"ping","extra":['+b'0,'*262144+b'0]}\n'+PING
    for n in [127,128,129]:
        yield 'sdk-value-depth-'+str(n),INIT+b'{"jsonrpc":"2.0","id":2,"method":"ping","extra":'+b'['*n+b'0'+b']'*n+b'}\n'+PING
    invalid=request('tools/call','schema',{'name':'hia_describe','arguments':{}})
    for size in [len(invalid),(8<<20),(8<<20)+1]:
        yield 'hia-raw-wire-bytes-'+str(size),INIT+b' '*(size-len(invalid))+invalid+b'\n'+PING
    for raw in [b'{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"hia_describe","arguments":{"section":"manifest","z":0,"a":0}}}',b'{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"hia_describe","arguments":{"section":"manifest","section":"manifest"}}}',b'{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"hia_describe","arguments":[]}}',b'{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"hia_describe","arguments":{},"arguments":{}}}',b'{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"hia_describe","arguments":{}},"extra":1,"extra":2}']:
        yield 'hia-schema-'+digest(raw)[:12],INIT+raw+b'\n'+PING
    for uri in ['missing','octofs://jobs/missing','octofs://jobs/','hia://missing']:
        yield 'resource-uri-'+digest(uri.encode())[:12],INIT+request('resources/read',9,{'uri':uri})+b'\n'+PING
    for escaped,size in [(False,(8<<20)+100),(False,(16<<20)-100),(True,1600000)]:
        id=b'"'+(b'\\u0061'*size if escaped else b'a'*size)+b'"'
        raw=b'{"jsonrpc":"2.0","method":"ping","id":'+id+b'}\n'
        yield 'large-id-'+str(escaped)+'-'+str(size),INIT+raw+PING
