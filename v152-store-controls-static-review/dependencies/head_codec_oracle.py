"""Independent test oracle; never imported by the HIA generator or production.

This file has not been executed.  The later controls must compare actual HIA
bytes with this format oracle and complete independently specified action
traces, not replace HIA execution with this Python code.
"""
from __future__ import annotations
from hashlib import sha256
import struct

HEAD_MAGIC=b'HIASTH01'
REQUEST_MAGIC=b'HIASCR01'
U64_MAX=(1<<64)-1


def exact_bytes(value,size,name):
    if type(value) is not bytes or len(value)!=size:raise ValueError(name)
    return value


def exact_u64(value,name):
    if type(value) is not int or not 0<=value<=U64_MAX:raise ValueError(name)
    return value


def encode_head(*,store_uuid,generation,parent_generation,root,parent_root,transaction_uuid,request_digest):
    store_uuid=exact_bytes(store_uuid,16,'store UUID')
    root=exact_bytes(root,32,'root');parent_root=exact_bytes(parent_root,32,'parent root')
    transaction_uuid=exact_bytes(transaction_uuid,16,'transaction UUID')
    request_digest=exact_bytes(request_digest,32,'request digest')
    generation=exact_u64(generation,'generation');parent_generation=exact_u64(parent_generation,'parent generation')
    if store_uuid==bytes(16):raise ValueError('zero store UUID')
    if generation==0:
        if parent_generation!=0 or parent_root+transaction_uuid+request_digest!=bytes(80):
            raise ValueError('genesis parent/transaction')
    elif parent_generation!=generation-1 or transaction_uuid==bytes(16):
        raise ValueError('non-genesis parent/transaction')
    prefix=(HEAD_MAGIC+struct.pack('<Q',1)+store_uuid+struct.pack('<QQ',generation,parent_generation)
            +root+parent_root+transaction_uuid+request_digest+struct.pack('<Q',1)+bytes(56))
    if len(prefix)!=224:raise AssertionError('format author error')
    return prefix+sha256(prefix).digest()


def decode_head(raw):
    raw=exact_bytes(raw,256,'head length')
    if raw[:8]!=HEAD_MAGIC or raw[8:16]!=struct.pack('<Q',1) or raw[160:168]!=struct.pack('<Q',1):
        raise ValueError('format/schema')
    if raw[168:224]!=bytes(56) or raw[224:]!=sha256(raw[:224]).digest():
        raise ValueError('reserved/hash')
    result={'store_uuid':raw[16:32],'generation':struct.unpack_from('<Q',raw,32)[0],
            'parent_generation':struct.unpack_from('<Q',raw,40)[0],'root':raw[48:80],
            'parent_root':raw[80:112],'transaction_uuid':raw[112:128],'request_digest':raw[128:160]}
    if encode_head(**result)!=raw:raise ValueError('noncanonical head')
    return result


def target_head(expected,root,transaction_uuid,request_digest):
    previous=decode_head(expected)
    if previous['generation']==U64_MAX:raise ValueError('generation exhausted')
    if transaction_uuid==previous['transaction_uuid']:raise ValueError('transaction reused')
    return encode_head(store_uuid=previous['store_uuid'],generation=previous['generation']+1,
                       parent_generation=previous['generation'],root=root,parent_root=previous['root'],
                       transaction_uuid=transaction_uuid,request_digest=request_digest)


def request(*,event,serial,action,result,nonce,payload=b''):
    for name,value in [('event',event),('serial',serial),('action',action),('result',result)]:exact_u64(value,name)
    nonce=exact_bytes(nonce,16,'nonce')
    if nonce==bytes(16) or type(payload) is not bytes or len(payload)>336:raise ValueError('nonce/payload')
    return REQUEST_MAGIC+struct.pack('<QQQQ',event,serial,action,result)+bytes(56)+nonce+bytes(16)+payload


def initial_request(*,nonce,expected,root,transaction_uuid,request_digest):
    target_head(expected,root,transaction_uuid,request_digest)
    return request(event=0,serial=0,action=0,result=0,nonce=nonce,
                   payload=expected+root+transaction_uuid+request_digest)


def decode_receipt(output,returned_extent):
    if type(output) is not bytes or len(output)<1152 or type(returned_extent) is not int:
        raise ValueError('complete output and integer extent required')
    if not 128<=returned_extent<=384 or output[:8]!=b'HIASCP01':raise ValueError('receipt')
    names=['status','action','serial','phase','claimed','possible_publication','directory_sync_ack',
           'payload_length','offset','extent','exact_target_replay','nonce_low','nonce_high',
           'desired_outcome','reason']
    result=dict(zip(names,struct.unpack_from('<15Q',output,8)))
    if returned_extent!=128+result['payload_length']:raise ValueError('payload extent')
    result['payload']=output[128:returned_extent]
    return result
