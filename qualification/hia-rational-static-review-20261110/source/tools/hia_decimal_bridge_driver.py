"""Opaque ABI dispatcher for the real HIA decimal bridge; no decimal arithmetic."""
import ctypes,struct
NONE=(1<<64)-1
class NativeDecimalBridge:
 def __init__(self,library):
  self.library=library;pair=[ctypes.c_void_p,ctypes.c_uint64]
  signatures={'decimal_bounded_init':pair+[ctypes.c_uint64],'decimal_bounded_scan_chunk':pair*2+[ctypes.c_uint64],'decimal_bounded_magnitude_page':pair*2+[ctypes.c_uint64],'decimal_bridge_init':pair*3,'decimal_bridge_step':pair*8+[ctypes.c_uint32],'pow5_step':pair*2+[ctypes.c_uint64,ctypes.c_uint32],'quotient_step':pair*4+[ctypes.c_uint32],'binary64_page':pair*2+[ctypes.c_uint64,ctypes.c_uint32],'rational_step':pair*4+[ctypes.c_uint64]*3+[ctypes.c_uint32],'pow5_multiply_page':pair*2+[ctypes.c_uint64]}
  for name,signature in signatures.items():fn=getattr(library,name);fn.argtypes=signature;fn.restype=ctypes.c_uint64;setattr(self,name,fn)
 def convert(self,token,*,chunk_size=64,cancel=False,fail_page=False):
  # Encoding, zero-filled opaque pages, native-request dispatch and final bits
  # are host boundaries. No classification or numerical conversion of text.
  raw=token.encode('utf-8') if type(token) is str else token
  dc=(ctypes.c_uint64*32)();status=self.decimal_bounded_init(dc,256,len(raw));calls=1
  if status!=1:return {'status':'rejected','stage':'input_extent','materialized':False,'native_status':status}
  apages={};bpages={};fault_count=0
  def page(store,index,allocate=False):
   nonlocal fault_count
   fault_count+=1
   if fail_page and fault_count==1:raise MemoryError('injected private page failure')
   if index not in store:
    if not allocate:raise MemoryError('missing requested opaque page')
    store[index]=(ctypes.c_uint64*32)()
   return store[index]
  try:
   while True:
    offset=dc[2];part=raw[offset:offset+chunk_size];source=(ctypes.c_ubyte*len(part)).from_buffer_copy(part);status=self.decimal_bounded_scan_chunk(dc,256,source,len(part),offset);calls+=1
    if status in (4,6):return {'status':'rejected','stage':'number_grammar','materialized':False,'native_status':status}
    if status==3:break
    if status==1:
     if dc[2]<=offset:raise ValueError('native decimal source no progress')
     continue
    if status!=2:raise ValueError('invalid native decimal action')
    while True:
     index=dc[11];reply=self.decimal_bounded_magnitude_page(dc,128,page(apages,index,True),256,index);calls+=1
     if reply==3:break
     if reply!=2 or dc[11]<=index:raise ValueError('native decimal magnitude failed or made no progress')
   st=(ctypes.c_uint64*32)();pw=(ctypes.c_uint64*32)();q=(ctypes.c_uint64*32)();op=(ctypes.c_uint64*32)();sa=(ctypes.c_uint64*16)();sb=(ctypes.c_uint64*16)();rs=(ctypes.c_uint64*16)();output=(ctypes.c_uint64*32)();zeros=[(ctypes.c_uint64*32)() for _ in range(3)]
   action=self.decimal_bridge_init(st,256,dc,256,pw,256);calls+=1
   if cancel:
    result=self.decimal_bridge_step(st,256,pw,256,q,256,op,256,sa,128,sb,128,rs,128,output,256,3);assert result==8
    return {'status':'cancelled','materialized':False}
   while action not in (5,6):
    if action in (7,8):return {'status':'rejected','stage':'bridge_protocol','materialized':False,'native_status':action}
    if action in (1,2):
     store=bpages if action==1 else apages
     while True:
      index=pw[11];before=(pw[1],pw[11],pw[16],pw[19]);reply=self.pow5_step(pw,256,page(store,index,True),256,index,0);calls+=1
      if reply==2:break
      if reply!=1 or before==(pw[1],pw[11],pw[16],pw[19]):raise ValueError('native power5 failed or made no progress')
    elif action==3:
     inner=st[8]
     while inner!=6:
      if inner in (7,8):return {'status':'rejected','stage':'quotient_protocol','materialized':False,'native_status':inner}
      if inner in (1,2):
       state=sa if inner==1 else sb;store=apages if inner==1 else bpages
       while True:
        index=state[3];reply=self.binary64_page(state,128,page(store,index),256,index,0);calls+=1
        if reply in (2,3):break
        if reply!=1 or state[3]>=index:raise ValueError('native bitlength failed or made no progress')
      elif inner in (3,4):
       while True:
        ai,bi,ci=op[10],op[11],op[12];before=op[8]
        reply=self.rational_step(op,256,zeros[0] if ai==NONE else page(apages,ai),256,zeros[1] if bi==NONE else page(bpages,bi),256,zeros[2] if ci==NONE else page(bpages,ci),256,ai,bi,ci,0);calls+=1
        if reply==2:break
        if reply!=1 or op[8]==before:raise ValueError('native rational operation failed or made no progress')
      elif inner==5:
       while True:
        index=op[11];reply=self.pow5_multiply_page(op,256,page(apages,index,True),256,index);calls+=1
        if reply==3:break
        if reply!=2 or op[11]<=index:raise ValueError('native binary scale multiply failed or made no progress')
      else:raise ValueError('invalid native quotient action')
      inner=self.quotient_step(q,256,op,256,sa,128,sb,128,0);calls+=1
    elif action==4:
     reply=self.binary64_page(rs,128,output,256,0,0);calls+=1
     if reply not in (2,3):raise ValueError('native final rounding failed')
    else:raise ValueError('invalid native bridge action')
    action=self.decimal_bridge_step(st,256,pw,256,q,256,op,256,sa,128,sb,128,rs,128,output,256,0);calls+=1
   bits=st[7]
   return {'status':'finite' if action==5 else 'overflow','bits':f'{bits:016x}','native_calls':calls,'source_bytes_consumed':int(dc[2]),'significant_digits':int(dc[24]),'discarded_digits':int(dc[25]),'discarded_sticky':bool(dc[26]),'coefficient_pages':len(apages),'denominator_pages':len(bpages),'materialized':False}
  except MemoryError:return {'status':'private_page_failure','materialized':False}
 @staticmethod
 def materialize_finite(result):
  if result['status']!='finite':raise ValueError('native finite conversion required')
  return struct.unpack('>d',bytes.fromhex(result['bits']))[0]
