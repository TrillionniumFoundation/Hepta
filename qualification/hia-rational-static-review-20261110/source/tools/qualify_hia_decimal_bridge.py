"""Independent strict-number full IEEE-bit differential, endpoints and original budget."""
from pathlib import Path
from hashlib import sha256
import argparse,ctypes,json,math,random,re,shutil,struct,sys
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from tools.hia_decimal_bridge_driver import NativeDecimalBridge
MAX_BYTES=8*1024*1024
EXPORTS=('decimal_bounded_init','decimal_bounded_scan_chunk','decimal_bounded_magnitude_page','decimal_bridge_init','decimal_bridge_step','pow5_step','quotient_step','binary64_page','rational_step','pow5_multiply_page')
def main():
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--smoke',action='store_true');p.add_argument('--mutant-sticky',action='store_true');a=p.parse_args();assert shutil.disk_usage('/workspace').free>700*1024**2;a.output.mkdir(parents=True,exist_ok=False)
 from hepta.hia_agent_assembly import assemble_program
 from hepta.hia_program_native import build_program_machine
 source=(ROOT/'hepta/native_numeric/json_decimal_bridge.hiaasm').read_bytes()
 def build(raw,folder):
  folder.mkdir();core=assemble_program(raw);(folder/'core.json').write_bytes(core.canonical_bytes);receipt=build_program_machine(core,folder/'bridge.so',linker='ld',foreign_buffer_exports=tuple((name,256) for name in EXPORTS));(folder/'BUILD.json').write_text(json.dumps({'source_sha256':sha256(raw).hexdigest(),'receipt':receipt},indent=2)+'\n');return NativeDecimalBridge(ctypes.CDLL(str(folder/'bridge.so')))
 native=build(source,a.output/'build');contract=json.loads(Path('/workspace/hia-next-evidence/json-float/old-contract/CONTRACT.json').read_text());cases=[('old_contract',r['token']) for r in contract['float_tokens']]
 rng=random.Random(700019)
 for _ in range(100):
  text=rng.choice(('','-'))+str(rng.randrange(1<<64))+'.'+''.join(str(rng.randrange(10)) for _ in range(rng.randrange(1,80)))+'e'+str(rng.randrange(-1200,401));cases.append(('random_exact_reference',text))
 def midpoint(m,k):return (m*5**(-k),k) if k<0 else (m<<k,0)
 def interval(m,k,endpoint,tailcount):
  coefficient,scale=midpoint(m,k);digits=str(coefficient);prefix=coefficient*10**(800-len(digits));grid_scale=scale-(800-len(digits))
  if endpoint=='lower_exact':tail='0'*tailcount
  elif endpoint=='lower_sticky':tail='0'*(tailcount-1)+'1'
  else:prefix-=1;tail='9'*tailcount
  return str(prefix)+tail+'e'+str(grid_scale-tailcount)
 mids=[((1<<53)+1,-53),((1<<53)+3,-53),(1,-1075),(3,-1075),((1<<54)-1,-1075),((1<<54)-1,970)]
 for m,k in mids:
  for endpoint in ('lower_exact','lower_sticky','upper_excluded'):
   text=interval(m,k,endpoint,33 if a.smoke else 2001)
   for sign in ('','-'):cases.append((endpoint,sign+text))
 if not a.smoke:
  cases += [('one_MiB_lower_midpoint_tail',interval((1<<53)+1,-53,'lower_sticky',1048577)),('one_MiB_upper_midpoint_tail',interval((1<<53)+3,-53,'upper_excluded',1048577))]
  zeros=MAX_BYTES-5-len(str(MAX_BYTES));text='0.'+'0'*zeros+'1e+'+str(zeros+1);assert len(text)==MAX_BYTES;cases.append(('max_bytes_leading_zero_exponent_cancellation',text))
  text='1e+'+'0'*(MAX_BYTES-4)+'0';assert len(text)==MAX_BYTES;cases.append(('max_bytes_leading_exponent_zeros',text))
  exponent='9'*4096;zeros=MAX_BYTES-len('-0.e+'+exponent);text='-0.'+'0'*zeros+'e+'+exponent;assert len(text)==MAX_BYTES;cases.append(('max_bytes_negative_zero_saturated_exponent',text))
  cases += [('one_byte_over_original_budget','1e+'+'0'*(MAX_BYTES-3)+'0')]
 if a.smoke:cases=[('smoke',t) for t in ('0.0','-0.0','0.1','1.5','1e4000','5e-324','1e-4000',interval((1<<53)+1,-53,'lower_sticky',33),interval((1<<53)+3,-53,'upper_excluded',33),'1e'+'9'*4096+'x')]
 number=re.compile(r'-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?\Z');rows=[]
 for label,text in cases:
  if len(text.encode())>MAX_BYTES or number.fullmatch(text) is None:expected={'status':'rejected'}
  else:
   reference=float(text);expected={'status':'finite' if math.isfinite(reference) else 'overflow','bits':struct.pack('>d',reference).hex()}
  actual=native.convert(text);row={'label':label,'input_sha256':sha256(text.encode()).hexdigest(),'input_bytes':len(text.encode()),'expected':expected,'actual':actual};rows.append(row);(a.output/'OBSERVATIONS.json').write_text(json.dumps(rows,indent=2)+'\n');assert all(actual[k]==v for k,v in expected.items()),row
  if expected['status'] in ('finite','overflow'):assert actual['source_bytes_consumed']==len(text.encode())
  if expected['status']=='finite':assert struct.pack('>d',native.materialize_finite(actual)).hex()==expected['bits']
 failures=[]
 cancelled=native.convert('0.1',cancel=True);failed=native.convert('1.23',fail_page=True);assert not cancelled['materialized'] and not failed['materialized'];failures += [cancelled,failed]
 original=native.pow5_step
 for fault in ('wrong_page','no_progress','partial_write'):
  def injected(*args):
   if fault=='wrong_page':return original(*args[:4],args[4]+1,args[5])
   if fault=='no_progress':return 1
   ctypes.cast(args[2],ctypes.POINTER(ctypes.c_uint64))[0]=0xffffffff;return 4
  native.pow5_step=injected
  try:native.convert('0.1');raise AssertionError('fault produced a result')
  except ValueError as error:failures.append({'fault':fault,'error':str(error),'materialized':False})
  finally:native.pow5_step=original
 assert native.convert('0.1')['bits']==struct.pack('>d',0.1).hex()
 mutation=None
 if a.mutant_sticky:
  text=source.decode();mutant,count=re.subn(r'bit\.or\((remainder_sticky_[A-Za-z_0-9]+),(decimal_sticky_[A-Za-z_0-9]+)\)',lambda m:'bit.or('+m[1]+','+m[1]+')',text);assert count==1
  altered=build(mutant.encode(),a.output/'mutant-sticky');token=interval((1<<53)+1,-53,'lower_sticky',2001);reference=native.convert(token);bad=altered.convert(token);assert bad['bits']!=reference['bits'];assert sha256((a.output/'build/bridge.so').read_bytes()).hexdigest()!=sha256((a.output/'mutant-sticky/bridge.so').read_bytes()).hexdigest();mutation={'native_HIA_single_change_detected':True,'original_source_sha256':sha256(source).hexdigest(),'mutant_source_sha256':sha256(mutant.encode()).hexdigest(),'original':reference,'mutant':bad}
 report={'status':'passed','scope':'smoke_only' if a.smoke else 'full_registered_component_oracle','source_sha256':sha256(source).hexdigest(),'observations':len(rows),'failures':failures,'sticky_mutation':mutation,'original_input_bytes':MAX_BYTES,'full_scan_required':True,'native_prefix_digits':800,'prefix_is_internal_exact_representation_not_input_cap':True,'independent_reference':'old Python float(token) only in test; strict JSON grammar separately checked','normal_Worker_migration':False,'cost_or_economic_claim':False}
 (a.output/'REPORT.json').write_text(json.dumps(report,indent=2)+'\n');(a.output/'SHA256.json').write_text(json.dumps({str(p.relative_to(a.output)):sha256(p.read_bytes()).hexdigest() for p in a.output.rglob('*') if p.is_file() and p.name!='SHA256.json'},indent=2)+'\n');print('PASS real HIA decimal bridge',len(rows),report['scope'])
if __name__=='__main__':main()
