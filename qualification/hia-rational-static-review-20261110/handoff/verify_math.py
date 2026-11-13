"""Portable pure-Python exact-integer review; NO native compilation/execution."""
from pathlib import Path
import argparse,json,sys

def round_rational_bits(n,d,negative=False):
 assert n>=0 and d>0
 sign=(1<<63) if negative else 0
 if n==0:return sign
 e=n.bit_length()-d.bit_length()
 if ((n<(d<<e)) if e>=0 else ((n<<(-e))<d)):e-=1
 quantum=max(e-52,-1074)
 numerator,denominator=(n,d<<quantum) if quantum>=0 else (n<<(-quantum),d)
 q,r=divmod(numerator,denominator)
 if 2*r>denominator or (2*r==denominator and q%2):q+=1
 if e<-1022:return sign|q
 if q==(1<<53):q>>=1;e+=1
 if e>1023:return sign|0x7ff0000000000000
 return sign|((e+1023)<<52)|(q-(1<<52))

def main():
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
 bound=((1<<54)-1)*5**1075
 assert 10**767<=bound<10**768
 assert ((1<<54)-1)*2**970<10**309
 for k in range(-1075,971):assert (((1<<54)-1)*5**(-k) if k<0 else ((1<<54)-1)*2**k)<10**768
 # Independent direct rational rounding reference, not the HIA quotient/sticky algorithm.
 known=[(0,1,0),(1,1<<1075,0),(3,1<<1075,2),(1,1<<1074,1),((1<<53)+1,1<<53,0x3ff0000000000000),((1<<53)+3,1<<53,0x3ff0000000000002),(((1<<54)-1)<<970,1,0x7ff0000000000000)]
 for n,d,bits in known:
  assert round_rational_bits(n,d)==bits
  assert round_rational_bits(n,d,True)==(bits|(1<<63))
 # (m,k, exact midpoint's lower neighbor bits, tie result bits, upper neighbor bits)
 mids=[((1<<53)+1,-53,0x3ff0000000000000,0x3ff0000000000000,0x3ff0000000000001),((1<<53)+3,-53,0x3ff0000000000001,0x3ff0000000000002,0x3ff0000000000002),(1,-1075,0,0,1),(3,-1075,1,2,2),((1<<53)-1,-1075,0x000fffffffffffff,0x0010000000000000,0x0010000000000000),((1<<54)-1,-1075,0x001fffffffffffff,0x0020000000000000,0x0020000000000000),((1<<54)-1,970,0x7fefffffffffffff,0x7ff0000000000000,0x7ff0000000000000)]
 rows=[]
 for m,k,lower,tie,upper in mids:
  c,scale=(m*5**(-k),k) if k<0 else (m<<k,0)
  digits=len(str(c));assert digits<=768
  prefix=c*10**(800-digits);grid_scale=scale-(800-digits)
  for tail_digits in (1,33,2001):
   denominator_tail=10**tail_digits
   for endpoint in ('lower_exact','lower_sticky_min','lower_sticky_max','upper_excluded_min','upper_excluded_max'):
    pfx=prefix-1 if endpoint.startswith('upper') else prefix
    tail=0 if endpoint=='lower_exact' else (denominator_tail-1 if endpoint.endswith('max') else 1)
    magnitude=pfx*denominator_tail+tail;power=grid_scale-tail_digits
    n,d=(magnitude*10**power,1) if power>=0 else (magnitude,10**(-power))
    if endpoint=='lower_exact':assert magnitude==prefix*denominator_tail;expected=tie
    elif endpoint.startswith('lower'):assert prefix*denominator_tail<magnitude<(prefix+1)*denominator_tail;expected=upper
    else:assert (prefix-1)*denominator_tail<magnitude<prefix*denominator_tail;expected=lower
    for negative in (False,True):
     actual=round_rational_bits(n,d,negative);assert actual==(expected|((1<<63) if negative else 0));rows.append({'midpoint_m':str(m),'binary_power':k,'endpoint':endpoint,'tail_digits':tail_digits,'negative':negative,'expected_bits':f'{actual:016x}'})
 # Full-input scanning itself is NOT proven by this algebra. These are count identities only.
 original_budget=8*1024*1024;zeros=original_budget-12;fraction_digits=zeros+1;explicit_exponent=zeros+1
 assert explicit_exponent-fraction_digits==0
 assert ((1<<63)|0)==0x8000000000000000
 report={'status':'EXACT_MATH_REVIEW_PASSED','scope':'portable integer mathematics only; NOT HIA/native/normal Worker qualification','bound_powers_checked':2046,'midpoint_coefficient_bound_digits':768,'retained_prefix_digits':800,'endpoint_observations':len(rows),'rounding_known_cases_both_signs':len(known)*2,'proof':'P has800 digits. An interior midpoint C*10^t with C<10^768 forces t-grid_scale>=32, hence M/10^grid_scale integer; impossible strictly between P and P+1. T=0 closes L; 0<T<10^D gives L<x<U; U excluded. Negative sign reverses interval, and signed zero is explicit metadata.','full_scan_not_executed':True,'native_oracle_status':'ALL_NOT_RUN','rows':rows}
 (a.output/'MATH_REPORT.json').write_text(json.dumps(report,indent=2)+'\n');print('Exact integer mathematics passed; native77/256/72/180 remain NOT_RUN')
if __name__=='__main__':main()
