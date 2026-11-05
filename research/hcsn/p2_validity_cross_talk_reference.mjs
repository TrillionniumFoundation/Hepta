/** HCSN P2 research-only validity-channel counterexample.
 * Replays the exact v <- v + write*(1-v·k)*k recurrence and
 * known mass = sigmoid(12*(v·k - 1/2)) in p2_reset_validity.py.
 * NO learned model or real checkpoint is evaluated here.
 */
import assert from 'node:assert/strict';

function dot(a,b) { return a.reduce((s,x,i)=>s+x*b[i],0); }
function update(v,k) {
  assert.equal(v.length,k.length);
  assert.ok(Math.abs(dot(k,k)-1)<1e-12);
  const pre=dot(v,k);
  return v.map((x,i)=>x+(1-pre)*k[i]);
}
function sigmoid(x) { return 1/(1+Math.exp(-x)); }
function known(v,k) { return sigmoid(12*(dot(v,k)-0.5)); }
function near(x,y,tol=1e-12) { assert.ok(Math.abs(x-y)<=tol,`${x} != ${y}`); }
function fp32Update(v,k) {
  const f=Math.fround;
  const pre=f(f(v[0]*k[0])+f(v[1]*k[1]));
  const step=f(1-pre);
  return [f(v[0]+f(step*k[0])),f(v[1]+f(step*k[1]))];
}
export function evidence() {
  const k1=[1,0], anti=[-3/5,4/5], orth=[0,1], unseen=[3/5,4/5];
  const first=update([0,0],k1);
  const priorKeyLost=update(first,anti);
  const twoStored=update(first,orth);
  const oldProjection=dot(priorKeyLost,k1);
  const unwrittenProjection=dot(twoStored,unseen);
  // Independent rational arithmetic: v_after_anti=(1/25,32/25)
  // and unwritten dot with v_after_orth = 7/5.
  near(priorKeyLost[0],1/25);
  near(priorKeyLost[1],32/25);
  near(oldProjection,1/25);
  near(twoStored[0],1);
  near(twoStored[1],1);
  near(unwrittenProjection,7/5);
  assert.ok(known(priorKeyLost,k1)<0.005);
  assert.ok(known(twoStored,unseen)>0.99997);
  assert.ok(dot(k1,anti)<0 && dot(k1,orth)===0);
  near(known([0,0],k1),sigmoid(-6));
  // Single-precision finite operands do not repair the phenomenon.
  const f=Math.fround;
  const fOld=fp32Update(fp32Update([0,0],k1),[f(-3/5),f(4/5)]);
  const fNew=fp32Update(fp32Update([0,0],k1),orth);
  const fKnown=sigmoid(12*(fOld[0]-.5));
  const fUnknown=sigmoid(12*(f(fNew[0]*f(3/5)+fNew[1]*f(4/5))-.5));
  assert.ok(fKnown<0.005 && fUnknown>0.99997);
  return {
    schema:'hcsn.p2.validity-projection-negative.v1',
    scope:'exact 2D subspace of 16D normalized keys, two detected writes, no resets; analytic recurrence only',
    original_subroutine:'research/hcsn/p2_reset_validity.py: validity <- validity+active_write*(1-bound_before)*key',
    preregistered:false, external_attestation:false, trained_checkpoint_tested:false,
    first_stored_key_lost:{
      k1,second_key:anti,postwrite_validity:priorKeyLost,
      exact_postwrite_validity:['1/25','32/25'],
      prior_key_projection:oldProjection,known_probability:known(priorKeyLost,k1),
      expected_semantics:'k1 was written, yet readout calls it UNKNOWN with probability > 0.995'
    },
    unwritten_key_accepted:{
      k1,second_key:orth,unwritten_key:unseen,postwrite_validity:twoStored,
      exact_unwritten_projection:'7/5',
      unwritten_projection:unwrittenProjection,known_probability:known(twoStored,unseen),
      expected_semantics:'key never written, yet readout allocates > 0.99997 probability to known classes'
    },
    exact_erasure_control:{post_reset_validity:[0,0],known_probability:known([0,0],k1)},
    binary32_controls:{known_written_key_probability:fKnown,unwritten_key_known_probability:fUnknown},
    p0_to_p6:Object.fromEntries(Array.from({length:7},(_,i)=>['P'+i,'OPEN'])),
    production_activation:false,pass_scope:'LIMITED_COUNTEREXAMPLE_ONLY'
  };
}
if (process.argv[1] && import.meta.url.endsWith(process.argv[1].replaceAll('\\','/'))) {
  const result=evidence();
  process.stdout.write(JSON.stringify(result,null,2)+'\n');
  if (process.argv.includes('--strict')) process.exitCode=2;
}
