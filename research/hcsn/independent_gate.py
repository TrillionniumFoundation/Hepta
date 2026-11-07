"""HCSN evidence-based P0-P6 release eligibility gate.

This gate is *not* a scientific theorem or a production deployment switch.
It verifies independently signed, preregistered, hashed evidence records against
an externally managed trust root. Zero trusted keys and zero evidence => OPEN.
There is no permanently hardcoded `full_closure=False`: external evidence can
advance an individually reviewed research gate once independently attested.

The public-key trust root MUST be managed outside the repository and outside
the evidence bundle, by a separate release authority. Never commit private
keys, install default keys, or accept evidence-authored trust roots.

Attested topic verdicts are review claims, not mechanized proof that a scientific
experiment was fair or that a system can run on production hardware.
"""
from __future__ import annotations

import argparse
import binascii
import base64
import hashlib
import json
from pathlib import Path
import re

SCHEMA='hcsn.independently-reviewed-gate.v2'
TOPICS={
 'P0': ('original_hx_a7','independent_numerics','global_parameter_domain','qvi_regeneration',
        'boundary_extremes','low_precision'),
 'P1': ('call_put_margin_ablations','parameter_match','signed_slope_match',
        'compute_match','independent_heldout_gain','negative_transfer'),
 'P2': ('selective_copy','mqar','long_joint_recall','irregular_timing',
        'trained_multiple_resets','gradient_stability','event_semantics'),
 'P3': ('text_encoder','speech_encoder','vision_encoder','video_encoder',
        'transformer_baseline','mamba_baseline','spiking_ssm_baseline','equal_compute'),
 'P4': ('heldout_temporal_alignment','entity_linking','missing_modality',
        'crossmodal_retrieval','negative_transfer'),
 'P5': ('cpu_sustained_throughput','gpu_sustained_throughput','real_hardware_energy',
        'peak_rss','p95_p99_end_to_end','fused_kernel','quantized_equivalence'),
 'P6': ('medium_pretrained_encoder','distillation','continued_pretraining',
        'long_context','frozen_budget','quality_cost_frontier')
}
HEX64=re.compile(r'^[a-f0-9]{64}$')
HEX40=re.compile(r'^[a-f0-9]{40}$')


def _canonical(o):
    return (json.dumps(o,sort_keys=True,separators=(',',':'),ensure_ascii=False)+'\n').encode('utf-8')


def _sha(data:bytes)->str:
    return hashlib.sha256(data).hexdigest()


def _inside(parent:Path,child:Path)->bool:
    try:child.relative_to(parent);return True
    except ValueError:return False


def _load(path:Path)->dict:
    v=json.loads(path.read_text('utf-8'))
    if not isinstance(v,dict):raise ValueError('Expected JSON object')
    return v


def verify(bundle:Path,trust_root:Path|None=None)->dict:
    """Return verifiable release *eligibility*, always fail-closed on defects."""
    gates={p:{'status':'OPEN','production_ready':False,'reasons':[]} for p in TOPICS}
    output={'schema':SCHEMA,'gates':gates,'full_closure':False,
            'production_activation':False,'independent_attestation_verified':False}
    if trust_root is None:
        reason='External trust root not configured'
        for p in gates:gates[p]['reasons'].append(reason)
        return output
    bundle=bundle.resolve();trust_root=trust_root.resolve()
    if _inside(bundle,trust_root) or _inside(bundle.parent,trust_root):
        for p in gates:gates[p]['reasons'].append('Trust root must be independently provisioned outside source/evidence tree')
        return output
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        evidence=_load(bundle/'evidence.json')
        att=_load(bundle/'attestations.json')
        trusted=_load(trust_root)
        if evidence.get('schema')!=SCHEMA or att.get('schema')!=SCHEMA or trusted.get('schema')!=SCHEMA:
            raise ValueError('Evidence/signature/trust schema mismatch')
        sha_source=evidence.get('source_commit')
        sha_reg=evidence.get('preregistration_sha256')
        if not isinstance(sha_source,str) or not HEX40.fullmatch(sha_source):raise ValueError('Invalid immutable source SHA')
        if not isinstance(sha_reg,str) or not HEX64.fullmatch(sha_reg):raise ValueError('Missing preregistration SHA256')
        if evidence.get('repo')!='TrillionniumFoundation/Hepta':raise ValueError('Wrong source repo')
        if trusted.get('allowed_source_commit')!=sha_source:raise ValueError('Commit not preapproved by release authority')
        protocol=bundle/'preregistration.json'
        if _sha(protocol.read_bytes())!=sha_reg:raise ValueError('Changed preregistration')
        data=_canonical(evidence)
        expected_digest=_sha(data)
        if expected_digest != att.get('evidence_sha256'):raise ValueError('Attestation digest mismatch')
        roles=trusted.get('trusted_roles',{})
        if set(roles)!={'evaluator','observer'} or roles['evaluator']==roles['observer']:
            raise ValueError('Require two distinct evaluator/observer public keys')
        signatures=att.get('signatures',{})
        if set(signatures)!={'evaluator','observer'}:raise ValueError('Missing independent signatures')
        signed=b'HCSN-EVIDENCE-V2\x00'+bytes.fromhex(expected_digest)
        for role in ('evaluator','observer'):
            pub=Ed25519PublicKey.from_public_bytes(bytes.fromhex(roles[role]))
            sig=base64.b64decode(signatures[role],validate=True)
            pub.verify(sig,signed)
        output['independent_attestation_verified']=True
        gate_data=evidence.get('gates')
        if not isinstance(gate_data,dict):raise ValueError('No per-phase evidence map')
        for phase, topics in TOPICS.items():
            d=gate_data.get(phase,{})
            items=d.get('topics',{}) if isinstance(d,dict) else {}
            if not isinstance(items,dict):items={}
            reasons=[]
            for topic in topics:
                t=items.get(topic,{})
                if not isinstance(t,dict) or t.get('accepted') is not True:
                    reasons.append(f'{topic}: independent acceptance missing')
                    continue
                rel=t.get('file');sha=t.get('sha256')
                if not isinstance(rel,str) or not rel or rel.startswith('/') or '..' in Path(rel).parts or not isinstance(sha,str) or not HEX64.fullmatch(sha):
                    reasons.append(f'{topic}: invalid evidence locator/digest');continue
                target=(bundle/rel).resolve()
                if not _inside(bundle,target) or not target.is_file():
                    reasons.append(f'{topic}: evidence file unavailable or escaped bundle');continue
                if _sha(target.read_bytes())!=sha:
                    reasons.append(f'{topic}: artifact digest mismatch')
            if reasons:gates[phase]['reasons']=reasons
            else:
                gates[phase].update({'status':'INDEPENDENTLY_ATTESTED','production_ready':False,
                                     'reasons':['Scientific assurance is limited to independently audited evidence; separate deployment authorization required']})
        output['full_closure']=all(g['status']=='INDEPENDENTLY_ATTESTED' for g in gates.values())
        return output
    except (OSError,ValueError,TypeError,KeyError,InvalidSignature,binascii.Error,AttributeError) as e:
        for p in gates:gates[p]['reasons'].append(f'Evidence validation failed: {type(e).__name__}: {e}')
        return output


if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('--bundle',type=Path,required=True)
    p.add_argument('--trust-root',type=Path,default=None)
    p.add_argument('--output',type=Path,default=None)
    p.add_argument('--strict',action='store_true')
    a=p.parse_args()
    result=verify(a.bundle,a.trust_root)
    if a.output:
        if a.output.exists():p.error('Refusing evidence output overwrite')
        a.output.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    else:print(json.dumps(result,indent=2,sort_keys=True))
    if a.strict and not result['full_closure']:raise SystemExit(2)
