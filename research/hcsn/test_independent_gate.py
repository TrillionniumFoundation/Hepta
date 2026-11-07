"""These are integrity-protocol tests only, NOT evidence of P0–P6 closure."""
from __future__ import annotations
import base64
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
try:from .independent_gate import SCHEMA,TOPICS,verify,_canonical
except ImportError:from independent_gate import SCHEMA,TOPICS,verify,_canonical

class SignatureProtocolTests(unittest.TestCase):
    def test_missing_trust_fails_closed_and_cannot_trigger_production(self):
        r=verify(Path(__file__).parent)
        self.assertFalse(r['full_closure']);self.assertFalse(r['production_activation'])
        self.assertEqual(len(r['gates']),7)
        self.assertTrue(all(v['status']=='OPEN' for v in r['gates'].values()))

    def _fixture(self,tmp:Path):
        source=tmp/'source_repo';source.mkdir()
        bundle=source/'bundle';bundle.mkdir()
        release_root=tmp/'external_trust';release_root.mkdir()
        trust=release_root/'release_root.json'
        protocol=b'{"registered_before_evaluation":true,"fixture_only":true}\n'
        (bundle/'preregistration.json').write_bytes(protocol)
        keys={role:Ed25519PrivateKey.generate() for role in ('evaluator','observer')}
        pub={role:keys[role].public_key().public_bytes(
            encoding=serialization.Encoding.Raw,format=serialization.PublicFormat.Raw).hex() for role in keys}
        sha=lambda x:hashlib.sha256(x).hexdigest()
        # Synthetic fixture never used by the real research gate or user report.
        content=b'{"fixture_only":true,"verified_results":false}\n'
        (bundle/'fixture.txt').write_bytes(content)
        gates={p:{'topics':{t:{'accepted':True,'file':'fixture.txt','sha256':sha(content)}
                             for t in topics}} for p,topics in TOPICS.items()}
        evidence={'schema':SCHEMA,'repo':'TrillionniumFoundation/Hepta',
                  'source_commit':'a'*40,'preregistration_sha256':sha(protocol),'gates':gates}
        (bundle/'evidence.json').write_text(json.dumps(evidence,sort_keys=True)+'\n')
        h=sha(_canonical(evidence))
        signed=b'HCSN-EVIDENCE-V2\0'+bytes.fromhex(h)
        signatures={role:base64.b64encode(keys[role].sign(signed)).decode() for role in keys}
        (bundle/'attestations.json').write_text(json.dumps({'schema':SCHEMA,
                   'evidence_sha256':h,'signatures':signatures}))
        trust.write_text(json.dumps({'schema':SCHEMA,'allowed_source_commit':'a'*40,
                                    'trusted_roles':pub}))
        return bundle,trust

    def test_synthetic_signed_fixture_is_technically_verifiable_not_scientific_proof(self):
        with tempfile.TemporaryDirectory() as root:
            d=Path(root);bundle,trust=self._fixture(d)
            r=verify(bundle,trust)
            self.assertTrue(r['independent_attestation_verified'])
            self.assertTrue(r['full_closure']) # technical protocol; fake fixture is not live evidence
            self.assertFalse(r['production_activation'])
            self.assertTrue(all(not z['production_ready'] for z in r['gates'].values()))
            try:
                from .gate_evidence import make_manifest
            except ImportError:
                from gate_evidence import make_manifest
            integrated=make_manifest(bundle,trust)
            self.assertTrue(integrated['full_closure'])  # synthetic protocol fixture only
            self.assertFalse(integrated['production_activation'])

    def test_tampering_and_public_key_swap_fail_closed(self):
        with tempfile.TemporaryDirectory() as root:
            d=Path(root);bundle,trust=self._fixture(d)
            (bundle/'fixture.txt').write_text('tampered')
            r=verify(bundle,trust)
            self.assertFalse(r['full_closure'])
            self.assertTrue(all(z['status']=='OPEN' for z in r['gates'].values()))
        with tempfile.TemporaryDirectory() as root:
            d=Path(root);bundle,trust=self._fixture(d)
            j=json.loads(trust.read_text())
            j['trusted_roles']['observer']=j['trusted_roles']['evaluator']
            trust.write_text(json.dumps(j))
            r=verify(bundle,trust)
            self.assertFalse(r['full_closure'])

    def test_no_self_declared_trust_root(self):
        with tempfile.TemporaryDirectory() as root:
            d=Path(root);bundle,trust=self._fixture(d)
            internal=bundle/'root.json';internal.write_bytes(trust.read_bytes())
            r=verify(bundle,internal)
            self.assertFalse(r['full_closure'])

if __name__=='__main__':unittest.main()
