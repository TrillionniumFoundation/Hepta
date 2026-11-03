"""Isolated adapter wiring checks; fake CFG/SSA stand-ins, not native qualification."""
import importlib
import json
import hashlib
from dataclasses import dataclass
from pathlib import Path
import sys
import types
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from test_hsir_v1 import pr14, pr36, signed
from hepta.hsir_v1 import integrate_v0


def sha_json(data):
    s = json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    return s, hashlib.sha256(s.encode()).hexdigest()


@dataclass
class Snap:
    schema: str
    canonical_json: str
    sha256: str
    def as_dict(self):
        return {**json.loads(self.canonical_json), 'sha256': self.sha256}


def lower_cfg(hsir):
    if hsir.schema != 'hepta.hsir.v0' or hsir.sha256 != hashlib.sha256(hsir.canonical_json.encode()).hexdigest():
        raise ValueError('bad source')
    d = json.loads(hsir.canonical_json)
    s, digest = sha_json({'source_hsir_sha256': hsir.sha256, 'source_sha256':d['source_sha256']})
    return Snap('hepta.cfg.v0', s, digest)


def lower_ssa(cfg):
    s, digest = sha_json({'source_cfg_sha256': cfg.sha256})
    return Snap('hepta.ssa.scalar.v0', s, digest)


def verify_ssa(ssa, cfg):
    s, digest = sha_json({'cfg_sha256': cfg.sha256, 'ssa_sha256': ssa.sha256})
    return Snap('hepta.ssa.verify.v0', s, digest)


for name, contents in [('hepta.hsir', {'HSIRSnapshot': Snap}),
                        ('hepta.cfg', {'lower_hsir_cfg': lower_cfg}),
                        ('hepta.ssa', {'lower_cfg_scalar_ssa': lower_ssa}),
                        ('hepta.ssa_verify', {'verify_scalar_ssa': verify_ssa})]:
    module = types.ModuleType(name)
    vars(module).update(contents)
    sys.modules[name] = module
from hepta.hsir_v1_ssa import lower_verified_v1_scalar_ssa, V1SSARejected


class LocalAdapterTests(unittest.TestCase):
    def test_legacy_frozen_producer_roundtrip(self):
        e=integrate_v0(pr36())
        x=lower_verified_v1_scalar_ssa(e)
        self.assertEqual(x['source_hsir_v1_sha256'],e['sha256'])
        self.assertTrue(x['claims']['structural_ssa_verified'])
        self.assertFalse(x['claims']['native_codegen_qualified_by_adapter'])
        self.assertEqual(x,lower_verified_v1_scalar_ssa(e))

    def test_incompatible_producer_fails(self):
        with self.assertRaisesRegex(V1SSARejected,'UNSUPPORTED_PRODUCER'):
            lower_verified_v1_scalar_ssa(integrate_v0(pr14()))

    def test_foreign_assumptions_fail_even_with_valid_digest(self):
        record=pr36()
        record["external_assumptions"]=[{"function":"foreign", "proved":False}]
        record=signed(record)
        with self.assertRaisesRegex(V1SSARejected,"FOREIGN_ASSUMPTIONS"):
            lower_verified_v1_scalar_ssa(integrate_v0(record))

    def test_altered_claim_fails(self):
        e=integrate_v0(pr36()); e['claims']['memory_safety_proved']=True
        with self.assertRaisesRegex(V1SSARejected,'IDENTITY'):
            lower_verified_v1_scalar_ssa(e)

if __name__=='__main__':unittest.main()
