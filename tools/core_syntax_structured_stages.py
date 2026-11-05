"""Compose bounded structured certificates into the unchanged ten-module DAG.

This builds proposals and independently checks their full input representations;
it does not run Lean or admit any proof.
"""
from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
import re
from types import MappingProxyType

from tools import core_syntax_stage_sources as legacy
from tools import check_core_syntax_lean as original

ROOT = Path(__file__).resolve().parents[1]
HELPERS = ROOT/'experiments/hia_initialization_frontiers_20261103/StructuredTransport.lean'
PROTOCOL = 'structured-prefix-certificates-v1'
require = legacy.require


def digest(data):
    return sha256(data).hexdigest()


def helper_source():
    source = HELPERS.read_text()
    require(not re.search(r'(?m)^\s*(import|prelude|set_option|axiom|unsafe|opaque|constant|initialize|run_cmd|run_elab)\b|\b(sorry|native_decide)\b',source),
            'forbidden structured helper command')
    names = re.findall(r'(?m)^theorem (\w+)',source)
    require(len(names)==29 and len(set(names))==29, 'structured helper inventory')
    return source,frozenset('HiaCoreSyntaxSlice.Structured.'+n for n in names)


def build_inputs():
    from tools.core_syntax_structured_sources import build_structured_input
    old = legacy.build_inputs()
    monolithic = original.build_inputs()
    helper,helper_names = helper_source()
    stages = list(old['stages'])
    manifest = json.loads(old['manifest_json'])
    certificates,bindings = {},{}
    for key,namespace,stem,module in legacy.INPUT_LAYOUT:
        prior = monolithic['positive'] if key in ('linear','parallel') else monolithic['negatives'][key]['source']
        literal = legacy._definition(prior,stem+'Bytes','List Nat')
        raw = legacy._bytes(literal)
        tree = original.strict_canonical(raw)
        full_namespace = legacy.NAMESPACE+('.'+namespace if namespace else '')
        cert = stem if key in ('linear','parallel') else 'mutated'
        value = build_structured_input(key,tree,raw,full_namespace,stem,cert)
        proposal = json.loads(value.manifest_json)
        require(digest(value.manifest_json.encode())==value.manifest_sha256,'structured manifest identity')
        certificates[key] = {'source':value.source,'manifest':proposal,
                             'manifest_sha256':value.manifest_sha256}
        bindings[key] = {'tree':tree,'bytes':raw}
        index = next(i for i,s in enumerate(stages) if s.name==module)
        before = stages[index]
        expected = frozenset(value.expected_theorems)
        require(before.expected_theorems<=expected, 'original six transport facts missing')
        source = 'import '+legacy.MODULE_PREFIX+'.SyntaxData\n'+value.source+legacy._printed(expected)
        stages[index] = replace(before,source=source,expected_theorems=expected)
    stages[1] = replace(stages[1],source=stages[1].source+helper+legacy._printed(helper_names),
                        expected_theorems=stages[1].expected_theorems|helper_names)
    for stage in stages:
        original.checked_source((stage.source,))
    total = sum(s.source_bytes for s in stages)
    require(total<=original.MAX_TOTAL_PROOF_BYTES,'aggregate structured proof source budget')
    manifest.update(protocol=PROTOCOL,structured_helper_sha256=digest(helper.encode()),
                    structured_helper_theorems=sorted(helper_names),
                    structured_certificates={k:v['manifest'] for k,v in certificates.items()},
                    structured_certificate_sha256={k:v['manifest_sha256'] for k,v in certificates.items()},
                    stages=[s.manifest() for s in stages],proof_input_bytes=total)
    encoded = json.dumps(manifest,sort_keys=True,separators=(',', ':'))
    result = {**old,'stages':tuple(stages),'sources':MappingProxyType({s.module_name:s.source for s in stages}),
              'manifest':manifest,'manifest_json':encoded,'manifest_sha256':digest(encoded.encode()),
              'structured_certificates':certificates,'binding_inputs':bindings}
    validate_bindings(result)
    return result


def validate_bindings(prepared):
    from tools.core_syntax_structured_sources import verify_structured_source
    manifest = prepared['manifest']
    require(manifest.get('protocol')==PROTOCOL,'structured protocol required')
    helper,names = helper_source()
    require(manifest['structured_helper_sha256']==digest(helper.encode()) and
            manifest['structured_helper_theorems']==sorted(names),'structured helper binding')
    known = {s.name:s for s in prepared['stages']}
    require(known['SyntaxData'].source.count(helper)==1 and names<=known['SyntaxData'].expected_theorems,
            'structured helpers missing from checked module')
    expected_keys = {r[0] for r in legacy.INPUT_LAYOUT}
    require(set(prepared['binding_inputs'])==set(prepared['structured_certificates'])==expected_keys,
            'all five structured bindings required')
    for key,namespace,stem,module in legacy.INPUT_LAYOUT:
        binding = prepared['binding_inputs'][key]
        raw = binding['bytes']
        tree = original.strict_canonical(raw)
        require(tree==binding['tree'],'independent canonical tree differs')
        old = manifest['inputs'][key]
        full_namespace = legacy.NAMESPACE+('.'+namespace if namespace else '')
        expected_cert = stem if key in ('linear','parallel') else 'mutated'
        require(digest(raw)==old['canonical_sha256'] and len(raw)==old['canonical_bytes'] and
                digest(original.render_raw(tree).encode())==old['raw_literal_sha256'] and
                digest(original.render_bytes(raw).encode())==old['byte_literal_sha256'],
                'original complete input binding differs')
        value = prepared['structured_certificates'][key]
        require(value['manifest']['key']==key and value['manifest']['namespace']==full_namespace and
                value['manifest']['stem']==stem and value['manifest']['cert']==expected_cert,
                'structured proof names differ from original input')
        encoded = json.dumps(value['manifest'],sort_keys=True,separators=(',', ':'))
        require(digest(encoded.encode())==value['manifest_sha256']==manifest['structured_certificate_sha256'][key]
                and value['manifest']==manifest['structured_certificates'][key], 'structured certificate identity differs')
        verify_structured_source(value['source'],value['manifest'],tree,raw)
        stage = known[module]
        require(stage.expected_theorems==frozenset(value['manifest']['expected_theorems']),
                'complete structured theorem inventory differs')
        require(stage.source=='import '+legacy.MODULE_PREFIX+'.SyntaxData\n'+value['source']+
                legacy._printed(stage.expected_theorems),'structured checked source differs')
        require(old['definition_module']==stage.module_name,'structured input module differs')
