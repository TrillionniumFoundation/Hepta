#!/usr/bin/env python3
"""Freeze a new matrix-specific CLI launcher without invoking a model."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0,str(ROOT))

from tools.hia_macro_exec_adapter import DISABLED_FEATURES
from tools.hia_agent_codex_transport import identity
from tools.hia_macro_multistep_provider import RESPONSE_SCHEMA, encoded
from tools.qualify_hia_macro_campaign import _json,_read_regular,_new_file


def prepare(registration_path,feature_list_path,output,*,real_cli,model,campaign_root):
    output = Path(output).absolute()
    output.mkdir(mode=0o700,exist_ok=False)
    reg = _json(_read_regular(registration_path))
    rows = [r for r in reg['tasks'] if r['purpose'] != 'firstuse']
    if len(rows) != 6 or len({r['id'] for r in rows}) != 6:
        raise ValueError('exact six-task registered matrix required')
    feature_raw = _read_regular(feature_list_path)
    registry = {}
    for line in feature_raw.decode().splitlines():
        parsed = re.fullmatch(r'([a-z][a-z0-9_.]*)\s+(.+?)\s+(true|false)',line.strip())
        if not parsed:
            raise ValueError('unexpected original feature-list shape')
        registry[parsed[1]] = parsed[2]
    if any(name not in registry or registry[name] == 'removed'
           for name in (*DISABLED_FEATURES,'skip_host_skill_discovery')):
        raise ValueError('a required local restriction is not a registered usable feature')
    if type(model) is not str or not model or model.startswith('-'):
        raise ValueError('explicit model selector required')
    cli = identity(real_cli)
    source = (ROOT/'tools/hia_macro_exec_adapter.py').read_bytes()
    config = {'schema':'hepta.hia.explicit-codex-launch-config.v2','real_cli':cli,'model':model,
        'campaign_root':str(Path(campaign_root).absolute()),'task_ids':[r['id'] for r in rows],
        'max_rounds':3,'disabled_features':list(DISABLED_FEATURES),
        'feature_list_sha256':sha256(feature_raw).hexdigest(),
        'response_schema_sha256':sha256(encoded(RESPONSE_SCHEMA)+b'\n').hexdigest(),
        'adapter_module_sha256':sha256(source).hexdigest(),
        'registration_sha256':sha256(_read_regular(registration_path)).hexdigest()}
    # Keep __future__ first by adding only the interpreter line before source.
    raw = b'#!/usr/bin/python3 -I\n' + source + b'\nif __name__ == "__main__":\n    execute(' \
        + repr(config).encode() + b')\n'
    launcher = output/'codex_exec_v2.py'
    _new_file(launcher,raw)
    launcher.chmod(0o700)
    binding = {'schema':'hepta.hia.explicit-codex-binding.v2','launcher':identity(launcher),
        'underlying_cli':cli,'configuration':config,
        'model_calls':0,'argv_adaptation_only':True,'global_configuration_changed':False,
        'authorization_or_provider_compatibility_claim':False,
        'source_scope':'exact source module embedded, launcher and underlying CLI identities separately recorded',
        'complete_capability_isolation_attested':False}
    _new_file(output/'BINDING.json',encoded(binding)+b'\n')
    return binding


if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--registration',required=True)
    p.add_argument('--feature-list',required=True)
    p.add_argument('--output',required=True)
    p.add_argument('--real-cli',required=True)
    p.add_argument('--model',required=True)
    p.add_argument('--campaign-root',required=True)
    args=p.parse_args()
    result=prepare(args.registration,args.feature_list,args.output,real_cli=args.real_cli,
        model=args.model,campaign_root=args.campaign_root)
    print(json.dumps({'launcher':result['launcher'],'underlying_cli':result['underlying_cli'],'model_calls':0}))
