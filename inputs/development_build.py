"""Run a fresh explicit development compiler chain and new launcher packaging."""
from pathlib import Path
import json
import sys

ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'source'))
from tests.test_hia_release_launch import prepare_development

if __name__=='__main__':
    output=Path(sys.argv[1])
    result=prepare_development(output)
    print(json.dumps({'status':result['status'],'output':str(output),
        'executables':{name:row['sha256'] for name,row in result['executables'].items()},
        'policy_sha256':result['policy_sha256'],'matching_cold':False,
        'whole_native':False},sort_keys=True))
