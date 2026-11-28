from pathlib import Path
import subprocess,json
p=Path('/home/qian-qi/hia-native-caller-selection-20261127-2ac5/original-ci-python-prerequisites-v1/bin/python')
print(json.dumps({'requested':str(p),'symlink':p.is_symlink(),'resolved':str(p.resolve(strict=True))}))
for candidate in (p,p.resolve(strict=True)):
 q=subprocess.run([str(candidate),'-B','-c','import sys,z3,jsonschema,json;print(json.dumps(dict(executable=sys.executable,prefix=sys.prefix,base_prefix=sys.base_prefix,z3=z3.get_version_string(),z3_file=z3.__file__)))'],capture_output=True)
 print(json.dumps({'candidate':str(candidate),'returncode':q.returncode,'stdout':q.stdout.decode(),'stderr':q.stderr.decode()},sort_keys=True))
