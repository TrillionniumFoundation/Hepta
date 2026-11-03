# Historical round-six tool source recovery

This directory preserves five Python audit and packaging tools from the surviving local Hepta round-six work area. Their bytes are unchanged. It adds no production-code edits and grants no new test, safety, performance or research qualification.

## Identities and scope

- Source under review: `9fa9e957a9ebc7b34b4018fd4b83d863ebbc717b`, tree `debee7040ed2ffac2cbaf953c28c1e2ca3fc8407`.
- Existing evidence publication: `ae391617e983b04d21b65f7915151623e8b45ba1`, directory `evidence/hia_round6_ci_recovered_20261029/`.
- `SOURCE_MANIFEST.json` records each script's original path, SHA-256, Git blob identity, byte size and mode, plus required input identities and existing remote sources.
- The prior `RESTORE.original.py` already exists at commit `999c63cae7a3143050a1ac71b66f5e040e489ab1`, path `evidence/hia_round5_recovered_20261029/RESTORE.py`; fresh remote text matched all 8,000 local bytes. It is not duplicated here.

## Verify the preserved source

From this directory, run the following read-only check. It parses the scripts without importing or executing them.

```sh
python3 - <<'PYVERIFY'
import ast, hashlib, json
from pathlib import Path
m = json.loads(Path('SOURCE_MANIFEST.json').read_text())
for row in m['files']:
    b = Path(row['path']).read_bytes()
    assert len(b) == row['bytes']
    assert hashlib.sha256(b).hexdigest() == row['sha256']
    assert hashlib.sha1(b'blob ' + str(len(b)).encode() + b'\0' + b).hexdigest() == row['git_blob_sha1']
    ast.parse(b.decode('utf-8'))
print('Verified', len(m['files']), 'historical source files')
PYVERIFY
```

## Reproduction inputs and behavior

These are preserved producer tools with fixed filesystem paths, commit identities and historical assertions. Source custody does not imply that running them from an arbitrary checkout recreates their results.

| Tool | Required inputs and behavior |
| --- | --- |
| `packager.py` | Exact source checkout; `INPUT_SELECTION.json` and the explicitly selected `round6-recovery/` inputs; hashes all members, assembles the historical TAR/XZ and invokes its verification reader. It requires fresh output destinations. |
| `publication_plan.py` | Exact clean source checkout and all 21 files of the historical evidence prefix; computes Git objects and publication manifests, writes a local backup, and refuses existing output files. It does not push Git refs. |
| `independent_final_audit.py` | Frozen selection, manifests, archive parts, original CI artifacts, source checkout and saved API observations; independently checks the historical package and writes its audit report. |
| `independent_remote_audit.py` | The exact saved GitHub GET response envelopes under `independent-remote-readback/` and frozen upload plan; verifies published object identities and writes its report. |
| `write_readme.py` | Historical archive, verification, selection and component reports; writes the historical summary and README. Embedded historical numbers remain historical. |

The manifest identifies primary local inputs and existing immutable remote files. It does not include logs, binary archives or saved API response envelopes. For a historical replay, reconstruct the original declared input set and directory layout, verify every referenced hash, then use a separate empty output area. Do not treat absent original input bytes as permission to synthesize successful records.

No historical scripts were executed for this source publication. Python AST parsing, source-byte checks and remote Git object readback are the validation for this recovery. The original dot host and active experiments remain outside this executor's observed scope.
