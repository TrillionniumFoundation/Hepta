"""Actual Python 3.11 default behavior and explicit unsupported ABI refusal."""
from __future__ import annotations
import base64
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import zlib


def main():
    source,packet_path,output=(Path(p).resolve() for p in sys.argv[1:])
    if sys.version_info[:2]!=(3,11):
        raise ValueError('an actual Python 3.11 interpreter is required')
    output.mkdir()
    sys.path.insert(0,str(source))
    from hepta import hia_agent_service as api
    from hepta import hia_service_requests_native as native
    if 'hepta.hia_service_requests_foreign' in sys.modules or native._mapped_requests.cache_info().currsize:
        raise ValueError('default import entered fixed native ABI ports or mapping')
    value=api.HIAAgentService._examples()
    if value['schema']!='hepta.hia.agent.examples.v1' or 'hepta.hia_service_requests_foreign' in sys.modules:
        raise ValueError('default static example entered native ABI ports')
    packet=json.loads(packet_path.read_bytes())
    image=zlib.decompress(base64.b64decode(packet['zlib_base64'],validate=True))
    if len(image)!=packet['bytes'] or sha256(image).hexdigest()!=packet['sha256']:
        raise ValueError('exact local development image differs')
    name='original-development.image.bin'
    (output/name).write_bytes(image)
    manifest={'schema':native.SCHEMA,'source_sha256':sha256(native.SOURCE.read_bytes()).hexdigest(),
        'image_path':name,'image_sha256':packet['sha256'],'compiler_sha256':packet['compiler_sha256']}
    path=output/'unsupported-development-manifest.json'
    path.write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n')
    effects=[]
    original=native.RequestsFrame._effect
    def forbidden(self):
        effects.append('business-effect')
        raise AssertionError('unsupported ABI entered business effects')
    native.RequestsFrame._effect=forbidden
    error=None
    try:
        native.installed_requests(path)
    except RuntimeError as caught:
        error={'type':type(caught).__name__,'message':str(caught)}
    finally:
        native.RequestsFrame._effect=original
    if error is None or 'reviewed CPython ABI' not in error['message'] or effects:
        raise AssertionError('unsupported selected ABI did not refuse at the explicit primitive boundary')
    report={'status':'PASS','python':sys.version,'default_import_native_ports':False,
        'default_example_schema':value['schema'],'selected_native_refusal':error,
        'selected_business_effects':effects,'current_source_cold':False,
        'whole_native':False,'scope':'ACTUAL_311_DEFAULT_AND_UNSUPPORTED_SELECTION_ONLY'}
    (output/'REPORT.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    print(json.dumps(report,sort_keys=True))


if __name__=='__main__':
    main()
