"""Create an explicit Page/wire Worker base pin; grant no build qualification."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path

from hepta import hia_native_helpers as authority
from hepta.hia_artifact_page_worker_bundle import SCHEMA, BASE_SCHEMAS


def build(output, *, base_bundle, base_sha256, page_bundle, portable=False):
    output = Path(output)
    base = authority._read(Path(base_bundle).absolute(), authority.MAX_BUNDLE_BYTES)
    page = authority._read(Path(page_bundle).absolute(), 8192)
    if not authority._digest(base_sha256) or sha256(base.raw).hexdigest() != base_sha256:
        raise ValueError('base Worker bundle pin differs')
    base_value = authority._decode(base.raw)
    page_value = authority._decode(page.raw)
    if type(base_value) is not dict or base_value.get('schema') not in BASE_SCHEMAS:
        raise ValueError('Page Worker composition requires a v1/v2/v3 helper base')
    if type(page_value) is not dict or page_value.get('schema') != 'hepta.hia.artifact-page-bundle.v2':
        raise ValueError('Page Worker composition requires an explicit Page bundle')
    parent = output.absolute().parent
    base_name = base.path.relative_to(parent).as_posix() if portable else str(base.path)
    page_name = page.path.relative_to(parent).as_posix() if portable else str(page.path)
    record = {'schema': SCHEMA, 'target': authority.TARGET, 'abi': authority.ABI,
              'base_bundle': base_name, 'base_bundle_sha256': base_sha256,
              'page_bundle': page_name, 'page_bundle_sha256': sha256(page.raw).hexdigest()}
    raw = (json.dumps(record, sort_keys=True, indent=2) + '\n').encode()
    if (authority._read(base.path, authority.MAX_BUNDLE_BYTES) != base
            or authority._read(page.path, 8192) != page):
        raise ValueError('Worker composition inputs changed')
    with output.open('xb') as stream:
        stream.write(raw)
    if (output.read_bytes() != raw or authority._read(base.path, authority.MAX_BUNDLE_BYTES) != base
            or authority._read(page.path, 8192) != page):
        raise ValueError('Worker composition changed before publication')
    return output


def stage_installed(output, scratch, release, compiler, cold_report, base_bundle):
    """Recompile both Page leaves and compare all bytes with the installed Store."""
    from tools.build_hia_artifact_page import build as build_page
    from tools.build_hia_worker_release import _copy_report
    output, scratch, release = Path(output), Path(scratch), Path(release)
    page = _copy_report(build_page(scratch / 'artifact-page', compiler, cold_report),
                        output / 'page')
    captured = {}
    for name, kind in (('policy', 'artifact-page-policy'), ('wire', 'json-wire')):
        installed = release / (kind + '-manifest.json')
        original = authority._read(installed, authority.MAX_MANIFEST_BYTES)
        built_path = page.parent / name / 'manifest.json'
        built = authority._read(built_path, authority.MAX_MANIFEST_BYTES)
        if original.raw != built.raw:
            raise ValueError('installed Page manifest differs from its matching cold rebuild: ' + kind)
        record = authority._decode(built.raw)
        image_name = record['image_path']
        old_image = authority._read(release / image_name, authority.MAX_IMAGE_BYTES)
        new_image = authority._read(built_path.parent / image_name, authority.MAX_IMAGE_BYTES)
        if (old_image.raw != new_image.raw
                or sha256(new_image.raw).hexdigest() != record['image_sha256']):
            raise ValueError('installed Page image differs from its matching cold rebuild: ' + kind)
        for item, limit in ((original, authority.MAX_MANIFEST_BYTES),
                            (built, authority.MAX_MANIFEST_BYTES),
                            (old_image, authority.MAX_IMAGE_BYTES),
                            (new_image, authority.MAX_IMAGE_BYTES)):
            captured[item.path] = (item, limit)
    base = authority._read(Path(base_bundle).absolute(), authority.MAX_BUNDLE_BYTES)
    result = build(output / 'page-worker.json', base_bundle=base.path,
                   base_sha256=sha256(base.raw).hexdigest(), page_bundle=page, portable=True)
    result_capture = authority._read(result.absolute(), authority.MAX_BUNDLE_BYTES)
    for original, limit in captured.values():
        if authority._read(original.path, limit) != original:
            raise ValueError('installed Page input changed after its actual rebuild')
    if (authority._read(base.path, authority.MAX_BUNDLE_BYTES) != base
            or authority._read(result_capture.path, authority.MAX_BUNDLE_BYTES) != result_capture):
        raise ValueError('installed Page Worker composition changed before publication')
    result.chmod(0o400)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-bundle', type=Path, required=True)
    parser.add_argument('--base-sha256', required=True)
    parser.add_argument('--page-bundle', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = build(args.output, base_bundle=args.base_bundle,
                   base_sha256=args.base_sha256, page_bundle=args.page_bundle)
    print(json.dumps({'path': str(result), 'sha256': sha256(result.read_bytes()).hexdigest(),
                      'qualification_granted': False}))


if __name__ == '__main__':
    main()
