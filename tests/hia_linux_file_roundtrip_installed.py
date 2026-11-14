"""Read only the installed explicit profile; never grant cold from a manifest.

This fresh -I -S child checks the real installed wheel's resource origin and
the copied cold-built ELF bytes before the parent's independent kernel run.
The report is an installation observation, not native or cold qualification.
"""
from pathlib import Path
import hashlib
import json
import stat
import sys


def main(argv):
    assert len(argv) == 2
    request_path = Path(argv[1]).resolve(strict=True)
    raw = request_path.read_bytes(); request = json.loads(raw)
    assert type(request) is dict and set(request) == {
        'installed', 'bundle', 'profile', 'profile_identity', 'executable_sha256', 'executable_bytes'}
    installed = Path(request['installed']).resolve(strict=True)
    sys.path.insert(0, str(installed))
    from hepta import hia_optional_profiles as optional
    from hepta.hia_linux_file_roundtrip import PROFILE, PROFILE_SOURCE_FILES
    assert request['profile'] == PROFILE
    assert Path(optional.__file__).resolve().is_relative_to(installed)
    identity, captured_sources = optional.fresh_profile_capture(PROFILE)
    assert identity == request['profile_identity']
    assert type(captured_sources) is dict and set(captured_sources) == set(PROFILE_SOURCE_FILES)
    paths = {name: str(optional.optional_profile_resource_path(PROFILE, name).resolve(strict=True))
             for name in PROFILE_SOURCE_FILES}
    for name, value in paths.items():
        path = Path(value)
        asset = captured_sources[name]
        assert path.is_relative_to(installed) and type(asset) is bytes and asset
        assert identity['files'][name] == {'bytes': len(asset), 'sha256': hashlib.sha256(asset).hexdigest()}
    bundle = Path(request['bundle']).resolve(strict=True)
    optional.guard_profile_identity(PROFILE, identity, resource_root=bundle / 'resources')
    executable = bundle / 'bin/hia-native-file-roundtrip'
    mode = executable.lstat().st_mode
    assert stat.S_ISREG(mode) and stat.S_IMODE(mode) == 0o500
    image = executable.read_bytes()
    assert type(request['executable_bytes']) is int and 0 < len(image) <= 1048576
    assert len(image) == request['executable_bytes']
    assert hashlib.sha256(image).hexdigest() == request['executable_sha256']
    optional.guard_profile_identity(PROFILE, identity)
    assert request_path.read_bytes() == raw
    print(json.dumps({'schema': 'hepta.hia.roundtrip-installed-observation.v1',
        'profile': PROFILE, 'identity': identity, 'paths': paths,
        'optional_module': str(Path(optional.__file__).resolve()),
        'executable_bytes': len(image), 'executable_sha256': hashlib.sha256(image).hexdigest(),
        'actual_kernel_execution': False, 'matching_cold': False,
        'whole_native': False, 'request_sha256': hashlib.sha256(raw).hexdigest()}, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
