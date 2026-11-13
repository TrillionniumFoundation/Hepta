"""Root-approved private input capture only. No request, owner or network call.

The exact original proxy values stay in one mode0600 file outside the public
operation. Stdout contains only its immutable opaque seal and non-secret scope.
"""
from pathlib import Path
import importlib.util
import json
import os
import sys

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('full32_private_network_io', ROOT / 'control/local_io.py')
io = importlib.util.module_from_spec(spec); spec.loader.exec_module(io)

def main():
    io.require(len(sys.argv) == 1, 'fixed private input capture accepts no arguments')
    policy = io.json_value((ROOT / 'POLICY.json').read_bytes())
    path = Path(policy['proxy_configuration_path'])
    io.require(path.is_absolute() and path.parent == Path('/tmp') and not os.path.lexists(path),
               'fresh fixed private proxy input required; no overwrite or resume')
    configuration = io.capture_proxy_configuration(policy['operation_root'])
    pin = io.create(path, configuration)
    actual, actual_pin = io.read_private_proxy(path, policy['operation_root'], pin['sha256'])
    io.require(actual == configuration and actual_pin == pin
               and actual == io.capture_proxy_configuration(policy['operation_root']),
               'actual inherited proxy configuration changed during private capture')
    print(json.dumps({'status': 'PRIVATE_ORIGINAL_PROXY_INPUT_SEALED_NO_NETWORK', 'input': pin,
                      'values_never_published': True, 'network_requests': 0,
                      'owner_invocations': 0, 'receiver_invocations': 0}, sort_keys=True))
    return 0

if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except BaseException as error:
        print(json.dumps({'status': 'HOLD', 'error': io.safe_error(error),
                          'values_never_published': True}, sort_keys=True))
        raise SystemExit(1)
