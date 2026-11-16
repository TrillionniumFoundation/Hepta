"""Disposable, strictly pinned exec setup for the new release-builder controls.

This process is replaced by the captured ELF. It is qualification setup, not
part of the installed executable or a runtime provider for the HIA policy.
"""
from __future__ import annotations
import argparse
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import resource
import struct


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    args = parser.parse_args()
    request_raw = args.request.read_bytes()
    if len(request_raw) > 16384 or sha256(request_raw).hexdigest() != args.sha256:
        raise ValueError('exec-release child request byte pin differs')
    request = json.loads(request_raw)
    if (type(request) is not dict
            or set(request) != {'schema', 'image', 'image_sha256', 'input', 'input_sha256', 'arguments', 'mode'}
            or request['schema'] != 'hepta.hia.exec-release-exec-request.v1'
            or request['mode'] not in ('ordinary', 'closed-stdin', 'full-stdout', 'mmap-failure')
            or type(request['arguments']) is not list
            or len(request['arguments']) > 3
            or any(type(x) is not str or '\0' in x or len(x.encode()) > 4096
                   for x in request['arguments'])):
        raise ValueError('closed exec-release child request differs')
    path, source = Path(request['image']), Path(request['input'])
    if not path.is_absolute() or not source.is_absolute():
        raise ValueError('captured image and input paths must be absolute')
    image = path.read_bytes()
    if (sha256(image).hexdigest() != request['image_sha256'] or len(image) <= 176
            or image[:16] != b'\x7fELF\x02\x01\x01' + bytes(9)
            or struct.unpack_from('<HHIQQQIHHHHHH', image, 16)
               != (2, 62, 1, 0x4000b0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
            or struct.unpack_from('<IIQQQQQQ', image, 64)
               != (1, 5, 0, 0x400000, 0x400000, len(image), len(image), 4096)
            or struct.unpack_from('<IIQQQQQQ', image, 120)
               != (0x6474e551, 6, 0, 0, 0, 0, 0, 16)):
        raise ValueError('captured canonical executable bytes differ')
    fd = os.memfd_create('hia-exec-release-qualified-image', os.MFD_ALLOW_SEALING)
    transferred = False
    try:
        at = 0
        while at < len(image):
            count = os.write(fd, image[at:])
            if count <= 0:
                raise OSError('short executable capture')
            at += count
        fcntl.fcntl(fd, 1033, 15)
        if fcntl.fcntl(fd, 1034) & 15 != 15 or os.pread(fd, len(image) + 1, 0) != image:
            raise ValueError('captured executable seal/readback differs')
        os.set_inheritable(fd, True)
        input_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            with os.fdopen(os.dup(input_fd), 'rb') as stream:
                raw = stream.read()
            if sha256(raw).hexdigest() != request['input_sha256']:
                raise ValueError('actual opened input differs')
            os.lseek(input_fd, 0, os.SEEK_SET)
            os.dup2(input_fd, 0)
        finally:
            if input_fd != 0:
                os.close(input_fd)
        if request['mode'] == 'closed-stdin':
            os.close(0)
        if request['mode'] == 'full-stdout':
            output_fd = os.open('/dev/full', os.O_WRONLY | os.O_NOFOLLOW)
            try:
                os.dup2(output_fd, 1)
            finally:
                if output_fd != 1:
                    os.close(output_fd)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        if request['mode'] == 'mmap-failure':
            resource.setrlimit(resource.RLIMIT_AS, (2 << 20, 2 << 20))
        executable = '/proc/self/fd/' + str(fd)
        # execve replaces this complete Python image. No PATH resolution or
        # inherited Python/Hepta selection is available inside the ELF.
        os.execve(executable, [executable, *request['arguments']],
                  {'PATH': '', 'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC'})
        transferred = True  # unreachable if execve succeeds
    finally:
        if not transferred:
            os.close(fd)


if __name__ == '__main__':
    main()
