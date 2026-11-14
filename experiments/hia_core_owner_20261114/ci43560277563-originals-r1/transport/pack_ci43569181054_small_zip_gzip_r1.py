"""Passive whole-ZIP gzip transport; no extraction, network or subprocess."""
import gzip
import hashlib
import json
import os
import stat
import zlib

ROOT = "/home/qq/hia-rewrite-20261113-e26e-r1"
SOURCE = ROOT + "/core-owner-ci43569181054-small-artifact-r1-original.zip"
OUTPUT = SOURCE + ".gz"
REPORT = ROOT + "/core-owner-ci43569181054-small-artifact-r1-original-GZIP-REPORT.json"

SIZE = 14627724
SHA256 = "8d939283e347be007ef85d0d4595385685f6c145ecaa2d25c1b6ecea6c0fd787"
LIMIT = 16 << 20
CHUNK = 1 << 20
FLAGS = os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK

# dev, ino, mode, uid, gid, nlink, size, mtime_ns, ctime_ns
EXPECTED_IDENTITY9 = (
    66306,
    79482845,
    33152,
    1000,
    1000,
    1,
    14627724,
    1794640265111614527,
    1794640265111614527,
)


def need(value, message):
    if not value:
        raise RuntimeError(message)


def identity(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid,
            s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def stable(path, stream, expected=None):
    s = os.fstat(stream.fileno())
    actual = identity(s)
    need(stat.S_ISREG(s.st_mode) and s.st_uid == 1000 and s.st_nlink == 1,
         "not an owned single-link regular file")
    need(identity(os.stat(path, follow_symlinks=False)) == actual,
         "path and opened descriptor differ")
    need(expected is None or actual == expected, "exact identity changed")
    return actual


def full_hash(stream, maximum):
    stream.seek(0)
    total, digest = 0, hashlib.sha256()
    while True:
        block = stream.read(CHUNK)
        if not block:
            break
        total += len(block)
        need(total <= maximum, "whole-file size exceeded")
        digest.update(block)
    return total, digest.hexdigest()


class BoundedSink:
    def __init__(self, stream):
        self.stream = stream
        self.size = 0
        self.digest = hashlib.sha256()

    def write(self, block):
        need(self.size + len(block) <= LIMIT, "gzip exceeds 16 MiB")
        need(self.stream.write(block) == len(block), "short gzip write")
        self.size += len(block)
        self.digest.update(block)
        return len(block)

    def flush(self):
        self.stream.flush()


need(type(EXPECTED_IDENTITY9) is tuple
     and len(EXPECTED_IDENTITY9) == 9
     and all(type(v) is int for v in EXPECTED_IDENTITY9),
     "invalid frozen input identity")
need(EXPECTED_IDENTITY9[3] == 1000
     and EXPECTED_IDENTITY9[5] == 1
     and EXPECTED_IDENTITY9[6] == SIZE,
     "frozen input role or size differs")
need(os.geteuid() == 1000, "unexpected effective uid")
os.umask(0o077)

result = {
    "schema": "hia.passive-whole-zip-gzip-transport.v1",
    "status": "HOLD",
    "source": SOURCE,
    "output": OUTPUT,
    "report": REPORT,
    "source_bytes": SIZE,
    "source_sha256": SHA256,
    "expected_source_identity9": EXPECTED_IDENTITY9,
    "gzip_limit_bytes": LIMIT,
    "gzip_mtime": 0,
    "gzip_filename": "",
    "output_created": False,
    "archive_members_extracted": False,
    "product_calls": 0,
    "network_calls": 0,
    "subprocess_calls": 0,
}
success = False

# Reserve the report first. Never overwrite an existing report or output.
report_fd = os.open(REPORT, os.O_RDWR | os.O_CREAT | os.O_EXCL | FLAGS, 0o600)
with os.fdopen(report_fd, "w+b") as report:
    try:
        stable(REPORT, report)
        source_fd = os.open(SOURCE, os.O_RDONLY | FLAGS)
        with os.fdopen(source_fd, "rb") as source:
            stable(SOURCE, source, EXPECTED_IDENTITY9)
            need(full_hash(source, SIZE) == (SIZE, SHA256),
                 "input pre-compression hash differs")
            stable(SOURCE, source, EXPECTED_IDENTITY9)

            output_fd = os.open(
                OUTPUT, os.O_RDWR | os.O_CREAT | os.O_EXCL | FLAGS, 0o600)
            result["output_created"] = True
            with os.fdopen(output_fd, "w+b") as output:
                stable(OUTPUT, output)
                sink = BoundedSink(output)
                source.seek(0)
                count, digest = 0, hashlib.sha256()
                try:
                    with gzip.GzipFile(
                            filename="", mode="wb", fileobj=sink,
                            compresslevel=6, mtime=0) as compressed:
                        while True:
                            block = source.read(CHUNK)
                            if not block:
                                break
                            count += len(block)
                            need(count <= SIZE, "input grew during compression")
                            digest.update(block)
                            need(compressed.write(block) == len(block),
                                 "short gzip input write")
                finally:
                    # Preserve and synchronize partial output on failure.
                    output.flush()
                    os.fsync(output.fileno())

                need((count, digest.hexdigest()) == (SIZE, SHA256),
                     "compression input hash differs")
                stable(SOURCE, source, EXPECTED_IDENTITY9)
                output_identity = stable(OUTPUT, output)
                need(output_identity[6] == sink.size <= LIMIT,
                     "gzip output size differs")

                output.seek(0)
                need(output.read(10) == b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff",
                     "gzip header is not fixed mtime0/no-filename/level6")

                # Independent single-member decoding to hashes only.
                output.seek(0)
                decoder = zlib.decompressobj(31)
                packed_hash, plain_hash = hashlib.sha256(), hashlib.sha256()
                packed_size = plain_size = 0
                while True:
                    block = output.read(CHUNK)
                    if not block:
                        break
                    packed_size += len(block)
                    need(packed_size <= LIMIT, "gzip grew during readback")
                    packed_hash.update(block)
                    plain = decoder.decompress(block, SIZE + 1 - plain_size)
                    plain_size += len(plain)
                    need(plain_size <= SIZE, "expanded output exceeds input")
                    plain_hash.update(plain)
                    need(not decoder.unconsumed_tail and not decoder.unused_data,
                         "extra gzip member, trailing data or expansion overflow")

                need(decoder.eof, "incomplete gzip stream")
                need((plain_size, plain_hash.hexdigest()) == (SIZE, SHA256),
                     "complete decoded ZIP hash differs")
                need(packed_size == sink.size
                     and packed_hash.hexdigest() == sink.digest.hexdigest(),
                     "complete gzip readback hash differs")
                stable(OUTPUT, output, output_identity)

                need(full_hash(source, SIZE) == (SIZE, SHA256),
                     "input post-compression hash differs")
                stable(SOURCE, source, EXPECTED_IDENTITY9)
                stable(OUTPUT, output, output_identity)
                result.update(
                    gzip_bytes=packed_size,
                    gzip_sha256=packed_hash.hexdigest(),
                    gzip_identity9=output_identity,
                    decoded_bytes=plain_size,
                    decoded_sha256=plain_hash.hexdigest(),
                    single_gzip_member=True,
                    trailing_bytes=0,
                    source_identity_preserved=True,
                )

        directory_fd = os.open(
            ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        result["status"] = "PASS_BYTE_TRANSPORT_ONLY"
        success = True
    except BaseException as error:
        result["error"] = {
            "type": type(error).__name__,
            "message": str(error),
        }

    raw = (json.dumps(result, sort_keys=True, indent=2) + "\n").encode("utf-8")
    need(report.write(raw) == len(raw), "short report write")
    report.flush()
    os.fsync(report.fileno())
    report_identity = stable(REPORT, report)
    report.seek(0)
    need(report.read(len(raw) + 1) == raw, "complete report readback differs")
    stable(REPORT, report, report_identity)

raise SystemExit(0 if success else 1)
