"""HIA rendering of target Linux std::io::Error Display strings.

The frozen GNU error names are qualified against the original Rust runtime.
No libc formatting or host interpreter is called by the generated HIA code.
"""
from __future__ import annotations
import argparse
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_system_jobctl_request import document

ERROR_NAMES = ('Success', 'Operation not permitted', 'No such file or directory', 'No such process', 'Interrupted system call', 'Input/output error', 'No such device or address', 'Argument list too long', 'Exec format error', 'Bad file descriptor', 'No child processes', 'Resource temporarily unavailable', 'Cannot allocate memory', 'Permission denied', 'Bad address', 'Block device required', 'Device or resource busy', 'File exists', 'Invalid cross-device link', 'No such device', 'Not a directory', 'Is a directory', 'Invalid argument', 'Too many open files in system', 'Too many open files', 'Inappropriate ioctl for device', 'Text file busy', 'File too large', 'No space left on device', 'Illegal seek', 'Read-only file system', 'Too many links', 'Broken pipe', 'Numerical argument out of domain', 'Numerical result out of range', 'Resource deadlock avoided', 'File name too long', 'No locks available', 'Function not implemented', 'Directory not empty', 'Too many levels of symbolic links', 'Unknown error 41', 'No message of desired type', 'Identifier removed', 'Channel number out of range', 'Level 2 not synchronized', 'Level 3 halted', 'Level 3 reset', 'Link number out of range', 'Protocol driver not attached', 'No CSI structure available', 'Level 2 halted', 'Invalid exchange', 'Invalid request descriptor', 'Exchange full', 'No anode', 'Invalid request code', 'Invalid slot', 'Unknown error 58', 'Bad font file format', 'Device not a stream', 'No data available', 'Timer expired', 'Out of streams resources', 'Machine is not on the network', 'Package not installed', 'Object is remote', 'Link has been severed', 'Advertise error', 'Srmount error', 'Communication error on send', 'Protocol error', 'Multihop attempted', 'RFS specific error', 'Bad message', 'Value too large for defined data type', 'Name not unique on network', 'File descriptor in bad state', 'Remote address changed', 'Can not access a needed shared library', 'Accessing a corrupted shared library', '.lib section in a.out corrupted', 'Attempting to link in too many shared libraries', 'Cannot exec a shared library directly', 'Invalid or incomplete multibyte or wide character', 'Interrupted system call should be restarted', 'Streams pipe error', 'Too many users', 'Socket operation on non-socket', 'Destination address required', 'Message too long', 'Protocol wrong type for socket', 'Protocol not available', 'Protocol not supported', 'Socket type not supported', 'Operation not supported', 'Protocol family not supported', 'Address family not supported by protocol', 'Address already in use', 'Cannot assign requested address', 'Network is down', 'Network is unreachable', 'Network dropped connection on reset', 'Software caused connection abort', 'Connection reset by peer', 'No buffer space available', 'Transport endpoint is already connected', 'Transport endpoint is not connected', 'Cannot send after transport endpoint shutdown', 'Too many references: cannot splice', 'Connection timed out', 'Connection refused', 'Host is down', 'No route to host', 'Operation already in progress', 'Operation now in progress', 'Stale file handle', 'Structure needs cleaning', 'Not a XENIX named type file', 'No XENIX semaphores available', 'Is a named type file', 'Remote I/O error', 'Disk quota exceeded', 'No medium found', 'Wrong medium type', 'Operation canceled', 'Required key not available', 'Key has expired', 'Key has been revoked', 'Key was rejected by service', 'Owner died', 'State not recoverable', 'Operation not possible due to RF-kill', 'Memory page has hardware error')

HELPERS = r"""
def io_error(w:mutbuf, at:u64, code:u64) -> u64:
    if code > 4294967295 or at > length(w) or length(w) - at < 256:
        return 18446744073709551615
    at = io_name(w, at, code)
    at = io_suffix(w, at)
    at = io_signed(w, at, code)
    store(w, at, 41)
    return at + 1

def io_signed(w:mutbuf, at:u64, code:u64) -> u64:
    if code >= 2147483648:
        store(w, at, 45)
        at = at + 1
        code = 4294967296 - code
    return io_decimal(w, at, code)

def io_decimal(w:mutbuf, at:u64, value:u64) -> u64:
    scale = 1
    while scale <= value // 10:
        scale = scale * 10
    while scale != 0:
        store(w, at, 48 + value // scale)
        value = value % scale
        scale = scale // 10
        at = at + 1
    return at

def io_put(w:mutbuf, at:u64, value:u64, size:u64) -> u64:
    if size == 8:
        word_store(w, at, value)
        return at + 8
    index = 0
    while index < size:
        store(w, at + index, (value >> (index * 8)) & 255)
        index = index + 1
    return at + size
"""

def literal(raw):
    source=''
    for at in range(0,len(raw),8):
        part=raw[at:at+8]
        source+=f'    at = io_put(w, at, {int.from_bytes(part,"little")}, {len(part)})\n'
    return source

def error_source():
    source=HELPERS+'\ndef io_name(w:mutbuf, at:u64, code:u64) -> u64:\n'
    for group in range((len(ERROR_NAMES)+7)//8):
        source+=f'    if code >= {group*8} and code < {min((group+1)*8,len(ERROR_NAMES))}:\n        return io_group_{group}(w, at, code)\n'
    source+=literal(b'Unknown error ')+'    return io_signed(w, at, code)\n'
    for group in range((len(ERROR_NAMES)+7)//8):
        source+=f'\ndef io_group_{group}(w:mutbuf, at:u64, code:u64) -> u64:\n'
        for code in range(group*8,min((group+1)*8,len(ERROR_NAMES))):
            source+=f'    if code == {code}:\n'+''.join('    '+line+'\n' for line in literal(ERROR_NAMES[code].encode()).splitlines())+'        return at\n'
        source+='    return at\n'
    source+='\ndef io_suffix(w:mutbuf, at:u64) -> u64:\n'+literal(b' (os error ')+'    return at\n'
    return source

def source_program():
    return r"""
def error_text(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) != 8 or length(o) < 256 or length(w) < 8:
        return 0
    result = io_error(o, 0, word_load(s, 0))
    if result == 18446744073709551615:
        return 0
    return result
"""+error_source()

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    doc=document(source_program(),'system_jobctl_error_text');args.output.write_text(render_assembly(doc))
    print(args.output,len(doc['functions']),sum(len(b['ops']) for f in doc['functions'] for b in f['blocks']),flush=True)

if __name__=='__main__':main()
