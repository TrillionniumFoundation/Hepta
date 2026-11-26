"""Linux x86-64 native-code syscall notification controls for qualification.

Filters are installed only on the calling test thread. Notifications suspend a
real syscall at the selected native instruction span; CONTINUE executes that
syscall in the kernel. Optional FUTEX_WAIT_PRIVATE denial is a kernel seccomp
policy error, never a patched native result, mutex word or instruction.
"""
import ctypes as C
import errno
import os

libc=C.CDLL(None,use_errno=True)
libc.syscall.restype=C.c_long
libc.prctl.restype=C.c_int
libc.ioctl.argtypes=[C.c_int,C.c_ulong,C.c_void_p]
libc.ioctl.restype=C.c_int

class Filter(C.Structure):
    _fields_=[('code',C.c_ushort),('jt',C.c_ubyte),('jf',C.c_ubyte),('k',C.c_uint)]
class Program(C.Structure):
    _fields_=[('length',C.c_ushort),('filters',C.POINTER(Filter))]
class Data(C.Structure):
    _fields_=[('nr',C.c_int),('arch',C.c_uint),('ip',C.c_ulonglong),('args',C.c_ulonglong*6)]
class Notification(C.Structure):
    _fields_=[('id',C.c_ulonglong),('pid',C.c_uint),('flags',C.c_uint),('data',Data)]
class Response(C.Structure):
    _fields_=[('id',C.c_ulonglong),('value',C.c_longlong),('error',C.c_int),('flags',C.c_uint)]

assert C.sizeof(Notification)==80 and C.sizeof(Response)==24
RECV=0xc0502100
SEND=0xc0182101
ALLOW=0x7fff0000
USER_NOTIF=0x7fc00000
ERRNO=0x00050000

def install(ip_start,ip_end,notification_syscall,*,deny_private_wait=False):
    """Return a NEW_LISTENER descriptor for this thread's fixed native span."""
    assert 0<ip_start<ip_end and ip_start>>32==(ip_end-1)>>32
    low=ip_start&0xffffffff;high=ip_end&0xffffffff;upper=ip_start>>32
    if deny_private_wait:
        instructions=[
            (0x20,0,0,12),(0x15,0,8,upper),
            (0x20,0,0,8),(0x35,0,6,low),(0x35,5,0,high),
            (0x20,0,0,0),(0x15,4,0,notification_syscall),(0x15,0,2,202),
            (0x20,0,0,24),(0x15,2,0,128),
            (0x06,0,0,ALLOW),(0x06,0,0,USER_NOTIF),(0x06,0,0,ERRNO|errno.EACCES)]
    else:
        instructions=[
            (0x20,0,0,12),(0x15,0,5,upper),
            (0x20,0,0,8),(0x35,0,3,low),(0x35,2,0,high),
            (0x20,0,0,0),(0x15,1,0,notification_syscall),
            (0x06,0,0,ALLOW),(0x06,0,0,USER_NOTIF)]
    code=(Filter*len(instructions))(*(Filter(*row)for row in instructions))
    program=Program(len(instructions),code)
    assert libc.prctl(38,1,0,0,0)==0,('PR_SET_NO_NEW_PRIVS',C.get_errno())
    fd=libc.syscall(C.c_long(317),C.c_long(1),C.c_long(8),C.byref(program))
    assert fd>=0,('SECCOMP_FILTER_FLAG_NEW_LISTENER',C.get_errno())
    return fd

def receive(fd):
    notification=Notification()
    while True:
        result=libc.ioctl(fd,RECV,C.byref(notification))
        if result==0:return notification
        if C.get_errno()==errno.EINTR:continue
        raise OSError(C.get_errno(),os.strerror(C.get_errno()))

def continue_syscall(fd,notification):
    response=Response(notification.id,0,0,1)
    assert libc.ioctl(fd,SEND,C.byref(response))==0,('SECCOMP_USER_NOTIF_FLAG_CONTINUE',C.get_errno())
