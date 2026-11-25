"""Author exact unsigned decimal public counter values with no fixed bit cap."""
from pathlib import Path
import re
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_system_jobctl_request import document
ROOT=Path(__file__).resolve().parents[1]
C={'MAGIC':int.from_bytes(b'HIAUVL01','little'),'REPLY':int.from_bytes(b'HIAVLR01','little'),'BAD':4294967293,'SHORT':4294967294}
SOURCE=r'''
def unsigned_decimal_values(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)<64 or read64(s,0)!=MAGIC:
        return BAD
    op=read64(s,8)
    a=read64(s,16)
    b=read64(s,24)
    if op>4 or a>length(s)-64:
        return BAD
    if b!=length(s)-64-a or (op<2 and b!=0):
        return BAD
    at=32
    while at<64:
        if read64(s,at)!=0:
            return BAD
        at=at+8
    if valid(s,64,a)==False:
        return reply(o,1,1,0)
    if op>=2 and valid(s,64+a,b)==False:
        return reply(o,1,1,0)
    compared=1
    if op==3 or op==4:
        compared=compare(s,a,b)
    if op==3:
        return reply(o,0,compared,0)
    if op==4 and compared==0:
        return reply(o,2,0,0)
    n=a
    carry=0
    if op==1:
        carry=1
    if op==1 or op==2:
        n=sum_length(s,a,b,carry)
    if op==4:
        n=difference_length(s,a,b)
    if length(o)<32 or n>length(o)-32:
        return SHORT
    reply(o,0,1,n)
    if op==0:
        i=0
        while i<a:
            store(o,32+i,byte(s,64+i))
            i=i+1
    elif op==1 or op==2:
        sum_write(s,o,a,b,carry,n)
    else:
        difference_write(s,o,a,b,n)
    return 0

def valid(s:readbuf,at:u64,n:u64) -> bool:
    if n==0 or (n>1 and byte(s,at)==48):
        return False
    i=0
    while i<n:
        digit=byte(s,at+i)
        if digit<48 or digit>57:
            return False
        i=i+1
    return True

def compare(s:readbuf,a:u64,b:u64) -> u64:
    if a<b:
        return 0
    if a>b:
        return 2
    i=0
    while i<a:
        left=byte(s,64+i)
        right=byte(s,64+a+i)
        if left<right:
            return 0
        if left>right:
            return 2
        i=i+1
    return 1

def digit_from_end(s:readbuf,at:u64,n:u64,index:u64) -> u64:
    if index>=n:
        return 0
    return byte(s,at+n-index-1)-48

def sum_length(s:readbuf,a:u64,b:u64,carry:u64) -> u64:
    n=a
    if b>n:
        n=b
    i=0
    while i<n:
        value=digit_from_end(s,64,a,i)+digit_from_end(s,64+a,b,i)+carry
        carry=value//10
        i=i+1
    return n+carry

def sum_write(s:readbuf,o:mutbuf,a:u64,b:u64,carry:u64,n:u64) -> u64:
    extent=a
    if b>extent:
        extent=b
    i=0
    while i<extent:
        value=digit_from_end(s,64,a,i)+digit_from_end(s,64+a,b,i)+carry
        store(o,32+n-i-1,48+value%10)
        carry=value//10
        i=i+1
    if n>extent:
        store(o,32,48+carry)
    return 0

def difference_length(s:readbuf,a:u64,b:u64) -> u64:
    borrow=0
    high=0
    i=0
    while i<a:
        left=digit_from_end(s,64,a,i)
        right=digit_from_end(s,64+a,b,i)+borrow
        value=0
        if left>=right:
            value=left-right
            borrow=0
        else:
            value=left+10-right
            borrow=1
        if value!=0:
            high=i+1
        i=i+1
    if high==0:
        return 1
    return high

def difference_write(s:readbuf,o:mutbuf,a:u64,b:u64,n:u64) -> u64:
    borrow=0
    i=0
    while i<a:
        left=digit_from_end(s,64,a,i)
        right=digit_from_end(s,64+a,b,i)+borrow
        value=0
        if left>=right:
            value=left-right
            borrow=0
        else:
            value=left+10-right
            borrow=1
        if i<n:
            store(o,32+n-i-1,48+value)
        i=i+1
    return 0

def reply(o:mutbuf,status:u64,compared:u64,n:u64) -> u32:
    if length(o)<32 or n>length(o)-32:
        return SHORT
    put(o,0,REPLY)
    put(o,8,status)
    put(o,16,compared)
    put(o,24,n)
    return 0

def read64(s:readbuf,at:u64) -> u64:
    value=0
    i=0
    while i<8:
        value=value|(byte(s,at+i)<<(8*i))
        i=i+1
    return value

def put(o:mutbuf,at:u64,value:u64) -> u64:
    i=0
    while i<8:
        store(o,at+i,(value>>(8*i))&255)
        i=i+1
    return 0
'''
def program():
 source=SOURCE
 for name,value in C.items():source=re.sub(r'\b'+name+r'\b',str(value),source)
 return document(source,'unsigned_decimal_values')
if __name__=='__main__':
 path=ROOT/'examples/hia_bootstrap/unsigned_decimal_values.hepta'
 path.write_text(render_assembly(program()))
 print(path.name,path.stat().st_size)
