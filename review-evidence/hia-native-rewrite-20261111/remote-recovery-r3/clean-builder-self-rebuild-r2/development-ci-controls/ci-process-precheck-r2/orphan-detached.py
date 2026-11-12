import os,time
r,w=os.pipe()
if os.fork()==0:
 os.close(r);os.setsid();os.write(w,b'x');os.close(w);time.sleep(600)
else:
 os.close(w);assert os.read(r,1)==b'x';os.close(r);os._exit(0)
