import os,time
if os.fork()==0:
 time.sleep(600)
else:
 os._exit(0)
