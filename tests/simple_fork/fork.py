#!/usr/bin/python

#LD_PRELOAD=libxlio.so ./fork.py
#XLIO_MEM_ALLOC_TYPE=2 LD_PRELOAD=libxlio.so ./fork.py
#XLIO_MEM_ALLOC_TYPE=2 XLIO_LOG_FILE="/tmp/libxlio.log.%d" XLIO_TRACELEVEL=4 LD_PRELOAD=libxlio.so ./fork.py

import os
import socket

def child():
	print 'A new child ',  os.getpid( )
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.close()
	os._exit(0)  

def parent():
	i = 0
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	while True:
		i = i + 1
		newpid = os.fork()
		if newpid == 0:
			child()
		else:
			pids = (os.getpid(), newpid)
			print "parent: %d, child: %d" % pids
		if i == 5: break
	s.close()

parent()

