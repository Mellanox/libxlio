#!/usr/bin/python
from socket import *
import fcntl, os, sys
import time
from collections import deque

BACKLOG=10
myHost = sys.argv[1]
myPort = int(sys.argv[2])
s = socket(AF_INET, SOCK_STREAM) # create a TCP socket
s.bind((myHost, myPort)) 
s.listen(BACKLOG) 

tempSock, tempAddr = s.accept()

print "Accepted"

rc = tempSock.recv(2048); # First
time.sleep(0.1)

os._exit(0)
#while len(rc) >= 0:
#    rc = tempSock.recv(2048);
#    time.sleep(5)

print "Done " + str(rc)


