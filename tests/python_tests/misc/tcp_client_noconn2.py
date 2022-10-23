#!/usr/bin/python
from socket import *
import fcntl, os, sys
import time
from collections import deque
import array

myHost = sys.argv[1]
myPort = int(sys.argv[2])

sock = socket(AF_INET, SOCK_STREAM)
rc = sock.connect_ex((myHost, myPort))
if rc != 0:
    print "Error"

data = array.array('i', range(2048))
#for x in range(2048):
#    data.append(x)

rc = sock.send(data)
while rc > 0:
    try:
        rc = sock.send(data)
    except Exception:
        print "Closed"
        rc = -1

print "Disconnected " + str(rc)

while rc != 0:
    rc = sock.connect_ex((myHost, myPort))

print "All sockets connected"


