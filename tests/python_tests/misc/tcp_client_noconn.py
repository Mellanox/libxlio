#!/usr/bin/python
from socket import *
import fcntl, os, sys
import time
from collections import deque

mySocksNum = 1
myHost = sys.argv[1]
myPort = int(sys.argv[2])
socks = []

for x in range(mySocksNum):
    socks.append(socket(AF_INET, SOCK_STREAM)) # create a TCP socket
    rc = -1
    while rc != 0:
        rc = socks[x].connect_ex((myHost, myPort))

print "All sockets connected"

for x in range(mySocksNum):
    socks[x].close()

