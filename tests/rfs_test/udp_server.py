#!/usr/bin/python
from socket import *
import fcntl, os, sys
import time
from collections import deque


BACKLOG=10
myHost = sys.argv[1]
myPort = int(sys.argv[2])
mySocksNum = int(sys.argv[3])
outerHost = sys.argv[4]
socks = []
buffs = []

for x in range(mySocksNum):
    socks.append(socket(AF_INET, SOCK_DGRAM)) # create a UDP socket
    print "ID:",x
    socks[x].setsockopt(SOL_SOCKET, SO_REUSEPORT, 1)
    socks[x].bind((myHost, myPort))
    socks[x].connect((outerHost, myPort + x + 1))

for x in range(mySocksNum):
    buffs.append(socks[x].recv(16))

for x in range(mySocksNum):
    socks[x].send(buffs[x])

for x in range(mySocksNum):
    socks[x].close()

