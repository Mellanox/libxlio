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
#s.bind((myHost, myPort)) 
socks = []
addrs = []
buffs = ["1234567890123456", "abcdefghijklmnop", "zozzozzozzoz1234"]
buffsRcv = []

for x in range(mySocksNum):
    socks.append(socket(AF_INET, SOCK_DGRAM)) # create a UDP socket
    socks[x].bind((outerHost, myPort + x + 1))
    socks[x].connect((myHost, myPort))

print "All sockets connected"

for x in range(mySocksNum):
    socks[x].send(buffs[x])

print "All buffs sent"

for x in range(mySocksNum):
    buffsRcv.append(socks[x].recv(16))

print "All buffs received"

for x in range(mySocksNum):
    if (buffs[x] == buffsRcv[x]):
        print x, " Correct ", buffsRcv[x]
    else:
        print x, " Wrong"

for x in range(mySocksNum):
    socks[x].close()

