#!/usr/bin/python
from socket import *
import fcntl, os, sys
import time
from collections import deque


BACKLOG=10
myHost = sys.argv[1]
myPort = int(sys.argv[2])
mySocksNum = int(sys.argv[3])
#s.bind((myHost, myPort)) 
#s.listen(BACKLOG) 
socks = []
addrs = []
buffs = ["1234567890123456", "abcdefghijklmnop", "zozzozzozzoz1234"]
buffsRcv = []

for x in range(mySocksNum):
    socks.append(socket(AF_INET, SOCK_STREAM)) # create a TCP socket
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
        print x, " Correct"
    else:
        print x, " Wrong"

for x in range(mySocksNum):
        socks[x].send(buffs[x])

for x in range(mySocksNum):
    socks[x].close()

