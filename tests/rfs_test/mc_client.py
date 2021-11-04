#!/usr/bin/python
from socket import *
import fcntl, os, sys
import time
import struct
from collections import deque


BACKLOG=10
myHost = sys.argv[1]
myPort = int(sys.argv[2])
mcHost = sys.argv[3]
mySocksNum = 3
socks = []
addrs = []
buffs = ["1234567890123456", "abcdefghijklmnop", "zozzozzozzoz1234"]
buffsRcv = []

group = inet_aton(myHost)
mreq = struct.pack('4sL', group, 8)

for x in range(mySocksNum):
    socks.append(socket(AF_INET, SOCK_DGRAM)) # create a UDP socket
    socks[x].setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    socks[x].bind((myHost, myPort + x + 1))

print "All sockets connected"

for x in range(mySocksNum):
    socks[x].sendto(buffs[x], (mcHost, myPort))

print "All buffs sent"

for x in range(mySocksNum):
    for y in range(mySocksNum):
        buffsRcv.append(socks[x].recv(16))

print "All buffs received"

for y in range(mySocksNum):
    for x in range(mySocksNum):
        if (buffs[x] == buffsRcv[x + (y * 3)]):
            print x + (y * 3), " Correct ", buffsRcv[x]
        else:
            print x + (y * 3), " Wrong", buffsRcv[x]

for x in range(mySocksNum):
    socks[x].close()

