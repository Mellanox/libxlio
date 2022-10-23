#!/usr/bin/python
from socket import *
import fcntl, os, sys
import time
from collections import deque

BACKLOG=10
myHost = sys.argv[1]
myPort = int(sys.argv[2])
mySocksNum = 1
addrs = []
buffs = "1234567890123456"
buffsRcv = []

socks1 = socket(AF_INET, SOCK_DGRAM) # create a UDP socket
socks1.bind((myHost, myPort))
socks2 = socket(AF_INET, SOCK_DGRAM) # create a UDP socket
socks2.bind((myHost, myPort + 1))

print "All sockets connected"

socks1.sendto(buffs, (myHost, myPort + 1))

print "All buffs sent"

buffsRcv.append(socks2.recv(16))

print "All buffs received"

for x in range(mySocksNum):
    if (buffs == buffsRcv[x]):
        print x, " Correct ", buffsRcv[x]
    else:
        print x, " Wrong"

socks1.close()
socks2.close()


