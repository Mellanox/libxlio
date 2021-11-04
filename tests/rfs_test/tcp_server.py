#!/usr/bin/python
from socket import *
import fcntl, os, sys
import time
from collections import deque


BACKLOG=10
myHost = sys.argv[1]
myPort = int(sys.argv[2])
mySocksNum = int(sys.argv[3])
s = socket(AF_INET, SOCK_STREAM) # create a TCP socket
s.bind((myHost, myPort)) 
s.listen(BACKLOG) 
socks = []
addrs = []
buffs = []

for x in range(mySocksNum):
    tempSock, tempAddr = s.accept()
    socks.append(tempSock)
    addrs.append(tempAddr)

for x in range(mySocksNum):
    buffs.append(socks[x].recv(16))

for x in range(mySocksNum):
    socks[x].send(buffs[x])

for x in range(mySocksNum):
    socks[x].close()

