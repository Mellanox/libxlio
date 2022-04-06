#!/usr/bin/python
from socket import *
import fcntl, os, sys
import time
import struct
from collections import deque

argc = len(sys.argv)
BACKLOG=10
myHost = sys.argv[1]
myPort = int(sys.argv[2])
mySocksNum = 3
outerHost = sys.argv[3]

is_bind_diff_port = 0
recv_factor = mySocksNum
if (argc > 4 and sys.argv[4] != ''):
    is_bind_diff_port = int(sys.argv[4])
    recv_factor = 1

socks = []
buffs = []

group = inet_aton(myHost)
mreq = struct.pack('4sL', group, 8)

for x in range(mySocksNum):
    socks.append(socket(AF_INET, SOCK_DGRAM)) # create a UDP socket
    print "ID:",x
    socks[x].setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)

    if (is_bind_diff_port != 0):
        socks[x].bind((myHost, myPort + x + 1))
    else:
        socks[x].bind((myHost, myPort))

    socks[x].setsockopt(IPPROTO_IP, IP_ADD_MEMBERSHIP, mreq)


for y in range(recv_factor):
    for x in range(mySocksNum):
        buffs.append(socks[x].recv(16))

for y in range(recv_factor):
    for x in range(mySocksNum):
        socks[x].sendto(buffs[x + (y * 3)], (outerHost, myPort + x + 1))

for x in range(mySocksNum):
    socks[x].close()

