#!/usr/bin/python
from socket import *
import fcntl, os, sys
import time
from collections import deque

ARG_LEN = 4
argc = len(sys.argv)
if (argc < ARG_LEN):
    print "Needs ", x - 1, " arguments [family, dst-addr, dst-port]"
    exit

myFamily = AF_INET
myFamilyStr = sys.argv[1]
if (myFamilyStr == "inet6"):
    myFamily = AF_INET6

myDstHost = sys.argv[2]
myDstPort = int(sys.argv[3])
mySrcHost = sys.argv[4]

sock = socket(myFamily, SOCK_DGRAM) # create a UDP socket

addrinfo = getaddrinfo(myDstHost, myDstPort, myFamily, SOCK_DGRAM)
print "Sending to: ", addrinfo[0][4]

addrinfo_src = getaddrinfo(mySrcHost, myDstPort, myFamily, SOCK_DGRAM)
print "Sending from: ", addrinfo_src[0][4]

print "Binding to: ", addrinfo_src[0][4]
rc = sock.bind(addrinfo_src[0][4])
print "bind: ", rc

bytes = sock.sendto("hello", addrinfo[0][4])
print "Sent ", bytes, " bytes"

bytes, src_addr = sock.recvfrom(16)
print "Received ", len(bytes), " bytes: ", bytes

sock.close()
