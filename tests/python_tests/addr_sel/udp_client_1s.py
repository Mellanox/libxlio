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

mySrcAddr = ""
if (argc > ARG_LEN):
    mySrcAddr = sys.argv[4]

sock = socket(myFamily, SOCK_DGRAM) # create a UDP socket

if (mySrcAddr != ""):
    addrinfo_src = getaddrinfo(mySrcAddr, myDstPort, myFamily, SOCK_DGRAM)
    rc = sock.bind(addrinfo_src[0][4])
    print "Binding to: ", addrinfo_src[0][4], " rc:", rc

addrinfo = getaddrinfo(myDstHost, myDstPort, myFamily, SOCK_DGRAM)
print "Sending to: ", addrinfo[0][4]

bytes = sock.sendto("hello", addrinfo[0][4])
print "Sent ", bytes, " bytes"

if (mySrcAddr != ""):
    bytes, src_addr = sock.recvfrom(16)
    print "Received ", len(bytes), " bytes: ", bytes

sock.close()
