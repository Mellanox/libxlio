#!/usr/bin/python
from socket import *
import fcntl, os, sys
import time
from collections import deque

ARG_LEN = 4
argc = len(sys.argv)
if (argc < ARG_LEN):
    print "Needs ", x - 1, " arguments [family, dst-addr, dst-port, [src-addr]]"
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

sock = socket(myFamily, SOCK_STREAM) # create a UDP socket

if (mySrcAddr != ""):
    addrinfo_src = getaddrinfo(mySrcAddr, myDstPort, myFamily, SOCK_STREAM)
    rc = sock.bind(addrinfo_src[0][4])
    print "Client Binding to: ", addrinfo_src[0][4], " rc:", rc

addrinfo = getaddrinfo(myDstHost, myDstPort, myFamily, SOCK_STREAM)
print "Connecting to: ", addrinfo[0][4]
sock.connect(addrinfo[0][4])

bytes = sock.send("hello")
print "Sent ", bytes, " bytes"

bytes = sock.recv(16)
print "Received ", len(bytes), " bytes: ", bytes

sock.close()
