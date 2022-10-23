#!/usr/bin/python

from socket import *
import fcntl, os, sys
import time
from collections import deque

ARG_LEN = 5
argc = len(sys.argv)
if (argc < ARG_LEN):
    print "Needs ", x - 1, " arguments [family, bind-addr, bind-port, expected-src-addr]"
    exit

myFamily = AF_INET
myFamilyStr = sys.argv[1]
if (myFamilyStr == "inet6"):
    myFamily = AF_INET6

myHost = sys.argv[2]
myPort = int(sys.argv[3])
myExpectedAddr = sys.argv[4]

addrinfo = getaddrinfo(myHost, myPort, myFamily, SOCK_STREAM)

lissock = socket(myFamily, SOCK_STREAM) # create a TCP socket
lissock.setsockopt(SOL_SOCKET, SO_REUSEPORT, 1)
print "Binding to: ", addrinfo[0][4]
lissock.bind(addrinfo[0][4])
lissock.listen(10);

sock, src_addr = lissock.accept()

print "Waiting in recvfrom ..."
bytes = sock.recv(16)
print "Received ", len(bytes), " bytes: ", bytes

print "Debug Received src_addr: ", src_addr[0]
if (myExpectedAddr != src_addr[0]):
    print "Unexpected received src_addr: ", src_addr[0]

sock.send("Greetings")

sock.close()
