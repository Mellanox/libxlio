To compile it you simply need to run the following commands:
>g++ -lpthread exchange.cpp -o exchange
>g++ -lpthread trader.cpp -o trader

It is very important for us to better understand the spikes situation you experienced.
Me and Alex made some changes today to the test and we plan to further improve the test till we get the desired results.
I would like to describe the test application, and hopefully with your help refine it so we could succeed with pin pointing the issue.
It's going to be a bit long but it's important for us that you will have all the information and could easily help refine the test.


The test app includes two applications - exchange and trader:
Exchange:
1.	Opens a MC socket and sends MC packets in a predefined rate.
2.	Open a UC socket and blocks on recvfrom().
a.	If an ORDER packet is received --> send ORD_ACK
b.	If a keep alive packet is received --> send KA_ACK
3.	Every X packets (configurable) --> send a MC QUOTE packet.
4.	Time measurement is performed in usec. It starts upon send of the MC QUOTE packet. It ends and prints upon receiving of the UC ORDER packet.

Trader:
1.	Opens X pairs of threads (configurable).
2.	Each pair opens one MC socket and one UC socket.
3.	The MC socket blocks on recv(). If it encounters the QUOTE packet it immediately sends a UC ORDER packet through the UC socket, and starts time measurement.
4.	The UC socket blocks on recvfrom() with SO_RCVTIMEO (configurable):
a.	If it times out then it sends a keep alive packet.
b.	If it receives reply for ORDER packet (i.e. ORD_ACK) --> it stops and prints the time measurement (for ORDER RTT).
c.	If it receives reply for keep alive packet (i.e. KA_ACK) --> it does nothing.

Running the application:
1.	First run the exchange app on one server and then the trader on another.
2.	If you run the app with no parameters (or with --help flag) you will get a usage print.
All of the configurable parameters are described along with their default parameters.
3.	There are only 2 mandatory parameters for the trader app (local interface IP and peer UC IP), and one mandatory parameter for the exchange app (local interface IP).
4.	I am now adding execution example with some printouts (it uses all of the defaults, meaning 2 pair of threads on the trader side):


Exchange side printout:
=======================

[odeds@hail18 Debug]$ XLIO_RX_POLL=-1 LD_PRELOAD=<path to>/libxlio.so exchange -l 1.1.1.18
 XLIO INFO   : -------------------------------------------------
 XLIO INFO   : Version: 6.1.7.0
 XLIO INFO   : Current Time: Thu May  3 15:28:26 2012
 XLIO INFO   : Cmd Line: exchange -l 1.1.1.18
 XLIO INFO   : Pid: 25628
 XLIO INFO   : OFED Version: OFED-XLIO-1.5.3-0010:
 XLIO INFO   : System: 2.6.32-71.el6.x86_64
 XLIO INFO   : Architecture: x86_64
 XLIO INFO   : Node: hail18
 XLIO INFO   : ---------------------------------------------------------
 XLIO INFO   :  Log Level                      3                          [XLIO_TRACELEVEL]
 XLIO INFO   :  Log File                                                  [XLIO_LOG_FILE]
 XLIO INFO   :  Rx Poll Loops                  -1                         [XLIO_RX_POLL]
 XLIO INFO   : ---------------------------------------------------------
 XLIO INFO   : ***************************************************************
 XLIO INFO   : * This XLIO license was granted to: cust                       *
 XLIO INFO   : * Successfully passed license validation, starting XLIO.       *
 XLIO INFO   : ***************************************************************
Opening datagram MC socket
 XLIO WARNING: ***************************************************************
 XLIO WARNING: * NO IMMEDIATE ACTION NEEDED!                                 *
 XLIO WARNING: * Not enough hugepage resources for XLIO memory allocation.    *
 XLIO WARNING: * XLIO will continue working with regular memory allocation.   *
 XLIO INFO   : * Optional: 1. Disable XLIO's hugepage support (XLIO_HUGETBL=0) *
 XLIO INFO   : *           2. Restart process after increasing the number of *
 XLIO INFO   : *              hugepages resources in the system:             *
 XLIO INFO   : * "cat /proc/meminfo |  grep -i HugePage"                     *
 XLIO INFO   : * "echo 1000000000 > /proc/sys/kernel/shmmax"                 *
 XLIO INFO   : * "echo 800 > /proc/sys/vm/nr_hugepages"                      *
 XLIO WARNING: * Read more about the Huge Pages in the XLIO's User Manual     *
 XLIO WARNING: ***************************************************************
Connecting..
Opening datagram UC socket....OK.
Binding datagram UC socket...OK.
BW(Gbps)= 0.134, MPS=     90076
BW(Gbps)= 0.135, MPS=     90898
BW(Gbps)= 0.135, MPS=     90899
BW(Gbps)= 0.135, MPS=     90899
BW(Gbps)= 0.135, MPS=     90899
BW(Gbps)= 0.135, MPS=     90899
BW(Gbps)= 0.135, MPS=     90899
BW(Gbps)= 0.135, MPS=     90900
BW(Gbps)= 0.135, MPS=     90900
BW(Gbps)= 0.135, MPS=     90900
BW(Gbps)= 0.135, MPS=     90900
BW(Gbps)= 0.135, MPS=     90899
BW(Gbps)= 0.135, MPS=     90899
BW(Gbps)= 0.135, MPS=     90899
BW(Gbps)= 0.135, MPS=     90899
@@@@@@@ QUOTE from port 15333 RTT in usec = 14738 @@@@@@@
@@@@@@@ QUOTE from port 15334 RTT in usec = 14757 @@@@@@@
BW(Gbps)= 0.135, MPS=     90899
@@@@@@@ QUOTE from port 15334 RTT in usec = 14736 @@@@@@@
@@@@@@@ QUOTE from port 15333 RTT in usec = 14746 @@@@@@@
BW(Gbps)= 0.135, MPS=     90898
@@@@@@@ QUOTE from port 15333 RTT in usec = 14781 @@@@@@@
@@@@@@@ QUOTE from port 15334 RTT in usec = 14791 @@@@@@@
BW(Gbps)= 0.135, MPS=     90899
@@@@@@@ QUOTE from port 15333 RTT in usec = 14706 @@@@@@@
@@@@@@@ QUOTE from port 15334 RTT in usec = 14717 @@@@@@@
BW(Gbps)= 0.135, MPS=     90898
@@@@@@@ QUOTE from port 15333 RTT in usec = 14801 @@@@@@@
@@@@@@@ QUOTE from port 15334 RTT in usec = 14812 @@@@@@@
BW(Gbps)= 0.135, MPS=     90899
@@@@@@@ QUOTE from port 15333 RTT in usec = 14766 @@@@@@@
@@@@@@@ QUOTE from port 15334 RTT in usec = 14779 @@@@@@@
BW(Gbps)= 0.135, MPS=     90899
@@@@@@@ QUOTE from port 15333 RTT in usec = 14745 @@@@@@@
BW(Gbps)= 0.135, MPS=     90899
@@@@@@@ QUOTE from port 15334 RTT in usec = 14738 @@@@@@@
BW(Gbps)= 0.135, MPS=     90899
BW(Gbps)= 0.135, MPS=     90899
@@@@@@@ QUOTE from port 15334 RTT in usec = 14736 @@@@@@@
@@@@@@@ QUOTE from port 15333 RTT in usec = 14746 @@@@@@@
BW(Gbps)= 0.135, MPS=     90898



Trader side printout:
=====================

[odeds@hail19 Debug]$ XLIO_RX_POLL=-1 LD_PRELOAD=<path to>/libxlio.so ./trader -l 1.1.1.19 -ua 1.1.1.18
 XLIO INFO   : -------------------------------------------------
 XLIO INFO   : Version: 6.1.7.0
 XLIO INFO   : Current Time: Thu May  3 15:28:57 2012
 XLIO INFO   : Cmd Line: ./trader -l 1.1.1.19 -ua 1.1.1.18
 XLIO INFO   : Pid: 27087
 XLIO INFO   : OFED Version: OFED-XLIO-1.5.3-0010:
 XLIO INFO   : System: 2.6.32-71.el6.x86_64
 XLIO INFO   : Architecture: x86_64
 XLIO INFO   : Node: hail19
 XLIO INFO   : ---------------------------------------------------------
 XLIO INFO   :  Log Level                      3                          [XLIO_TRACELEVEL]
 XLIO INFO   :  Log File                                                  [XLIO_LOG_FILE]
 XLIO INFO   :  Rx Poll Loops                  -1                         [XLIO_RX_POLL]
 XLIO INFO   : ---------------------------------------------------------
 XLIO INFO   : ***************************************************************
 XLIO INFO   : * This XLIO license was granted to: Mellanox internal evaluation license. Not for external use! *
 XLIO INFO   : * Successfully passed license validation, starting XLIO.       *
 XLIO INFO   : ***************************************************************
Opening MC datagram socket 1
 XLIO WARNING: ***************************************************************
 XLIO WARNING: * NO IMMEDIATE ACTION NEEDED!                                 *
 XLIO WARNING: * Not enough hugepage resources for XLIO memory allocation.    *
 XLIO WARNING: * XLIO will continue working with regular memory allocation.   *
 XLIO INFO   : * Optional: 1. Disable XLIO's hugepage support (XLIO_HUGETBL=0) *
 XLIO INFO   : *           2. Restart process after increasing the number of *
 XLIO INFO   : *              hugepages resources in the system:             *
 XLIO INFO   : * "cat /proc/meminfo |  grep -i HugePage"                     *
 XLIO INFO   : * "echo 1000000000 > /proc/sys/kernel/shmmax"                 *
 XLIO INFO   : * "echo 800 > /proc/sys/vm/nr_hugepages"                      *
 XLIO WARNING: * Read more about the Huge Pages in the XLIO's User Manual     *
 XLIO WARNING: ***************************************************************
Opening MC datagram socket num = 1....OK.
Setting SO_REUSEADDR on MC socket num = 1...OK.
Binding MC datagram socket num = 1...OK.
Adding multicast group for socket num = 1...OK.
Opening datagram uc socket fd=23....OK.
Binding datagram uc socket num 1....OK.
Opening MC datagram socket 2
Opening MC datagram socket num = 2....OK.
Setting SO_REUSEADDR on MC socket num = 2...OK.
Binding MC datagram socket num = 2...OK.
Adding multicast group for socket num = 2...OK.
Opening datagram uc socket fd=27....OK.
Binding datagram uc socket num 2....OK.
MC Thread number 1 entered recv_loop
MC Thread number 2 entered recv_loop
#### Thread num = 1 - ORDER sent and received ####. RTT time = 398011
#### Thread num = 2 - ORDER sent and received ####. RTT time = 398028
#### Thread num = 2 - ORDER sent and received ####. RTT time = 597608
#### Thread num = 1 - ORDER sent and received ####. RTT time = 597612
#### Thread num = 1 - ORDER sent and received ####. RTT time = 14781
#### Thread num = 2 - ORDER sent and received ####. RTT time = 14794
#### Thread num = 1 - ORDER sent and received ####. RTT time = 14704
#### Thread num = 2 - ORDER sent and received ####. RTT time = 14715
#### Thread num = 1 - ORDER sent and received ####. RTT time = 199447
#### Thread num = 2 - ORDER sent and received ####. RTT time = 199461
#### Thread num = 1 - ORDER sent and received ####. RTT time = 399008
#### Thread num = 2 - ORDER sent and received ####. RTT time = 399017
#### Thread num = 1 - ORDER sent and received ####. RTT time = 14742
#### Thread num = 2 - ORDER sent and received ####. RTT time = 799166
#### Thread num = 2 - ORDER sent and received ####. RTT time = 200353
#### Thread num = 1 - ORDER sent and received ####. RTT time = 200359




Suggestions for further testing with this test app:
===================================================

1. 	TCP connection (instead of the UC UDP)
2. 	Add a mutex lock on the UC socket on the trader side


Open issues found with this tool:
=================================

1.	with the default SO_RCVTIMEO value - 20usec - there is a 15000usec overhead to the time measurement.
	If the value is larger (i.e. 20000usec) it doesn't happen.
	It doesn't happen with OS.
2. 	There are spikes of upto 1 sec, only on the trader UC socket RTT.
	With the OS such spikes also happen but less frequent.
