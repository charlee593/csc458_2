# Simple router with NAT (CSC458)

A simple NAT that can handle ICMP and TCP. It will implement a subset of the functionality specified by RFC5382 and RFC5508. Expect to refer often to these RFCs.

The topology of NAT is as follows, where the NAT's internal interface (eth1) faces the client and its external interface (eth2) has two application servers connected with a switch:

<img src="http://www.cs.toronto.edu/~yganjali/resources/Course-Handouts/CSC458/nat_topo.png">

Topology for NAT
A correct implementation should support the following operations from the emulated client host:

Pinging the NAT's internal interface from the emulated client host
Pinging any of the app servers (e.g. 172.64.3.21, 172.64.3.22 above)
Downloading files using HTTP from the app servers All packets to external hosts (app servers) should appear to come from eth2's address (e.g. 172.64.3.1 above).


http://www.cs.toronto.edu/~yganjali/courses/csc458/assignments/nat/
