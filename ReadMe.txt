This homework is about to implement a iterative DNS resolver.

The source code includes:
dnsResolver_utils.h
dnsResolver_utils.cpp
dnsResolver_main.cpp

The other files are:
Makefile
Sample.txt
Design.txt

The compiling environment is the CSE server at cse.unl.edu. To compile the program, just upload all the source codes and the Makefile to the CSE server and simply type "make".

After compiling the program, you can run the program as:
$ ./DNS_Resolver [hostname]
the program will give you the corresponding output. If the input is a valid hostname, the output would be the CNAME (if it has) and IPv4 addresses. Otherwise, the program would indicate the IP address cannot be found.
