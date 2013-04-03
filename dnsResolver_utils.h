#include <vector>
#include <string>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stack>
#include <set>
#include <iostream>
#include <cstdio>

using namespace std;

// Print char in hex format
void PrintCharInHex(unsigned char c);

// Get the indicated bit in a char variable
// if bit is 1, return 1; if bit is 0, return 0
int GetBit(unsigned char input, int i);

// Set the indicated bit in a char variable
// lower bits are in the right
void SetBit(unsigned char& input, int i);

// Clear the indicated bit in a char variable
void ClearBit(unsigned char& input, int i);

// Given the four bytes of binary IPv4 address, convert it
// to string format
void ConvertBinaryIPToString(string& ip_str, unsigned char byte);

// Construct the DNS query packet based on the 
// given input hostname
void ConstructDNSQueryPacket(char* hostname, unsigned char dns_query_packet[]);

// Calculate the number of labels in the given
// input hostname. e.g. www.unl.edu has 3 labels
// www, unl, and edu.
int CalcNumOfLabels(char* hostname);

// Calculate the number of bytes required to hold
// the QNAME section. If the format of the input hostname
// is not correct, the function will return false. e.g.
// "www..unl.edu" is not in a correct format
bool CalcNumOfBytesQNAME(char* hostname, int& bytes_num);

// Function for send out the DNS query and get the response packet
bool SendDNSQuery(unsigned char dns_query_packet[], int query_packet_len, const char* serv_ip,\
    unsigned char dns_response_packet[], int response_packet_len, int& num_bytes_received);

// Function for parse the DNS response packet from server
bool ParseDNSResponse(unsigned char dns_query_packet[], int query_packet_len, int num_bytes_QNAME, \
    unsigned char dns_response_packet[],int num_bytes_received, vector<string>& answer_A_rr, vector<string>& answer_CNAME_rr, vector<string>& answer_NS_rr, vector<string>& additional_rr);

// Function for parse the RDATA field in CNAME answer Rresouce Record
bool ParseHostname(unsigned char dns_response_packet[], string& CNAME_str, int index);

// main function used to do dns resolve
bool DNSResolve(unsigned char dns_query_packet[], int num_bytes_total,  int num_bytes_QNAME, stack<string>& name_servers, \
                set<string>& queryed_name_servers, unsigned char dns_response_packet[], int& num_bytes_received, vector<string>& answer_ip);

