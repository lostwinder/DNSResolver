#include "dnsResolver_utils.h"

using namespace std;

// Global variable for root servers to query
vector<string> root_servers;

void Initialize_RootServer(vector<string>& root_servers){
    root_servers.push_back("198.41.0.4");
    root_servers.push_back("192.228.79.201");
    root_servers.push_back("192.33.4.12");
    root_servers.push_back("199.7.91.13");
    root_servers.push_back("192.203.230.10");
    root_servers.push_back("192.5.5.241");
    root_servers.push_back("192.112.36.4");
    root_servers.push_back("128.63.2.53");
    root_servers.push_back("192.36.148.17");
}

int main(int argc, char** argv){
    
    if(argc != 2){
        cout << "Wrong input parameters!" << endl;
        cout << "Usage: " << argv[0] << " [hostname]" << endl;
        return 1;
    }
    
    // this is the hostname the DNS resolver would find IP address for
    char* hostname = argv[1];
    int len = strlen(hostname);

    // Calculate the number of bytes required for the DNS query packet
    int num_bytes_total = 0;
    int num_bytes_QNAME = 0;
    if(!CalcNumOfBytesQNAME(hostname, num_bytes_QNAME)){
        cout << "Invalid format of hostname." << endl;
        cout << "Example hostname: www.unl.edu" << endl;
        cout << "Quit." << endl;
        return 1;
    }
    
    // remove the last dot
    if (hostname[len-1] == '.') {
        hostname[len-1] = '\0';
    }

    //cout << "The number of bytes for QNAME is: " << num_bytes_QNAME << endl;
    
    // DNS header has length of 12 bytes, QTYPE and QCLASS has 2 bytes respectively
    num_bytes_total = 12 + num_bytes_QNAME + 2 + 2;

    unsigned char dns_query_packet[1024];

    ConstructDNSQueryPacket(hostname, dns_query_packet);

    // debug
    /*for(int i = 0; i < num_bytes_total; i++){
        PrintCharInHex(dns_query_packet[i]);
    }
    cout << endl;*/

    // starting point of socket programming
    int num_bytes_received = 0;
    unsigned char dns_response_packet[1024];

    // initialize the root servers
    Initialize_RootServer(root_servers);
    
    int num_root_servers = root_servers.size();
    
    stack<string> name_servers;
    set<string> queryed_name_servers;
    for (int i = 0; i < num_root_servers; i ++) {
        name_servers.push(root_servers[i]);
        queryed_name_servers.insert(root_servers[i]);
    }
    
    vector<string> answer_ip;
    
    bool flag =  DNSResolve(dns_query_packet, num_bytes_total, num_bytes_QNAME, name_servers, queryed_name_servers, dns_response_packet, num_bytes_received, answer_ip);
    
    if(flag){
        for (int i = 0; i < answer_ip.size(); i++) {
            cout << "Parsed IPv4 address is: " << answer_ip[i] << endl;
        }
        return 0;
    }
    
    cout << "Could not find the IP address for the hostname." << endl;
    
    return 0;
}
