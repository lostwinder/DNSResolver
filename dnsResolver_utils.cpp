#include "dnsResolver_utils.h"

using namespace std;

set<string> queryed_cname;
set<string> queryed_cname_print;


void PrintCharInHex(unsigned char c){
    char alphabet[] = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
    int lower_4bits = c & 0x0F;
    int upper_4bits = (c >> 4) & 0x0F;
    cout << alphabet[upper_4bits] << alphabet[lower_4bits] << " ";
    return;
}

int GetBit(unsigned char input, int i){
    if(input & (0x01 << i)){
        return 1;
    }
    else{
        return 0;
    }
}

void SetBit(unsigned char& input, int i){
    input | (1 << i);
}

void ClearBit(unsigned char& input, int i){
    input & (~(1 << i));
}

void ConvertCharToBinaryString(string& ip_str, unsigned char byte){
    int i = 0;
    i = byte / 100;
    if(i != 0){
        ip_str.push_back('0' + i);
    }
    int ii = 0;
    byte = byte - i * 100;
    ii = byte / 10;
    if(ii != 0 || (ii ==0 && i != 0)){
        ip_str.push_back('0' + ii);
    }
    byte = byte - ii * 10;
    ip_str.push_back('0' + byte);
}

void ConstructDNSQueryPacket(char* hostname, unsigned char dns_query_packet[]){
    
    srand(time(NULL));
    int id = rand() % 65536;
    unsigned char id_lower_8bits = (unsigned char)(id & 0xFF);
    unsigned char id_upper_8bits = (unsigned char)((id >> 8) & 0xFF);

    // Add the ID to the first two bytes
    dns_query_packet[0] = id_upper_8bits;
    dns_query_packet[1] = id_lower_8bits;

    unsigned char option_upper_8bits = 0;
    unsigned char option_lower_8bits = 0;

    // Set QR bit to be 0 for query
    // Set OPCODE to be 0 for standard query, e.g. 0000
    // Since by default, all the bits in the option bytes
    // set to be 0, we just simply copy these two bytes

    dns_query_packet[2] = option_upper_8bits;
    dns_query_packet[3] = option_lower_8bits;
    
    // Set QDCOUNT to be 1 because there is 1 query
    dns_query_packet[4] = 0;
    dns_query_packet[5] = 1;

    // Set ANCOUNT, NSCOUNT and ARCOUNT
    for(int i = 6; i <= 11; i++){
        dns_query_packet[i] = 0;
    }

    // debug
    //cout << "DNS query header successfully added." << endl;

    // Next, handle the DNS Questions section
    // First is QNAME
    int label_length_index = 12;
    int j = 0;
    int m = 13;
    unsigned char count = 0;
    while(hostname[j] != '\0'){
        count = 0;
        while(hostname[j] != '.' && hostname[j] != '\0'){
            count ++;
            dns_query_packet[m] = hostname[j];
            m ++;
            j ++;
        }

        dns_query_packet[label_length_index] = count;
        label_length_index = m;

        if(hostname[j] == '\0'){
            dns_query_packet[label_length_index] = 0x00;
            m ++;
            break;
        }
        m ++;
        j ++;

        if(hostname[j] == '\0'){
            dns_query_packet[m] = 0x00;
            m ++;
            break;
        }
    }

    // debug
    //cout << "QNAME has been successfully added in DNS query packet." << endl;

    // Handle the QTYPE, 0x0001 for Type A query
    dns_query_packet[m] = 0x00;
    dns_query_packet[m+1] = 0x01;
    // Handle the QCLASS. 0x0001 for Internet address
    dns_query_packet[m+2] = 0x00;
    dns_query_packet[m+3] = 0x01;

}



// For the uncorrected formats, we handles two cases, one
// is the string starts with '.', the other case is that
// there are two or more consecutive '.' in the hostname
bool CalcNumOfBytesQNAME(char* hostname, int& bytes_num){
    if(hostname[0] == '.'){
        return false;
    }
    int i = 1;
    char prev = hostname[0];
    while(hostname[i] != '\0'){
        if(prev == '.'){
            if(hostname[i] == prev){
                return false;
            }
        }
        prev = hostname[i];
        i ++;
    }
    
    bool is_dot_end = false;
    if(hostname[i-1] == '.'){
        is_dot_end = true;
    }
    int str_length = strlen(hostname);
    int dot_num = 0;
    for(i = 0; i < str_length; i++){
        if(hostname[i] == '.'){
            dot_num ++;
        }
    }
    int label_num = 0;
    if(is_dot_end){
        label_num = dot_num;
        bytes_num = str_length + 1;
    }
    else{
        label_num = dot_num + 1;
        bytes_num = str_length + 2;
    }

    return true;

}

bool SendDNSQuery(unsigned char dns_query_packet[], int query_packet_len, const char* serv_ip, \
    unsigned char dns_response_packet[], int response_packet_len, int& num_bytes_received){
    int sockfd = 0;
    struct sockaddr_in serv_addr;

    memset(dns_response_packet, '0', response_packet_len);
    // Create the socket
    if((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0){
        cout << "Error: could not create socket." << endl;
        return false;
    }
    
    memset(&serv_addr, '0', sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(53);

    // Convert the string of IP address to binary format
    if(inet_pton(AF_INET, serv_ip, &serv_addr.sin_addr) <= 0){
        cout << "Error in inet_pton function." << endl;
        return false;
    }

    // debug
    //cout << "The server ip address that is connecting is: " << serv_ip << endl;

    // Connect to the server from local DNS resolver
    if(connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0){
        cout << "Connect to the server failed." << endl;
        return false;
    }

    // debug
    //cout << "Connect to the server is successful." << endl;

    // send the DNS query packet to the server
    send(sockfd, dns_query_packet, query_packet_len, 0);
    // debug
    //cout << "Number of bytes sent to the server is: " << query_packet_len << endl;
    
    // use select to check if there is incoming data within timeout interval before calling recv()
    fd_set rfds;
    struct timeval tv;
    int retval;
    
    FD_ZERO(&rfds);
    FD_SET(sockfd, &rfds);
    //wait up to one second
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    
    retval = select(sockfd+1, &rfds, NULL, NULL, &tv);
    
    if(retval == -1){
        perror("select()");
        return false;
    }
    else if(retval){
        num_bytes_received = recv(sockfd, dns_response_packet, response_packet_len, 0);
        if (num_bytes_received == -1) {
            cout << "Error in receiving from the name server for response. Timeout." << endl;
            return false;
        }
        if (num_bytes_received  == 0) {
            cout << "Name server close the connection. Error." << endl;
            return false;
        }
        // debug
        /*cout << "Number of bytes received from server's response is: " << num_bytes_received << endl;
        int j = 0;
        for(j = 0; j < num_bytes_received; j ++){
            PrintCharInHex(dns_response_packet[j]);
        }
        cout << endl;*/
        return true;        
    }
    else{
        //cout << "No data within one seconds." << endl;
        return false;
    }

}

bool ParseDNSResponse(unsigned char dns_query_packet[], int query_packet_len, int num_bytes_QNAME, \
    unsigned char dns_response_packet[], int num_bytes_received, vector<string>& answer_A_rr, vector<string>& answer_CNAME_rr, vector<string>& answer_NS_rr, vector<string>& additional_rr){
    
    // First, check whether the ID of response matches the ID of query
    if(dns_query_packet[0] != dns_response_packet[0] || dns_query_packet[1] != dns_response_packet[1]){
        cout << "ID of DNS query packet does not match the ID of DNS response packet." << endl;
        return false;
    }

    // Check the QR bit to see whether this is a dns reponse or not
    if(! GetBit(dns_response_packet[2], 7)){
        cout << "This packet is not a valid DNS query response." << endl;
        return false;
    }

    // Since we construct the DNS query packet as a standard query, OPCODE should be
    // 0000, otherwise, there is something wrong.
    if(dns_response_packet[2] & 0x78){
        cout << "The OPCODE does not stand for standard query. Miss match occurs." << endl;
        return false;
    }

    // AA bit stands for whether the responding name server is an authority for the domain name
    // in question section.
    bool is_authority = false;
    if(! GetBit(dns_response_packet[2], 2)){
        //cout << "The name server that provides response is not an authority." << endl;
    }
    else{
        //cout << "The name server that provides response is an authority." << endl;
        is_authority = true;
    }

    // TC bit is the bit to indicate whether the message is truncated. If it is, we need to report
    // error and return false;
    if(GetBit(dns_response_packet[2], 1)){
        //cout << "The response message is truncated. Error." << endl;
        return false;
    }

    // RD bit should be 0, since we don't want recursive lookup when we construct the DNS query.
    if(GetBit(dns_response_packet[2], 0)){
        //cout << " The response indicate recursive resolution desired. Error." << endl;
        return false;
    }

    // RA bit indicates whether the name server support recursive query.
    if(GetBit(dns_response_packet[3], 7)){
        //cout << "The name server support recursive query." << endl;
    }
    else{
        //cout << "The name server does not support recursive query." << endl;
    }

    // Z should be 000, otherwise something is wrong
    if(dns_response_packet[3] & 0x70){
        //cout << "Error: Z is not 000." << endl;
        return false;
    }

    // RCODE has 5 different cases
    unsigned char RCODE = dns_response_packet[3] & 0x0F;
    //cout << "Test RCODE failure conditions: ";
    switch(RCODE){
        case 0x00:
            //cout << "No error condition." << endl;
            break;
        case 0x01:
            //cout << "Format failure: The name server was unable to interpret the query." << endl;
            return false;
            break;
        case 0x02:
            //cout << "Server failure: The name server was unable to process this query due to a problem with the name server." << endl;
            return false;
            break;
        case 0x03:
            if(is_authority){
                //cout << "The domain name referenced in the query does not exist in this authority name server." << endl;
                return false;
            }
            else{
                //cout << "Error code that is not documented." << endl;
                return false;
            }
            break;
        case 0x04:
            //cout << "Not implemented: The name server does not support the requested kind of query." << endl;
            return false;
            break;
        case 0x05:
            //cout << "Refused: The name server refuses to perform the specified operation for policy reasons." << endl;
            return false;
            break;
        default:
            return false;
    }

    // QDCOUNT stands for the number of questions, which should be the same as that in DNS query packet.
    if(dns_response_packet[4] != dns_query_packet[4] || dns_response_packet[5] != dns_query_packet[5]){
        //cout << "QDCOUNT does not match between DNS query and DNS response." << endl;
        return false;
    }

    // ANCOUNT stands for the number of records in the Answer section
    int num_answers = int(dns_response_packet[6])*256 + int(dns_response_packet[7]);
    //cout << "There are " << num_answers << " answers in the answer section." << endl;
    // NSCOUNT stands for the number of records in the Authority section
    int num_authority = int(dns_response_packet[8])*256 + int(dns_response_packet[9]);
    //cout << "There are " << num_authority << " records in the authority section." << endl;
    // ARCOUNT stands for the number of records in the Additional section
    int num_additional = int(dns_response_packet[10])*256 + int(dns_response_packet[11]);
    //cout << "There are " << num_additional << " records in the additional section." << endl;

    // The Question section should be the same as the the Question section in the DNS query packet
    // use index m to represent the index for the data in dns_reponse_packet
    int m = 12;
    for(m = 12; m < 12 + num_bytes_QNAME + 4; m ++){
        if(dns_response_packet[m] != dns_query_packet[m]){
            //cout << "Question section does not match between DNS query and DNS response." << endl;
            return false;
        }
    }


    // now m is at the bytes where Answers section or Authority section begins, depends on the response.
    // We use UDP to setup the socket, the reponse packet uses compression machenism.
    // There are three possibilities: 
    // 1. a sequence of labels ending in a zero octet
    // 2. a pointer
    // 3. a sequence of labels ending with a pointer


    // There are two cases in terms of number of Answer RRs. 0 or not 0. If the number is not 0,
    // we only need to read the RRs in Answer Section and return; if the number is 0, there is no
    // RRs in Answer Section, we only need to record the IP addresses in the Additional Sections
    // for the further lookup to query on.
    
    int counter_answer = 0;
    int counter_authority = 0;
    int counter_additional = 0;
    if(num_answers != 0){
        while(counter_answer < num_answers){
            bool is_CNAME = false;
            if((dns_response_packet[m] & 0xC0) == 0xC0){
                // case 2
                int offset = int(dns_response_packet[m] & 0x3F)*256 + int(dns_response_packet[m+1]);
                if(dns_response_packet[m+2] == 0x00 && dns_response_packet[m+3] == 0x01){
                    // A record
                    counter_answer ++;
                }
                if(dns_response_packet[m+2] == 0x00 && dns_response_packet[m+3] == 0x05){
                    // CNAME
                    counter_answer ++;
                    is_CNAME = true;
                }
                if(dns_response_packet[m+2] == 0x00 && dns_response_packet[m+3] == 0x06){
                    // SOA record
                    return false;
                }
                
                if(!(dns_response_packet[m+4] == 0x00 && dns_response_packet[m+5] == 0x01)){
                    cout << "Error: Not Expected Internet Addresses in Answer section." << endl;
                    return false;
                }
                // byte m+6 ... m+9 are TTL data
                // RDLENGTH is the length for RDATA field
                int RDLENGTH = int(dns_response_packet[m+10])*256 + int(dns_response_packet[m+11]);
                
                // If the RDATA is a A Type Answer, the RDLENGTH should be 00 04, the RDATA field contains
                // four bytes, each byte represents a label in binary format.
                if (!is_CNAME) {
                    // check RDLENGTH should be 4
                    if(RDLENGTH != 4){
                        cout << "Error: IPv4 address does not have RDATA field with length = 4" << endl;
                        return false;
                    }
                    string ipv4_addr;
                    // parse the ipv4 address and save it in vector<string> answer_A_rr
                    int m_prime = m + 11 + 1;
                    
                    for (int i = 0; i < 4; i ++) {
                        ConvertCharToBinaryString(ipv4_addr, dns_response_packet[m_prime+i]);
                        if (i != 3) {
                            ipv4_addr.push_back('.');
                        }
                    }
                    
                    //cout << "Parsed IPv4 address in Answer section is: " << ipv4_addr << endl;
                    answer_A_rr.push_back(ipv4_addr);

                }
                else{// The answer is a CNAME, 3 compression schemes apply here
                    string CNAME_str;
                    // parse the CNAME string and save it in vector<string> answer_CNAME_rr
                    int m_prime = m + 11 + 1;
                    // for the RDATA field, three 3 different compression schemes also apply
                    
                    if (!ParseHostname(dns_response_packet, CNAME_str, m_prime)) {
                        return false;
                    }
                    if (queryed_cname.find(CNAME_str) == queryed_cname.end()) {
                        cout << "Parsed CNAME address in Answer section is: " << CNAME_str << endl;
                        
                    }
                    answer_CNAME_rr.push_back(CNAME_str);
                    
                    
                }
                m = m + 11 + RDLENGTH + 1;
            }
            else if((dns_response_packet[m] & 0xC0) == 0x00){
                // case 1 or case 3
                // first handle the NAME
                while(1){
                    int label_length = int(dns_response_packet[m]);
                    m = m + label_length + 1;
                    if(dns_response_packet[m] == 0x00){// case 1: this is the end of the label sequences.
                        m = m + 1;
                        break;
                    }
                    if((dns_response_packet[m] & 0xC0) == 0xC0){// case 3: the name ends with a pointer.
                        m = m + 2;
                        break;
                    }
                }
                // continue handling the remaining stuff in one RR, the same as in case 2, just copy
                // this is not quite elegant, probably need a little bit refactoring later
                if(dns_response_packet[m] == 0x00 && dns_response_packet[m+1] == 0x01){
                    // A record
                    counter_answer ++;
                }
                if(dns_response_packet[m] == 0x00 && dns_response_packet[m+1] == 0x05){
                    // CNAME
                    counter_answer ++;
                    is_CNAME = true;
                }
                if(!(dns_response_packet[m+2] == 0x00 && dns_response_packet[m+3] == 0x01)){
                    cout << "Error: Not Expected Internet Addresses in Answer section." << endl;
                    return false;
                }
                // byte m+4 ... m+7 are TTL data
                // RDLENGTH is the length for RDATA field
                int RDLENGTH = int(dns_response_packet[m+8])*256 + int(dns_response_packet[m+9]);
                
                // If the RDATA is a A Type Answer, the RDLENGTH should be 00 04, the RDATA field contains
                // four bytes, each byte represents a label in binary format.
                if (!is_CNAME) {
                    // check RDLENGTH should be 4
                    if(RDLENGTH != 4){
                        cout << "Error: IPv4 address does not have RDATA field with length = 4" << endl;
                        return false;
                    }
                    string ipv4_addr;
                    // parse the ipv4 address and save it in vector<string> answer_A_rr
                    int m_prime = m + 9 + 1;
                    
                    for (int i = 0; i < 4; i ++) {
                        ConvertCharToBinaryString(ipv4_addr, dns_response_packet[m_prime+i]);
                        if (i != 3) {
                            ipv4_addr.push_back('.');
                        }
                    }
                    
                    //cout << "Parsed IPv4 address in Answer section is: " << ipv4_addr << endl;
                    answer_A_rr.push_back(ipv4_addr);
                    
                }
                else{// The answer is a CNAME, 3 compression schemes apply here
                    string CNAME_str;
                    // parse the CNAME string and save it in vector<string> answer_CNAME_rr
                    int m_prime = m + 9 + 1;
                    // for the RDATA field, three 3 different compression schemes also apply
                    
                    if (!ParseHostname(dns_response_packet, CNAME_str, m_prime)) {
                        return false;
                    }
                    if (queryed_cname.find(CNAME_str) == queryed_cname.end()) {
                        cout << "Parsed CNAME address in Answer section is: " << CNAME_str << endl;
                        
                    }
                    answer_CNAME_rr.push_back(CNAME_str);
                }
                m = m + 9 + RDLENGTH + 1;

                
            }
            else{
                //cout << "Unable to parse the NAME in Answer section Resource Record." << endl;
                return false;
            }
        }
    }
    else{
        // there is no answer section in DNS response packet, directly read the Authority and Additional section

        // first handle the authority section
        while(counter_authority < num_authority){
            if((dns_response_packet[m] & 0xC0) == 0xC0){
                // case 2. byte m and m+1 are for offset
                int offset = int(dns_response_packet[m] & 0x3F)*256 + int(dns_response_packet[m+1]);
                
                if(dns_response_packet[m+2] == 0x00 && dns_response_packet[m+3] == 0x02){
                    counter_authority ++;
                }
                if(dns_response_packet[m+2] == 0x00 && dns_response_packet[m+3] == 0x06){
                    // SOA record
                    return false;
                }
                
                
                if(!(dns_response_packet[m+4] == 0x00 && dns_response_packet[m+5] == 0x01)){
                    cout << "Error: Not Expected Internet Addresses in Authority section. " << counter_authority << endl;
                    return false;
                }
                // byte m+6 ... m+9 are TTL data
                // RDLENGTH is the length for RDATA field
                int RDLENGTH = int(dns_response_packet[m+10])*256 + int(dns_response_packet[m+11]);

                // For RDATA field, it should be the hostname of the name server
                string NS_str;
                // parse the name server string and save it in vector<string> answer_NS_rr
                int m_prime = m + 11 + 1;
                // for the RDATA field, three 3 different compression schemes also apply
                
                if (!ParseHostname(dns_response_packet, NS_str, m_prime)) {
                    return false;
                }
                
                //cout << "Parsed name server hostname address in Authority section is: " << NS_str << endl;
                answer_NS_rr.push_back(NS_str);
                
                m = m + 11 + RDLENGTH + 1;
            }
            else if((dns_response_packet[m] & 0xC0) == 0x00){
                // case 1 or case 3
                // first handle the NAME
                while(1){
                    int label_length = int(dns_response_packet[m]);
                    m = m + label_length + 1;
                    if(dns_response_packet[m] == 0x00){// case 1: this is the end of the label sequences.
                        m = m + 1;
                        break;
                    }
                    if((dns_response_packet[m] & 0xC0) == 0xC0){// case 3: the name ends with a pointer. 
                        m = m + 2;
                        break;
                    }
                }
                // continue handling the remaining stuff in one RR, the same as in case 2, just copy
                // this is not quite elegant, probably need a little bit refactoring later
                if(dns_response_packet[m] == 0x00 && dns_response_packet[m+1] == 0x02){
                    counter_authority ++;
                }
                if(dns_response_packet[m] == 0x00 && dns_response_packet[m+1] == 0x06){
                    // SOA record
                    return false;
                }

                if(!(dns_response_packet[m+2] == 0x00 && dns_response_packet[m+3] == 0x01)){
                    cout << "Error: Not Expected Internet Addresses in Authority section. " << counter_authority << endl;
                    return false;
                }
                // byte m+4 ... m+7 are TTL data
                // RDLENGTH is the length for RDATA field
                int RDLENGTH = int(dns_response_packet[m+8])*256 + int(dns_response_packet[m+9]);
                
                // For RDATA field, it should be the hostname of the name server
                string NS_str;
                // parse the name server string and save it in vector<string> answer_NS_rr
                int m_prime = m + 11 + 1;
                // for the RDATA field, three 3 different compression schemes also apply
                
                if (!ParseHostname(dns_response_packet, NS_str, m_prime)) {
                    return false;
                }
                
                //cout << "Parsed name server hostname address in Authority section is: " << NS_str << endl;
                answer_NS_rr.push_back(NS_str);
                
                m = m + 9 + RDLENGTH + 1;
            }
            else{
                cout << "Unable to parse the NAME in Authority section Resource Record." << endl;
                return false;
            }
        }
        // then handle the Additional section, handle the Additional section is very similar as
        // Authority section, the only difference is that now we need to parse out the RDATA field
        // and save it to make a record. Also, for the RDATA section, it either host IPv4 address with
        // RDLENGTH = 4 or RDLENGTH = other value for IPv6.
        while(counter_additional < num_additional){
            bool is_ipv6 = false;
            if((dns_response_packet[m] & 0xC0) == 0xC0){
                // case 2
                //int offset = int(dns_response_packet[m] & 0x3F)*256 + int(dns_response_packet[m+1]);
                int offset = int(dns_response_packet[m+1]);
                // A Type - IPv4
                if(dns_response_packet[m+2] == 0x00 && dns_response_packet[m+3] == 0x01){
                    counter_additional ++;
                }
                // AAAA Type - IPv6
                if(dns_response_packet[m+2] == 0x00 && dns_response_packet[m+3] == 0x1C){
                    counter_additional ++;
                    is_ipv6 = true;
                }
                if(!(dns_response_packet[m+4] == 0x00 && dns_response_packet[m+5] == 0x01)){
                    cout << "Error: Not Expected Internet Addresses in Additional section." << endl;
                    return false;
                }
                // byte m+6 ... m+9 are TTL data
                // RDLENGTH is the length for RDATA field
                int RDLENGTH = int(dns_response_packet[m+10])*256 + int(dns_response_packet[m+11]);

                // For RDATA field, it should be the IP address of the name server, since we can only use 
                // the IP to connect socket, thus we need to parse out each IPv4 address and ignore IPv6 address
                
                if(!is_ipv6){
                    // check RDLENGTH should be 4
                    if(RDLENGTH != 4){
                        cout << "Error: IPv4 address does not have RDATA field with length = 4" << endl;
                        return false;
                    }
                    string ipv4_addr;
                    // parse the ipv4 address and save it in vector<string> additional_rr
                    int m_prime = m + 11 + 1;
                    
                    for (int i = 0; i < 4; i ++) {
                        ConvertCharToBinaryString(ipv4_addr, dns_response_packet[m_prime+i]);
                        if (i != 3) {
                            ipv4_addr.push_back('.');
                        }
                    }
                    
                    //cout << "Parsed IPv4 address in Additional section is: " << ipv4_addr << endl;
                    additional_rr.push_back(ipv4_addr);
                    
                }
                m = m + 11 + RDLENGTH + 1;
            }
            else if((dns_response_packet[m] & 0xC0) == 0x00){
                // case 1 or case 3
                // first handle the NAME
                while(1){
                    int label_length = int(dns_response_packet[m]);
                    m = m + label_length + 1;
                    if(dns_response_packet[m] == 0x00){// case 1: this is the end of the label sequences.
                        m = m + 1;
                        break;
                    }
                    if((dns_response_packet[m] & 0xC0) == 0xC0){// case 3: the name ends with a pointer. 
                        m = m + 2;
                        break;
                    }
                }
                // continue handling the remaining stuff in one RR, the same as in case 2, just copy
                // this is not quite elegant, probably need a little bit refactoring later
                if(dns_response_packet[m] == 0x00 && dns_response_packet[m+1] == 0x01){
                    counter_additional ++;
                }
                if(dns_response_packet[m] == 0x00 && dns_response_packet[m+1] == 0x1C){
                    counter_additional ++;
                    is_ipv6 = true;
                }
                if(!(dns_response_packet[m+2] == 0x00 && dns_response_packet[m+3] == 0x01)){
                    cout << "Error: Not Expected Internet Addresses in Additional section." << endl;
                    return false;
                }
                // byte m+4 ... m+7 are TTL data
                // RDLENGTH is the length for RDATA field
                int RDLENGTH = int(dns_response_packet[m+8])*256 + int(dns_response_packet[m+9]);

                // only parse the ipv4 address
                if(!is_ipv6){
                    string ipv4_addr;
                    // parse the ipv4 address and save it in vector<string> additional_rr
                    int m_prime = m + 9 + 1;
                    
                    for (int i = 0; i < 4; i ++) {
                        ConvertCharToBinaryString(ipv4_addr, dns_response_packet[m_prime+i]);
                        if (i != 3) {
                            ipv4_addr.push_back('.');
                        }
                    }
                    
                    //cout << "Parsed IPv4 address in Additional section is: " << ipv4_addr << endl;
                    additional_rr.push_back(ipv4_addr);

                }
                m = m + 9 + RDLENGTH + 1;
            }
            else{
                cout << "Unable to parse the NAME in Additional section Resource Record." << endl;
                return false;
            }
        }
    }
    
    return true;
}


bool ParseHostname(unsigned char dns_response_packet[], string& hostname_str, int index){
    if ((dns_response_packet[index] & 0xC0) == 0xC0) {
        // case 2
        int offset = int(dns_response_packet[index] & 0x3F)*256 + int(dns_response_packet[index+1]);
        
        return ParseHostname(dns_response_packet, hostname_str, offset);
    }
    else if((dns_response_packet[index] & 0xC0) == 0x00){
        // case 1 or case 3
        while(1){
            int label_length = int(dns_response_packet[index]);
            for(int k = index + 1; k < index+1+label_length; k++){
                hostname_str.push_back(dns_response_packet[k]);
            }
            hostname_str.push_back('.');
            index = index + label_length + 1;
            if(dns_response_packet[index] == 0x00){// case 1: this is the end of ip address
                return true;
            }
            if((dns_response_packet[index] & 0xC0) == 0xC0){// case 3: this label sequence ends with a pointer
                int offset = int(dns_response_packet[index] & 0x3F)*256 + int(dns_response_packet[index+1]);
                return ParseHostname(dns_response_packet, hostname_str, offset);
            }
        }
    }
    else{
        //cout << "Unable to parse the RDATA field in Answer section." << endl;
        return false;
    }
}


bool DNSResolve(unsigned char dns_query_packet[], int num_bytes_total,  int num_bytes_QNAME, stack<string>& name_servers, \
                set<string>& queryed_name_servers, unsigned char dns_response_packet[], int& num_bytes_received, vector<string>& answer_ip){
    while (! name_servers.empty()) {
        if(!(SendDNSQuery(dns_query_packet, num_bytes_total, name_servers.top().c_str(), \
                          dns_response_packet, 1024, num_bytes_received))){
            //cout << "Communication with server " << name_servers.top() << " failed." << endl;
            name_servers.pop();
            continue;
        }
        
        vector<string> answer_A_rr; // used to host the answer entries, A Type
        vector<string> answer_CNAME_rr; // used to host the answer entries, CNAME Type
        vector<string> answer_NS_rr; // used to host the authority section RRs
        vector<string> additional_rr; // used to host the IP of name servers for next level query
        
        // Parse the DNS response packet
        if(! ParseDNSResponse(dns_query_packet, num_bytes_total, num_bytes_QNAME, \
                              dns_response_packet, num_bytes_received, answer_A_rr, answer_CNAME_rr, answer_NS_rr, additional_rr)){
            //cout << "Failed in parsing the DNS response packet due to above reasons." << endl;
            name_servers.pop();
            continue;
        }
        
        name_servers.pop();
        
        if (answer_A_rr.size()) {
            for (int i = 0; i < answer_A_rr.size(); i ++) {
                answer_ip.push_back(answer_A_rr[i]);
            }
            return true;
            break;
        }
        else {
            if (additional_rr.size()) {
                for (int j = 0; j < additional_rr.size(); j ++) {
                    if (queryed_name_servers.find(additional_rr[j]) == queryed_name_servers.end()) {
                        name_servers.push(additional_rr[j]);
                        queryed_name_servers.insert(additional_rr[j]);
                    }
                    
                }
            }
            else{// there is no additional section, we need to query the IP of the name servers in authority section
                if (answer_NS_rr.size()) {
                    int length = strlen(answer_NS_rr[0].c_str());
                    char NS_hostname[length+1];
                    strcpy(NS_hostname, answer_NS_rr[0].c_str());
                    if (NS_hostname[length-1] == '.') {
                        NS_hostname[length-1] = '\0';
                    }
                    NS_hostname[length] = '\0';
                    
                    // Calculate the number of bytes required for the DNS query packet
                    int num_bytes_total_prime = 0;
                    int num_bytes_QNAME_prime = 0;
                    if(!CalcNumOfBytesQNAME(NS_hostname, num_bytes_QNAME_prime)){
                        cout << "Invalid format of hostname." << endl;
                        cout << "Quit." << endl;
                        return 1;
                    }
                    
                    //cout << "The number of bytes for QNAME is: " << num_bytes_QNAME_prime << endl;
                    
                    // DNS header has length of 12 bytes, QTYPE and QCLASS has 2 bytes respectively
                    num_bytes_total_prime = 12 + num_bytes_QNAME_prime + 2 + 2;
                    
                    unsigned char dns_query_packet_prime[1024];
                    unsigned char dns_response_packet_prime[1024];
                    
                    ConstructDNSQueryPacket(NS_hostname, dns_query_packet_prime);
                    
                    // debug
                    /*for(int i = 0; i < num_bytes_total_prime; i++){
                        PrintCharInHex(dns_query_packet_prime[i]);
                    }
                    cout << endl;*/
                    stack<string> name_servers_prime;
                    name_servers_prime.push("198.41.0.4");
                    name_servers_prime.push("192.228.79.201");
                    name_servers_prime.push("192.33.4.12");
                    name_servers_prime.push("199.7.91.13");
                    name_servers_prime.push("192.203.230.10");
                    name_servers_prime.push("192.5.5.241");
                    name_servers_prime.push("192.112.36.4");
                    name_servers_prime.push("128.63.2.53");
                    name_servers_prime.push("192.36.148.17");
                    
                    set<string> queryed_name_servers_prime;
                    queryed_name_servers_prime.insert("198.41.0.4");
                    queryed_name_servers_prime.insert("192.228.79.201");
                    queryed_name_servers_prime.insert("192.33.4.12");
                    queryed_name_servers_prime.insert("199.7.91.13");
                    queryed_name_servers_prime.insert("192.203.230.10");
                    queryed_name_servers_prime.insert("192.5.5.241");
                    queryed_name_servers_prime.insert("192.112.36.4");
                    queryed_name_servers_prime.insert("128.63.2.53");
                    queryed_name_servers_prime.insert("192.36.148.17");
                    
                    vector<string> answer_ip_prime;
                    bool flag = DNSResolve(dns_query_packet_prime, num_bytes_total_prime, num_bytes_QNAME_prime, name_servers_prime, \
                                           queryed_name_servers_prime, dns_response_packet_prime, num_bytes_received, answer_ip_prime);

                    if(flag){
                        for (int i = 0; i < answer_ip_prime.size(); i++) {
                            name_servers.push(answer_ip_prime[i]);
                        }
                        // debug
                        //cout << "Debug purpose: IP address of authority name servers has been inserted" << endl;
                    }
                }
                
            }
            
            if (answer_CNAME_rr.size()) { // when there is no A answer, but only CNAME answer, we need to change the query packet
                // this is the hostname the DNS resolver would find IP address for
                // const char* CNAME_hostname = answer_CNAME_rr[0].c_str();
                int length = strlen(answer_CNAME_rr[0].c_str());
                char CNAME_hostname[length+1];
                strcpy(CNAME_hostname, answer_CNAME_rr[0].c_str());
                if (CNAME_hostname[length-1] == '.') {
                    CNAME_hostname[length-1] = '\0';
                }
                CNAME_hostname[length] = '\0';
                
                // Calculate the number of bytes required for the DNS query packet
                num_bytes_total = 0;
                num_bytes_QNAME = 0;
                if(!CalcNumOfBytesQNAME(CNAME_hostname, num_bytes_QNAME)){
                    cout << "Invalid format of hostname." << endl;
                    cout << "Quit." << endl;
                    return 1;
                }
                
                //cout << "The number of bytes for QNAME is: " << num_bytes_QNAME << endl;
                
                // DNS header has length of 12 bytes, QTYPE and QCLASS has 2 bytes respectively
                num_bytes_total = 12 + num_bytes_QNAME + 2 + 2;
                
                if (queryed_cname.find(answer_CNAME_rr[0]) == queryed_cname.end()) {
                    queryed_cname.insert(answer_CNAME_rr[0]);
                    ConstructDNSQueryPacket(CNAME_hostname, dns_query_packet);
                    
                    while (!name_servers.empty()) {
                        name_servers.pop();
                    }
                    name_servers.push("198.41.0.4");
                    name_servers.push("192.228.79.201");
                    name_servers.push("192.33.4.12");
                    name_servers.push("199.7.91.13");
                    name_servers.push("192.203.230.10");
                    name_servers.push("192.5.5.241");
                    name_servers.push("192.112.36.4");
                    name_servers.push("128.63.2.53");
                    name_servers.push("192.36.148.17");
                    
                    queryed_name_servers.clear();
                    queryed_name_servers.insert("198.41.0.4");
                    queryed_name_servers.insert("192.228.79.201");
                    queryed_name_servers.insert("192.33.4.12");
                    queryed_name_servers.insert("199.7.91.13");
                    queryed_name_servers.insert("192.203.230.10");
                    queryed_name_servers.insert("192.5.5.241");
                    queryed_name_servers.insert("192.112.36.4");
                    queryed_name_servers.insert("128.63.2.53");
                    queryed_name_servers.insert("192.36.148.17");

                }
                

                
                // debug
                /*for(int i = 0; i < num_bytes_total; i++){
                    PrintCharInHex(dns_query_packet[i]);
                }
                cout << endl;*/
            }
        }
        
    }
    
    return false;

}
