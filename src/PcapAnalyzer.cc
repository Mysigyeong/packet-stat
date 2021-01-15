#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "common.h"
#include "PcapAnalyzer.h"

#define IPV6_TCP    6
#define IPV6_UDP    17
#define IPV6_HEADER_LEN 40

using ether_header = struct ether_header;
using ip_header = struct ip;
using ip6_header = struct ip6_hdr;
using tcp_header = struct tcphdr;
using udp_header = struct udphdr;
using pcap_header = struct pcap_pkthdr;


CPcapAnalyzer::CPcapAnalyzer(char* filename)
{
    int res = 0;
    int length = 0;
    bool is_first = true;
    struct timeval init = { 0 };
    struct timeval cur = { 0 };
    pcap_header* header = NULL;
	const u_char* packet = NULL;
    char errbuf[PCAP_ERRBUF_SIZE] = { 0 };

    ether_header* ether_header_ptr = NULL;
    ip_header* ip_header_ptr = NULL;
    ip6_header* ip6_header_ptr = NULL;
    tcp_header* tcp_header_ptr = NULL;
    udp_header* udp_header_ptr = NULL;

    // open pcap file
    if (!(m_pcap_handle = pcap_open_offline(filename, errbuf))) {
        cerr << "pcap_open_offline(" << filename << ") failed. " << errbuf << endl;
        exit(1);
    }


    // parse pcap file
    while (1 == (res = pcap_next_ex(m_pcap_handle, &header, &packet))) {
        // get ethernet header
        ether_header_ptr = (ether_header*)packet;

        if (is_first) {
            init.tv_sec = header->ts.tv_sec;
            init.tv_usec = header->ts.tv_usec;
            is_first = false;
        }

        length = header->caplen;

        // ethernet endpoint information
        address_t mac_src_addr(ether_header_ptr->ether_shost);
        endpoint_data_t tx(1, length);
        address_t mac_dest_addr(ether_header_ptr->ether_dhost);
        endpoint_data_t rx(0, 0, 1, length);

        m_ethernet_endpoint.push(mac_src_addr, tx);
        m_ethernet_endpoint.push(mac_dest_addr, rx);

        if (header->ts.tv_usec < init.tv_usec) {
            cur.tv_usec = 1000000 + header->ts.tv_usec - init.tv_usec;
            cur.tv_sec = header->ts.tv_sec - init.tv_sec - 1;
        }
        else {
            cur.tv_usec = header->ts.tv_usec - init.tv_usec;
            cur.tv_sec = header->ts.tv_sec - init.tv_sec;
        }

        // ethernet conversation information
        conversation_data_t mac_conversation(1, length, 0, 0, cur, cur);
        address_pair mac_pair(mac_src_addr, mac_dest_addr, &mac_conversation);

        m_ethernet_conversation.push(mac_pair, mac_conversation);

        if (ETHERTYPE_IP == ntohs(ether_header_ptr->ether_type)) {
            // ipv4
            ip_header_ptr = (ip_header*)(packet + sizeof(ether_header));

            if (ip_header_ptr->ip_v != 4)
                continue;

            // ipv4 endpoint information
            address_t ip_src_addr(ip_header_ptr->ip_src.s_addr);
            address_t ip_dest_addr(ip_header_ptr->ip_dst.s_addr);
            
            m_ipv4_endpoint.push(ip_src_addr, tx);
            m_ipv4_endpoint.push(ip_dest_addr, rx);

            // ipv4 conversation information
            conversation_data_t ip_conversation(1, length, 0, 0, cur, cur);
            address_pair ip_pair(ip_src_addr, ip_dest_addr, &ip_conversation);

            m_ipv4_conversation.push(ip_pair, ip_conversation);

            if (ip_header_ptr->ip_p == IPPROTO_TCP) {
                // tcp endpoint information
                tcp_header_ptr = (tcp_header*)(packet + sizeof(ether_header) + ip_header_ptr->ip_hl * 4);
                address_t tcp_src_addr(ip_header_ptr->ip_src.s_addr, ntohs(tcp_header_ptr->source));
                address_t tcp_dest_addr(ip_header_ptr->ip_dst.s_addr, ntohs(tcp_header_ptr->dest));

                m_tcp_endpoint.push(tcp_src_addr, tx);
                m_tcp_endpoint.push(tcp_dest_addr, rx);

                // tcp conversation information
                conversation_data_t tcp_conversation(1, length, 0, 0, cur, cur);
                address_pair tcp_pair(tcp_src_addr, tcp_dest_addr, &tcp_conversation);

                m_tcp_conversation.push(tcp_pair, tcp_conversation);
            }
            else if (ip_header_ptr->ip_p == IPPROTO_UDP) {
                // udp endpoint information
                udp_header_ptr = (udp_header*)(packet + sizeof(ether_header) + ip_header_ptr->ip_hl * 4);
                address_t udp_src_addr(ip_header_ptr->ip_src.s_addr, ntohs(udp_header_ptr->source));
                address_t udp_dest_addr(ip_header_ptr->ip_dst.s_addr, ntohs(udp_header_ptr->dest));

                m_udp_endpoint.push(udp_src_addr, tx);
                m_udp_endpoint.push(udp_dest_addr, rx);

                // udp conversation information
                conversation_data_t udp_conversation(1, length, 0, 0, cur, cur);
                address_pair udp_pair(udp_src_addr, udp_dest_addr, &udp_conversation);

                m_udp_conversation.push(udp_pair, udp_conversation);
            }
        }
        else if (ETHERTYPE_IPV6 == ntohs(ether_header_ptr->ether_type)) {
            //ipv6
            ip6_header_ptr = (ip6_header*)(packet + sizeof(ether_header));

            // ipv6 endpoint information
            address_t ip6_src_addr(ip6_header_ptr->ip6_src.s6_addr, 70000);
            address_t ip6_dest_addr(ip6_header_ptr->ip6_dst.s6_addr, 70000);
            
            m_ipv6_endpoint.push(ip6_src_addr, tx);
            m_ipv6_endpoint.push(ip6_dest_addr, rx);

            // ipv6 conversation information
            conversation_data_t ip6_conversation(1, length, 0, 0, cur, cur);
            address_pair ip6_pair(ip6_src_addr, ip6_dest_addr, &ip6_conversation);

            m_ipv6_conversation.push(ip6_pair, ip6_conversation);

            if (IPV6_TCP == ip6_header_ptr->ip6_ctlun.ip6_un1.ip6_un1_nxt) {
                // ipv6 tcp endpoint information
                tcp_header_ptr = (tcp_header*)(packet + sizeof(ether_header) + IPV6_HEADER_LEN);
                address_t tcp_src_addr(ip6_header_ptr->ip6_src.s6_addr, ntohs(tcp_header_ptr->source));
                address_t tcp_dest_addr(ip6_header_ptr->ip6_dst.s6_addr, ntohs(tcp_header_ptr->dest));

                m_ipv6_tcp_endpoint.push(tcp_src_addr, tx);
                m_ipv6_tcp_endpoint.push(tcp_dest_addr, rx);

                // ipv6 tcp conversation information
                conversation_data_t tcp_conversation(1, length, 0, 0, cur, cur);
                address_pair tcp_pair(tcp_src_addr, tcp_dest_addr, &tcp_conversation);

                m_ipv6_tcp_conversation.push(tcp_pair, tcp_conversation);
            }
            else if (IPV6_UDP == ip6_header_ptr->ip6_ctlun.ip6_un1.ip6_un1_nxt) {
                // ipv6 udp endpoint information
                udp_header_ptr = (udp_header*)(packet + sizeof(ether_header) + IPV6_HEADER_LEN);
                address_t udp_src_addr(ip6_header_ptr->ip6_src.s6_addr, ntohs(udp_header_ptr->source));
                address_t udp_dest_addr(ip6_header_ptr->ip6_dst.s6_addr, ntohs(udp_header_ptr->dest));

                m_ipv6_udp_endpoint.push(udp_src_addr, tx);
                m_ipv6_udp_endpoint.push(udp_dest_addr, rx);

                // ipv6 udp conversation information
                conversation_data_t udp_conversation(1, length, 0, 0, cur, cur);
                address_pair udp_pair(udp_src_addr, udp_dest_addr, &udp_conversation);

                m_ipv6_udp_conversation.push(udp_pair, udp_conversation);
            }
        }
    }
    
    if (-1 == res) {
        cerr << "pcap_next_ex failed. " << pcap_geterr(m_pcap_handle) << endl;
        exit(1);
    }

    pcap_close(m_pcap_handle);
}

char* CPcapAnalyzer::reduceNumber(uint32_t num, uint32_t len)
{
    char* buf = new char[len + 1];
    uint32_t count = 0;
    char suffix = 0;

    while (10000 < num) {
        num /= 1000;
        count++;
    }

    switch(count)
    {
    case 1:
        suffix = 'k';
        break;
    case 2:
        suffix = 'm';
        break;
    case 3:
        suffix = 'b';
        break;
    }

    snprintf(buf, len + 1, "%u%c", num, suffix);

    return buf;
}

void CPcapAnalyzer::printEthernet(void)
{
    cout << "Ethernet Endpoints" << endl;
    printf("%20s%9s%7s%12s%10s%12s%10s\n", "Address", "Packets", "Bytes", "Tx Packets", "Tx Bytes", "Rx Packets", "Rx Bytes");
    cout << "--------------------------------------------------------------------------------" << endl;
    uint32_t length = m_ethernet_endpoint.get_length();
    for (uint32_t i = 0; i < length; i++) {
        address_t temp_addr = m_ethernet_endpoint.get_key(i);
        endpoint_data_t temp_data = m_ethernet_endpoint.get_value(i);
        char* addr_buf = temp_addr.get_address();
        char* bytes_buf = reduceNumber(temp_data.tx_bytes + temp_data.rx_bytes, 7);
        char* tx_bytes = reduceNumber(temp_data.tx_bytes, 10);
        char* rx_bytes = reduceNumber(temp_data.rx_bytes, 10);

        printf("%20s%9u%7s%12u%10s%12u%10s\n", addr_buf,
               temp_data.tx_packets + temp_data.rx_packets,
               bytes_buf, temp_data.tx_packets, tx_bytes,
               temp_data.rx_packets, rx_bytes);

        delete[] addr_buf;
        delete[] bytes_buf;
        delete[] tx_bytes;
        delete[] rx_bytes;
    }

    cout << endl << endl;
}

void CPcapAnalyzer::printIPv4(void)
{
    cout << "IPv4 Endpoints" << endl;
    printf("%20s%9s%7s%12s%10s%12s%10s\n", "Address", "Packets", "Bytes", "Tx Packets", "Tx Bytes", "Rx Packets", "Rx Bytes");
    cout << "--------------------------------------------------------------------------------" << endl;
    uint32_t length = m_ipv4_endpoint.get_length();
    for (uint32_t i = 0; i < length; i++) {
        address_t temp_addr = m_ipv4_endpoint.get_key(i);
        endpoint_data_t temp_data = m_ipv4_endpoint.get_value(i);
        char* addr_buf = temp_addr.get_address();
        char* bytes_buf = reduceNumber(temp_data.tx_bytes + temp_data.rx_bytes, 7);
        char* tx_bytes = reduceNumber(temp_data.tx_bytes, 10);
        char* rx_bytes = reduceNumber(temp_data.rx_bytes, 10);

        printf("%20s%9u%7s%12u%10s%12u%10s\n", addr_buf,
               temp_data.tx_packets + temp_data.rx_packets,
               bytes_buf, temp_data.tx_packets, tx_bytes,
               temp_data.rx_packets, rx_bytes);

        delete[] addr_buf;
        delete[] bytes_buf;
        delete[] tx_bytes;
        delete[] rx_bytes;
    }

    cout << endl << endl;
}

void CPcapAnalyzer::printIPv6(void)
{
    cout << "IPv6 Endpoints" << endl;
    printf("%41s%9s%7s%12s%10s%12s%10s\n", "Address", "Packets", "Bytes", "Tx Packets", "Tx Bytes", "Rx Packets", "Rx Bytes");
    cout << "-----------------------------------------------------------------------------------------------------" << endl;
    uint32_t length = m_ipv6_endpoint.get_length();
    for (uint32_t i = 0; i < length; i++) {
        address_t temp_addr = m_ipv6_endpoint.get_key(i);
        endpoint_data_t temp_data = m_ipv6_endpoint.get_value(i);
        char* addr_buf = temp_addr.get_address();
        char* bytes_buf = reduceNumber(temp_data.tx_bytes + temp_data.rx_bytes, 7);
        char* tx_bytes = reduceNumber(temp_data.tx_bytes, 10);
        char* rx_bytes = reduceNumber(temp_data.rx_bytes, 10);

        printf("%41s%9u%7s%12u%10s%12u%10s\n", addr_buf,
               temp_data.tx_packets + temp_data.rx_packets,
               bytes_buf, temp_data.tx_packets, tx_bytes,
               temp_data.rx_packets, rx_bytes);

        delete[] addr_buf;
        delete[] bytes_buf;
        delete[] tx_bytes;
        delete[] rx_bytes;
    }

    cout << endl << endl;
}

void CPcapAnalyzer::printTCP(void)
{
    cout << "TCP Endpoints" << endl;
    const char* printf_buf;
    uint32_t ipv6_length = m_ipv6_tcp_endpoint.get_length();
    if (0 == ipv6_length) {
        printf("%20s%7s%9s%7s%12s%10s%12s%10s\n", "Address", "Port", "Packets", "Bytes", "Tx Packets", "Tx Bytes", "Rx Packets", "Rx Bytes");
        cout << "---------------------------------------------------------------------------------------" << endl;
        printf_buf = "%20s%7u%9u%7s%12u%10s%12u%10s\n";
    }
    else {
        printf("%41s%7s%9s%7s%12s%10s%12s%10s\n", "Address", "Port", "Packets", "Bytes", "Tx Packets", "Tx Bytes", "Rx Packets", "Rx Bytes");
        cout << "------------------------------------------------------------------------------------------------------------" << endl;
        printf_buf = "%41s%7u%9u%7s%12u%10s%12u%10s\n";
    }

    uint32_t length = m_tcp_endpoint.get_length();
    for (uint32_t i = 0; i < length; i++) {
        address_t temp_addr = m_tcp_endpoint.get_key(i);
        endpoint_data_t temp_data = m_tcp_endpoint.get_value(i);
        char* addr_buf = temp_addr.get_address();
        char* bytes_buf = reduceNumber(temp_data.tx_bytes + temp_data.rx_bytes, 7);
        char* tx_bytes = reduceNumber(temp_data.tx_bytes, 10);
        char* rx_bytes = reduceNumber(temp_data.rx_bytes, 10);


        printf(printf_buf, addr_buf, temp_addr.port,
               temp_data.tx_packets + temp_data.rx_packets,
               bytes_buf, temp_data.tx_packets, tx_bytes,
               temp_data.rx_packets, rx_bytes);

        delete[] addr_buf;
        delete[] bytes_buf;
        delete[] tx_bytes;
        delete[] rx_bytes;
    }

    for (uint32_t i = 0; i < ipv6_length; i++) {
        address_t temp_addr = m_ipv6_tcp_endpoint.get_key(i);
        endpoint_data_t temp_data = m_ipv6_tcp_endpoint.get_value(i);
        char* addr_buf = temp_addr.get_address();
        char* bytes_buf = reduceNumber(temp_data.tx_bytes + temp_data.rx_bytes, 7);
        char* tx_bytes = reduceNumber(temp_data.tx_bytes, 10);
        char* rx_bytes = reduceNumber(temp_data.rx_bytes, 10);


        printf(printf_buf, addr_buf, temp_addr.port,
               temp_data.tx_packets + temp_data.rx_packets,
               bytes_buf, temp_data.tx_packets, tx_bytes,
               temp_data.rx_packets, rx_bytes);

        delete[] addr_buf;
        delete[] bytes_buf;
        delete[] tx_bytes;
        delete[] rx_bytes;
    }

    cout << endl << endl;
}

void CPcapAnalyzer::printUDP(void)
{
    cout << "UDP Endpoints" << endl;
    const char* printf_buf;
    uint32_t ipv6_length = m_ipv6_udp_endpoint.get_length();
    if (0 == ipv6_length) {
        printf("%20s%7s%9s%7s%12s%10s%12s%10s\n", "Address", "Port", "Packets", "Bytes", "Tx Packets", "Tx Bytes", "Rx Packets", "Rx Bytes");
        cout << "---------------------------------------------------------------------------------------" << endl;
        printf_buf = "%20s%7u%9u%7s%12u%10s%12u%10s\n";
    }
    else {
        printf("%41s%7s%9s%7s%12s%10s%12s%10s\n", "Address", "Port", "Packets", "Bytes", "Tx Packets", "Tx Bytes", "Rx Packets", "Rx Bytes");
        cout << "------------------------------------------------------------------------------------------------------------" << endl;
        printf_buf = "%41s%7u%9u%7s%12u%10s%12u%10s\n";
    }

    uint32_t length = m_udp_endpoint.get_length();
    for (uint32_t i = 0; i < length; i++) {
        address_t temp_addr = m_udp_endpoint.get_key(i);
        endpoint_data_t temp_data = m_udp_endpoint.get_value(i);
        char* addr_buf = temp_addr.get_address();
        char* bytes_buf = reduceNumber(temp_data.tx_bytes + temp_data.rx_bytes, 7);
        char* tx_bytes = reduceNumber(temp_data.tx_bytes, 10);
        char* rx_bytes = reduceNumber(temp_data.rx_bytes, 10);

        printf(printf_buf, addr_buf, temp_addr.port,
               temp_data.tx_packets + temp_data.rx_packets,
               bytes_buf, temp_data.tx_packets, tx_bytes,
               temp_data.rx_packets, rx_bytes);

        delete[] addr_buf;
        delete[] bytes_buf;
        delete[] tx_bytes;
        delete[] rx_bytes;
    }

    for (uint32_t i = 0; i < ipv6_length; i++) {
        address_t temp_addr = m_ipv6_udp_endpoint.get_key(i);
        endpoint_data_t temp_data = m_ipv6_udp_endpoint.get_value(i);
        char* addr_buf = temp_addr.get_address();
        char* bytes_buf = reduceNumber(temp_data.tx_bytes + temp_data.rx_bytes, 7);
        char* tx_bytes = reduceNumber(temp_data.tx_bytes, 10);
        char* rx_bytes = reduceNumber(temp_data.rx_bytes, 10);

        printf(printf_buf, addr_buf, temp_addr.port,
               temp_data.tx_packets + temp_data.rx_packets,
               bytes_buf, temp_data.tx_packets, tx_bytes,
               temp_data.rx_packets, rx_bytes);

        delete[] addr_buf;
        delete[] bytes_buf;
        delete[] tx_bytes;
        delete[] rx_bytes;
    }

    cout << endl << endl;
}

void CPcapAnalyzer::printEthernetConversation(void)
{
    cout << "Ethernet Conversations" << endl;
    printf("%20s%20s%9s%7s%16s%14s%16s%14s%11s%10s%15s%15s\n", "Address A", "Address B",
           "Packets", "Bytes", "Packets A to B", "Bytes A to B", "Packets B to A",
           "Bytes B to A", "Rel Start", "Duration", "Bits/s A to B", "Bits/s B to A");
    cout << "-----------------------------------------------------------------------------------------------------------------------------------------------------------------------" << endl;
    uint32_t length = m_ethernet_conversation.get_length();
    for (uint32_t i = 0; i < length; i++) {
        address_pair temp_addr = m_ethernet_conversation.get_key(i);
        conversation_data_t temp_data = m_ethernet_conversation.get_value(i);
        char* addr_buf1 = temp_addr.get_address1();
        char* addr_buf2 = temp_addr.get_address2();
        char* time_buf1 = temp_data.get_rel_start();
        char* time_buf2 = temp_data.get_duration();
        char* bits_buf1 = temp_data.get_bits_1_2();
        char* bits_buf2 = temp_data.get_bits_2_1();
        char* bytes_buf = reduceNumber(temp_data.m_bytes_1_2 + temp_data.m_bytes_2_1, 7);
        char* bytes_1_2 = reduceNumber(temp_data.m_bytes_1_2, 14);
        char* bytes_2_1 = reduceNumber(temp_data.m_bytes_2_1, 14);

        printf("%20s%20s%9u%7s%16u%14s%16u%14s%11s%10s%15s%15s\n",
               addr_buf1, addr_buf2, temp_data.m_packets_1_2 + temp_data.m_packets_2_1,
               bytes_buf, temp_data.m_packets_1_2, bytes_1_2, temp_data.m_packets_2_1, bytes_2_1,
               time_buf1, time_buf2, bits_buf1, bits_buf2);

        delete[] addr_buf1;
        delete[] addr_buf2;
        delete[] time_buf1;
        delete[] time_buf2;
        delete[] bits_buf1;
        delete[] bits_buf2;
        delete[] bytes_buf;
        delete[] bytes_1_2;
        delete[] bytes_2_1;
    }

    cout << endl << endl;
}

void CPcapAnalyzer::printIPv4Conversation(void)
{
    cout << "IPv4 Conversations" << endl;
    printf("%20s%20s%9s%7s%16s%14s%16s%14s%11s%10s%15s%15s\n", "Address A", "Address B",
           "Packets", "Bytes", "Packets A to B", "Bytes A to B", "Packets B to A",
           "Bytes B to A", "Rel Start", "Duration", "Bits/s A to B", "Bits/s B to A");
    cout << "-----------------------------------------------------------------------------------------------------------------------------------------------------------------------" << endl;
    uint32_t length = m_ipv4_conversation.get_length();
    for (uint32_t i = 0; i < length; i++) {
        address_pair temp_addr = m_ipv4_conversation.get_key(i);
        conversation_data_t temp_data = m_ipv4_conversation.get_value(i);
        char* addr_buf1 = temp_addr.get_address1();
        char* addr_buf2 = temp_addr.get_address2();
        char* time_buf1 = temp_data.get_rel_start();
        char* time_buf2 = temp_data.get_duration();
        char* bits_buf1 = temp_data.get_bits_1_2();
        char* bits_buf2 = temp_data.get_bits_2_1();
        char* bytes_buf = reduceNumber(temp_data.m_bytes_1_2 + temp_data.m_bytes_2_1, 7);
        char* bytes_1_2 = reduceNumber(temp_data.m_bytes_1_2, 14);
        char* bytes_2_1 = reduceNumber(temp_data.m_bytes_2_1, 14);

        printf("%20s%20s%9u%7s%16u%14s%16u%14s%11s%10s%15s%15s\n",
               addr_buf1, addr_buf2, temp_data.m_packets_1_2 + temp_data.m_packets_2_1,
               bytes_buf, temp_data.m_packets_1_2, bytes_1_2, temp_data.m_packets_2_1, bytes_2_1,
               time_buf1, time_buf2, bits_buf1, bits_buf2);

        delete[] addr_buf1;
        delete[] addr_buf2;
        delete[] time_buf1;
        delete[] time_buf2;
        delete[] bits_buf1;
        delete[] bits_buf2;
        delete[] bytes_buf;
        delete[] bytes_1_2;
        delete[] bytes_2_1;
    }

    cout << endl << endl;
}

void CPcapAnalyzer::printIPv6Conversation(void)
{
    cout << "IPv6 Conversations" << endl;
    printf("%41s%41s%9s%7s%16s%14s%16s%14s%11s%10s%15s%15s\n", "Address A", "Address B",
           "Packets", "Bytes", "Packets A to B", "Bytes A to B", "Packets B to A",
           "Bytes B to A", "Rel Start", "Duration", "Bits/s A to B", "Bits/s B to A");
    cout << "-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------" << endl;
    uint32_t length = m_ipv6_conversation.get_length();
    for (uint32_t i = 0; i < length; i++) {
        address_pair temp_addr = m_ipv6_conversation.get_key(i);
        conversation_data_t temp_data = m_ipv6_conversation.get_value(i);
        char* addr_buf1 = temp_addr.get_address1();
        char* addr_buf2 = temp_addr.get_address2();
        char* time_buf1 = temp_data.get_rel_start();
        char* time_buf2 = temp_data.get_duration();
        char* bits_buf1 = temp_data.get_bits_1_2();
        char* bits_buf2 = temp_data.get_bits_2_1();
        char* bytes_buf = reduceNumber(temp_data.m_bytes_1_2 + temp_data.m_bytes_2_1, 7);
        char* bytes_1_2 = reduceNumber(temp_data.m_bytes_1_2, 14);
        char* bytes_2_1 = reduceNumber(temp_data.m_bytes_2_1, 14);

        printf("%41s%41s%9u%7s%16u%14s%16u%14s%11s%10s%15s%15s\n",
               addr_buf1, addr_buf2, temp_data.m_packets_1_2 + temp_data.m_packets_2_1,
               bytes_buf, temp_data.m_packets_1_2, bytes_1_2, temp_data.m_packets_2_1, bytes_2_1,
               time_buf1, time_buf2, bits_buf1, bits_buf2);

        delete[] addr_buf1;
        delete[] addr_buf2;
        delete[] time_buf1;
        delete[] time_buf2;
        delete[] bits_buf1;
        delete[] bits_buf2;
        delete[] bytes_buf;
        delete[] bytes_1_2;
        delete[] bytes_2_1;
    }

    cout << endl << endl;
}

void CPcapAnalyzer::printTCPConversation(void)
{
    cout << "TCP Conversations" << endl;
    const char* printf_buf;
    uint32_t ipv6_length = m_ipv6_tcp_conversation.get_length();
    if (0 == ipv6_length) {
        printf("%20s%8s%20s%8s%9s%7s%16s%14s%16s%14s%11s%10s%15s%15s\n", "Address A", "Port A", "Address B",
               "Port B", "Packets", "Bytes", "Packets A to B", "Bytes A to B", "Packets B to A",
               "Bytes B to A", "Rel Start", "Duration", "Bits/s A to B", "Bits/s B to A");
        cout << "---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------" << endl;
        printf_buf = "%20s%8u%20s%8u%9u%7s%16u%14s%16u%14s%11s%10s%15s%15s\n";
    }
    else {
        printf("%41s%8s%41s%8s%9s%7s%16s%14s%16s%14s%11s%10s%15s%15s\n", "Address A", "Port A", "Address B",
               "Port B", "Packets", "Bytes", "Packets A to B", "Bytes A to B", "Packets B to A",
               "Bytes B to A", "Rel Start", "Duration", "Bits/s A to B", "Bits/s B to A");
        cout << "---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------" << endl;
        printf_buf = "%41s%8u%41s%8u%9u%7s%16u%14s%16u%14s%11s%10s%15s%15s\n";
    }

    uint32_t length = m_tcp_conversation.get_length();
    for (uint32_t i = 0; i < length; i++) {
        address_pair temp_addr = m_tcp_conversation.get_key(i);
        conversation_data_t temp_data = m_tcp_conversation.get_value(i);
        char* addr_buf1 = temp_addr.get_address1();
        char* addr_buf2 = temp_addr.get_address2();
        char* time_buf1 = temp_data.get_rel_start();
        char* time_buf2 = temp_data.get_duration();
        char* bits_buf1 = temp_data.get_bits_1_2();
        char* bits_buf2 = temp_data.get_bits_2_1();
        char* bytes_buf = reduceNumber(temp_data.m_bytes_1_2 + temp_data.m_bytes_2_1, 7);
        char* bytes_1_2 = reduceNumber(temp_data.m_bytes_1_2, 14);
        char* bytes_2_1 = reduceNumber(temp_data.m_bytes_2_1, 14);

        printf(printf_buf, addr_buf1, temp_addr.get_port1(), addr_buf2, temp_addr.get_port2(),
               temp_data.m_packets_1_2 + temp_data.m_packets_2_1, bytes_buf,
               temp_data.m_packets_1_2, bytes_1_2, temp_data.m_packets_2_1, bytes_2_1,
               time_buf1, time_buf2, bits_buf1, bits_buf2);

        delete[] addr_buf1;
        delete[] addr_buf2;
        delete[] time_buf1;
        delete[] time_buf2;
        delete[] bits_buf1;
        delete[] bits_buf2;
        delete[] bytes_buf;
        delete[] bytes_1_2;
        delete[] bytes_2_1;
    }

    for (uint32_t i = 0; i < ipv6_length; i++) {
        address_pair temp_addr = m_ipv6_tcp_conversation.get_key(i);
        conversation_data_t temp_data = m_ipv6_tcp_conversation.get_value(i);
        char* addr_buf1 = temp_addr.get_address1();
        char* addr_buf2 = temp_addr.get_address2();
        char* time_buf1 = temp_data.get_rel_start();
        char* time_buf2 = temp_data.get_duration();
        char* bits_buf1 = temp_data.get_bits_1_2();
        char* bits_buf2 = temp_data.get_bits_2_1();
        char* bytes_buf = reduceNumber(temp_data.m_bytes_1_2 + temp_data.m_bytes_2_1, 7);
        char* bytes_1_2 = reduceNumber(temp_data.m_bytes_1_2, 14);
        char* bytes_2_1 = reduceNumber(temp_data.m_bytes_2_1, 14);

        printf(printf_buf, addr_buf1, temp_addr.get_port1(), addr_buf2, temp_addr.get_port2(),
               temp_data.m_packets_1_2 + temp_data.m_packets_2_1, bytes_buf,
               temp_data.m_packets_1_2, bytes_1_2, temp_data.m_packets_2_1, bytes_2_1,
               time_buf1, time_buf2, bits_buf1, bits_buf2);

        delete[] addr_buf1;
        delete[] addr_buf2;
        delete[] time_buf1;
        delete[] time_buf2;
        delete[] bits_buf1;
        delete[] bits_buf2;
        delete[] bytes_buf;
        delete[] bytes_1_2;
        delete[] bytes_2_1;
    }

    cout << endl << endl;
}

void CPcapAnalyzer::printUDPConversation(void)
{
    cout << "UDP Conversations" << endl;
    const char* printf_buf;
    uint32_t ipv6_length = m_ipv6_udp_conversation.get_length();
    if (0 == ipv6_length) {
        printf("%20s%8s%20s%8s%9s%7s%16s%14s%16s%14s%11s%10s%15s%15s\n", "Address A", "Port A", "Address B",
               "Port B", "Packets", "Bytes", "Packets A to B", "Bytes A to B", "Packets B to A",
               "Bytes B to A", "Rel Start", "Duration", "Bits/s A to B", "Bits/s B to A");
        cout << "---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------" << endl;
        printf_buf = "%20s%8u%20s%8u%9u%7s%16u%14s%16u%14s%11s%10s%15s%15s\n";
    }
    else {
        printf("%41s%8s%41s%8s%9s%7s%16s%14s%16s%14s%11s%10s%15s%15s\n", "Address A", "Port A", "Address B",
               "Port B", "Packets", "Bytes", "Packets A to B", "Bytes A to B", "Packets B to A",
               "Bytes B to A", "Rel Start", "Duration", "Bits/s A to B", "Bits/s B to A");
        cout << "---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------" << endl;
        printf_buf = "%41s%8u%41s%8u%9u%7s%16u%14s%16u%14s%11s%10s%15s%15s\n";
    }

    uint32_t length = m_udp_conversation.get_length();
    for (uint32_t i = 0; i < length; i++) {
        address_pair temp_addr = m_udp_conversation.get_key(i);
        conversation_data_t temp_data = m_udp_conversation.get_value(i);
        char* addr_buf1 = temp_addr.get_address1();
        char* addr_buf2 = temp_addr.get_address2();
        char* time_buf1 = temp_data.get_rel_start();
        char* time_buf2 = temp_data.get_duration();
        char* bits_buf1 = temp_data.get_bits_1_2();
        char* bits_buf2 = temp_data.get_bits_2_1();
        char* bytes_buf = reduceNumber(temp_data.m_bytes_1_2 + temp_data.m_bytes_2_1, 7);
        char* bytes_1_2 = reduceNumber(temp_data.m_bytes_1_2, 14);
        char* bytes_2_1 = reduceNumber(temp_data.m_bytes_2_1, 14);

        printf(printf_buf, addr_buf1, temp_addr.get_port1(), addr_buf2, temp_addr.get_port2(),
               temp_data.m_packets_1_2 + temp_data.m_packets_2_1, bytes_buf,
               temp_data.m_packets_1_2, bytes_1_2, temp_data.m_packets_2_1, bytes_2_1,
               time_buf1, time_buf2, bits_buf1, bits_buf2);

        delete[] addr_buf1;
        delete[] addr_buf2;
        delete[] time_buf1;
        delete[] time_buf2;
        delete[] bits_buf1;
        delete[] bits_buf2;
        delete[] bytes_buf;
        delete[] bytes_1_2;
        delete[] bytes_2_1;
    }

    for (uint32_t i = 0; i < ipv6_length; i++) {
        address_pair temp_addr = m_ipv6_udp_conversation.get_key(i);
        conversation_data_t temp_data = m_ipv6_udp_conversation.get_value(i);
        char* addr_buf1 = temp_addr.get_address1();
        char* addr_buf2 = temp_addr.get_address2();
        char* time_buf1 = temp_data.get_rel_start();
        char* time_buf2 = temp_data.get_duration();
        char* bits_buf1 = temp_data.get_bits_1_2();
        char* bits_buf2 = temp_data.get_bits_2_1();
        char* bytes_buf = reduceNumber(temp_data.m_bytes_1_2 + temp_data.m_bytes_2_1, 7);
        char* bytes_1_2 = reduceNumber(temp_data.m_bytes_1_2, 14);
        char* bytes_2_1 = reduceNumber(temp_data.m_bytes_2_1, 14);

        printf(printf_buf, addr_buf1, temp_addr.get_port1(), addr_buf2, temp_addr.get_port2(),
               temp_data.m_packets_1_2 + temp_data.m_packets_2_1, bytes_buf,
               temp_data.m_packets_1_2, bytes_1_2, temp_data.m_packets_2_1, bytes_2_1,
               time_buf1, time_buf2, bits_buf1, bits_buf2);

        delete[] addr_buf1;
        delete[] addr_buf2;
        delete[] time_buf1;
        delete[] time_buf2;
        delete[] bits_buf1;
        delete[] bits_buf2;
        delete[] bytes_buf;
        delete[] bytes_1_2;
        delete[] bytes_2_1;
    }

    cout << endl << endl;
}


CPcapAnalyzer::address_t::address_t(void)
    : type(NONE)
{}

CPcapAnalyzer::address_t::address_t(uint32_t ip)
    : type(IPv4), ipv4(ip)
{}

CPcapAnalyzer::address_t::address_t(uint32_t ip, uint32_t input_port)
    : type(TCP_UDP), ipv4(ip), port(input_port)
{}

CPcapAnalyzer::address_t::address_t(u_char* mac_ptr)
    : type(MAC)
{
    for (uint32_t i = 0; i < MAC_LEN; i++)
        mac[i] = mac_ptr[i];
}

CPcapAnalyzer::address_t::address_t(u_char* ipv6_ptr, uint32_t input_port)
{
    if (65535 < input_port) {
        type = IPv6;
    }
    else {
        type = IPv6_TCP_UDP;
        port = input_port;
    }

    for (uint32_t i = 0; i < IPv6_LEN; i++)
        ipv6[i] = ipv6_ptr[i];
}

CPcapAnalyzer::address_t::address_t(const address_t& obj)
{
    if (obj.type == IPv4) {
        type = IPv4;
        ipv4 = obj.ipv4;
    }
    else if (obj.type == MAC) {
        type = MAC;
        for (uint32_t i = 0; i < MAC_LEN; i++) {
            mac[i] = obj.mac[i];
        }
    }
    else if (obj.type == TCP_UDP) {
        type = TCP_UDP;
        ipv4 = obj.ipv4;
        port = obj.port;
    }
    else if (obj.type == IPv6) {
        type = IPv6;
        for (uint32_t i = 0; i < IPv6_LEN; i++) {
            ipv6[i] = obj.ipv6[i];
        }
    }
    else if (obj.type == IPv6_TCP_UDP) {
        type = IPv6_TCP_UDP;
        for (uint32_t i = 0; i < IPv6_LEN; i++) {
            ipv6[i] = obj.ipv6[i];
        }
        port = obj.port;
    }
    else {
        type = NONE;
    }
}

char* CPcapAnalyzer::address_t::get_address(void)
{
    char* addr_buf = NULL;
    uint8_t* ip_ptr = NULL;

    if (type == NONE)
        return NULL;

    if (type == MAC) {
        addr_buf = new char[18];
        sprintf(addr_buf, "%02x:%02x:%02x:%02x:%02x:%02x",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

        return addr_buf;
    }

    if (type == IPv6 || type == IPv6_TCP_UDP) {
        addr_buf = new char[40];
        ip_ptr = (uint8_t*)&ipv6;
        sprintf(addr_buf, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                ip_ptr[0], ip_ptr[1], ip_ptr[2], ip_ptr[3], ip_ptr[4], ip_ptr[5], ip_ptr[6], ip_ptr[7],
                ip_ptr[8], ip_ptr[9], ip_ptr[10], ip_ptr[11], ip_ptr[12], ip_ptr[13], ip_ptr[14], ip_ptr[15]);

        return addr_buf;
    }

    addr_buf = new char[16];
    ip_ptr = (uint8_t*)&ipv4;
    sprintf(addr_buf, "%u.%u.%u.%u", ip_ptr[0], ip_ptr[1], ip_ptr[2], ip_ptr[3]);

    return addr_buf;
}

bool CPcapAnalyzer::address_t::operator==(address_t& obj)
{
    if (type != obj.type) {
        return false;
    }
    
    if (type == NONE) {
        return true;
    }
    
    if (type == IPv4) {
        return ipv4 == obj.ipv4;
    }

    if (type == TCP_UDP) {
        return ipv4 == obj.ipv4 && port == obj.port;
    }

    if (type == MAC) {
        for (uint32_t i = 0; i < MAC_LEN; i++) {
            if (mac[i] != obj.mac[i])
                return false;
        }
        return true;
    }

    for (uint32_t i = 0; i < IPv6_LEN; i++) {
        if (ipv6[i] != obj.ipv6[i])
            return false;
    }

    if (type == IPv6_TCP_UDP)
        return port == obj.port;
    
    return true;
}

CPcapAnalyzer::address_t& CPcapAnalyzer::address_t::operator=(address_t& obj)
{
    if (obj.type == NONE) {
        type = NONE;

        return *this;
    }

    if (obj.type == IPv4) {
        type = IPv4;
        ipv4 = obj.ipv4;

        return *this;
    }

    if (obj.type == TCP_UDP) {
        type = TCP_UDP;
        ipv4 = obj.ipv4;
        port = obj.port;

        return *this;
    }

    if (obj.type == MAC) {
        type = MAC;
        for (uint32_t i = 0; i < MAC_LEN; i++) {
            mac[i] = obj.mac[i];
        }

        return *this;
    }

    for (uint32_t i = 0; i < IPv6_LEN; i++) {
        ipv6[i] = obj.ipv6[i];
    }

    if (obj.type == IPv6_TCP_UDP) {
        type = IPv6_TCP_UDP;
        port = obj.port;
    }
    else {
        type = IPv6;
    }

    return *this;
}


CPcapAnalyzer::endpoint_data_t::endpoint_data_t(void)
    : tx_packets(0), tx_bytes(0), rx_packets(0), rx_bytes(0)
{}

CPcapAnalyzer::endpoint_data_t::endpoint_data_t(uint32_t tx_p, uint32_t tx_b, uint32_t rx_p, uint32_t rx_b)
    : tx_packets(tx_p), tx_bytes(tx_b), rx_packets(rx_p), rx_bytes(rx_b)
{}

CPcapAnalyzer::endpoint_data_t::endpoint_data_t(const endpoint_data_t& obj)
    : tx_packets(obj.tx_packets)
    , tx_bytes(obj.tx_bytes)
    , rx_packets(obj.rx_packets)
    , rx_bytes(obj.rx_bytes)
{}

CPcapAnalyzer::endpoint_data_t& CPcapAnalyzer::endpoint_data_t::operator=(endpoint_data_t& obj)
{
    tx_packets = obj.tx_packets;
    tx_bytes = obj.tx_bytes;
    rx_packets = obj.rx_packets;
    rx_bytes = obj.rx_bytes;

    return *this;
}

CPcapAnalyzer::endpoint_data_t& CPcapAnalyzer::endpoint_data_t::operator+=(endpoint_data_t& obj)
{
    tx_packets += obj.tx_packets;
    tx_bytes += obj.tx_bytes;
    rx_packets += obj.rx_packets;
    rx_bytes += obj.rx_bytes;

    return *this;
}


CPcapAnalyzer::conversation_data_t::conversation_data_t(void)
    : m_packets_1_2(0), m_bytes_1_2(0)
    , m_packets_2_1(0), m_bytes_2_1(0)
    , m_rel_start({ 0, 0 }), m_end({ 0, 0 })
    , m_direction_flag(false)
{}

CPcapAnalyzer::conversation_data_t::conversation_data_t(uint32_t p_1_2, uint32_t b_1_2,
                                                        uint32_t p_2_1, uint32_t b_2_1,
                                                        struct timeval rel_start,
                                                        struct timeval end, bool flag)
    : m_packets_1_2(p_1_2), m_bytes_1_2(b_1_2)
    , m_packets_2_1(p_2_1), m_bytes_2_1(b_2_1)
    , m_rel_start(rel_start), m_end(end)
    , m_direction_flag(flag)
{}

CPcapAnalyzer::conversation_data_t::conversation_data_t(const conversation_data_t& obj)
    : m_packets_1_2(obj.m_packets_1_2), m_bytes_1_2(obj.m_bytes_1_2)
    , m_packets_2_1(obj.m_packets_2_1), m_bytes_2_1(obj.m_bytes_2_1)
    , m_rel_start(obj.m_rel_start), m_end(obj.m_end)
    , m_direction_flag(obj.m_direction_flag)
{}

char* CPcapAnalyzer::conversation_data_t::reduceNumber(uint32_t num, uint32_t len)
{
    char* buf = new char[len + 1];
    uint32_t count = 0;
    char suffix = 0;

    while (10000 < num) {
        num /= 1000;
        count++;
    }

    switch(count)
    {
    case 1:
        suffix = 'k';
        break;
    case 2:
        suffix = 'm';
        break;
    case 3:
        suffix = 'b';
        break;
    }

    snprintf(buf, len + 1, "%u%c", num, suffix);

    return buf;
}

char* CPcapAnalyzer::conversation_data_t::get_rel_start(void)
{
    char* buf = new char[10];
    snprintf(buf, 10, "%lu.%06lu", m_rel_start.tv_sec, m_rel_start.tv_usec);

    return buf;
}

struct timeval CPcapAnalyzer::conversation_data_t::calc_duration(void)
{
    struct timeval duration = { 0, 0 };
    
    if (m_end.tv_usec < m_rel_start.tv_usec) {
        duration.tv_usec = 1000000 + m_end.tv_usec - m_rel_start.tv_usec;
        duration.tv_sec = m_end.tv_sec - m_rel_start.tv_sec - 1;
    }
    else {
        duration.tv_usec = m_end.tv_usec - m_rel_start.tv_usec;
        duration.tv_sec = m_end.tv_sec - m_rel_start.tv_sec;
    }

    return duration;
}

char* CPcapAnalyzer::conversation_data_t::get_duration(void)
{
    char* buf = new char[9];
    struct timeval duration = calc_duration();

    snprintf(buf, 9, "%lu.%06lu", duration.tv_sec, duration.tv_usec);

    return buf;
}

char* CPcapAnalyzer::conversation_data_t::get_bits_1_2(void)
{
    struct timeval duration = calc_duration();
    double double_duration = (double)duration.tv_sec + ((double)(duration.tv_usec) / 1000000.0);
    double result = (double)(m_bytes_1_2 * 8) / double_duration;
    uint32_t display = (uint32_t)result;

    return reduceNumber(display, 13);
}

char* CPcapAnalyzer::conversation_data_t::get_bits_2_1(void)
{
    struct timeval duration = calc_duration();
    double double_duration = (double)duration.tv_sec + ((double)(duration.tv_usec) / 1000000.0);
    double result = (double)(m_bytes_2_1 * 8) / double_duration;
    uint32_t display = (uint32_t)result;

    return reduceNumber(display, 13);
}

CPcapAnalyzer::conversation_data_t& CPcapAnalyzer::conversation_data_t::operator=(conversation_data_t& obj)
{
    m_packets_1_2 = obj.m_packets_1_2;
    m_bytes_1_2 = obj.m_bytes_1_2;
    m_packets_2_1 = obj.m_packets_2_1;
    m_bytes_2_1 = obj.m_bytes_2_1;
    m_rel_start = obj.m_rel_start;
    m_end = obj.m_end;
    m_direction_flag = obj.m_direction_flag;

    return *this;
}

CPcapAnalyzer::conversation_data_t& CPcapAnalyzer::conversation_data_t::operator+=(conversation_data_t& obj)
{
    if (obj.m_direction_flag) {
        m_packets_1_2 += obj.m_packets_2_1;
        m_bytes_1_2 += obj.m_bytes_2_1;
        m_packets_2_1 += obj.m_packets_1_2;
        m_bytes_2_1 += obj.m_bytes_1_2;
    }
    else {
        m_packets_1_2 += obj.m_packets_1_2;
        m_bytes_1_2 += obj.m_bytes_1_2;
        m_packets_2_1 += obj.m_packets_2_1;
        m_bytes_2_1 += obj.m_bytes_2_1;
    }

    m_end.tv_sec = obj.m_end.tv_sec;
    m_end.tv_usec = obj.m_end.tv_usec;

    return *this;
}


CPcapAnalyzer::address_pair::address_pair(address_t addr1, address_t addr2, conversation_data_t* ptr)
    : m_addr1(addr1), m_addr2(addr2), m_conv_ptr(ptr)
{}

CPcapAnalyzer::address_pair::address_pair(const address_pair& obj)
    : m_addr1(obj.m_addr1), m_addr2(obj.m_addr2), m_conv_ptr(obj.m_conv_ptr)
{}

bool CPcapAnalyzer::address_pair::operator==(address_pair& obj)
{
    if (m_addr1 == obj.m_addr1 && m_addr2 == obj.m_addr2) {
        m_conv_ptr = NULL;
        return true;
    }
    else if (m_addr1 == obj.m_addr2 && m_addr2 == obj.m_addr1) {
        obj.m_conv_ptr->set_direction_flag(true);
        m_conv_ptr = NULL;
        return true;
    }

    m_conv_ptr = NULL;
    return false;
}

CPcapAnalyzer::address_pair& CPcapAnalyzer::address_pair::operator=(address_pair& obj)
{
    m_addr1 = obj.m_addr1;
    m_addr2 = obj.m_addr2;
    m_conv_ptr = obj.m_conv_ptr;

    return *this;
}