#ifndef __PCAPANALYZER__
#define __PCAPANALYZER__

#include <pcap/pcap.h>
#include "Map.h"

#define MAC_LEN 6
#define IPv6_LEN    16

class CPcapAnalyzer
{
public:
    CPcapAnalyzer(char* filename);

    char* reduceNumber(uint32_t num, uint32_t len);
    void printEthernet(void);
    void printIPv4(void);
    void printIPv6(void);
    void printTCP(void);
    void printUDP(void);
    void printEthernetConversation(void);
    void printIPv4Conversation(void);
    void printIPv6Conversation(void);
    void printTCPConversation(void);
    void printUDPConversation(void);

private:
    class address_t
    {
        friend class CPcapAnalyzer;
        friend class address_pair;
    public:
        address_t(void);
        address_t(uint32_t ip);
        address_t(uint32_t ip, uint32_t input_port);
        address_t(u_char* mac_ptr);
        address_t(u_char* ipv6_ptr, uint32_t input_port);
        address_t(const address_t& obj);
        
        char* get_address(void);

        bool operator==(address_t& obj);
        address_t& operator=(address_t& obj);

    private:
        enum address_type {
            NONE, MAC, IPv4, TCP_UDP, IPv6, IPv6_TCP_UDP
        };
        address_type type;
        u_char mac[MAC_LEN];
        uint32_t ipv4;
        u_char ipv6[IPv6_LEN];
        uint32_t port;
    };


    class endpoint_data_t
    {
        friend class CPcapAnalyzer;
    public:
        endpoint_data_t(void);
        endpoint_data_t(uint32_t tx_p, uint32_t tx_b, uint32_t rx_p = 0, uint32_t rx_b = 0);
        endpoint_data_t(const endpoint_data_t& obj);

        endpoint_data_t& operator=(endpoint_data_t& obj);
        endpoint_data_t& operator+=(endpoint_data_t& obj);

    private:
        uint32_t tx_packets;
        uint32_t tx_bytes;
        uint32_t rx_packets;
        uint32_t rx_bytes;
    };


    class conversation_data_t
    {
        friend class CPcapAnalyzer;
    public:
        conversation_data_t(void);
        conversation_data_t(uint32_t p_1_2, uint32_t b_1_2,
                            uint32_t p_2_1, uint32_t b_2_1,
                            struct timeval rel_start,
                            struct timeval duration, bool flag=false);
        conversation_data_t(const conversation_data_t& obj);

        void set_direction_flag(bool flag) { m_direction_flag = flag; }

        char* reduceNumber(uint32_t num, uint32_t len);
        char* get_rel_start(void);
        struct timeval calc_duration(void);
        char* get_duration(void);
        char* get_bits_1_2(void);
        char* get_bits_2_1(void);

        conversation_data_t& operator=(conversation_data_t& obj);
        conversation_data_t& operator+=(conversation_data_t& obj);

    private:
        uint32_t m_packets_1_2;
        uint32_t m_bytes_1_2;
        uint32_t m_packets_2_1;
        uint32_t m_bytes_2_1;
        struct timeval m_rel_start;
        struct timeval m_end;

        bool m_direction_flag;
    };


    class address_pair
    {
        friend class PcapAnalyzer;
    public:
        address_pair(void) {}
        address_pair(address_t addr1, address_t addr2, conversation_data_t* ptr);
        address_pair(const address_pair& obj);

        char* get_address1(void) { return m_addr1.get_address(); }
        char* get_address2(void) { return m_addr2.get_address(); }
        uint32_t get_port1(void) { return m_addr1.port; }
        uint32_t get_port2(void) { return m_addr2.port; }

        bool operator==(address_pair& obj);
        address_pair& operator=(address_pair& obj);

    private:
        address_t m_addr1;
        address_t m_addr2;
        conversation_data_t* m_conv_ptr;
    };


    pcap_t* m_pcap_handle;

    CMap<address_t, endpoint_data_t> m_ethernet_endpoint;
    CMap<address_t, endpoint_data_t> m_ipv4_endpoint;
    CMap<address_t, endpoint_data_t> m_tcp_endpoint;
    CMap<address_t, endpoint_data_t> m_udp_endpoint;
    CMap<address_t, endpoint_data_t> m_ipv6_endpoint;
    CMap<address_t, endpoint_data_t> m_ipv6_tcp_endpoint;
    CMap<address_t, endpoint_data_t> m_ipv6_udp_endpoint;

    CMap<address_pair, conversation_data_t> m_ethernet_conversation;
    CMap<address_pair, conversation_data_t> m_ipv4_conversation;
    CMap<address_pair, conversation_data_t> m_tcp_conversation;
    CMap<address_pair, conversation_data_t> m_udp_conversation;
    CMap<address_pair, conversation_data_t> m_ipv6_conversation;
    CMap<address_pair, conversation_data_t> m_ipv6_tcp_conversation;
    CMap<address_pair, conversation_data_t> m_ipv6_udp_conversation;
};

#endif