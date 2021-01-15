#include "common.h"
#include "PcapAnalyzer.h"

int main(int argc, char** argv)
{
    if (argc != 2) {
        cout << "Usage : ip-stat <pcap file>" << endl;
        return 0;
    }
    
    CPcapAnalyzer analyzer(argv[1]);

    analyzer.printEthernet();
    analyzer.printIPv4();
    analyzer.printIPv6();
    analyzer.printTCP();
    analyzer.printUDP();
    
    analyzer.printEthernetConversation();
    analyzer.printIPv4Conversation();
    analyzer.printIPv6Conversation();
    analyzer.printTCPConversation();
    analyzer.printUDPConversation();
    return 0;
}