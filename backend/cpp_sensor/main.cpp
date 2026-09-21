#define WIN32_LEAN_AND_MEAN

#include <pcap.h>
#include <iostream>
#include <string>
#include <winsock2.h>
#include <windows.h>
#include <iomanip>

#pragma comment(lib, "ws2_32.lib")

// Ethernet header
struct eth_header {
    u_char  ether_dhost[6];
    u_char  ether_shost[6];
    u_short ether_type;
};

// ARP header
#pragma pack(push, 1)
struct arp_header {
    u_short hw_type;
    u_short proto_type;
    u_char hw_len;
    u_char proto_len;
    u_short opcode;
    u_char sender_mac[6];
    u_char sender_ip[4];
    u_char target_mac[6];
    u_char target_ip[4];
};
#pragma pack(pop)

// IPv4 header
struct ip_header {
    u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    u_char  tos;            // Type of service
    u_short tlen;           // Total length
    u_short identification; // Identification
    u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl;            // Time to live
    u_char  proto;          // Protocol
    u_short crc;            // Header checksum
    struct in_addr saddr;   // Source address
    struct in_addr daddr;   // Destination address
};

// TCP header
struct tcp_header {
    u_short sport;          // Source port
    u_short dport;          // Destination port
    u_int   seq;            // Sequence number
    u_int   ack;            // Acknowledgement number
    u_char  data_res;       // Data offset (4 bits) + Reserved (4 bits)
    u_char  flags;          // Flags
    u_short win;            // Window
    u_short crc;            // Checksum
    u_short urp;            // Urgent pointer
};

// UDP header
struct udp_header {
    u_short sport;          // Source port
    u_short dport;          // Destination port
    u_short len;            // Datagram length
    u_short crc;            // Checksum
};

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

int main(int argc, char **argv) {
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int i = 0;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // Check args
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <interface_name_or_ip>" << std::endl;
        return 1;
    }
    std::string target_iface = argv[1];

    if (pcap_findalldevs_ex((char *)PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
        std::cerr << "Error in pcap_findalldevs: " << errbuf << std::endl;
        return 1;
    }

    pcap_if_t *selected_dev = nullptr;
    for (d = alldevs; d; d = d->next) {
        std::string d_name = d->name ? d->name : "";
        std::string d_desc = d->description ? d->description : "";
        
        if (d_name.find(target_iface) != std::string::npos || d_desc.find(target_iface) != std::string::npos) {
            selected_dev = d;
            break;
        }
        // Check IP addresses for a match
        pcap_addr_t *a;
        for (a = d->addresses; a; a = a->next) {
            if (a->addr->sa_family == AF_INET) {
                char *ip_str = inet_ntoa(((struct sockaddr_in *)a->addr)->sin_addr);
                if (target_iface == ip_str) {
                    selected_dev = d;
                    break;
                }
            }
        }
        if (selected_dev) break;
    }

    if (!selected_dev) {
        std::cerr << "Could not find interface matching: " << target_iface << std::endl;
        std::cerr << "Available interfaces:" << std::endl;
        for (d = alldevs; d; d = d->next) {
            std::cerr << "  Name: " << (d->name ? d->name : "null") << std::endl;
            std::cerr << "  Desc: " << (d->description ? d->description : "null") << std::endl;
        }
        pcap_freealldevs(alldevs);
        return 1;
    }

    // Open the adapter
    pcap_t *adhandle = pcap_open(selected_dev->name,
                                 65536,             // portion of the packet to capture
                                 PCAP_OPENFLAG_PROMISCUOUS, // promiscuous mode
                                 10,                // read timeout
                                 NULL,              // remote authentication
                                 errbuf);
                                 
    if (adhandle == NULL) {
        std::cerr << "Unable to open the adapter. " << selected_dev->name << " is not supported by Npcap" << std::endl;
        pcap_freealldevs(alldevs);
        return 1;
    }

    // Compile filter for IP and ARP traffic
    u_int netmask = 0xffffff;
    struct bpf_program fcode;
    if (pcap_compile(adhandle, &fcode, (char *)"ip or arp", 1, netmask) >= 0) {
        pcap_setfilter(adhandle, &fcode);
    }

    std::cerr << "[CPP_SENSOR] Listening on " << selected_dev->description << std::endl;
    pcap_freealldevs(alldevs);
    
    // Start capture loop
    pcap_loop(adhandle, 0, packet_handler, NULL);
    
    pcap_close(adhandle);
    return 0;
}

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
    struct eth_header *eh = (struct eth_header *)pkt_data;
    u_short ether_type = ntohs(eh->ether_type);

    if (ether_type == 0x0806) {
        // Handle ARP
        if (header->len < 14 + sizeof(struct arp_header)) return;
        struct arp_header *ah = (struct arp_header *)(pkt_data + 14);
        
        char smac[18], dmac[18];
        snprintf(smac, sizeof(smac), "%02x:%02x:%02x:%02x:%02x:%02x", ah->sender_mac[0], ah->sender_mac[1], ah->sender_mac[2], ah->sender_mac[3], ah->sender_mac[4], ah->sender_mac[5]);
        snprintf(dmac, sizeof(dmac), "%02x:%02x:%02x:%02x:%02x:%02x", ah->target_mac[0], ah->target_mac[1], ah->target_mac[2], ah->target_mac[3], ah->target_mac[4], ah->target_mac[5]);
        
        std::string src_ip = std::to_string(ah->sender_ip[0]) + "." + std::to_string(ah->sender_ip[1]) + "." + std::to_string(ah->sender_ip[2]) + "." + std::to_string(ah->sender_ip[3]);
        std::string dst_ip = std::to_string(ah->target_ip[0]) + "." + std::to_string(ah->target_ip[1]) + "." + std::to_string(ah->target_ip[2]) + "." + std::to_string(ah->target_ip[3]);
        
        double timestamp = header->ts.tv_sec + (header->ts.tv_usec / 1000000.0);
        
        std::cout << "{\"type\":\"arp\",\"opcode\":" << ntohs(ah->opcode) 
                  << ",\"src_mac\":\"" << smac << "\",\"dst_mac\":\"" << dmac 
                  << "\",\"src_ip\":\"" << src_ip << "\",\"dst_ip\":\"" << dst_ip 
                  << "\",\"ts\":" << std::fixed << std::setprecision(6) << timestamp 
                  << "}\n";
        return;
    } 
    else if (ether_type == 0x0800) {
        // Handle IPv4
        struct ip_header *ih = (struct ip_header *)(pkt_data + 14); // Ethernet header is 14 bytes
        int ip_len = (ih->ver_ihl & 0xf) * 4;
        
        std::string src_ip = inet_ntoa(ih->saddr);
        std::string dst_ip = inet_ntoa(ih->daddr);
        
        int src_port = 0, dst_port = 0;
        int hdr_len = 14 + ip_len;
        int payload_len = 0;
        int win = 0;
        std::string flags = "";
        
        if (ih->proto == IPPROTO_TCP) {
            struct tcp_header *th = (struct tcp_header *)((u_char*)ih + ip_len);
            src_port = ntohs(th->sport);
            dst_port = ntohs(th->dport);
            
            int tcp_hlen = ((th->data_res >> 4) & 0x0F) * 4;
            hdr_len += tcp_hlen;
            payload_len = ntohs(ih->tlen) - ip_len - tcp_hlen;
            win = ntohs(th->win);
            
            // Extract flags
            if (th->flags & 0x01) flags += "F";
            if (th->flags & 0x02) flags += "S";
            if (th->flags & 0x04) flags += "R";
            if (th->flags & 0x08) flags += "P";
            if (th->flags & 0x10) flags += "A";
            if (th->flags & 0x20) flags += "U";
            if (th->flags & 0x40) flags += "E";
            if (th->flags & 0x80) flags += "C";
        } else if (ih->proto == IPPROTO_UDP) {
            struct udp_header *uh = (struct udp_header *)((u_char*)ih + ip_len);
            src_port = ntohs(uh->sport);
            dst_port = ntohs(uh->dport);
            hdr_len += 8;
            payload_len = ntohs(ih->tlen) - ip_len - 8;
        } else if (ih->proto == IPPROTO_ICMP) {
            src_port = 0;
            dst_port = 0;
            hdr_len += 8; // ICMP base header
            payload_len = ntohs(ih->tlen) - ip_len - 8;
        } else {
            return; // Ignore non-TCP/UDP/ICMP for IDS
        }
        
        // Prevent negative payload
        if (payload_len < 0) payload_len = 0;
        
        double timestamp = header->ts.tv_sec + (header->ts.tv_usec / 1000000.0);
        
        // Fast JSON serialization to stdout
        std::cout << "{\"type\":\"ipv4\",\"src_ip\":\"" << src_ip << "\","
                  << "\"dst_ip\":\"" << dst_ip << "\","
                  << "\"src_port\":" << src_port << ","
                  << "\"dst_port\":" << dst_port << ","
                  << "\"proto\":" << (int)ih->proto << ","
                  << "\"pkt_len\":" << header->len << ","
                  << "\"hdr_len\":" << hdr_len << ","
                  << "\"payload_len\":" << payload_len << ","
                  << "\"win\":" << win << ","
                  << "\"flags\":\"" << flags << "\","
                  << "\"ts\":" << std::fixed << std::setprecision(6) << timestamp
                  << "}\n";
    }
}
