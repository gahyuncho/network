#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>
#include "myheader.h"

void print_mac(const u_char *mac)
{
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_payload(const u_char *payload, int len)
{
    int i;
    for (i = 0; i < len; i++) {
        unsigned char c = payload[i];
        if (isprint(c) || c == '\n' || c == '\r' || c == '\t')
            putchar(c);
        else
            putchar('.');
    }
    printf("\n");
}

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                 const u_char *packet)
{
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) != 0x0800) {
        return;
    }

    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
    int ip_header_len = ip->iph_ihl * 4;   
    if (ip->iph_protocol != IPPROTO_TCP) {
        return;
    }

    struct tcpheader *tcp = (struct tcpheader *)((u_char *)ip + ip_header_len);
    int tcp_header_len = TH_OFF(tcp) * 4;  /* TCP Header 도 32bit word 단위 */

    printf("=========================================================\n");

    printf("[Ethernet Header]\n");
    printf("  Src MAC : ");
    print_mac(eth->ether_shost);
    printf("\n");
    printf("  Dst MAC : ");
    print_mac(eth->ether_dhost);
    printf("\n");

    printf("[IP Header]\n");
    printf("  Src IP  : %s\n", inet_ntoa(ip->iph_sourceip));
    printf("  Dst IP  : %s\n", inet_ntoa(ip->iph_destip));
    printf("  IP Header Len : %d bytes\n", ip_header_len);
    printf("  Total IP Len  : %d bytes\n", ntohs(ip->iph_len));

    printf("[TCP Header]\n");
    printf("  Src Port: %d\n", ntohs(tcp->th_sport));
    printf("  Dst Port: %d\n", ntohs(tcp->th_dport));
    printf("  TCP Header Len : %d bytes\n", tcp_header_len);

    
    int total_header_len = sizeof(struct ethheader) + ip_header_len + tcp_header_len;
    int ip_total_len     = ntohs(ip->iph_len);
    int payload_len       = ip_total_len - ip_header_len - tcp_header_len;

    int captured_payload_len = header->caplen - total_header_len;
    if (payload_len > captured_payload_len)
        payload_len = captured_payload_len;

    if (payload_len > 0) {
        const u_char *payload = packet + total_header_len;
        printf("[HTTP Message] (%d bytes)\n", payload_len);
        print_payload(payload, payload_len);
    } else {
        printf("[HTTP Message] (payload 없음 - SYN/ACK 등 handshake 패킷)\n");
    }

    printf("=========================================================\n\n");
}

int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    char filter_exp[] = "tcp";  
    struct bpf_program fp;
    bpf_u_int32 net = 0;
    char *dev;

    if (argc >= 2) {
        dev = argv[1];
    } else {
        pcap_if_t *alldevs;
        if (pcap_findalldevs(&alldevs, errbuf) == -1 || alldevs == NULL) {
            fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
            return 1;
        }
        dev = strdup(alldevs->name);
        pcap_freealldevs(alldevs);
    }

    printf("Listening on interface: %s\n", dev);

    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 1;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        return 1;
    }

    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    return 0;
}