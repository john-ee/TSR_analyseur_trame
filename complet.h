#ifndef _COMPLET_H
#define __COMPLET_H

#define UDP 0x0006
#define TCP 0x0011

void parse_udp(const u_char* packet);
void parse_tcp(const u_char* packet);
void parse_ip(const u_char* packet);
void parse_eth(const u_char* packet);
void packet_reader_complet(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* packet);

#endif