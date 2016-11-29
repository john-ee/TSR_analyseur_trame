#ifndef _COMPLET_H
#define __COMPLET_H

#define UDP 0x0006
#define TCP 0x0011

//Ports de protocoles applicatifs
#define SMTP 0x024b
#define HTTP 0x0050
#define HTTPS 0x01bb
#define DNS 0x0035
#define BOOTPS 0x0043 //server
#define BOOTPC 0x0044 //client
#define DHCP 0x0222

void parse_udp(const u_char* packet);
void parse_tcp(const u_char* packet);
void parse_ip(const u_char* packet);
void parse_eth(const u_char* packet);
void packet_reader_complet(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* packet);

#endif