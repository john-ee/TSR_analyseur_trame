#ifndef _CONCIS_H
#define __CONCIS_H

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
#define FTPS 0x0015 //server
#define FTPC 0x0016 //client

void parse_udp_concis(const u_char *packet);
void parse_tcp_concis(const u_char *packet);
void parse_ip_concis(const u_char *packet);
void packet_reader_concis(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* packet);

#endif