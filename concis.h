#ifndef _CONCIS_H
#define __CONCIS_H

#define UDP 0x0006
#define TCP 0x0011

void packet_ip(const u_char *packet);
void packet_reader_concis(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* packet);

#endif