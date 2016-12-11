/*
 * auteur : John-Nathan HILL
 * brief : 
 */


void print_ascii(const u_char* packet, int length);
void telnet_option(const u_char option);
void parse_telnet_complet(const u_char* packet, int length);
void parse_bootp(const u_char* packet);
void parse_port_complet(const u_char* packet, int length, short source, short dest);
void parse_udp_complet(const u_char* packet, int length);
void parse_tcp_complet(const u_char* packet, int length);
void parse_ip_complet(const u_char* packet, int length);
void parse_eth(const u_char* packet, int length);
void packet_reader_complet(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* packet);