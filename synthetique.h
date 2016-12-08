void parse_bootp_synthetique(const u_char* packet);
void parse_port_synthetique(const u_char* packet, int length, short source, short dest);
void parse_udp_synthetique(const u_char* packet, int length);
void parse_tcp_synthetique(const u_char* packet, int length);
void parse_ip_synthetique(const u_char* packet, int length);
void parse_eth_synthetique(const u_char* packet, int length);
void packet_reader_synthetique(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* packet);