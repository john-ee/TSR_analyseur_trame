void print_ascii(const u_char* packet, int length);
void parse_port_complet(const u_char* packet, int length, short source, short dest);
void parse_udp_complet(const u_char* packet, int length);
void parse_tcp_complet(const u_char* packet, int length);
void parse_ip_complet(const u_char* packet, int length);
void parse_eth(const u_char* packet, int length);
void packet_reader_complet(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* packet);