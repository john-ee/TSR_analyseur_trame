void parse_smtp(const u_char* packet);
void parse_udp_complet(const u_char* packet);
void parse_tcp_complet(const u_char* packet);
void parse_ip_complet(const u_char* packet);
void parse_eth(const u_char* packet);
void packet_reader_complet(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* packet);