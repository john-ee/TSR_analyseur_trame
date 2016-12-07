void parse_udp_concis(const u_char *packet);
void parse_tcp_concis(const u_char *packet);
void parse_ip_concis(const u_char *packet);
void packet_reader_concis(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* packet);