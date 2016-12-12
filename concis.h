/*
 * auteur : John-Nathan HILL
 */

/*
 * Cette fonction se sert de deux switch pour reconnaître les ports
 * Si l'on reconnait le port source alors on l'affiche
 * Sinon on regarde le port destination pour reconnaître le port
 * On affiche que l'on reconnaît pas le port si c'est le cas
 */
void parse_port_concis(short source, short dest);

/*
 * Grâce à une structure on récupère les ports source et destination
 * On affiche aussi qu'il s'agit d'un paquet UDP
 */
void parse_udp_concis(const u_char *packet);

/*
 * Grâce à une structure on récupère les ports source et destination
 * On regarde aussi les flags et on affiche ceux reconnu grâce à des if
 */
void parse_tcp_concis(const u_char *packet);

/*
 * Grâce à une structure, on recupère les adresses IP
 * ainsi que la version d'IP.
 * Puis on cherche à reconnaître le protcole de la couche suivante
 */
void parse_ip_concis(const u_char *packet);

/*
 * Grâce à une structure, on recupère les adresses MAC
 * On regarde ensuite le protocole de la couche suivante
 */
void packet_reader_concis(u_char *useless, const struct pcap_pkthdr* pkthdr, const u_char* packet);