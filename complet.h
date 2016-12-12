/*
 * auteur : John-Nathan HILL
 */

/*
 * Cette fonction affiche la trame en ascii
 * Après un certain nombre de caractères on fait retour au ligne
 * Avant d'afficher le caractère on vérifie si il est imprimable
 * Sinon on affiche un point
 */
void print_ascii(const u_char* packet, int length);

/*
 * Cette fonction prend un entrée un u_char
 * Grâce à un switch on regarde si l'on reconnaît l'option ou non
 */
void telnet_option(const u_char option);

/*
 * On utilise un struct pour décoder la trame
 * On parcours la trame pour reconnaître les termes
 * On utilise les define de telnet.h
 */
void parse_telnet_complet(const u_char* packet, int length);

/*
 * On utilise un struct pour décoder la trame
 * On parcours la trame pour reconnaître les termes
 * On utilise les define de bootp.h
 * On vérifie d'abord la présence du magic cookie
 * Puis onregarde s'il s'agit d'un message DHCP
 * Si c'est le cas on parcours la trame
 * Sinon on affiche que l'on a reconnu la présences d'extensions
 */
void parse_bootp(const u_char* packet);

/*
 * Cette fonction se sert de deux switch pour reconnaître les ports
 * Si l'on reconnait le port source alors on l'affiche
 * Sinon on regarde le port destination pour reconnaître le port
 * On affiche que l'on reconnaît pas le port si c'est le cas
 * Selon le por reconnu on décode ou non la trame
 */
void parse_port_complet(const u_char* packet, int length, short source, short dest);

/*
 * Grâce à une structure on récupère les ports source et destination
 * On affiche aussi qu'il s'agit d'un paquet UDP
 */
void parse_udp_complet(const u_char* packet, int length);

/*
 * Grâce à une structure on récupère les ports source et destination
 * On regarde aussi les flags et on affiche ceux reconnu grâce à des if
 */
void parse_tcp_complet(const u_char* packet, int length);

/*
 * Grâce à une structure, on recupère les adresses IP
 * ainsi que la version d'IP.
 * Puis on cherche à reconnaître le protcole de la couche suivante
 */
void parse_ip_complet(const u_char* packet, int length);

/*
 * On caste l'objet paquet dans un struct Ethernet
 * On affiche les adresses MAC
 * Puis on regarde le protocole utilisé dans la couche dessous
 */
void parse_eth(const u_char* packet, int length);

/*
 * Grâce à uen variable statique on compte les paquets
 * Puis on lance le décodage
 */
void packet_reader_complet(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* packet);