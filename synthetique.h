/*
 * auteur : John-Nathan HILL
 * brief : Ce module permet de décoder les trames en -v 2
 */

/*
 * Cette fonction parcourt la trame
 * Grâce à des compteurs, si l'on reconnait un caractères, on les incrémente
 * Si les compteurs correspondent à la taille des mot-clés correspondant
 * On affiche le mot-clé
 * Dans le cas d'un échange sécurisé, on ne peut pas décoder la trame
 * Mais on le tente tout de même
 * On se sert de port.h
 */
void parse_smtp_synthetique(const u_char* packet, int length);

/*
 * Cette fonction parcourt la trame
 * Grâce à des compteurs, si l'on reconnait un caractères, on les incrémente
 * Si les compteurs correspondent à la taille des mot-clés correspondant
 * On affiche le mot-clé
 * Dans le cas d'un échange sécurisé, on ne peut pas décoder la trame
 * Mais on le tente tout de même
 * On se sert de port.h
 */
void parse_http_synthetique(const u_char* packet, int length);

/*
 * Grâce au header bootp.h, on caste l'objet packet dans un struct
 * On regarde d'abord le type de message BOOTP dont il s'agit
 * Puis on vérifie la présence du magic cookie
 * Si c'est le cas, on regarde s'il s'agit d'un message dhcp
 * Si c'est aussi le cas, on affiche le type de message
 * Sinon on affiche la présence d'extensions
 */
void parse_bootp_synthetique(const u_char* packet);

/*
 * A l'aide de deux switch et port.h
 * On regarde si l'on ne reconnait pas le port applicatif
 * On regarde d'abord le port source et si l'on ne reconnait pas le port
 * On regarde le port destination
 * Si les ports ne sont pas reconnus, on l'affiche
 */
void parse_port_synthetique(const u_char* packet, int length, short source, short dest);

/*
 * On caste l'objet paquet dans un struct UDP
 * Puis on lance la fonction parse_port
 */
void parse_udp_synthetique(const u_char* packet, int length);

/*
 * On caste l'objet paquet dans un struct TCP
 * On tente de reconnaître les flags
 * Puis on paquet dans la fonction parse_port
 */
void parse_tcp_synthetique(const u_char* packet, int length);

/*
 * On caste l'objet paquet dans un struct IP
 * On affiche la version utilisée
 * Puis selon le protocole de transport on envoie le packet dans la fonction correspondante
 */
void parse_ip_synthetique(const u_char* packet, int length);

/*
 * On caste l'objet paquet dans un struct Ethernet
 * On affiche les adresses MAC
 * Puis on regarde le protocole utilisé dans la couche dessous
 */
void parse_eth_synthetique(const u_char* packet, int length);

/*
 * Grâce à uen variable statique on compte les paquets
 * Puis on lance le décodage
 */
void packet_reader_synthetique(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* packet);