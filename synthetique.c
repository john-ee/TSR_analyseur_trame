/*
 * auteur : John-Nathan HILL
 * brief : Ce module permet de décoder les trames en -v 2
 */

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <ctype.h>
#include <string.h>
#include "synthetique.h"
#include "bootp.h"
#include "port.h"


void parse_smtp_synthetique(const u_char* packet, int length)
{
	// On récupère les tableaux dans port.h
	// On comparera les caractères de la trame 
	// aux caractères contenues dans les tableaux suivants
	const u_char mail[] = MAIL;
	const u_char rcpt[] = RCPT;
	const u_char data[] = DATA;
	const u_char ehlo[] = EHLO;
	const u_char auth[] = AUTH;
	const u_char starttls[] = STARTTLS;

	// i et j serviront pour les boucles for
	int i = 0, j = 0;
	// Ces variables sont incrémentées à chaque comparaisons justes
	int mailcmp = 0, rcptcmp = 0, datacmp = 0;
	int ehlocmp = 0, authcmp = 0, tlscmp = 0;

	// On parcourt la trame
	while (i<length)
	{
		// On réinitialise les compteurs de comparaisons
		mailcmp = 0;
		rcptcmp = 0;
		datacmp = 0;
		ehlocmp = 0;
		authcmp = 0;
		tlscmp = 0;

		// On parcours les quatre caractères et on icnrémentes les compteurs
		for (j=0;j<4;j++)
		{
			if (mail[j] == packet[i+j])
				mailcmp++;
			if (rcpt[j] == packet[i+j])
				rcptcmp++;
			if (data[j] == packet[i+j])
				datacmp++;
			if (ehlo[j] == packet[i+j])
				ehlocmp++;
			if (auth[j] == packet[i+j])
				authcmp++;
			if (starttls[j] == packet[i+j])
				tlscmp++;
		}

		// Dans ce cas on affiche la trame pour voir l'adresse e-mail
		if (mailcmp == 4 || rcptcmp == 4)
		{
			while (i<length){
				if(isprint(packet[i]))
					printf("%c", packet[i]);
				else
					printf(".");
				i++;
			}
		}

		// On affiche un message correspondant au compteurs
		if (datacmp == 4)
			printf("Contenu de l'e-mail ");

		if (ehlocmp == 4)
			printf("Requête EHLO");

		if (authcmp == 4)
			printf("Authentification ");

		// On va quelques caractères plus loin pour finir la comparaions
		if (i < length-8){
			for (j=4;j<8;j++){
				if (starttls[j] == packet[i+j])
					tlscmp++;
			}
			if (tlscmp == 8)
				printf("Echange en TLS ");
		}

		i++;
	}
	printf("\n");
}


void parse_http_synthetique(const u_char* packet, int length)
{
	// On récupère les tableaux dans port.h
	// On comparera les caractères de la trame 
	// aux caractères contenues dans les tableaux suivants
	const u_char get[] = GET;
	const u_char put[] = PUT;
	const u_char head[] = HEAD;
	const u_char post[] = POST;

	// i et j serviront pour les boucles for
	int i = 0, j = 0;
	// Ces variables sont incrémentées à chaque comparaisons justes
	int getcmp = 0, putcmp = 0, headcmp = 0, postcmp = 0;

	// On parcours les quatre caractères et on icnrémentes les compteurs
	while (i<length-4)
	{
		getcmp = 0;
		putcmp = 0;
		headcmp = 0;
		postcmp = 0;

		for (j=0;j<3;j++)
		{
			if (get[j] == packet[i+j])
				getcmp++;
			if (put[j] == packet[i+j])
				putcmp++;
			if (head[j] == packet[i+j])
				headcmp++;
			if (post[j] == packet[i+j])
				postcmp++;
		}
		j = 3;
		// Selon les compteurs, on affiche le mot clé reconnu
		if (getcmp == 3)
			printf("GET");

		if (putcmp == 3)
			printf("PUT");

		if (head[j] == packet[i+j] && headcmp == 4)
			printf("HEAD");

		if (post[j] == packet[i+j] && postcmp == 4)
			printf("POST");

		i++;
	}

	printf("\n");
}


void parse_bootp_synthetique(const u_char* packet)
{
	// On cast le packet dans un en-tête bootp
	struct bootp *bootp_header = (struct bootp *) packet;
	// Ces variables permettront de parcourir le packet
	int i = 0, j, dhcp = 0;
	int size = 0;

	printf("\tBOOTP ");

	// On regarde de quelle type de message il s'agit
	switch (bootp_header->bp_op)
	{
		case BOOTREPLY : printf("BOOTREPLY "); break;
		case BOOTREQUEST : printf("BOOTREQUEST "); break;
		default : break;
	}

	// On récupère le magic cookie pour la comparaison
	u_char *vendor = bootp_header->bp_vend;
	u_char magic_cookie[] = VM_RFC1048;
	
	for (i=0;i<4;i++)
	{
		if (vendor[i] == magic_cookie[i])
			dhcp++;
	}

	// Dans le cas où l'on reconnait le magic cookie
	// On s'intéresse au fait si on a du DHCP ou non
	if (dhcp == 4)
	{
		i=4;
		if (vendor[i] == 53)
		{
			printf("DHCP ");
			i+=2;
			// On affiche le type de message DHCP
			switch(vendor[i])
			{
				case 01 : printf("discover\n"); break;
				case 02 : printf("offer\n"); break;
				case 03 : printf("request\n"); break;
				case 05 : printf("ack\n"); break;
				case 07 : printf("release\n"); break;
				default : printf("\n"); break;
			}
		}
		else
			printf("Extensions présentes\n");
	}
}


void parse_port_synthetique(const u_char* packet, int length, short source, short dest)
{
	// Cette variable servira a savoir si l'on a reconnu un port
	int not_parsed = 0;
	printf("%x -> %x\n",source, dest);

	// On regarde d'abord le port source
	switch(source)
	{
			case FTPC:
				printf("\tFTP: Envoi de données\n");
				break;

			case FTPS: 
				printf("\tFTP: Envoi de requêtes\n");
				break;

			case HTTP:
				printf("\tHTTP ");
				parse_http_synthetique(packet, length);
				break;

			case HTTPS:
				printf("\tHTTP sécurisé ");
				parse_http_synthetique(packet, length);
				break;

			case DNS:
				printf("\tDNS\n");
				break;

			case SMTP:
				printf("\tSMTP ");
				parse_smtp_synthetique(packet, length);
				break;

			case SMTPS:
				printf("\tSMTP sécurisé ");
				parse_smtp_synthetique(packet, length);
				break;

			case BOOTPS:
			case BOOTPC:
				parse_bootp_synthetique(packet);
				break;

			case TELNET:
				printf("\tTELNET\n");
				break;

		default: not_parsed++; break;

		}

	// Si l'on ne reconnait pas le port source, on regarde le port destination
	if (not_parsed)
	{
		switch(dest)
		{
			case FTPC:
				printf("\t\tFTP: Envoi de données\n");
				break;

			case FTPS: 
				printf("\t\tFTP: Envoi de requêtes\n");
				break;

			case HTTP:
				printf("\tHTTP ");
				parse_http_synthetique(packet, length);
				break;

			case HTTPS:
				printf("\tHTTP sécurisé ");
				parse_http_synthetique(packet, length);
				break;

			case DNS:
				printf("\tDNS\n");
				break;

			case SMTP:
				printf("\tSMTP ");
				parse_smtp_synthetique(packet, length);
				break;

			case SMTPS:
				printf("\tSMTP sécurisé ");
				parse_smtp_synthetique(packet, length);
				break;

			case BOOTPS:
			case BOOTPC:
				parse_bootp_synthetique(packet);
				break;

			case TELNET:
				printf("\tTELNET\n");
				break;

			// Arriver à ce cas, on affiche que l'on ne reconnait pas le port
			default:
				printf("\tPort Applicatif non reconnu\n");
				break;
			}
	}
}


void parse_udp_synthetique(const u_char* packet, int length)
{
	int i;
	// On castE le packet dans le struct correspondant
	struct udphdr *udp_header = (struct udphdr *) packet;
	int size = sizeof(struct udphdr);
	short source = ntohs(udp_header->uh_sport);
	short dest = ntohs(udp_header->uh_dport);
	int not_parsed = 0;

	printf("\tUDP ");

	for (i=0;i<size;i++)
		packet++;

	parse_port_synthetique(packet, length-size, source, dest);
}


void parse_tcp_synthetique(const u_char* packet, int length)
{
	int i;
	// On caste le packet dans le struct correspondant
	struct tcphdr *tcp_header = (struct tcphdr *) packet;
	int size = (int)tcp_header->th_off;
	short source = ntohs(tcp_header->th_sport);
	short dest = ntohs(tcp_header->th_dport);

	printf("\tTCP Flags: ");

	if (tcp_header->th_flags & TH_FIN)
		printf("FIN ");
	if (tcp_header->th_flags & TH_SYN)
		printf("SYN ");
	if (tcp_header->th_flags & TH_RST)
		printf("RST ");
	if (tcp_header->th_flags & TH_PUSH)
		printf("PUSH ");
	if (tcp_header->th_flags & TH_ACK)
		printf("ACK ");
	if (tcp_header->th_flags & TH_URG)
		printf("URG ");

	for (i=0;i<size;i++)
		packet++;
	printf(" ");
	
	parse_port_synthetique(packet, length-size, source, dest);
}


void parse_ip_synthetique(const u_char* packet, int length)
{
	int i;

	struct ip *ip_header = (struct ip *) packet;
	int size = sizeof(struct ip);
	
	printf("\tIPv%x ",ip_header->ip_v);

	for (i=0;i<size;i++)
		packet++;

	char *src = strdup(inet_ntoa(ip_header->ip_src));
	char *dst = strdup(inet_ntoa(ip_header->ip_dst));
	printf("%s -> %s\n", src, dst);

	free(src);
	free(dst);

	switch (ip_header->ip_p)
	{
		case UDP:
			parse_udp_synthetique(packet, length - size);
			break;
		case TCP:
			parse_tcp_synthetique(packet, length - size);
			break;
		default:
			printf("\tNi TCP ni UDP\n");
			break;
	}

}


void parse_eth_synthetique(const u_char* packet, int length)
{
	u_char *ptr;

    int i;

    // ethernet header
    struct ether_header *eptr = (struct ether_header *) packet;
    int size = sizeof(struct ether_header);

    ptr = eptr->ether_shost;
	printf("\t");
	for(i=0;i<6;i++)
		printf("%x:",ptr[i]);
	printf("%x",ptr[i++]);

	printf(" -> ");

	ptr = eptr->ether_dhost;
	for(i=0;i<5;i++)
		printf("%x:",ptr[i]);
	printf("%x",ptr[i++]);
	printf("\n");

	for (i=0;i<size;i++)
		packet++;

	// on verifie si c'est protocole IP 
	if (ntohs(eptr->ether_type) == ETHERTYPE_IP)
		parse_ip_synthetique(packet, length - size);

	else if (ntohs (eptr->ether_type) == ETHERTYPE_ARP)
		printf("\tPacket ARP\n");

	else if (ntohs (eptr->ether_type) == ETHERTYPE_REVARP)
		printf("\tPacket RSARP\n");

	else
		printf("\tPacket ni IP ni ARP\n");
}


void packet_reader_synthetique(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
	static int count = 1;
	printf("[%d]\n",count);
    // on lit la taille du packet
	printf("\tlength: %d\n",pkthdr->len);
    parse_eth_synthetique(packet, pkthdr->len);
	count++;
	fflush(stdout);
}