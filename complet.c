#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <ctype.h>
#include "complet.h"

void parse_http(const u_char* packet){
	;
}


void parse_smtp(const u_char* packet){
	printf("\t\tSMTP\n");
	int i = 0;
	while (packet[i] != '\0'){
		if(isprint(packet[i]))
			printf("%c", packet[i]);
		else
			printf(".");
		i++;
	}
	printf("\n");

}

void parse_udp_complet(const u_char* packet){
	int i;

	struct udphdr *udp_header = (struct udphdr *) packet;
	int size = sizeof(struct udphdr);

	printf("\tUDP\n");

	switch(udp_header->uh_sport){
		case FTPC: printf("\t\tFTP: Envoi de données\n"); break;
		case FTPS: printf("\t\tFTP: Envoi de requêtes\n"); break;
		case HTTP: printf("\t\tHTTP"); break;
		case HTTPS: printf("\t\tHTTPS\n"); break;
		case DNS: printf("\t\tDNS\n"); break;
		case SMTP: parse_smtp(packet); break;

		default: printf("\t\tPort Destination : %x\n",udp_header->uh_sport); break;
	}

	switch(udp_header->uh_dport){
		case FTPC: printf("\t\tFTP: Envoi de données\n"); break;
		case FTPS: printf("\t\tFTP: Envoi de requêtes\n"); break;
		case HTTP: printf("\t\tHTTP"); break;
		case HTTPS: printf("\t\tHTTPS\n"); break;
		case DNS: printf("\t\tDNS\n"); break;
		case SMTP: parse_smtp(packet); break;

		default: printf("\t\tPort Destination : %x\n",udp_header->uh_dport); break;
	}

	for (i=0;i<size;i++)
		packet++;
}


void parse_tcp_complet(const u_char* packet){
	int i;

	struct tcphdr *tcp_header = (struct tcphdr *) packet;
	int size = sizeof(struct ip);
	int offset = (int)tcp_header->th_off;
	u_short source = tcp_header->th_sport;
	u_short dest = tcp_header->th_dport;

	printf("\tTCP\n");

	if (tcp_header->th_flags & TH_FIN)
		printf("\t\tFlag : FIN\n");
	if (tcp_header->th_flags & TH_SYN)
		printf("\t\tFlag : SYN\n");
	if (tcp_header->th_flags & TH_RST)
		printf("\t\tFlag : RST\n");
	if (tcp_header->th_flags & TH_PUSH)
		printf("\t\tFlag : PUSH\n");
	if (tcp_header->th_flags & TH_ACK)
		printf("\t\tFlag : ACK\n");
	if (tcp_header->th_flags & TH_URG)
		printf("\t\tFlag : URG\n");

	packet = packet + offset*4;

	printf("\t\tData Offset : %d\n",offset);
	switch(source){
		case FTPC: printf("\t\tFTP: Réception de données\n"); break;
		case FTPS: printf("\t\tFTP: Réception de requêtes\n"); break;
		case HTTP: printf("\t\tHTTP\n"); break;
		case HTTPS: printf("\t\tHTTPS\n"); break;
		case DNS: printf("\t\tDNS\n"); break;
		case SMTP: parse_smtp(packet); break;

		default: printf("\t\tPort Source      : %x\n",source); break;
	}


	switch(dest){
		case FTPC: printf("\t\tFTP: Envoi de données\n"); break;
		case FTPS: printf("\t\tFTP: Envoi de requêtes\n"); break;
		case HTTP: printf("\t\tHTTP"); break;
		case HTTPS: printf("\t\tHTTPS\n"); break;
		case DNS: printf("\t\tDNS\n"); break;
		case SMTP: parse_smtp(packet); break;

		default: printf("\t\tPort Destination : %x\n",dest); break;
	}
}


void parse_ip_complet(const u_char* packet){
	int i;

	struct ip *ip_header = (struct ip *) packet;
	int size = sizeof(struct ip);

	printf("\tIP\n");
	
	printf("\t\tIPv%x\n",ip_header->ip_v);
	//printf("\t\tTaille de l'en-tête %x\n",ip_header->ip_hl);
	//printf("\t\tType de service %x\n",ip_header->ip_tos);

	//printf("\t\tData offset %d\n",ip_header->ip_off);

	for (i=0;i<size;i++)
		packet++;

	char *ip = inet_ntoa(ip_header->ip_src);
	printf("\t\tAddresse Source      : %s\n",ip);

	ip = inet_ntoa(ip_header->ip_dst);
	printf("\t\tAddresse Destination : %s\n",ip);

	switch (ip_header->ip_p){
		case UDP:
			//printf("\t\tProtocole UDP\n");
			parse_udp_complet(packet);
			break;
		case TCP:
			//printf("\t\tProtocole TCP\n");
			parse_tcp_complet(packet);
			break;
		default:
			printf("\t\tNi TCP ni UDP\n");
			break;
	}

}


void parse_eth(const u_char* packet){
	u_char *ptr;

    int i;

    /* ethernet header */
    struct ether_header *eptr = (struct ether_header *) packet;
    int size = sizeof(struct ether_header);
	printf("\tEthernet\n");

	ptr = eptr->ether_dhost;
	printf("\t\tAdresse destination :  ");
	for(i=0;i<5;i++)
		printf("%x:",ptr[i]);
	printf("%x",ptr[i++]);
	printf("\n");

	ptr = eptr->ether_shost;
	printf("\t\tAdresse source      :  ");
	for(i=0;i<6;i++)
		printf("%x:",ptr[i]);
	printf("%x\n",ptr[i++]);

	for (i=0;i<size;i++)
		packet++;

	/* on verifie si c'est protocole IP */
	if (ntohs(eptr->ether_type) == ETHERTYPE_IP){
		//printf("\t\tPacket IP\n");

		parse_ip_complet(packet);
	}

	else if (ntohs (eptr->ether_type) == ETHERTYPE_ARP)
		printf("\tPacket ARP\n");

	else if (ntohs (eptr->ether_type) == ETHERTYPE_REVARP)
		printf("\tPacket RSARP\n");

	else
		printf("\t\tPacket ni IP ni ARP\n");
}


void packet_reader_complet(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
	static int count = 1;
	printf("[%d]\n",count);
    /* on lit la taille du packet */
	fprintf(stdout,"\tlength: %d\n",pkthdr->len);
    parse_eth(packet);

	count++;
	fflush(stdout);

}