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
#include "complet.h"

#define UDP 0x0006
#define TCP 0x0011

//Ports de protocoles applicatifs
#define SMTP 587

void parse_udp(const u_char* packet){
	int i;

	struct udphdr *udp_header = (struct udphdr *) packet;
	int size = sizeof(struct udphdr);

	printf("\tUDP\n");

	printf("\t\tPort Source      : %x\n",udp_header->uh_sport);
	printf("\t\tPort Destination : %x\n",udp_header->uh_dport);



	for (i=0;i<size;i++)
		packet++;
}


void parse_tcp(const u_char* packet){
	int i;

	struct tcphdr *tcp_header = (struct tcphdr *) packet;
	int size = sizeof(struct ip);

	printf("\tTCP\n");

	printf("\t\tPort Source      : %x\n",tcp_header->th_sport);
	printf("\t\tPort Destination : %x\n",tcp_header->th_dport);


}


void parse_ip(const u_char* packet){
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
			parse_udp(packet);
			break;
		case TCP:
			//printf("\t\tProtocole TCP\n");
			parse_tcp(packet);
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

		parse_ip(packet);
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