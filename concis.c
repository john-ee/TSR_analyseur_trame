#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "concis.h"
#include "port.h"


void parse_port_concis(short source, short dest){
		int port = 0;

	switch(source){
		case FTPC: printf("FTP:Client  "); break;
		case FTPS: printf("FTP:Serveur  "); break;
		case HTTP: printf("HTTP  "); break;
		case HTTPS: printf("HTTPS  "); break;
		case DNS: printf("DNS  "); break;
		case SMTP: printf("SMTP  "); break;

		default: port++; break;
	}

	switch(dest){
		case FTPC: printf("FTP:Client  "); break;
		case FTPS: printf("FTP:Serveur  "); break;
		case HTTP: printf("HTTP  "); break;
		case HTTPS: printf("HTTPS  "); break;
		case DNS: printf("DNS  "); break;
		case SMTP: printf("SMTP  "); break;

		default: port++; break;
	}

	if (port==2)
		printf("Port Applicatif non reconnu  ");
}


void parse_udp_concis(const u_char *packet){
	struct udphdr *udp_header = (struct udphdr *) packet;
	short source = ntohs(udp_header->uh_sport);
	short dest = ntohs(udp_header->uh_dport);

	printf("UDP  ");

	parse_port_concis(source, dest);
}

void parse_tcp_concis(const u_char *packet){
	struct tcphdr *tcp_header = (struct tcphdr *) packet;
	int size = sizeof(struct ip);
	int offset = (int)tcp_header->th_off;
	short source = ntohs(tcp_header->th_sport);
	short dest = ntohs(tcp_header->th_dport);
	int port = 0;

	printf("TCP {");

	if (tcp_header->th_flags & TH_FIN)
		printf(" FIN");
	if (tcp_header->th_flags & TH_SYN)
		printf(" SYN");
	if (tcp_header->th_flags & TH_RST)
		printf(" RST");
	if (tcp_header->th_flags & TH_PUSH)
		printf(" PUSH");
	if (tcp_header->th_flags & TH_ACK)
		printf(" ACK");
	if (tcp_header->th_flags & TH_URG)
		printf(" URG");

	printf(" }  ");

	parse_port_concis(source, dest);
}


void parse_ip(const u_char *packet){
	int i;

	struct ip *ip_header = (struct ip *) packet;
	int size = sizeof(struct ip);
	
	printf("IPv%x ",ip_header->ip_v);

	for (i=0;i<size;i++)
		packet++;

	char *ip = inet_ntoa(ip_header->ip_src);
	printf("%s  ->  ",ip);

	ip = inet_ntoa(ip_header->ip_dst);
	printf("%s  ",ip);

	switch (ip_header->ip_p){
		case UDP:
			parse_udp_concis(packet);
			break;
		case TCP:
			parse_tcp_concis(packet);
			break;
		default:
			printf("ni TCP ni UDP  ");
			break;
	}

}

void packet_reader_concis(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
	static int count = 1;
	printf("[%d]  ",count);
    /* on lit la taille du packet */
	fprintf(stdout,"\tlength: %d  ",pkthdr->len);

	u_char *ptr;

    int i;

    /* ethernet header */
    struct ether_header *eptr = (struct ether_header *) packet;
    int size = sizeof(struct ether_header);

	/*ptr = eptr->ether_shost;
	for(i=0;i<5;i++)
		printf("%x:",ptr[i]);
	printf("%x ->  ",ptr[i++]);

	ptr = eptr->ether_dhost;
	for(i=0;i<5;i++)
		printf("%x:",ptr[i]);
	printf("%x  ",ptr[i++]);*/

	for (i=0;i<size;i++)
		packet++;


	switch(ntohs(eptr->ether_type)){
		case ETHERTYPE_IP:
			//printf("IP  ");
			parse_ip(packet);
			break;
		case ETHERTYPE_ARP:
			printf("ARP  ");
			break;
		default:
			printf("ni IP ni ARP  ");
			break;
	}

	count++;
	printf("\n");
	fflush(stdout);

}