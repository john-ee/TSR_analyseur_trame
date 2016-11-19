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
#include "concis.h"

void packet_ip(const u_char *packet){
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
			printf("UDP  ");
			break;
		case TCP:
			printf("TCP  ");
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
			packet_ip(packet);
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