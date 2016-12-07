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
#include "complet.h"
#include "bootp.h"
#include "port.h"

void print_ascii(const u_char* packet)
{
	printf("\tASCII");
	int i = 0, dhcp = 0;
	while (packet[i] != '\0'){
		if (i%47==0)
			printf("\n\t\t");
		if(isprint(packet[i]))
			printf("%c", packet[i]);
		else
			printf(".");
		i++;
	}
	printf("\n");
}

void parse_http(const u_char* packet){
	;
}


void parse_smtp(const u_char* packet){
	printf("\tSMTP\n");
}

void parse_bootp(const u_char* packet){
	printf("\tBOOTP\n");
	struct bootp *bootp_header = (struct bootp *) packet;
	int i = 0, dhcp = 0;

	switch (bootp_header->bp_op){
		case BOOTREPLY : printf("\t\tBOOTREPLY\n"); break;
		case BOOTREQUEST : printf("\t\tBOOTREQUEST\n"); break;
		default : break;
	}

	u_char *vendor = bootp_header->bp_vend;
	unsigned char magic_cookie[] = VM_RFC1048;
	
	for (i=0;i<4;i++){
		if (vendor[i] == magic_cookie[i])
			dhcp++;
	}
	if (dhcp == 4)
		printf("\t\tExtensions présentes\n");
}

void parse_udp_complet(const u_char* packet){
	int i;

	struct udphdr *udp_header = (struct udphdr *) packet;
	int size = sizeof(struct udphdr);
	int source = udp_header->uh_sport;
	int dest = udp_header->uh_dport;

	printf("\tUDP\n");

	for (i=0;i<size;i++)
		packet++;

	switch(source){
		case FTPC: printf("\t\tFTP: Envoi de données\n"); break;
		case FTPS: printf("\t\tFTP: Envoi de requêtes\n"); break;
		case HTTP:
		case HTTPS: printf("\t\tHTTP\n"); break;
		case DNS: printf("\t\tDNS\n"); break;
		case SMTP:
		case SMTPS: parse_smtp(packet); break;
		case BOOTPS:
		case BOOTPC: parse_bootp(packet); break;

		default: printf("\t\tPort Destination : %x\n",source); break;
	}

	switch(dest){
		case FTPC: printf("\t\tFTP: Envoi de données\n"); break;
		case FTPS: printf("\t\tFTP: Envoi de requêtes\n"); break;
		case HTTP:
		case HTTPS: printf("\t\tHTTP\n"); break;
		case DNS: printf("\t\tDNS\n"); break;
		case SMTP:
		case SMTPS: parse_smtp(packet); break;
		case BOOTPS:
		case BOOTPC: parse_bootp(packet); break;

		default: printf("\t\tPort Destination : %x\n",dest); break;
	}

	print_ascii(packet);
}


void parse_tcp_complet(const u_char* packet){
	int i;

	struct tcphdr *tcp_header = (struct tcphdr *) packet;
	int size = sizeof(struct ip);
	int offset = (int)tcp_header->th_off;
	int source = tcp_header->th_sport;
	int dest = tcp_header->th_dport;

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

	for (i=0;i<offset;i++)
		packet++;

	printf("\t\tData Offset : %d\n",offset);
	switch(source){
		case FTPC: printf("\t\tFTP: Envoi de données\n"); break;
		case FTPS: printf("\t\tFTP: Envoi de requêtes\n"); break;
		case HTTP:
		case HTTPS: printf("\t\tHTTP\n"); break;
		case DNS: printf("\t\tDNS\n"); break;
		case SMTP:
		case SMTPS: parse_smtp(packet); break;
		case BOOTPS:
		case BOOTPC: parse_bootp(packet); break;

		default: printf("\t\tPort Source      : %x\n",source); break;
	}


	switch(dest){
		case FTPC: printf("\t\tFTP: Envoi de données\n"); break;
		case FTPS: printf("\t\tFTP: Envoi de requêtes\n"); break;
		case HTTP:
		case HTTPS: printf("\t\tHTTP\n"); break;
		case DNS: printf("\t\tDNS\n"); break;
		case SMTP:
		case SMTPS: parse_smtp(packet); break;
		case BOOTPS:
		case BOOTPC: parse_bootp(packet); break;

		default: printf("\t\tPort Destination : %x\n",dest); break;
	}

	print_ascii(packet);
}


void parse_ip_complet(const u_char* packet){
	int i;

	struct ip *ip_header = (struct ip *) packet;
	int size = sizeof(struct ip);

	printf("\tIP\n");
	
	printf("\t\tIPv%x\n",ip_header->ip_v);

	for (i=0;i<size;i++)
		packet++;

	char *ip = inet_ntoa(ip_header->ip_src);
	printf("\t\tAddresse Source      : %s\n",ip);

	ip = inet_ntoa(ip_header->ip_dst);
	printf("\t\tAddresse Destination : %s\n",ip);

	switch (ip_header->ip_p){
		case UDP:
			parse_udp_complet(packet);
			break;
		case TCP:
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