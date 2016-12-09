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
	printf("\tSMTP ");

	u_char mail[] = MAIL;
	u_char rcpt[] = RCPT;
	u_char data[] = DATA;
	u_char ehlo[] = EHLO;
	u_char auth[] = AUTH;

	u_char message[4];

	int i = 0, j = 0;
	int mailcmp = 0, rcptcmp = 0, datacmp = 0;
	int ehlocmp = 0, authcmp = 0;

	while (i<length-4)
	{
		mailcmp = 0;
		rcptcmp = 0;
		datacmp = 0;
		for (j=0;j<4;j++)
			message[j] = packet[i+j];

		for (j=0;j<4;j++)
		{
			if (mail[j] == message[j])
				mailcmp++;
			else if (rcpt[j] == message[j])
				rcptcmp++;
			else if (data[j] == message[j])
				datacmp++;
		}
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

		else if (datacmp == 4)
			printf("DATA");

		i++;
	}
	printf("\n");
}


void parse_http_synthetique(const u_char* packet, int length)
{
	u_char get[] = GET;
	u_char head[] = HEAD;
	u_char post[] = POST;

	u_char message[4];

	int i = 0, j = 0;
	int getcmp = 0, headcmp = 0, postcmp = 0;

	while (i<length-4)
	{
		getcmp = 0;
		headcmp = 0;
		postcmp = 0;
		for (j=0;j<4;j++)
			message[j] = packet[i+j];

		for (j=0;j<3;j++)
		{
			if (get[j] == message[j])
				getcmp++;
			else if (head[j] == message[j])
				headcmp++;
			else if (post[j] == message[j])
				postcmp++;
		}
		if (getcmp == 3)
			printf("\tGET\n");

		else if (head[j] == message[j] && headcmp == 4)
			printf("\tHEAD\n");

		else if (post[j] == message[j] && postcmp == 4)
			printf("\tPOST\n");

		i++;
	}
}


void parse_bootp_synthetique(const u_char* packet){
	struct bootp *bootp_header = (struct bootp *) packet;
	int i = 0, j, dhcp = 0;
	u_char info[BP_VEND_LEN];
	int size = 0;

	switch (bootp_header->bp_op){
		case BOOTREPLY : printf("\tBOOTREPLY\n"); break;
		case BOOTREQUEST : printf("\tBOOTREQUEST\n"); break;
		default : break;
	}

	u_char *vendor = bootp_header->bp_vend;
	u_char magic_cookie[] = VM_RFC1048;
	
	for (i=0;i<4;i++){
		if (vendor[i] == magic_cookie[i])
			dhcp++;
	}
	if (dhcp == 4){
		printf("\tExtensions présentes\n");

		i=4;
		if (vendor[i] == 53){
			printf("\tDHCP ");
			i+=2;
			switch(vendor[i]){
				case 01 : printf("discover\n"); break;
				case 02 : printf("offer\n"); break;
				case 03 : printf("request\n"); break;
				case 05 : printf("ack\n"); break;
				case 07 : printf("release\n"); break;
				default : printf("\n"); break;
			}
		}
	}
}

void parse_port_synthetique(const u_char* packet, int length, short source, short dest){
	
	int not_parsed = 0;
	printf("\t%x -> %x\n",source, dest);

	switch(source){
		case FTPC:
			printf("\t\tFTP: Envoi de données\n");
			break;

		case FTPS: 
			printf("\t\tFTP: Envoi de requêtes\n");
			break;
		case HTTP:
		case HTTPS:
			printf("\tHTTP\n");
			break;

		case DNS:
			printf("\tDNS\n");
			break;

		case SMTP:
		case SMTPS:
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
		case HTTPS:
			printf("\tHTTP\n");
			break;

		case DNS:
			printf("\tDNS\n");
			break;

		case SMTP:
		case SMTPS:
			parse_smtp_synthetique(packet, length);
			break;

		case BOOTPS:
		case BOOTPC:
			parse_bootp_synthetique(packet);
			break;

		case TELNET:
			printf("\tTELNET\n");
			break; 
			default: printf("\tPort Applicatif non reconnu\n");
					 break;
		}
	}
}

void parse_udp_synthetique(const u_char* packet, int length){
	int i;

	struct udphdr *udp_header = (struct udphdr *) packet;
	int size = sizeof(struct udphdr);
	short source = ntohs(udp_header->uh_sport);
	short dest = ntohs(udp_header->uh_dport);
	int not_parsed = 0;

	printf("\tUDP\n");

	for (i=0;i<size;i++)
		packet++;

	parse_port_synthetique(packet, length-size, source, dest);
}


void parse_tcp_synthetique(const u_char* packet, int length){
	int i;

	struct tcphdr *tcp_header = (struct tcphdr *) packet;
	int size = (int)tcp_header->th_off;
	short source = ntohs(tcp_header->th_sport);
	short dest = ntohs(tcp_header->th_dport);
	int not_parsed = 0;

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
	printf("\n");
	
	parse_port_synthetique(packet, length-size, source, dest);
}


void parse_ip_synthetique(const u_char* packet, int length){
	int i;

	struct ip *ip_header = (struct ip *) packet;
	int size = sizeof(struct ip);
	
	printf("\tIPv%x\n",ip_header->ip_v);

	for (i=0;i<size;i++)
		packet++;

	char *src = strdup(inet_ntoa(ip_header->ip_src));
	char *dst = strdup(inet_ntoa(ip_header->ip_dst));
	printf("\t%s -> %s\n", src, dst);

	free(src);
	free(dst);

	switch (ip_header->ip_p){
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


void parse_eth_synthetique(const u_char* packet, int length){
	u_char *ptr;

    int i;

    /* ethernet header */
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

	/* on verifie si c'est protocole IP */
	if (ntohs(eptr->ether_type) == ETHERTYPE_IP){
		//printf("\t\tPacket IP\n");

		parse_ip_synthetique(packet, length - size);
	}

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
    /* on lit la taille du packet */
	fprintf(stdout,"\tlength: %d\n",pkthdr->len);
    parse_eth_synthetique(packet, pkthdr->len);

	count++;
	fflush(stdout);

}