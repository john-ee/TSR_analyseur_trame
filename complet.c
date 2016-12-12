/*
 * auteur : John-Nathan HILL
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
#include "complet.h"
#include "bootp.h"
#include "telnet.h"
#include "port.h"


void print_ascii(const u_char* packet, int length)
{
	int i = 0, dhcp = 0;
	while (i<length){
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


void parse_smtp_complet(const u_char* packet, int length)
{
	const u_char mail[] = MAIL;
	const u_char rcpt[] = RCPT;
	const u_char data[] = DATA;
	const u_char ehlo[] = EHLO;
	const u_char auth[] = AUTH;
	const u_char starttls[] = STARTTLS;

	int i = 0, j = 0;
	int mailcmp = 0, rcptcmp = 0, datacmp = 0;
	int ehlocmp = 0, authcmp = 0, tlscmp = 0;

	while (i<length-4)
	{
		mailcmp = 0;
		rcptcmp = 0;
		datacmp = 0;
		ehlocmp = 0;
		authcmp = 0;
		tlscmp = 0;

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

		if (mailcmp == 4)
			printf("\t\tEmetteur ");

		if (rcptcmp == 4)
			printf("\t\tRécepteur ");

		if (datacmp == 4)
			printf("\t\tContenu de l'e-mail ");

		if (ehlocmp == 4)
			printf("\t\tRequête EHLO ");

		if (authcmp == 4)
			printf("\t\tAuthentification ");

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
	print_ascii(packet, length);
}


void parse_http_complet(const u_char* packet, int length)
{
	const u_char get[] = GET;
	const u_char put[] = PUT;
	const u_char head[] = HEAD;
	const u_char post[] = POST;
	
	int i = 0, j = 0;
	int getcmp = 0, putcmp = 0, headcmp = 0, postcmp = 0;

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
		if (getcmp == 3)
			printf("\t\tGET");

		if (putcmp == 3)
			printf("\t\tPUT");

		if (head[j] == packet[i+j] && headcmp == 4)
			printf("\t\tHEAD");

		if (post[j] == packet[i+j] && postcmp == 4)
			printf("\t\tPOST");

		i++;
	}

	print_ascii(packet, length);
}


void telnet_option(const u_char option)
{
	switch(option)
	{

		case TOECHO : printf("echo"); break;

		case TONOGA : printf("suppresion du go-ahead"); break;

		case TOTERMTYPE : printf("type de terminal"); break;

		case TOLINEMODE : printf("line mode "); break;

		case TOWINSIZE : printf("taille de fenetre"); break;

		case TOTERMSPEED : printf("vitesse du terminal"); break;

		case TOVARIABLES : printf("variables de l'envrionnement"); break;

		case TONEWVARIABLES : printf("variables de l'envrionnement corrigé"); break;		

		default : printf("option non reconnu"); break;
	}
	printf("\n");
}


void parse_telnet_complet(const u_char* packet, int length)
{
	int i = 0, parsed = 1;
	printf("\tTELNET\n");
	while (i<length)
	{

		switch(packet[i])
		{
			case TCSB :
				printf("\t\tdébut de sous-négocitation\n");
				break;

			case TCSE :
				printf("\t\tfin de sous-négocitation\n");
				break;

			case TCWILL :
				printf("\t\twill ");
				i++;
				telnet_option(packet[i]);
				break;

			case TCWONT :
				printf("\t\twon't ");
				i++;
				telnet_option(packet[i]);
				break;

			case TCDO :
				printf("\t\tdo ");
				i++;
				telnet_option(packet[i]);
				break;


			case TCDONT :
				printf("\t\tdon't ");
				i++;
				telnet_option(packet[i]);
				break;

			default :
				break;
		}
		i++;
	}
	printf("\n");
}


void parse_bootp(const u_char* packet)
{
	printf("\tBOOTP\n");
	struct bootp *bootp_header = (struct bootp *) packet;
	int i = 0, j, dhcp = 0;
	u_char info[BP_VEND_LEN];
	int size = 0;

	switch (bootp_header->bp_op)
	{
		case BOOTREPLY : printf("\t\tBOOTREPLY\n"); break;
		case BOOTREQUEST : printf("\t\tBOOTREQUEST\n"); break;
		default : break;
	}

	u_char *vendor = bootp_header->bp_vend;
	u_char magic_cookie[] = VM_RFC1048;
	
	for (i=0;i<4;i++)
	{
		if (vendor[i] == magic_cookie[i])
			dhcp++;
	}
	if (dhcp == 4)
	{

		i=4;
		if (vendor[i] == 53)
		{
			printf("\t\tDHCP ");
			i+=2;
			switch(vendor[i])
			{
				case 01 : printf("discover\n"); break;
				case 02 : printf("offer\n"); break;
				case 03 : printf("request\n"); break;
				case 05 : printf("ack\n"); break;
				case 07 : printf("release\n"); break;
				default : printf("\n"); break;
			}
			i++;

			while (vendor[i] != TAG_PAD)
			{
				size = vendor[i+1];

				if (size)
				{
					for (j=0;j<size;j++)
						info[j] = vendor[i+2+j];
					info[j] = '\0';

					switch(vendor[i])
					{
						case TAG_SUBNET_MASK :
							printf("\t\tMasque du sous-réseau");
							for (j=0;j<size;j++)
							{
								if (j%21==0)
									printf("\n\t\t");
								printf("%x ", vendor[i+2+j]);
							}
							printf("\n");
							break;

						case TAG_TIME_OFFSET :
							printf("\t\tTime Offset");
							for (j=0;j<size;j++)
							{
								if (j%21==0)
									printf("\n\t\t");
								printf("%x ", vendor[i+2+j]);
							}
							printf("\n");
							break;

						case TAG_GATEWAY :
							printf("\t\tGateway");
							for (j=0;j<size;j++)
							{
								if (j%21==0)
									printf("\n\t\t");
								printf("%x ", vendor[i+2+j]);
							}
							printf("\n");
							break;

						case TAG_DOMAIN_SERVER :
							printf("\t\tServeur DNS");
							for (j=0;j<size;j++)
							{
								if (j%21==0)
									printf("\n\t\t");
								printf("%x ", vendor[i+2+j]);
							}
							printf("\n");
							break;

						case TAG_HOSTNAME :
							printf("\t\tNom de l'hôte");
							for (j=0;j<size;j++)
							{
								if (j%21==0)
									printf("\n\t\t");
								if (isprint(vendor[i+2+j]))
									printf("%c ", vendor[i+2+j]);
								else
									printf(".");
							}
							printf("\n");
							break;

						case TAG_DOMAINNAME	:
							printf("\t\tNom de domaine");
							for (j=0;j<size;j++)
							{

								if (j%21==0)
									printf("\n\t\t");
								if (isprint(vendor[i+2+j]))
									printf("%c ", vendor[i+2+j]);
								else
									printf(".");
							}
							printf("\n");
							break;


						default : break;
					}
					i+=size;
				}
				else
					i++;
			}
		}
		else
			printf("\t\tExtensions présentes\n");
	}

}


void parse_port_complet(const u_char* packet, int length, short source, short dest)
{
	printf("\t\tPort Source : %x\n",source);
	printf("\t\tPort Source : %x\n",dest);
	int not_parsed = 0;

	switch(source)
	{
		case FTPC:
			printf("\t\tFTP: Envoi de données\n");
			print_ascii(packet, length);
			break;

		case FTPS:
			printf("\t\tFTP: Envoi de requêtes\n");
			print_ascii(packet, length);
			break;

		case HTTP:
			printf("\tHTTP\n");
			parse_http_complet(packet,length);
			break;

		case HTTPS:
			printf("\tHTTP sécurisé\n");
			parse_http_complet(packet,length);
			break;

		case DNS:
			printf("\tDNS\n");
			print_ascii(packet, length);
			break;

		case SMTP:
			printf("\tSMTP\n");
			parse_smtp_complet( packet, length);
			break;

		case SMTPS:
			printf("\tSMTP sécurisé\n");
			parse_smtp_complet( packet, length);
			break;

		case BOOTPS:
		case BOOTPC:
			parse_bootp(packet);
			break;

		case TELNET:
			parse_telnet_complet(packet, length);
			break; 

		default: not_parsed++; break;
	}

	if (not_parsed)
	{
		switch(dest)
		{
			case FTPC:
				printf("\t\tFTP: Envoi de données\n");
				print_ascii(packet, length);
				break;

			case FTPS:
				printf("\t\tFTP: Envoi de requêtes\n");
				print_ascii(packet, length);
				break;

			case HTTP:
				printf("\tHTTP\n");
				parse_http_complet(packet,length);
				break;

			case HTTPS:
				printf("\tHTTP sécurisé\n");
				parse_http_complet(packet,length);
				break;

			case DNS:
				printf("\tDNS\n");
				print_ascii(packet, length);
				break;

			case SMTP:
				printf("\tSMTP\n");
				parse_smtp_complet( packet, length);
				break;

			case SMTPS:
				printf("\tSMTP sécurisé\n");
				parse_smtp_complet( packet, length);
				break;

			case BOOTPS:
			case BOOTPC:
				parse_bootp(packet);
				break;

			case TELNET:
				parse_telnet_complet(packet, length);
				break; 

			default:
				break;
		}
	}
}


void parse_udp_complet(const u_char* packet, int length)
{
	int i;

	struct udphdr *udp_header = (struct udphdr *) packet;
	int size = sizeof(struct udphdr);
	short source = ntohs(udp_header->uh_sport);
	short dest = ntohs(udp_header->uh_dport);
	int not_parsed = 0;

	printf("\tUDP\n");

	for (i=0;i<size;i++)
		packet++;

	parse_port_complet(packet, length-size, source, dest);
}


void parse_tcp_complet(const u_char* packet, int length)
{
	int i;

	struct tcphdr *tcp_header = (struct tcphdr *) packet;
	int size = (int)tcp_header->th_off;
	short source = ntohs(tcp_header->th_sport);
	short dest = ntohs(tcp_header->th_dport);
	int not_parsed = 0;

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

	for (i=0;i<size;i++)
		packet++;

	printf("\t\tData Offset : %d\n",size);
	
	parse_port_complet(packet, length-size, source, dest);
}


void parse_ip_complet(const u_char* packet, int length)
{
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
			parse_udp_complet(packet, length - size);
			break;
		case TCP:
			parse_tcp_complet(packet, length - size);
			break;
		default:
			printf("\t\tNi TCP ni UDP\n");
			break;
	}

}


void parse_eth(const u_char* packet, int length)
{
    int i;

    u_char *ptr;

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

	if (ntohs(eptr->ether_type) == ETHERTYPE_IP)
	{

		parse_ip_complet(packet, length - size);
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
	printf("\tlength: %d\n",pkthdr->len);
    parse_eth(packet, pkthdr->len);

	count++;
	fflush(stdout);

}