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

void print_ascii(const u_char* packet, int length)
{
	//printf("\tASCII");
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

void parse_http(const u_char* packet){
	;
}

void parse_bootp(const u_char* packet){
	printf("\tBOOTP\n");
	struct bootp *bootp_header = (struct bootp *) packet;
	int i = 0, j, dhcp = 0;
	u_char info[BP_VEND_LEN];
	int size = 0;

	switch (bootp_header->bp_op){
		case BOOTREPLY : printf("\t\tBOOTREPLY\n"); break;
		case BOOTREQUEST : printf("\t\tBOOTREQUEST\n"); break;
		default : break;
	}

	u_char *vendor = bootp_header->bp_vend;
	u_char magic_cookie[] = VM_RFC1048;
	
	for (i=0;i<4;i++){
		if (vendor[i] == magic_cookie[i])
			dhcp++;
	}
	if (dhcp == 4){
		printf("\t\tExtensions présentes\n");

		i=4;
		if (vendor[i] == 53){
			printf("\t\tDHCP ");
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

		while (vendor[i] != TAG_PAD){
			size = vendor[i+1];

			if (size)
			{
				for (j=0;j<size;j++)
					info[j] = vendor[i+2+j];
				info[j] = '\0';

				switch(vendor[i]){
					case TAG_SUBNET_MASK :
						printf("\t\tMasque du sous-réseau");
						for (j=0;j<size;j++){
							if (j%21==0)
								printf("\n\t\t");
							printf("%x ", vendor[i+2+j]);
						}
						printf("\n");
						break;
					case TAG_TIME_OFFSET :
						printf("\t\tTime Offset");
						for (j=0;j<size;j++){
							if (j%21==0)
								printf("\n\t\t");
							printf("%x ", vendor[i+2+j]);
						}
						printf("\n");
						break;
					case TAG_GATEWAY :
						printf("\t\tGateway");
						for (j=0;j<size;j++){
							if (j%21==0)
								printf("\n\t\t");
							printf("%x ", vendor[i+2+j]);
						}
						printf("\n");
						break;
					case TAG_DOMAIN_SERVER :
						printf("\t\tServeur DNS");
						for (j=0;j<size;j++){
							if (j%21==0)
								printf("\n\t\t");
							printf("%x ", vendor[i+2+j]);
						}
						printf("\n");
						break;
					case TAG_HOSTNAME :
						printf("\t\tNom de l'hôte");
						for (j=0;j<size;j++){
							if (j%21==0)
								printf("\n\t\t");
							printf("%x ", vendor[i+2+j]);
						}
						printf("\n");
						break;
					case TAG_DOMAINNAME	:
						printf("\t\tNom de domaine");
						for (j=0;j<size;j++){
							if (j%21==0)
								printf("\n\t\t");
							printf("%x ", vendor[i+2+j]);
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

}

void parse_port_complet(const u_char* packet, int length, short source, short dest){

	printf("\t\tPort Source : %x\n",source);
	printf("\t\tPort Source : %x\n",dest);
	int not_parsed = 0;
	switch(source){
		case FTPC:  printf("\t\tFTP: Envoi de données\n");
					print_ascii(packet, length);
					break;

		case FTPS:  printf("\t\tFTP: Envoi de requêtes\n");
					print_ascii(packet, length);
					break;
		case HTTP:
		case HTTPS: printf("\tHTTP\n");
					print_ascii(packet, length);
					break;

		case DNS: printf("\tDNS\n");
				  print_ascii(packet, length);
				  break;

		case SMTP:
		case SMTPS: printf("\tSMTP\n");
					print_ascii(packet, length);
					break;

		case BOOTPS:
		case BOOTPC: parse_bootp(packet); break;

		default: not_parsed++; break;

		}

	if (not_parsed)
	{
		switch(dest)
		{
			case FTPC:  printf("\t\tFTP: Envoi de données\n");
						print_ascii(packet, length);
						break;

			case FTPS:  printf("\t\tFTP: Envoi de requêtes\n");
						print_ascii(packet, length);
						break;

			case HTTP:  
			case HTTPS: printf("\tHTTP\n");
						print_ascii(packet, length);
						break;

			case DNS: printf("\tDNS\n");
				  	  print_ascii(packet, length);
					  break;

			case SMTP:
			case SMTPS:	printf("\tSMTP\n");
						print_ascii(packet, length);
						break;

			case BOOTPS:
			case BOOTPC: parse_bootp(packet);
						 break;

			default: printf("\t\tPort Applicatif non reconnu\n");
					 print_ascii(packet, length);
					 break;
		}
	}
}

void parse_udp_complet(const u_char* packet, int length){
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


void parse_tcp_complet(const u_char* packet, int length){
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


void parse_ip_complet(const u_char* packet, int length){
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


void parse_eth(const u_char* packet, int length){
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
    /* on lit la taille du packet */
	fprintf(stdout,"\tlength: %d\n",pkthdr->len);
    parse_eth(packet, pkthdr->len);

	count++;
	fflush(stdout);

}