#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <getopt.h>
#include "complet.h"
#include "concis.h"


int main(int argc, char *argv[])
{
	int option = 0;
	char *dev = NULL, *file = NULL;
	char *filter_exp = NULL;
	int verb = 0;
	char pause;

	/*if (argc == 1){
		printf("Pour éxécuter le programme :\n");
		printf("\t./main -i <interface> OU ./main -o <fichier>\n");
		printf("Si les deux arguments sont fournis, le fichier sera traité avant l'écoute sur l'interface\n");
		printf("Trois niveaux de verbosité disponible\n\t-v <1,2,3>\n");
		printf("\t1 : Concis\n\t2 : Synthétique\n\t3 : Complet\n");
		printf("Filtrage disponible selon les ports  \n\t-f 'port <entier>'\n");
	}*/

	while((option=getopt(argc,argv,"i:o:v:f:")) != -1) {
		switch(option) {
			case 'i' : dev = optarg;
				printf("%s  ",dev);
				break;
			case 'o' : file = optarg;
				break;
			case 'v' : verb = atoi(optarg);
				break;
			case 'f' : filter_exp = optarg;
				break;
			default : break;
		}
	}


	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	bpf_u_int32 maskp;		/* The netmask of our sniffing device */
	bpf_u_int32 netp;		/* The IP of our sniffing device */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */
	struct in_addr addr;
	struct bpf_program fp;		/* The compiled filter expression */

	if (file != NULL)
	{
		handle = pcap_open_offline(file, errbuf);
		printf("Appuyer sur Entrée pour lire trame par trame\n");
		printf("Appuyer sur Espace 2 fois puis Entrée pour annalyser toutes les trames\n\n");

		while ((packet=pcap_next(handle, &header)) != NULL)
		{
			switch (verb){
				case 3: packet_reader_complet(NULL, &header, packet); break;
				default : packet_reader_concis(NULL, &header, packet); break;
			}

			if (pause != ' '){
				while ((pause=getchar()) != '\n' && (pause=getchar()) != ' '){
					;
				}
			}
		}
	}

	if (dev != NULL)
	{
		printf("Interface: %s\n", dev);
		handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "N'a pas pu ouvrir %s: %s\n", dev, errbuf);
		 	exit(1);
		}
		if (pcap_lookupnet(dev, &netp, &maskp, errbuf) == -1) {
			fprintf(stderr, "N'a pas pu trouver de netmask pour %s\n", dev);
			netp = 0;
			maskp = 0;
		}
		/* get the network address in a human readable form */
		addr.s_addr = netp;
		char *net = inet_ntoa(addr);
		if(net == NULL)
		{
			perror("inet_ntoa");
			exit(1);
		}
		printf("NET: %s\n",net);
		/* get the mask */
		addr.s_addr = maskp;
		char *mask = inet_ntoa(addr);
		if(net == NULL)
		{
			perror("inet_ntoa");
			exit(1);
		}
		printf("MASK: %s\n",mask);

		if (filter_exp != NULL){
			if (pcap_compile(handle, &fp, filter_exp, 0, netp) == -1) {
				fprintf(stderr, "N'a pas pu filtrer %s: %s\nMettre l'argument -f en ''\n", filter_exp, pcap_geterr(handle));
				return(2);
			}
			if (pcap_setfilter(handle, &fp) == -1) {
				fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
				return(2);
			}
		}

		if (pcap_datalink(handle) != DLT_EN10MB) {
			fprintf(stderr, "L'interface %s n'est pas compatible avec Ethernet\n", dev);
			exit(1);
		}

		switch (verb){
				case 3 : pcap_loop(handle,-1,packet_reader_complet,NULL); break;
				default: pcap_loop(handle,-1,packet_reader_concis,NULL); break;
		}
		/* And close the session */
		pcap_close(handle);
		printf("\n");
	}

	return(0);
}