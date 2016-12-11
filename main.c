/*
 * auteur : John-Nathan HILL
 * brief : Ce module permet de lancer le programme 'analyseur'
 */

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
#include "synthetique.h"
#include "main.h"


/*
 * brief : Cette fonction est appelé lorsque le 
 * programme n'est pas lancé avec les bons arguments
 */
void usage()
{
	printf("\nPour éxécuter le programme :\n");
	printf("\t./main -i <interface> OU ./main -o <fichier>\n");
	printf("Si les deux arguments sont fournis, le fichier sera traité avant l'écoute sur l'interface\n");
	printf("Trois niveaux de verbosité disponible\n\t-v <1,2,3>\n");
	printf("\t1 : Concis\n\t2 : Synthétique\n\t3 : Complet\n");
	printf("Si l'argument est différent de <1,2,3> ou est non fournie, -v 1 sera utilisé\n");
	printf("Filtrage disponible selon les ports applicatifs \n\t-f 'port <entier>'\n");
}

/*
 * brief : Fonction main qui éxécute l'analyse des trames en internet
 * ou appelle en boucle la fonction qui pars eles trames d'un fichier
 */
int main(int argc, char *argv[])
{
	// Variables pour gérer les arguments en entrée
	int option = 0;
	char *dev = NULL, *file = NULL;
	char *filter_exp = NULL;
	int verb = 0;
	char pause;

	while((option=getopt(argc,argv,"i:o:v:f:")) != -1)
	{
		switch(option)
		{
			case 'i' :
			// L'interface que l'on souhaite écouter
				dev = optarg;
				printf("%s  ",dev);
				break;
			case 'o' :
			// Le fichier à décoder
				file = optarg;
				break;
			case 'v' :
			// Niveau de verbosité souhaité
			// Par défaut ou si entier != <2,3> verbosité 1 sera utilisé
				verb = atoi(optarg);
				break;
			case 'f' :
			// Filtrage selon le port pour l'écouté par interface
			// Par défaut à null
				filter_exp = optarg;
				break;
			default :
				break;
		}
	}

	if (argc == 1 || (dev == NULL && file == NULL))
		usage();

	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];	// Message d'erreur
	bpf_u_int32 maskp;		// Masque de sous-réseau de l'interface
	bpf_u_int32 netp;		// L'adresse IP de l'interface 
	struct pcap_pkthdr header;	// L'entête fournit par pcap
	const u_char *packet;		// La trame à décoder
	struct in_addr addr;	// Cette variable permettra d'afficher des addresses IP
	struct bpf_program fp;		// L'expression compilé du filtre

	if (file != NULL)
	{
		// Dans le case où un fichier en fourni, on le traite
		handle = pcap_open_offline(file, errbuf);

		// On relance la boucle à tant qu'on n'a pas parcouru la boucle en entière
		while ((packet=pcap_next(handle, &header)) != NULL)
		{
			// Selon la verbosité, on décode plus ou moins en détail
			switch (verb){
				case 2: packet_reader_synthetique(NULL, &header, packet); break;
				case 3: packet_reader_complet(NULL, &header, packet); break;
				default : packet_reader_concis(NULL, &header, packet); break;
			}

			// Tant que l'utilisateur n'a pas pressé Espace Espace Entrée,
			// on affiche la trame suivant
			if (pause != ' '){
				printf("\nAppuyer sur Entrée pour lire trame par trame\n");
				printf("Appuyer sur Espace 2 fois puis Entrée pour annalyser toutes les trames\n");

				//Permet l'attente d'un caractère en entrée
				while ((pause=getchar()) != '\n' && (pause=getchar()) != ' ')
				{
					;
				}
			}
		}
	}

	if (dev != NULL)
	{
		// On vérifie que l'on peut écouter à traver l'interface fournie
		printf("Interface: %s\n", dev);
		handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "N'a pas pu ouvrir %s: %s\n", dev, errbuf);
		 	exit(1);
		}
		// On récupère le masque de sous-réseau
		if (pcap_lookupnet(dev, &netp, &maskp, errbuf) == -1) {
			fprintf(stderr, "N'a pas pu trouver de netmask pour %s\n", dev);
			netp = 0;
			maskp = 0;
		}
		// On rend l'adresse IP lisible
		addr.s_addr = netp;
		char *net = inet_ntoa(addr);
		if(net == NULL)
		{
			fprintf(stderr,"inet_ntoa");
			exit(1);
		}
		printf("NET: %s\n",net);
		// On rend le masque de sous-réseau lisible
		addr.s_addr = maskp;
		char *mask = inet_ntoa(addr);
		if(net == NULL)
		{
			fprintf(stderr,"inet_ntoa");
			exit(1);
		}
		printf("MASK: %s\n",mask);

		// On met en place le filtre
		if (filter_exp != NULL)
		{
			if (pcap_compile(handle, &fp, filter_exp, 0, netp) == -1) {
				fprintf(stderr, "N'a pas pu compiler l'argument %s: %s\nMettre l'argument -f entre ''\n", filter_exp, pcap_geterr(handle));
				return(2);
			}
			if (pcap_setfilter(handle, &fp) == -1)
			{
				fprintf(stderr, "N'a pas pu mettre en place %s: %s\n", filter_exp, pcap_geterr(handle));
				return(2);
			}
		}

		// On vérifie la compatibilité avec ethernet
		if (pcap_datalink(handle) != DLT_EN10MB)
		{
			fprintf(stderr, "L'interface %s n'est pas compatible avec Ethernet\n", dev);
			exit(1);
		}

		// Selon la verbosité fournie, on lance le décodage
		switch (verb)
		{
			case 2 : pcap_loop(handle,-1,packet_reader_synthetique,NULL); break;
			case 3 : pcap_loop(handle,-1,packet_reader_complet,NULL); break;
			default: pcap_loop(handle,-1,packet_reader_concis,NULL); break;
		}
		// On ferme la session
		pcap_close(handle);
		printf("\n");
	}

	return(0);
}