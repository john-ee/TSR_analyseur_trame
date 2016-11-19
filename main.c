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
	int verb;

	while((option=getopt(argc,argv,"i:o:v:")) != -1) {
		switch(option) {
			case 'i' : dev = optarg;
				printf("%s  ",dev);
				break;
			case 'o' : file = optarg;
				break;
			case 'v' : verb = atoi(optarg);
				break;
			default : break;
		}
	}

	
	printf("Device: %s\n", dev);

	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter expression */
	char filter_exp[] = "port 80";	/* The filter expression */
	bpf_u_int32 maskp;		/* The netmask of our sniffing device */
	bpf_u_int32 netp;		/* The IP of our sniffing device */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */
	struct in_addr addr;

	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
	 	exit(1);
	}
	if (pcap_lookupnet(dev, &netp, &maskp, errbuf) == -1) {
		fprintf(stderr, "Can't get netmask for device %s\n", dev);
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


	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev);
		exit(1);
	}


	if(verb==1)
		pcap_loop(handle,-1,packet_reader_concis,NULL);
	else if (verb==3)
		pcap_loop(handle,-1,packet_reader_complet,NULL);
	/* And close the session */
	pcap_close(handle);
	printf("\n");

	return(0);
}