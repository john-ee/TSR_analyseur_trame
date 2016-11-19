#include <ctype.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <netinet/if_ether.h>
#include <sys/ioctl.h>
 
 
#define MAXBYTES2CAPTURE 2048
 
void processPacket(u_char *arg, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
 
int i, j, k;
 
printf(", Len: %i (0x%x)\n",hdr->caplen,hdr->caplen);
 
for (i=0;i<=hdr->caplen/16;i++)
 {
 if(i*16 != hdr->caplen)
  printf("0x%.2x  ",i*16);
 
 k =(((i+1)*16)>hdr->caplen)?hdr->caplen-(i*16):16;
 
 for (j=0;j<k;j++)
  {
  printf("%.2x ",*packet);
  packet++;
  }
 
 if (k != 16)
  for (j=k;j<16;j++)
   printf("   " );
 
 printf("  " );
 packet-=k;
 
 for (j=0;j<k;j++)
  {
  if (*packet>20)
   printf("%c",*packet);
  else
   printf("." );
  packet++;
  }
 
 if (i*16 != hdr->caplen)
  printf("\n" );
 }
printf("\n" );
}
 
int main() {
 
 int i=0, count=0;
 pcap_t* descr=NULL;
 char errbuf[PCAP_ERRBUF_SIZE], *device=NULL;
 memset(errbuf, 0, PCAP_ERRBUF_SIZE);
 
 /* Get the name of the first device suitable for capture */
/* device=pcap_lookupdev(errbuf);
 printf("Opening device %s\n", device); */
 
 /* Open device in promiscuous mode */
 descr=pcap_open_live("ath0", MAXBYTES2CAPTURE, 1, 512, errbuf);
 
 int dl;
        dl = pcap_datalink(descr);
 
 int *dlt_buf;         /* array of supported data link types */
 int num;              /* number of supported link type */
 int ii;                /* counter for for loop */
 
 /*Enumerate the data link types, amd display readable-human names and descriptions for them*/
 num = pcap_list_datalinks(descr, &dlt_buf);
 for (ii=0; ii<num; ii++) {
     printf("%d - %s - %s\n\n",dlt_buf[ii],
              pcap_datalink_val_to_name(dlt_buf[ii]),
              pcap_datalink_val_to_description(dlt_buf[ii]));
 }
 
 
/*    if (dl == DLT_IEEE802_11) {
  printf("802.11 Frame\n" );
    } else if (dl == DLT_RAW) {
  printf("Raw IP packets\n" );
 } else if (dl == DLT_PRISM_HEADER) {
  printf("For 802.11 cards using the Prism II chips, with a link-layer header including Prism monitor mode information plus an 802.11 header\n" );
 }  
    else if (dl != DLT_PRISM_HEADER) {
     pcap_close(descr);
     fprintf(stderr, "%s does not appear to be an 802.11 capture file\n" );
     exit(1);
 } */
 
 /* Loop forever and call processPacket for every packet received*/
 pcap_loop(descr, 10, processPacket, (u_char *) &count);
 
    pcap_close(descr);  
 
 return EXIT_SUCCESS; 