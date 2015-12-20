// structures d'entêtes
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

void got_packet(u_char *verb,const struct pcap_pkthdr* pkthdr,const u_char* packet){
	const struct ether_header *eth;
	printf("Réception: %d\n", pkthdr->ts);
	int size_ethernet = sizeof(eth);
	eth = (struct ether_header*)(packet);
	
	printf("\tAdresse MAC destination: ");
	for (int i = 0; i < sizeof(eth->ether_dhost); ++i)
	{
		printf("%x:", eth->ether_dhost[i]);
	}
	printf("\n\tAdresse MAC source: ");
	for (int i = 0; i < sizeof(eth->ether_shost); ++i)
	{
		printf("%x:", eth->ether_shost[i]);
	}
	printf("%d\n", sizeof(eth->ether_type));

}