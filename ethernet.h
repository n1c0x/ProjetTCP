#include <net/ethernet.h>
#include "ip4.h"
#include "ip6.h"

void ethernet(const struct pcap_pkthdr* pkthdr,const u_char* packet){
	/* Déclarations des fonctions utilisées */
	void ip4(const u_char* packet);
	void ip6(const u_char* packet);
	
	const struct ether_header *eth;
	
	printf("Heure de réception: %d\n", pkthdr->ts);

	int size_ethernet = sizeof(eth);
	eth = (struct ether_header*)(packet);
	
	printf("\tMAC destination: ");
	for (int i = 0; i < sizeof(eth->ether_dhost); ++i)
	{
		printf("%x:", eth->ether_dhost[i]);
	}
	printf("\n\tMAC source: ");
	for (int i = 0; i < sizeof(eth->ether_shost); ++i)
	{
		printf("%x:", eth->ether_shost[i]);
	}
	printf("\n");
	printf("\tProtocole: ");

	switch(ntohs(eth->ether_type)) {

		case 0x0200:
			printf("Xerox PUP");
		break;
		case 0x0500:
			printf("Sprite");
		break;
		case 0x0800:
			ip4(packet);
		break;
		case 0x0806:
			printf("ARP");
		break;
		case 0x8035:
			printf("Reverse ARP");
		break;
		case 0x80B9:
			printf("AppleTalk");
		break;
		case 0x80F3:
			printf("AppleTalk ARP");
		break;
		case 0x8100:
			printf("Tag VLAN");
		break;
		case 0x8137:
			printf("IPX");
		break;
		case 0x86DD:
			ip6(packet);
		break;
		case 0x9000:
			printf("Tests");
		break;		
		default :
			printf("Protocole inconnu");
	}
	packet = packet + size_ethernet;
	printf("\n-----------------------------------\n");
}