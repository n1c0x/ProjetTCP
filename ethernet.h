#include <net/ethernet.h>

void ethernet(const struct pcap_pkthdr* pkthdr,const u_char* packet){
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

	switch(eth->ether_type) {

		case 0x0002:
			printf("Xerox PUP");
		break;
		case 0x0005:
			printf("Sprite");
		break;
		case 0x0008:
			printf("IPv4");
		break;
		case 0x0608:
			printf("ARP");
		break;
		case 0x3580:
			printf("Reverse ARP");
		break;
		case 0xB980:
			printf("AppleTalk");
		break;
		case 0xF380:
			printf("AppleTalk ARP");
		break;
		case 0x0081:
			printf("Tag VLAN");
		break;
		case 0x3781:
			printf("IPX");
		break;
		case 0xDD86:
			printf("IPv6");
		break;
		case 0x0090:
			printf("Tests");
		break;		
		default :
			printf("Protocole inconnu");
	}
	printf("\n");
}