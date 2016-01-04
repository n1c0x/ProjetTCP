#include <net/ethernet.h>
#include <time.h>
#include "ip4.h"
#include "ip6.h"

void ethernet(const struct pcap_pkthdr* pkthdr,const u_char* packet);
void show_eth_protocol(const struct ether_header *eth, const u_char* packet);
void show_eth_mac(const struct ether_header *eth);

void ethernet(const struct pcap_pkthdr* pkthdr,const u_char* packet){

	const struct ether_header *eth;
	int size_ethernet;
	eth = (const struct ether_header*)(packet);
	size_ethernet = sizeof(eth->ether_dhost) + sizeof(eth->ether_shost) + sizeof(eth->ether_type);
	packet = packet + size_ethernet;

	printf("%d bytes (%d bits) recieved on %s",pkthdr->caplen, pkthdr->caplen * 8, ctime((const time_t*)&pkthdr->ts));
	
	if (arg_v == 1){
		show_eth_protocol(eth, packet);
	}else{
		printf("\n");
		show_eth_mac(eth);
		line("-",70);
		show_eth_protocol(eth, packet);
	}
	line("=",70);
}

void show_eth_protocol(const struct ether_header *eth, const u_char* packet){
	if (arg_v != 1){
		printf("\tNetwork protocol: ");
	}
	switch(ntohs(eth->ether_type)) {

		case 0x0200:
			printf("Xerox PUP\n");
		break;
		case 0x0500:
			printf("Sprite\n");
		break;
		case 0x0800:
			ip4(packet);
		break;
		case 0x0806:
			printf("ARP\n");
		break;
		case 0x8035:
			printf("Reverse ARP\n");
		break;
		case 0x80B9:
			printf("AppleTalk\n");
		break;
		case 0x80F3:
			printf("AppleTalk ARP\n");
		break;
		case 0x8100:
			printf("Tag VLAN\n");
		break;
		case 0x8137:
			printf("IPX\n");
		break;
		case 0x86DD:
			ip6();
		break;
		case 0x9000:
			printf("Tests\n");
		break;		
		default :
			unknown_protocol();
	}
}

void show_eth_mac(const struct ether_header *eth){
	printf("\tDestination MAC adress: ");
	for (int i = 0; i < sizeof(eth->ether_dhost); ++i){
		printf("%x:", eth->ether_dhost[i]);
	}
	printf("\n\tSource MAC adress: ");
	for (int i = 0; i < sizeof(eth->ether_shost); ++i){
		printf("%x:", eth->ether_shost[i]);
	}
	printf("\n");
}