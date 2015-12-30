#include <net/ethernet.h>
#include <time.h>
#include "ip4.h"
#include "ip6.h"
#include "var_global.h"

void unknown_protocol();
int arg_v;

void ethernet(const struct pcap_pkthdr* pkthdr,const u_char* packet){
	/* Déclarations des fonctions utilisées */
	void ip4(const u_char* packet);
	void ip6(const u_char* packet);

	const struct ether_header *eth;
	
	//printf("Send/Recieve date: %d\n", pkthdr->ts);
	printf("%d bytes (%d bits) recieved on %s",pkthdr->caplen, pkthdr->caplen * 8, ctime((const time_t*)&pkthdr->ts));

	int size_ethernet;
	eth = (struct ether_header*)(packet);

	size_ethernet = sizeof(eth->ether_dhost) + sizeof(eth->ether_shost) + sizeof(eth->ether_type);

	if (arg_v == 2){
		printf("\n");
		printf("\tNetwork protocol: ");
		packet = packet + size_ethernet;
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
				unknown_protocol();
		}
	}else if (arg_v == 3){
		printf("\tDestination MAC adress: ");
		for (int i = 0; i < sizeof(eth->ether_dhost); ++i){
			printf("%x:", eth->ether_dhost[i]);
		}
		printf("\n\tSource MAC adress: ");
		for (int i = 0; i < sizeof(eth->ether_shost); ++i){
			printf("%x:", eth->ether_shost[i]);
		}
		printf("\n");
		printf("\tNetwork protocol: ");
		packet = packet + size_ethernet;
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
				unknown_protocol();
		}
	}
	printf("\n-----------------------------------\n");
}