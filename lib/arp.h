#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

void arp(const u_char* packet);
void show_arp(const struct arphdr* arp);
void show_arp_mac(const u_char* packet, char* type);
void show_arp_ip(const u_char* packet, char* type);

void arp(const u_char* packet){
	const struct arphdr *arp;
	arp = (const struct arphdr*)(packet);

	styled_print("bold","ARP");

	if (arg_v == 1){
		
	}else if (arg_v == 2){
		show_arp(arp);
	}else{
		show_arp(arp);
		show_arp_mac(packet, "Sender");
		show_arp_ip(packet, "Sender");
		show_arp_mac(packet, "Target");
		show_arp_ip(packet, "Target");
	}
}

void show_arp(const struct arphdr* arp){
	printf("\t\tHardware type: %x ",ntohs(arp->ar_hrd));
	if (ntohs(arp->ar_hrd) == 1)
	{
		printf("(Ethernet)\n");
	}else{
		printf("(Experimental Ethernet)\n");
	}

	printf("\t\tProtocol address: %x ", ntohs(arp->ar_pro));
	if (ntohs(arp->ar_pro) == 0x0800)
	{
		printf("(IPv4)\n");
	}else{
		printf("Unknown\n");
	}

	printf("\t\tLength of hardware address: %x\n", arp->ar_hln);
	printf("\t\tLength of protocol address: %x\n", arp->ar_pln);
	printf("\t\tOperation code: %x ", ntohs(arp->ar_op));
	if (ntohs(arp->ar_op) == 1)
	{
		printf("(Request)\n");
	}else{
		printf("(Reply)\n");
	}
}

void show_arp_mac(const u_char* packet, char* type){
	const struct ether_arp *ether_arp;
	ether_arp = (const struct ether_arp*)(packet);

	printf("\t\t%s mac address: ",type);
	for (int i = 0; i < MAC_ADDR_SIZE; ++i)
	{
		if (type == "Sender"){
			printf("%x:", ether_arp->arp_sha[i]);
		}else{
			printf("%x:", ether_arp->arp_tha[i]);
		}
	}
	printf("\n");
	packet = packet + MAC_ADDR_SIZE;
}

void show_arp_ip(const u_char* packet, char* type){
	const struct ether_arp *ether_arp;
	ether_arp = (const struct ether_arp*)(packet);

	printf("\t\t%s IP address: ",type);
	for (int i = 0; i < IP_ADDR_SIZE; ++i)
	{
		if (type == "Sender"){
			printf("%d.", ether_arp->arp_spa[i]);
		}else{
			printf("%d.", ether_arp->arp_tpa[i]);
		}
	}
	printf("\n");
	packet = packet + IP_ADDR_SIZE;
}