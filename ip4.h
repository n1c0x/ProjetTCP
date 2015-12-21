#include <netinet/ip.h>

void ip4(const u_char* packet){
	printf("IPv4\n");
	const struct ip *ip;
	
	int size_ip = sizeof(ip);

	ip = (struct ip*)(packet);
	printf("version: %d\n", ip->ip_v);
	printf("header length: %d\n", ip->ip_hl);
	printf("type of service: %d\n", ip->ip_tos);
	printf("total length: %d\n", ip->ip_len);
	printf("identification: %d\n", ip->ip_id);
	printf("offset: %d\n", ip->ip_off);
	printf("time to live: %d\n", ip->ip_ttl);
	printf("protocol: %d\n", ip->ip_p);
	printf("checksum: %d\n", ip->ip_sum);

	//printf("protocol2: %d\n", ip->ip_ttl);
	/*
	printf("\tAdresse IP destination: ");
	for (int i = 0; i < sizeof(in_addr->ip_src); ++i)
	{
		printf("%x:", ip->ether_dhost[i]);
	}
	printf("\n\tAdresse IP source: ");
	for (int i = 0; i < sizeof(ip->ether_shost); ++i)
	{
		printf("%x:", ip->ether_shost[i]);
	}
	printf("\n");
	printf("\tProtocole: ");


	switch(ip->ip_p) {

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
	}*/
	printf("\n");
}