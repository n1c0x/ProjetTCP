#include <netinet/ip.h>
#include <arpa/inet.h>
#include "udp.h"
#include "tcp.h"

void unknown_protocol();

void ip4(const u_char* packet){
	/* Déclarations des fonctions utilisées */
	void udp(const u_char* packet);
	void tcp(const u_char* packet);


	printf("IPv4\n");
	const struct iphdr *ip;
	struct in_addr addr;
	
	int size_ip = sizeof(ip);

	ip = (struct iphdr*)(packet);
/*
	printf("version: %x\n", ip->version);
	printf("header length: %x\n", ip->ihl);
	printf("type of service: %x\n", ip->tos);
	printf("total length: %x\n", ntohs(ip->tot_len));
	printf("identification: %x\n", ntohs(ip->id));
	printf("offset: %x\n", ip->frag_off);
	printf("time to live: %x\n", ip->ttl);
	printf("protocol: %x\n", ip->protocol);
	printf("checksum: %x\n", ntohs(ip->check));
	printf("IP src: %x\n", ntohl(ip->saddr));
	printf("IP dst: %x\n", ntohl(ip->daddr));
*/

	/* On multiplie par 4 parce que la taille du champ IHL est de 4 bits */
	size_ip = ip->ihl * 4 ;

	addr.s_addr = ip->saddr;
	printf("\t\tAdresse IP source: %s\n",inet_ntoa(addr));
	addr.s_addr = ip->daddr;
	printf("\t\tAdresse IP destination: %s\n",inet_ntoa(addr));

	packet = packet + size_ip;
	printf("\t\tProtocole: ");
	switch(ip->protocol) {

		case 0x01:
			printf("\t\t");
			printf("ICMP");
		break;
		case 0x06:
			//printf("TCP");
			tcp(packet);
		break;
		case 0x11:
			//printf("UDP");
			udp(packet);
		break;
		case 0x3A:
			printf("\t\t");
			printf("IPv6-ICMP");
		break;
		case 0x73:
			printf("\t\t");
			printf("L2TP");
		break;
		case 0x84:
			printf("\t\t");
			printf("SCTP");
		break;
		default :
			printf("\t\t");
			unknown_protocol();
	}
	printf("\n");
}