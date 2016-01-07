#include <netinet/ip.h>
#include <arpa/inet.h>
#include "udp.h"
#include "tcp.h"

void ip4(const u_char* packet);
void show_ip(const struct iphdr *ip,struct in_addr addr);
void show_ip_protocol(const u_char* packet, const struct iphdr *ip);
void show_ip_else(const struct iphdr *ip);

void ip4(const u_char* packet){

	const struct iphdr *ip;
	struct in_addr addr;
	
	int size_ip = sizeof(ip);

	ip = (const struct iphdr*)(packet);

	/* On multiplie par 4 parce que la taille du champ IHL est de 4 bits */
	size_ip = ip->ihl * 4 ;
	packet = packet + size_ip;

	if (arg_v == 1){
		show_ip(ip, addr);
		show_ip_protocol(packet, ip);
	}else if (arg_v == 2){
		show_ip(ip, addr);
		line("-",70,1);
		show_ip_protocol(packet, ip);
	}else{
		show_ip(ip, addr);
		show_ip_else(ip);
		line("-",70,1);
		show_ip_protocol(packet, ip);
	}
	printf("\n");
}

void show_ip(const struct iphdr *ip,struct in_addr addr){
	if (arg_v == 1)
	{
		addr.s_addr = ip->saddr;
		printf("From %s ",inet_ntoa(addr));
		addr.s_addr = ip->daddr;
		printf("to %s",inet_ntoa(addr));
	}else{
		styled_print("bold","IPv4",1);
		addr.s_addr = ip->saddr;
		printf("\t\tSource IP address: %s\n",inet_ntoa(addr));
		addr.s_addr = ip->daddr;
		printf("\t\tDestination IP address: %s\n",inet_ntoa(addr));
	}
}

void show_ip_protocol(const u_char* packet, const struct iphdr *ip){
	
	if (arg_v != 1){
		printf("\t\tTransport protocol: ");
	}else{
		printf(" over ");
	}
	switch(ip->protocol) {

		case 0x01:
			printf("ICMP");
		break;
		case 0x06:
			tcp(packet);
		break;
		case 0x11:
			udp(packet);
		break;
		case 0x3A:
			printf("IPv6-ICMP");
		break;
		case 0x73:
			printf("L2TP");
		break;
		case 0x84:
			printf("SCTP");
		break;
		default :
			unknown_protocol();
	}
}

void show_ip_else(const struct iphdr *ip){
	printf("\t\tIP Header Length: %d Bytes\n", ip->ihl);
	printf("\t\tType Of Service: %x\n", ip->tos);
	printf("\t\tTotal Length: %d Bytes\n", ntohs(ip->tot_len));
	printf("\t\tIdentification: 0x%x\n", ntohs(ip->id));
	printf("\t\tOffset: %d\n", ip->frag_off);
	printf("\t\tTime To Live: %d Hops\n", ip->ttl);
	printf("\t\tChecksum: 0x%x\n", ntohs(ip->check));
}