#include <netinet/udp.h>

void unknown_protocol();

void udp(const u_char* packet){
	printf("UDP\n");
	const struct udphdr *udp;
	
	udp = (struct udphdr*)(packet);
	//ip_src = (struct ip_src*)(packet->in_addr);

	printf("source port: %x\n", udp->source);
	printf("dest port: %x\n", udp->dest);
	printf("length: %x\n", udp->len);
	printf("checksum: %x\n", udp->check);

/*
	addr.s_addr = ip->saddr;
	printf("\t\tAdresse IP source: %s\n",inet_ntoa(addr));
	addr.s_addr = ip->daddr;
	printf("\t\tAdresse IP destination: %s\n",inet_ntoa(addr));
	
	//printf("Protocole: %x\n", ip->protocol);
	/*
	printf("\n\tAdresse IP source: ");
	for (int i = 0; i < sizeof(ip->ether_shost); ++i)
	{
		printf("%x:", ip->ether_shost[i]);
	}
	printf("\n");
	printf("\tProtocole: ");


	switch(ip->protocol) {

		case 0x01:
			printf("\t\t");
			printf("ICMP");
		break;
		case 0x06:
			printf("\t\t");
			printf("TCP");
		break;
		case 0x11:
			printf("\t\t");
			printf("UDP");
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
			unknown_protocol();
	}
	printf("\n");*/
}