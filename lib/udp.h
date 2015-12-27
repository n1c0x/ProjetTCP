#include <netinet/udp.h>

void unknown_protocol();

void udp(const u_char* packet){
	printf("UDP\n");
	const struct udphdr *udp;
	
	udp = (struct udphdr*)(packet);

/*
	printf("source port: %x\n", ntohs(udp->source));
	printf("dest port: %x\n", ntohs(udp->dest));
	printf("length: %x\n", ntohs(udp->len));
	printf("checksum: %x\n", ntohs(udp->check));
*/

	printf("\t\t\tPort source: %d\n",ntohs(udp->source));
	printf("\t\t\tPort destination: %d\n",ntohs(udp->dest));
	printf("\t\t\tLongueur: %d octets\n", ntohs(udp->len));
	
	printf("\t\t\tProtocole applicatif: ");
	switch(ntohs(udp->dest)) {
		case 07:
			printf("Echo");
		break;
		case 20:
			printf("FTP-data");
		break;
		case 21:
			printf("FTP");
		break;
		case 22:
			printf("SSH");
		break;
		case 23:
			printf("Telnet");
		break;
		case 25:
			printf("SMTP");
		break;
		case 53:
			printf("DNS");
		break;
		case 67:
			printf("BOOTPS");
		break;
		case 68:
			printf("BOOTPC");
		break;
		case 69:
			printf("TFTP");
		break;
		default :
			unknown_protocol();
	}
	printf("\n");
}