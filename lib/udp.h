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
	
	switch(ntohs(udp->dest)) {
		case 07:
			printf("\t\t\t");
			printf("Echo");
		break;
		case 20:
			printf("\t\t\t");
			printf("FTP-data");
		break;
		case 21:
			printf("\t\t\t");
			printf("FTP");
		break;
		case 22:
			printf("\t\t\t");
			printf("SSH");
		break;
		case 23:
			printf("\t\t\t");
			printf("Telnet");
		break;
		case 25:
			printf("\t\t\t");
			printf("SMTP");
		break;
		case 53:
			printf("\t\t\t");
			printf("DNS");
		break;
		case 67:
			printf("\t\t\t");
			printf("BOOTPS");
		break;
		case 68:
			printf("\t\t\t");
			printf("BOOTPC");
		break;
		case 69:
			printf("\t\t\t");
			printf("TFTP");
		break;
		default :
			printf("\t\t\t");
			unknown_protocol();
	}
	printf("\n");
}