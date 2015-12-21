#include <netinet/tcp.h>

void unknown_protocol();

void tcp(const u_char* packet){
	printf("TCP\n");
	const struct tcphdr *tcp;
	
	tcp = (struct tcphdr*)(packet);

/*
	printf("source port: %x\n", ntohs(udp->source));
	printf("dest port: %x\n", ntohs(udp->dest));
	printf("length: %x\n", ntohs(udp->len));
	printf("checksum: %x\n", ntohs(udp->check));
*/

	printf("\t\t\tPort source: %d\n",ntohs(tcp->source));
	printf("\t\t\tPort destination: %d\n",ntohs(tcp->dest));
	printf("\t\t\tNuméro de sequence: %d\n", ntohs(tcp->seq));
	printf("\t\t\tNuméro d'acquittement': %d\n", ntohs(tcp->seq));

	printf("\t\t\tFIN: %x\n",ntohs(tcp->fin));
	printf("\t\t\tSYN: %x\n",ntohs(tcp->syn));
	printf("\t\t\tRST: %x\n",ntohs(tcp->rst));
	printf("\t\t\tPSH: %x\n",ntohs(tcp->psh));
	printf("\t\t\tACK: %x\n",ntohs(tcp->ack));
	printf("\t\t\tURG: %x\n",ntohs(tcp->urg));


	//printf("%s\n", set_tcp_flags(res1));

	switch(ntohs(tcp->dest)) {
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
		case 80:
			printf("\t\t\t");
			printf("HTTP");
		break;
		case 110:
			printf("\t\t\t");
			printf("POP3");
		break;
		case 143:
			printf("\t\t\t");
			printf("IMAP");
		break;
		case 443:
			printf("\t\t\t");
			printf("HTTPS");
		break;
		default :
			printf("\t\t\t");
			unknown_protocol();
	}
	printf("\n");
}