#include <netinet/tcp.h>

void unknown_protocol();

void tcp(const u_char* packet){
	printf("TCP\n");
	const struct tcphdr *tcp;
	
	tcp = (struct tcphdr*)(packet);

	printf("\t\t\tSource port: %d\n",ntohs(tcp->source));
	printf("\t\t\tDestination port: %d\n",ntohs(tcp->dest));
	printf("\t\t\tSequence number: %d\n", ntohs(tcp->seq));
	printf("\t\t\tAcknowledge number: %d\n", ntohs(tcp->seq));

	printf("\t\t\tFlags: ");
	if (ntohs(tcp->fin)){printf("FIN ");}
	if (ntohs(tcp->syn)){printf("SYN ");}
	if (ntohs(tcp->rst)){printf("RST ");}
	if (ntohs(tcp->psh)){printf("PSH ");}
	if (ntohs(tcp->ack)){printf("ACK ");}
	if (ntohs(tcp->urg)){printf("URG ");}
	printf("\n");

	printf("\t\t\tApplication protocol: ");
	switch(ntohs(tcp->dest)) {
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
		case 80:
			printf("HTTP");
		break;
		case 110:
			printf("POP3");
		break;
		case 143:
			printf("IMAP");
		break;
		case 443:
			printf("HTTPS");
		break;
		default :
			unknown_protocol();
	}
	printf("\n");
}