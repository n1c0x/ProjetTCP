#include <netinet/tcp.h>
//#include "functions.h"

void unknown_protocol();
void show_tcp_ports(const struct tcphdr *tcp);
void show_tcp_else(const struct tcphdr *tcp);
void show_tcp_protocol(const struct tcphdr *tcp);
void show_tcp_flags(const struct tcphdr *tcp);
void show_tcp_options(const struct tcphdr *tcp);


void tcp(const u_char* packet){
	printf("TCP");
	const struct tcphdr *tcp;
	tcp = (struct tcphdr*)(packet);

	if (arg_v == 1){
		show_tcp_protocol(tcp);
	}else if (arg_v == 2){
		show_tcp_ports(tcp);
	}else{
		show_tcp_ports(tcp);
		show_tcp_else(tcp);
		show_tcp_flags(tcp);
		line("-",70);
		show_tcp_protocol(tcp);
		show_tcp_options(tcp);
	}

}

void show_tcp_ports(const struct tcphdr *tcp){
	printf("\n");
	printf("\t\t\tSource Port: %d\n",ntohs(tcp->source));
	printf("\t\t\tDestination Port: %d\n",ntohs(tcp->dest));
}

void show_tcp_flags(const struct tcphdr *tcp){
	printf("\t\t\tFlags: ");
	if (ntohs(tcp->fin)){printf("FIN ");}
	if (ntohs(tcp->syn)){printf("SYN ");}
	if (ntohs(tcp->rst)){printf("RST ");}
	if (ntohs(tcp->psh)){printf("PSH ");}
	if (ntohs(tcp->ack)){printf("ACK ");}
	if (ntohs(tcp->urg)){printf("URG ");}
	printf("\n");
}

void show_tcp_else(const struct tcphdr *tcp){
	printf("\t\t\tData Offset: %d words (Header Length = %d Bytes)\n", tcp->doff, (tcp->doff*32)/8);
	printf("\t\t\tSequence number: 0x%x\n", ntohl(tcp->seq));
	printf("\t\t\tAcknowledge number: 0x%x\n", ntohl(tcp->ack_seq));
	printf("\t\t\tWindow Size: 0x%x\n", ntohs(tcp->window));
	printf("\t\t\tChecksum: 0x%x\n", ntohs(tcp->check));
	printf("\t\t\tUrgent Pointer: %d\n", ntohs(tcp->urg_ptr));
}

void show_tcp_options(const struct tcphdr *tcp){

}

void show_tcp_protocol(const struct tcphdr *tcp){
	if (arg_v != 1){
		printf("\t\t\tApplication protocol: ");
	}else{
		printf(": ");
	}
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
}