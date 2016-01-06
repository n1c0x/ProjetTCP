#include <netinet/udp.h>
#include "dns.h"


void udp(const u_char* packet);
void unknown_protocol(void);
void line(char* separator, int length, int cr);
void show_udp_ports(const struct udphdr *udp);
void show_udp_protocol(const struct udphdr *udp, const u_char* packet);
void show_udp_length(const struct udphdr *udp);
void styled_print(char* style, char* text);

int arg_v;

void udp(const u_char* packet){
	printf("\033[1m");
	printf("UDP");
	printf("\033[0m");

	const struct udphdr *udp;
	udp = (const struct udphdr*)(packet);

	if (arg_v == 1){
		show_udp_protocol(udp, packet);
	}else if (arg_v == 2){
		show_udp_ports(udp);
		show_udp_length(udp);
	}else{
		show_udp_ports(udp);
		show_udp_length(udp);
		line("-",70, 1);
		show_udp_protocol(udp, packet);
	}
}

void show_udp_ports(const struct udphdr *udp){
	printf("\n");
	printf("\t\t\tSource Port: %d\n",ntohs(udp->source));
	printf("\t\t\tDestination Port: %d\n",ntohs(udp->dest));
}

void show_udp_length(const struct udphdr *udp){
	printf("\t\t\tLength: %d Bytes \n", ntohs(udp->len));
}

void show_udp_protocol(const struct udphdr *udp, const u_char* packet){
	if (arg_v != 1){
		printf("\t\t\tApplication protocol: ");
	}else{
		printf(": ");
	}
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
			dns(packet);
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
			switch(ntohs(udp->source)) {
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
					dns(packet);
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
	}
}