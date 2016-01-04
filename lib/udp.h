#include <netinet/udp.h>

void udp(const u_char* packet);
void unknown_protocol(void);
void line(char* separator, int length);
void show_udp_ports(const struct udphdr *udp);
void show_udp_protocol(const struct udphdr *udp);
void show_udp_length(const struct udphdr *udp);

int arg_v;

void udp(const u_char* packet){
	printf("UDP");
	const struct udphdr *udp;
	udp = (const struct udphdr*)(packet);

	if (arg_v == 1){
		show_udp_protocol(udp);
	}else if (arg_v == 2){
		show_udp_ports(udp);
		show_udp_length(udp);
	}else{
		show_udp_ports(udp);
		show_udp_length(udp);
		line("-",70);
		show_udp_protocol(udp);
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

void show_udp_protocol(const struct udphdr *udp){
	if (arg_v != 1){
		printf("\t\t\tApplication protocol: ");
	}else{
		printf(": ");
	}
	switch(ntohs(udp->dest)) {
		case 07:
			printf("Echo\n");
		break;
		case 20:
			printf("FTP-data\n");
		break;
		case 21:
			printf("FTP\n");
		break;
		case 22:
			printf("SSH\n");
		break;
		case 23:
			printf("Telnet\n");
		break;
		case 25:
			printf("SMTP\n");
		break;
		case 53:
			printf("DNS\n");
		break;
		case 67:
			printf("BOOTPS\n");
		break;
		case 68:
			printf("BOOTPC\n");
		break;
		case 69:
			printf("TFTP\n");
		break;
		default :
			switch(ntohs(udp->source)) {
				case 07:
					printf("Echo\n");
				break;
				case 20:
					printf("FTP-data\n");
				break;
				case 21:
					printf("FTP\n");
				break;
				case 22:
					printf("SSH\n");
				break;
				case 23:
					printf("Telnet\n");
				break;
				case 25:
					printf("SMTP\n");
				break;
				case 53:
					printf("DNS\n");
				break;
				case 67:
					printf("BOOTPS\n");
				break;
				case 68:
					printf("BOOTPC\n");
				break;
				case 69:
					printf("TFTP\n");
				break;
				default :
					unknown_protocol();
			}
	}
}