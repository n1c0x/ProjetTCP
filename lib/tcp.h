#include <netinet/tcp.h>

void tcp(const u_char* packet);
void show_tcp_ports(const struct tcphdr *tcp);
void show_tcp_else(const struct tcphdr *tcp);
void show_tcp_protocol(const struct tcphdr *tcp, const u_char* packet);
void show_tcp_flags(const struct tcphdr *tcp);
void show_tcp_options(const u_char* packet, int size_options);
void styled_print(char* style, char* text);

void tcp(const u_char* packet){
	printf("\033[1m");
	printf("TCP");
	printf("\033[0m");

	const struct tcphdr *tcp;
	tcp = (const struct tcphdr*)(packet);

	if (arg_v == 1){
		show_tcp_protocol(tcp,packet);
	}else if (arg_v == 2){
		show_tcp_ports(tcp);
	}else{
		show_tcp_ports(tcp);
		show_tcp_else(tcp);
		show_tcp_flags(tcp);
		packet = packet + SIZE_TCP_HEADER;
		int size_options = (tcp->doff*32)/8 - SIZE_TCP_HEADER;
		show_tcp_options(packet, size_options);
		line("-",70);
		show_tcp_protocol(tcp, packet);
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

void show_tcp_options(const u_char* packet, int size_options){
	/* type, longueur et valeur des options */
	int type;
	int length;
	int value;
	int count = 0;
	char* set_tcp_options(int option);

	styled_print("underline", "\t\t\tOptions TCP:");
	
	while(count <= size_options){
		type = *packet;
		printf("\t\t\tType: %x ", type);
		packet++;
		count++;
		switch(type){
			case 0:
				printf("(%s)\n", set_tcp_options(type));
				break;
			case 1:
				printf("(%s)\n", set_tcp_options(type));
				break;
			default:
				printf("(%s)\n", set_tcp_options(type));
				length = *packet;
				printf("\t\t\t\tLongueur: %d\n", length);
				printf("\t\t\t\tValeur: ");
				/* On boucle sur le champ de valeur pour tous les afficher. -2 parce que le champ length compte aussi pour le type et la longueur */
				for (int i = 0; i < length-2; ++i){
					packet++;
					count++;
					value = *packet;
					printf("%x", value);
				}
				count = count + length;
		}
	}
	printf("\n");
}



void show_tcp_protocol(const struct tcphdr *tcp, const u_char* packet){
	if (arg_v != 1){
		printf("\t\t\tApplication protocol: ");
	}else{
		printf(": ");
	}
	switch(ntohs(tcp->dest)) {
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
		case 80:
			printf("HTTP\n");
		break;
		case 110:
			printf("POP3\n");
		break;
		case 143:
			printf("IMAP\n");
		break;
		case 443:
			printf("HTTPS\n");
		break;
		default :
			switch(ntohs(tcp->source)) {
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
				case 80:
					printf("HTTP\n");
				break;
				case 110:
					printf("POP3\n");
				break;
				case 143:
					printf("IMAP\n");
				break;
				case 443:
					printf("HTTPS\n");
				break;
				default :
					unknown_protocol();
			}
	}
}