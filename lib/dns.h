void styled_print(char* style, char* text);
void line(char* separator, int length, int cr);
void unknown_protocol();
void shift(int shift);
void show_dns_flags(const u_char* packet);
void show_query(const u_char* packet);

int arg_v;

struct dnshdr {
        unsigned        id :16;         /* query identification number */
#if BYTE_ORDER == BIG_ENDIAN
                        /* fields in third byte */
        unsigned        qr: 1;          /* response flag */
        unsigned        opcode: 4;      /* purpose of message */
        unsigned        aa: 1;          /* authoritive answer */
        unsigned        tc: 1;          /* truncated message */
        unsigned        rd: 1;          /* recursion desired */
                        /* fields in fourth byte */
        unsigned        ra: 1;          /* recursion available */
        unsigned        unused :3;      /* unused bits (MBZ as of 4.9.3a3) */
        unsigned        rcode :4;       /* response code */
#endif
#if BYTE_ORDER == LITTLE_ENDIAN || BYTE_ORDER == PDP_ENDIAN
                        /* fields in third byte */
        unsigned        rd :1;          /* recursion desired */
        unsigned        tc :1;          /* truncated message */
        unsigned        aa :1;          /* authoritive answer */
        unsigned        opcode :4;      /* purpose of message */
        unsigned        qr :1;          /* response flag */
                        /* fields in fourth byte */
        unsigned        rcode :4;       /* response code */
        unsigned        unused :3;      /* unused bits (MBZ as of 4.9.3a3) */
        unsigned        ra :1;          /* recursion available */
#endif
                        /* remaining bytes */
        unsigned        qdcount :16;    /* number of question entries */
        unsigned        ancount :16;    /* number of answer entries */
        unsigned        nscount :16;    /* number of authority entries */
        unsigned        arcount :16;    /* number of resource entries */
};

void dns(const u_char* packet){
	styled_print("bold","DNS");

	packet = packet + SIZE_UDP_HEADER;
	const struct dnshdr* dns;
	dns = (const struct dnshdr*)(packet);

	printf("\033[31m");
	line("#",70,1);
	printf("\033[0m");

	if (arg_v != 1){
		shift(4);
		printf("Transaction ID: 0x%x\n", ntohs(dns->id));
		show_dns_flags(packet);
		shift(4);
		printf("Number of questions: 0x%x\n", ntohs(dns->qdcount));
		shift(4);
		printf("Number of answers: 0x%x\n", ntohs(dns->ancount));
		shift(4);
		printf("Number of authority entries: 0x%x\n", ntohs(dns->nscount));
		shift(4);
		printf("Number of resource entries: 0x%x\n", ntohs(dns->arcount));
		show_query(packet);
	}
}

void show_query(const u_char* packet){
	packet = packet + SIZE_DNS_HEADER;
	int query;
	query = *packet;
	shift(4);
	styled_print("underline","Queries");
	printf("0x%x\n", query);
}

void show_dns_flags(const u_char* packet){
	const struct dnshdr* dns;
	dns = (const struct dnshdr*)(packet);

	shift(4);
	printf("Flags:\n");
	shift(5);
	if (dns->qr){
		printf("DNS Response\n");
	}else{
		printf("DNS Query\n");
	}
	shift(5);
	switch (dns->opcode){
		case 0:
			printf("Standard query\n");
		break;
		case 1:
			printf("Inverse query (obsolete)\n");
		break;
		case 2:
			printf("Status\n");
		break;
		case 3:
			printf("Unassigned\n");
		break;
		case 4:
			printf("Notify\n");
		break;
		case 5:
			printf("Update\n");
		break;
		default:
			printf("Unassigned\n");
	}
	shift(5);
	if (dns->aa){
		printf("Authoritative Answer Flag\n");
	}else{
		printf("Non Authoritative Answer Flag\n");
	}
	shift(5);
	if (dns->tc){
		printf("Message truncated\n");
	}else{
		printf("Message is not truncated\n");
	}
	shift(5);
	if (dns->rd){
		printf("Recursion desired\n");
	}else{
		printf("Recursion not desired\n");
	}
	shift(5);
	if (dns->ra){
		printf("Recursion available\n");
	}else{
		printf("Recursion not available\n");
	}
	shift(5);
	switch (dns->rcode){
		case 0:
			printf("No error\n");
		break;
		case 1:
			printf("Format error\n");
		break;
		case 2:
			printf("Server failure\n");
		break;
		case 3:
			printf("Name error\n");
		break;
		case 4:
			printf("Not implemented\n");
		break;
		case 5:
			printf("Refused\n");
		break;
		case 6:
			printf("YX Domain\n");
		break;
		case 7:
			printf("YXRRSet\n");
		break;
		case 8:
			printf("NXRRSet\n");
		break;
		case 9:
			printf("NotAuth\n");
		break;
		case 10:
			printf("NotZone\n");
		break;
		default:
			unknown_protocol();
	}
}