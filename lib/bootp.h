#include "var_global.h"

void bootp(const u_char* packet);
void show_bootp_messages_type(const u_char* packet);
void show_bootp_flags(const u_char* packet);
void show_bootp_ipaddr(const u_char* packet);
void show_bootp_macaddr(const u_char* packet);
void show_bootp_vendor_specific(const u_char* packet);
void styled_print(char* style, char* text, int cr);
char* set_bootp_options(int option);

struct bootp {
	u_int8_t	bp_op;		/* packet opcode type */
	u_int8_t	bp_htype;	/* hardware addr type */
	u_int8_t	bp_hlen;	/* hardware addr length */
	u_int8_t	bp_hops;	/* gateway hops */
	u_int32_t	bp_xid;		/* transaction ID */
	u_int16_t	bp_secs;	/* seconds since boot began */
	u_int16_t	bp_flags;	
	struct in_addr	bp_ciaddr;	/* client IP address */
	struct in_addr	bp_yiaddr;	/* 'your' IP address */
	struct in_addr	bp_siaddr;	/* server IP address */
	struct in_addr	bp_giaddr;	/* gateway IP address */
	u_int8_t	bp_chaddr[16];	/* client hardware address */
	u_char	bp_sname[64];	/* server host name */
	u_char	bp_file[128];	/* boot file name */
	u_char	bp_vend[64];	/* vendor-specific area */
};

void bootp(const u_char* packet){

	

	const struct bootp* bootp;
	bootp = (const struct bootp*)(packet);

	if (arg_v == 1)
	{	
		styled_print("bold","DHCP", 0);
	}else{
		styled_print("bold","DHCP", 1);
		show_bootp_messages_type(packet);
		show_bootp_flags(packet);
		show_bootp_ipaddr(packet);
		show_bootp_macaddr(packet);
		show_bootp_vendor_specific(packet);
	}
}
void show_bootp_messages_type(const u_char* packet){
	const struct bootp* bootp;
	bootp = (const struct bootp*)(packet);
	
	if (bootp->bp_op == BOOTPREQUEST){
		printf("Bootp Request\n");
	}else{
		printf("Bootp Reply\n");
	}
	printf("Hardware type: ");
	if (bootp->bp_htype == 1){
		printf("Ethernet\n");
	}else{
		printf("Unknown\n");
	}
	printf("Hardware address length: %d\n", bootp->bp_hlen);
	printf("Gateway hops: %d\n", bootp->bp_hops);
	printf("Transaction ID: 0x%x\n", ntohl(bootp->bp_xid));
	printf("Seconds since boot begin: %d\n", bootp->bp_secs);
}

void show_bootp_flags(const u_char* packet){
	const struct bootp* bootp;
	bootp = (const struct bootp*)(packet);

	styled_print("undeline", "Flags:",1);
	printf("Flags: ");
	printf("%d\n", bootp->bp_flags);
}

void show_bootp_ipaddr(const u_char* packet){
	const struct bootp* bootp;
	bootp = (const struct bootp*)(packet);

	struct in_addr addr;

	addr = bootp->bp_ciaddr;
	printf("Client IP address %s\n",inet_ntoa(addr));
	addr = bootp->bp_yiaddr;
	printf("Your IP address %s\n",inet_ntoa(addr));
	addr = bootp->bp_siaddr;
	printf("Server IP address %s\n",inet_ntoa(addr));
	addr = bootp->bp_giaddr;
	printf("Gateway IP address %s\n",inet_ntoa(addr));
}

void show_bootp_macaddr(const u_char* packet){
	const struct bootp* bootp;
	bootp = (const struct bootp*)(packet);

	printf("Client hardware address: ");
	for (int i = 0; i < MAC_ADDR_SIZE; i++){
		if (i != 0){
			printf(":");
		}
		printf("%x",bootp->bp_chaddr[i]);
	}
	printf("\n");
	printf("Server Host name: ");
	for (int i = 0; i < 64; i++){
		printf("%c",bootp->bp_sname[i]);
	}
	printf("\n");
	printf("Boot file name: ");
	for (int i = 0; i < 128; i++){
		printf("%c",bootp->bp_file[i]);
	}
	printf("\n");
}

void show_bootp_vendor_specific(const u_char* packet){
	const struct bootp* bootp;
	bootp = (const struct bootp*)(packet);

	styled_print("underline", "Vendor specific options: ",1);
	printf("Magic Cookie: ");
	for (int i = 0; i < 4; i++){
		printf("%x",bootp->bp_vend[i]);
	}
	printf("\n");
	packet = packet + SIZE_MAGIC_COOKIE + SIZE_BOOTP_HEADER;
/*
	for (int i = 0; i < 64; i++){
		printf("%x",bootp->bp_vend[i]);
	}
*/
/*
	int type;
	int length;
	int value;
	int count = 0;
	styled_print("underline", "Options DHCP:");
	while(count <= SIZE_VENDOR_SPECIFIC){
		type = *packet;
		printf("Type: %x ", type);
		packet++;
		count++;
		printf("(%s)\n", set_bootp_options(type));
		length = *packet;
		printf("Longueur: %d\n", length);
		printf("Valeur: ");
		/* On boucle sur le champ de valeur pour toutes les afficher. */
		/*
		for (int i = 0; i < length-2; ++i){
			packet++;
			count++;
			value = *packet;
			printf("%x", value);
		}
		printf("\n");
		count = count + length;
	}*/
	printf("\n");

}
