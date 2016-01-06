#include <netinet/tcp.h>
#include <string.h>
#include "lib/var_global.h"
#include "lib/ethernet.h"

void error(char* reason);
void usage(void);
void sudo(void);
int iface_exists(char* interface_input, char* errbuf);
int sniff_online(char* arg_i, char* arg_f, char* errbuf, char* inter);
void sniff_offline(char* arg_o, char* errbuf);
void filter(char* arg_f, pcap_t* p, char* errbuf, char* inter);
void got_packet(u_char *verb,const struct pcap_pkthdr* pkthdr,const u_char* packet);
char* set_tcp_options(int option);


void got_packet(u_char *verb,const struct pcap_pkthdr* pkthdr,const u_char* packet){
	ethernet(pkthdr, packet);
}
/* Fonction de décallage */
void shift(int shift){
	for (int i = 1; i <= shift; ++i){
		printf("\t");
	}
}
/* Fonction d'affichage du message de protocole inconnu */
void unknown_protocol(){
	printf("Unknown");
}

/* Fonction d'affichage d'un message d'erreur */
void error(char* reason){
	printf("Error: %s\n", reason);
}

/* Fonction d'affichage de l'utilisation du programme */
void usage(){
	printf("Usage: ./analyseur {-i <interface> -f <filter>,-o <capture file>}, -v <verbose level>\n");
}

/* Fonction d'affichage d'une ligne de symboles, de longueur donnée, avec ou sans retour à la ligne */
void line(char* separator, int length, int cr){
	for (int i = 0; i < length; ++i){
		printf("%s", separator);
	}
	if (cr){
		printf("\n");
	}
}

/* Fonction d'affichage de demande de droits sudo */
void sudo(){
	printf("Use sudo to launch the program\n");
}

/* Fonction de vérification si l'interface donnée en entrée existe */
int iface_exists(char* interface_input, char* errbuf){
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int i=0;

	if (pcap_findalldevs(&alldevs, errbuf) == -1){
		error("Unable to use the given interface");
	}
	for(d = alldevs; d != NULL; d = d->next){
		if(strcmp(d->name, interface_input))
			return 1;
		else
			return 0;
	}

	if (i == 0){
		error("No interface found.\n");
	}
	pcap_freealldevs(alldevs);
	return 0;
}

/* Fonction qui réalise la capture de paquets à partir de l'interface et du filtre donnés */
int sniff_online(char* arg_i, char* arg_f, char* errbuf, char* inter){
	pcap_t* p;	// capture

	// En cas d'absence de valeur pour l'option -i, l'interface par défaut est utilisée
	if (arg_i != NULL){
		arg_i = inter;
	}
	if(iface_exists(arg_i, errbuf) == 0){
		printf("Chosen interface OK\n");
		p = pcap_open_live(arg_i,PACKET_SIZE ,PROMISC ,TO_MS, errbuf);
		if(p != NULL){
			filter(arg_f, p, errbuf, inter);
			pcap_loop(p, CNT, got_packet, NULL);
			pcap_close(p);
			return 0;
		}else{
			error("Unable to open stream");
			return 1;
		}
	}else{
		error("Chosen interface incorrect. Please chose another interface");
		return 1;
	}
}

/* Fonction qui réalise la capture de paquets avec un fichier pcap donné en entrée */
void sniff_offline(char* arg_o, char* errbuf){
	pcap_t* p;	// capture
	p = pcap_open_offline(arg_o, errbuf);
	if (p != NULL){
		pcap_loop(p, CNT, got_packet, NULL);
	}else{
		error("Unable to open capture file");
	}
	pcap_close(p);
}

/* Fonction de création et d'utilisation d'un filtre BPF */
void filter(char* arg_f, pcap_t* p, char* errbuf, char* inter){
	printf("Filter: %s\n", arg_f);
	bpf_u_int32 netaddr;
	bpf_u_int32 netmask;

	if(pcap_lookupnet(inter, &netaddr, &netmask, errbuf) != 0){
			perror("Unable to get the address and netmask");
	}

	struct in_addr addr;
	addr.s_addr=netaddr;
	struct in_addr mask;
	mask.s_addr=netmask;

	struct bpf_program fp;

	if (pcap_compile(p, &fp, arg_f, 0, netmask) == -1) {
		printf("Couldn't parse filter \"%s\"\n", arg_f);
	}
	if (pcap_setfilter(p, &fp) == -1) {
		printf("Couldn't install filter \"%s\"\n", arg_f);
	}
}

/* Fonction qui renvoie l'option TCP en fonction du flag */
char* set_tcp_options(int option){
	char* tbl_option[255];
	tbl_option[0] = "End of Option List";
	tbl_option[1] = "No-Operation";
	tbl_option[2] = "Maximum Segment Size";
	tbl_option[3] = "Window Scale";
	tbl_option[4] = "SACK Permitted";
	tbl_option[5] = "SACK";
	tbl_option[6] = "Echo";
	tbl_option[7] = "Echo Reply";
	tbl_option[8] = "Timestamps";
	tbl_option[9] = "Partial Order Connection Permitted";
	tbl_option[10] = "Partial Order Service Profile";
	tbl_option[11] = "CC";
	tbl_option[12] = "CC.NEW";
	tbl_option[13] = "CC.ECHO";
	tbl_option[14] = "TCP Alternate Checksum Request";
	tbl_option[15] = "TCP Alternate Checksum Data";
	tbl_option[16] = "Skeeter";
	tbl_option[17] = "Bubba";
	tbl_option[18] = "Trailer Checksum Option";
	tbl_option[19] = "MD5 Signature Option";
	tbl_option[20] = "SCPS Capabilities";
	tbl_option[21] = "Selective Negative Acknowledgements";
	tbl_option[22] = "Record Boundaries";
	tbl_option[23] = "Corruption experienced";
	tbl_option[24] = "SNAP";
	tbl_option[25] = "Unassigned";
	tbl_option[26] = "TCP Compression Filter";
	tbl_option[27] = "Quick-Start Response";
	tbl_option[28] = "User Timeout Option";
	tbl_option[29] = "TCP Authentication Option";
	tbl_option[30] = "Multipath TCP";
	for (int i = 31; i <= 33; ++i){
		tbl_option[i] = "Reserved";
	}
	tbl_option[34] = "TCP Fast Open Cookie";
	for (int i = 35; i <= 252; ++i){
		tbl_option[i] = "Reserved";
	}
	tbl_option[253] = "RFC3692-style Experiment 1";
	tbl_option[254] = "RFC3692-style Experiment 2";

	return tbl_option[option];
}

/* Fonction qui affiche le texte donné en argument avec différents styles (gras, souligné, en couleur, etc) */
void styled_print(char* style, char* text){
	if (style == "bold"){
		printf("\033[1m");
		printf("%s\n",text);
		printf("\033[0m");
	}else if (style == "underline")
	{
		printf("\033[4m");
		printf("%s\n",text);
		printf("\033[24m");
	}else if (style == "inverse")
	{
		printf("\033[7m");
		printf("%s\n",text);
		printf("\033[27m");
	}else if (style == "red")
	{
		printf("\033[31m");
		printf("%s\n",text);
		printf("\033[0m");
	}
}
