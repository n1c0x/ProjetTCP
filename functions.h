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

void got_packet(u_char *verb,const struct pcap_pkthdr* pkthdr,const u_char* packet){
	ethernet(pkthdr, packet);
}

void unknown_protocol(){
	printf("Unknown\n");
}
void error(char* reason){
	printf("Error: %s\n", reason);
}
void usage(){
	printf("Usage: ./analyseur {-i <interface> -f <filter>,-o <capture file>}, -v <verbose level>\n");
}
void line(char* separator, int length){
	for (int i = 0; i < length; ++i){
		printf("%s", separator);
	}
	printf("\n");
}
void sudo(){
	printf("Use sudo to launch the program\n");
}

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

// TO DO
/* Fonction donnant en retour l'application en fonction du port 
char* set_tcp_ports(int port){
	char* ports[65536];
	Remplir le tableau
	
	ports[1] = "tcpmux";
	ports[2] = "compressnet";
	
	port = ports[port];
	return port;
}
char* set_udp_ports(int port){
	char* ports[65536];
	Remplir le tableau
	
	ports[1] = "tcpmux";
	ports[2] = "compressnet";
	
	port = ports[port];
	return port;
}
*/