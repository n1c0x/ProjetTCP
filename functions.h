#include <netinet/tcp.h>
#include <string.h>
#include "lib/var_global.h"
#include "lib/ethernet.h"

void unknown_protocol();
void error(char* reason);
void usage();
void line(char* separator, int length);
int iface_exists(char* interface_input, char* errbuf);
void sniff_online(char* arg_i, char* errbuf);
void sniff_offline(char* arg_o, char* errbuf);
void filter(char* arg_f, char* errbuf);
void got_packet(u_char *verb,const struct pcap_pkthdr* pkthdr,const u_char* packet);



void got_packet(u_char *verb,const struct pcap_pkthdr* pkthdr,const u_char* packet){
	void ethernet(const struct pcap_pkthdr* pkthdr,const u_char* packet);
	ethernet(pkthdr, packet);
}

void unknown_protocol(){
	printf("Unknown");
}
void error(char* reason){
	printf("Error: %s\n", reason);
}
void usage(){
	printf("Usage: ./analyseur {-i <interface>,-o <capture file>}, -f <BPF filter> -v <verbose level>\n");
}
void line(char* separator, int length){
	for (int i = 0; i < length; ++i){
		printf("%s", separator);
	}
	printf("\n");
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
}

void sniff_online(char* arg_i, char* errbuf){
	pcap_t* p;	// capture
	if(iface_exists(arg_i, errbuf) == 0){
		printf("Chosen interface OK\n");
		p = pcap_open_live(arg_i,PACKET_SIZE ,PROMISC ,TO_MS, errbuf);
		if(p != NULL){
			pcap_loop(p, CNT, got_packet, NULL);
		}else{
			error("Unable to open stream");
		}
		pcap_close(p);
	}else{
		error("Chosen interface incorrect. Please chose another interface");
	}
}

void sniff_offline(char* arg_o,char* errbuf){
	pcap_t* p;	// capture
	p = pcap_open_offline(arg_o, errbuf);
	if (p != NULL){
		pcap_loop(p, CNT, got_packet, NULL);
	}else{
		error("Unable to open capture file");
	}
	pcap_close(p);
}

void filter(char* arg_f, char* errbuf){
	printf("%s\n", arg_f);
}

// TO DO
/* Fonction donnant en retour l'application en fonction du port 
char* set_tcp_ports(int port){
	char* ports[65536];
	/* Remplir le tableau */
	/* 
	ports[1] = "tcpmux";
	ports[2] = "compressnet";
	*
	port = ports[port];
	return port;
}
char* set_udp_ports(int port){
	char* ports[65536];
	/* Remplir le tableau *
	/* 
	ports[1] = "tcpmux";
	ports[2] = "compressnet";
	*
	port = ports[port];
	return port;
}
Fonction donnant en retour le flag en fonction de l'identifiant
char* set_tcp_flags(int port){
	char* flags[10];
	flags[0] = "Reservé";
	flags[1] = "ECN";
	flags[2] = "CWR";
	flags[3] = "ECN-Echo";
	flags[4] = "URG";
	flags[5] = "ACK";
	flags[6] = "PSH";
	flags[7] = "RST";
	flags[8] = "SYN";
	flags[9] = "FIN";
}*/