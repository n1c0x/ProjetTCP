// structures d'entêtes
#include <netinet/tcp.h>
#include <string.h>
#include "lib/ethernet.h"


void got_packet(u_char *verb,const struct pcap_pkthdr* pkthdr,const u_char* packet){
	void ethernet(const struct pcap_pkthdr* pkthdr,const u_char* packet);
	ethernet(pkthdr, packet);
}

void unknown_protocol(){
	printf("Inconnu");
}

int iface_exists(char* interface_input, char* errbuf){

	pcap_if_t *alldevs;
	pcap_if_t *d;
	int i=0;

	if (pcap_findalldevs(&alldevs, errbuf) == -1){
		printf("Erreur lors de la récupération des interfaces: %s\n", errbuf);
	}
	for(d = alldevs; d != NULL; d = d->next){
		if(strcmp(d->name, interface_input))
			return 1;
		else
			return 0;
	}

	if (i == 0){
		printf("\nAucune interface trouvée.\n");
	}

	pcap_freealldevs(alldevs);
}

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