// structures d'entêtes
#include <netinet/tcp.h>
#include "lib/ethernet.h"


void got_packet(u_char *verb,const struct pcap_pkthdr* pkthdr,const u_char* packet){
	void ethernet(const struct pcap_pkthdr* pkthdr,const u_char* packet);
	ethernet(pkthdr, packet);
}

void unknown_protocol(){
	printf("Unknown protocol");
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