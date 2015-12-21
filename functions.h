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