// structures d'entêtes
#include <time.h>
//#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "ethernet.h"


void got_packet(u_char *verb,const struct pcap_pkthdr* pkthdr,const u_char* packet){
	void ethernet(const struct pcap_pkthdr* pkthdr,const u_char* packet);
	ethernet(pkthdr, packet);

	void ip(const struct pcap_pkthdr* pkthdr,const u_char* packet);
	ip(pkthdr, packet);
}
