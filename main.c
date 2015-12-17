#include <stdio.h>
#include <pcap/pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

int main(int argc, char *argv[])
	{
		char errbuf[PCAP_ERRBUF_SIZE];
		bpf_u_int32 netaddr;
		bpf_u_int32 netmask;
		//char* addr;
		//char* mask;

		char* inter = pcap_lookupdev(errbuf);
		if(pcap_lookupnet(inter, &netaddr, &netmask, errbuf) != 0){
			perror("Impossible de récupérer l'adresse");
		}

		struct in_addr addr;
		addr.s_addr=netaddr;
		printf ("%s\n", inet_ntoa(addr));
		struct in_addr mask;
		mask.s_addr=netmask;
		printf ("%s\n", inet_ntoa(mask));

		printf("Carte réseau: %s\n", inter);

		return(0);
	}
