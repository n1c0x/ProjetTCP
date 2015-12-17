#include <stdio.h>
#include <pcap/pcap.h>

int main(int argc, char *argv[])
	{
		char errbuf[PCAP_ERRBUF_SIZE];

		char* inter = pcap_lookupdev(errbuf);

		printf("Device: %s\n", inter);
		return(0);
	}
