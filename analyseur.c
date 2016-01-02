#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include "functions.h"
#include "lib/var_global.h"


//#define LOCAL "rpcap://"
int arg_v;

int main(int argc, char *argv[])
	{
		char errbuf[PCAP_ERRBUF_SIZE];
		bpf_u_int32 netaddr;
		bpf_u_int32 netmask;
		int c;		// Arguments
		pcap_t* p;	// capture
		const u_char *packet;

		// Interface par défaut
		char* inter = pcap_lookupdev(errbuf);

		/*
		if(pcap_lookupnet(inter, &netaddr, &netmask, errbuf) != 0){
			perror("Impossible de récupérer l'adresse");
		}
		struct in_addr addr;
		addr.s_addr=netaddr;
		struct in_addr mask;
		mask.s_addr=netmask;
		*/
		// Initialisation des flags permettant de controler l'utilisation des options
		int flag_i = 0;
		int flag_o = 0;
		int flag_f = 0;
		int flag_v = 0;
		char* arg_i;
		char* arg_o;
		char* arg_f;
		
		while ((c = getopt (argc, argv, "i:o:fv:")) != -1){
		    switch (c)
		    {
		    	case 'i':
		    		flag_i = 1;
		    		arg_i = optarg;
					break;
		    	case 'o':
		    		flag_o = 1;
		    		arg_o = optarg;
					break;
		    	case 'f':
		    		flag_f = 1;
		    		arg_f = optarg;
		    		// filtre BPF, optionnel

		        break;
		    	case 'v':
		    		flag_v = 1;
					arg_v = atoi(strdup(optarg));
				break;
		        default:
		        	usage();
			}
		}

		if (flag_o && flag_i){
			error("-i and -o options can't be used simultaneously");
		}else if (flag_i){
			sniff_online(arg_i, errbuf);
		} else if (flag_o){
			sniff_offline(arg_o, errbuf);
		} else if(flag_f){
			filter(arg_f, errbuf);
		}

		return(0);
	}
