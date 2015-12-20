#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include "functions.h"


// définition des constantes
#define PACKET_SIZE 1514 	// taille du paquet
#define TO_MS 0				// renvoie immédiatement du paquet après la capture
#define PROMISC 1			// mode promiscious (1: on ,0: off)
#define CNT 0				// nombre de paquets à analyser. 0: infini

int main(int argc, char *argv[])
	{
		char errbuf[PCAP_ERRBUF_SIZE];
		bpf_u_int32 netaddr;
		bpf_u_int32 netmask;
		int c;		// Arguments
		pcap_t* p;	// capture

		const u_char *packet;
	    struct pcap_pkthdr hdr;     /* pcap.h */
	    struct ether_header *eptr;  /* net/ethernet.h */


		char* inter = pcap_lookupdev(errbuf);
		if(pcap_lookupnet(inter, &netaddr, &netmask, errbuf) != 0){
			perror("Impossible de récupérer l'adresse");
		}

		struct in_addr addr;
		addr.s_addr=netaddr;
		struct in_addr mask;
		mask.s_addr=netmask;
		
/*
		printf("Carte réseau: %s\n", inter);
		printf ("Réseau: %s\n", inet_ntoa(addr));
		printf ("Masque: %s\n", inet_ntoa(mask));
*/
		while ((c = getopt (argc, argv, "io:fv:")) != -1)
	    switch (c)
	    {
	    	// soit 'i', soit 'o'
	    	case 'i':
	      		// utilisation de l'interface définie
	    		// si non présent, prendre l'interface par défaut
				/*
	    		p = pcap_open_live(inter,PACKET_SIZE ,PROMISC ,TO_MS, errbuf);
	        	if(p != NULL){

	        	}else{
	        		perror("Impossible de commencer la capture");
	        	}*/
	        break;
	    	case 'o':
	        	// fichier d'entrée pour analyse offline
				p = pcap_open_offline(optarg, errbuf);
		    	if (p != NULL){
					printf("Fichier ouvert\n");
					pcap_loop(p, CNT, got_packet, NULL);
				}else{
					perror("Impossible d'ouvrir le fichier");
				}
				pcap_close(p);
	        break;
	    	case 'f':
	    		// filtre BPF, optionnel

	        break;
	    	case 'v':
	    	    // niveau de verbosité <1 ... 3> (1=très concis ; 2=synthétique ; 3=complet)
	        break;
	        default:
	        	printf("Usage: \n");
	      }

		return(0);
	}
