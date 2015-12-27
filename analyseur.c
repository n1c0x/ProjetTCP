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
#define LOCAL "rpcap://"

int main(int argc, char *argv[])
	{
		char errbuf[PCAP_ERRBUF_SIZE];
		bpf_u_int32 netaddr;
		bpf_u_int32 netmask;
		int c;		// Arguments
		pcap_t* p;	// capture
		const u_char *packet;

		//int iface_exists(errbuf);

		
		// Interface par défaut
		char* inter = pcap_lookupdev(errbuf);

		if(pcap_lookupnet(inter, &netaddr, &netmask, errbuf) != 0){
			perror("Impossible de récupérer l'adresse");
		}
		struct in_addr addr;
		addr.s_addr=netaddr;
		struct in_addr mask;
		mask.s_addr=netmask;
		
		while ((c = getopt (argc, argv, "i:o:fv:")) != -1){
		    switch (c)
		    {
		    	// soit 'i', soit 'o'
		    	// case 'i|o':
		    	// 	printf("Erreur\n");
		    	// 	break;
		    	case 'i':
		      		// utilisation de l'interface définie
		    		// si non présent, prendre l'interface par défaut
					
		    		if(iface_exists(optarg, errbuf) == 0){
						printf("Interface choisie correcte\n");
						p = pcap_open_live(optarg,PACKET_SIZE ,PROMISC ,TO_MS, errbuf);
		        		if(p != NULL){
		        			pcap_loop(p, CNT, got_packet, NULL);
						}else{
							perror("Impossible d'ouvrir le fichier");
						}
						pcap_close(p);
					}else{
						printf("Interface incorrecte\n");
						break;
					}
		    		/*
					*/
		        break;
		    	case 'o':
		        	// fichier d'entrée pour analyse offline
					p = pcap_open_offline(optarg, errbuf);
			    	if (p != NULL){
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
	      }

		return(0);
	}
