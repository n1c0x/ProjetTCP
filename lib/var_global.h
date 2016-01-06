#define PACKET_SIZE 1514
#define TO_MS 0				// renvoie immédiatement du paquet après la capture
#define PROMISC 1			// mode promiscious (1: on ,0: off)
#define CNT 0				// nombre de paquets à analyser. 0: infini

#define SIZE_TCP_HEADER 20	// taille du header tcp
#define SIZE_UDP_HEADER 8	// taille du header udp
#define SIZE_DNS_HEADER 12	// taille du header dns (flags, options, sans les queries)

#define MAC_ADDR_SIZE 6		// longueur d'une adresse mac
#define IP_ADDR_SIZE 4		// longueur d'une adresse mac