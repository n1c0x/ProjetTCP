#define PACKET_SIZE 1514
#define TO_MS 0				// renvoie immédiatement du paquet après la capture
#define PROMISC 1			// mode promiscious (1: on ,0: off)
#define CNT 0				// nombre de paquets à analyser. 0: infini

#define SIZE_TCP_HEADER 20	// taille du header tcp
#define SIZE_UDP_HEADER 8	// taille du header udp
#define SIZE_DNS_HEADER 12	// taille du header dns (flags, options, sans les queries)

#define MAC_ADDR_SIZE 6		// longueur d'une adresse mac
#define IP_ADDR_SIZE 4		// longueur d'une adresse mac


/* Constantes Bootp */
#define SIZE_BOOTP_HEADER 236 	//taille du header bootp
#define SIZE_MAGIC_COOKIE 4 	//taille du header bootp
#define SIZE_VENDOR_SPECIFIC 64	//taille du vendor specific bootp
/*
 * UDP port numbers, server and client.
 */
#define	IPPORT_BOOTPS		67
#define	IPPORT_BOOTPC		68

#define BOOTPREPLY		2
#define BOOTPREQUEST		1


/* DHCP Message types (values for TAG_DHCP_MESSAGE option) */
#define		DHCPDISCOVER	1
#define		DHCPOFFER	2
#define		DHCPREQUEST	3
#define		DHCPDECLINE	4
#define		DHCPACK		5
#define		DHCPNAK		6
#define		DHCPRELEASE	7
#define		DHCPINFORM	8