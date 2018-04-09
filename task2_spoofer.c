/*
	I have done both parts b and c in this program. You can choose to run the ICMP
	spoofer by passing 1 as a command line argument. You can choose to run the 
	Ethernet spoofer by passing 2 as a command line argument. Both options will call
	separate functions.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>  

void
create_IP_Header(struct iphdr *ip_header) {
	/*
	// iphdr struct as defined in linux/ip.h

	struct iphdr {
	#if defined(__LITTLE_ENDIAN_BITFIELD)
		__u8	ihl:4,
			version:4;
	#elif defined (__BIG_ENDIAN_BITFIELD)
		__u8	version:4,
	  		ihl:4;
	#else
	#error	"Please fix <asm/byteorder.h>"
	#endif
		__u8	tos;
		__be16	tot_len;
		__be16	id;
		__be16	frag_off;
		__u8	ttl;
		__u8	protocol;
		__sum16	check;
		__be32	saddr;
		__be32	daddr;
	};
	*/

	const char *ip_src 		= "192.168.15.92"; // spoofed IP
	const char *ip_dst 		= "172.217.8.174"; // remote machine IP
	// const char *ip_dst              = "192.168.15.5";

    ip_header->tot_len 		= sizeof(struct iphdr) + sizeof(struct icmphdr);
    ip_header->ttl 			= 64;
    ip_header->frag_off		= 0x0;
    ip_header->protocol 	= IPPROTO_ICMP;
    ip_header->saddr 		= inet_addr(ip_src);
    ip_header->daddr 		= inet_addr(ip_dst);
    ip_header->version 		= 4;
	ip_header->ihl         	= 5; // set internet header length to be 5-byte words
}

void
create_ICMP_Header(struct icmphdr *icmp_header) {
	/*
	// icmphdr struct as defined in linux/icmp.h

	struct icmphdr {
	  __u8		type;
	  __u8		code;
	  __sum16	checksum;
	  union {
		struct {
			__be16	id;
			__be16	sequence;
		} echo;
		__be32	gateway;
		struct {
			__be16	__unused;
			__be16	mtu;
		} frag;
		__u8	reserved[4];
	  } un;
	};
	*/

	icmp_header->type = ICMP_ECHO;
	icmp_header->code = 8;
}

void
create_Eth_Header(struct ethhdr *eth_header) {
	// ethhdr struct is defined in linux/if_ether.h

	// 01:02:03:04:05:06
	const unsigned char ether_src_addr[]	= {0x01,0x02,0x03,0x04,0x05,0x06};
	memcpy(eth_header->h_source,ether_src_addr,6);
	eth_header->h_proto = htons(ETH_P_IP);
}

int
getInterfaceIdx(char* interface_name, int sd) {
	struct ifreq intrfc_buf;
	memset(&intrfc_buf, 0x00, sizeof(intrfc_buf));
	strncpy(intrfc_buf.ifr_name, interface_name, IFNAMSIZ);
	ioctl(sd, SIOCGIFINDEX, &intrfc_buf);
	return intrfc_buf.ifr_ifindex;
}

/*
Using raw sockets is quite straightforward; it involves four steps: 
	(1) create a raw socket, 
	(2) set socket option, 
	(3) construct the packet, and 
	(4) send out the packet through the raw socket.
*/

int ICMP_Spoofer(void) {
	int i;
	int sd; 
	struct sockaddr_in sin;
	// This buffer will be used to construct raw packet.
	char buffer[1024]; // You can change the buffer size

	/* Create a raw socket with IP protocol. The IPPROTO_RAW parameter
	 * tells the sytem that the IP header is already included;
	 * this prevents the OS from adding another IP header.  */
	sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if(sd < 0) {
		perror("socket() error"); exit(-1);
	}

	/* This data structure is needed when sending the packets
	 * using sockets. Normally, we need to fill out several
	 * fields, but for raw sockets, we only need to fill out
	 * this one field */
	sin.sin_family = AF_INET;

	// Here you can construct the IP packet using buffer[]
	//    - construct the IP header ...
	//    - construct the TCP/UDP/ICMP header ...
	//    - fill in the data part if needed ...
	// Note: you should pay attention to the network/host byte order.
	struct iphdr *ip_header = (struct iphdr *) buffer;
	struct icmphdr *icmp_header = (struct icmphdr *) (buffer + sizeof(struct iphdr));
	create_IP_Header(ip_header);	
	create_ICMP_Header(icmp_header);

	// program 
	if(sendto(sd, buffer, ip_header->tot_len, 0, (struct sockaddr *)&sin, 
		sizeof(sin)) < 0) {

		perror("sendto() error"); exit(-1);
	}
	return 1;
}

int 
EthernetFrame_Spoofer(void) {

	int i;
	int sd; 
	
	// This buffer will be used to construct raw packet.
	char buffer[1024]; // You can change the buffer size

	sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
	if(sd < 0) {
		perror("socket() error"); exit(-1);
	}

	char *intrfc_name = "eth14"; // network interface through which to send
	// getting the indx of the network adaptor through which to send the eth frame
	int intrfc_idx = getInterfaceIdx(intrfc_name,sd);

	// setting up the headers
	struct ethhdr *eth_header = (struct ethhdr *) buffer;
	struct iphdr *ip_header = (struct iphdr *) (buffer + sizeof(struct ethhdr));
	struct icmphdr *icmp_header = (struct icmphdr *) (buffer + 
		sizeof(struct ethhdr) + sizeof(struct iphdr));
	create_Eth_Header(eth_header);
	create_IP_Header(ip_header);	
	create_ICMP_Header(icmp_header);

	// setting up the linklayer sockaddr data structure to send out the packets
	struct sockaddr_ll saddrll;
	memset((void*)&saddrll, 0, sizeof(saddrll)); // zeroing out everything before
	saddrll.sll_ifindex = intrfc_idx; // the lnklyr adaptor through which to send/rcv

	if(sendto(sd, buffer, ip_header->tot_len+6, 0, 
		(struct sockaddr*)&saddrll, sizeof(saddrll)) < 0) {

		perror("sendto() error"); exit(-1);
	}
	return 1;
}

void 
print_app_usage(void) {
	printf("Usage: task2_spoofer <option #>\n");				
	printf("Options:\n");		
	printf("	1: ICMP Echo Request\n");
	printf("	2: Ethernet Frame\n\n");
}

int main(int argc, char const *argv[])
{
    if (argc != 2 || (atoi(argv[1]) != 1 && atoi(argv[1]) != 2)) {
		printf("Error: unrecognized command-line option\n\n");
		print_app_usage();
		exit(1);
	}

	int choice = atoi(argv[1]);
	int success;

	if (choice == 1) {
		success = ICMP_Spoofer();
		if (success != 1) {
			printf("ICMP Packet spoofing failed.\n");
			exit(1);
		}
	} else {
		success = EthernetFrame_Spoofer();
		if (success != 1) {
			printf("EthernetFrame spoofing failed.\n");
			exit(1);
		}
	}

	printf("\nSpoofing complete.\n");

	return 0;
}
