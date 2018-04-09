#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>  

#define APP_NAME		"task3_sniff_snoop"

static const char *MACHINE_A_IP =	"192.168.15.5"; // do not change
static const char *MACHINE_B_IP =	"192.168.15.4"; // do not change

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

struct sniff_icmp {
	u_char type;
	u_char code;
	u_short chksum;
	u_short id;
	u_short sequence;
};

void
print_app_usage(void);

/*
 * print help text
 */
void
print_app_usage(void)
{

	printf("Usage: %s [interface]\n", APP_NAME);
	printf("\n");
	printf("Options:\n");
	printf("    interface    Listen on <interface> for packets.\n");
	printf("\n");

return;
}

void
create_IP_Header(struct iphdr *ip_header, const struct sniff_ip *ip) {
	ip_header->tot_len 		= sizeof(struct iphdr) + sizeof(struct icmphdr);
    ip_header->ttl 			= 52;
    ip_header->protocol 	= IPPROTO_ICMP;
    ip_header->frag_off		= 0;
    ip_header->saddr 		= inet_addr(inet_ntoa(ip->ip_dst));
    ip_header->daddr 		= inet_addr(MACHINE_A_IP);
    // ip_header->daddr 		= inet_addr("192.168.15.5");
    ip_header->version 		= 4;
	ip_header->ihl         	= 5; // set internet header length to be 5-byte words
}

void
create_ICMP_Header(struct icmphdr *icmp_header, const struct sniff_icmp *icmp) {
	icmp_header->type = ICMP_ECHOREPLY;
	icmp_header->code = 0;
	icmp_header->un.echo.id = icmp->id;
	icmp_header->un.echo.sequence =  icmp->sequence;
	icmp_header->checksum = 0;
}

void
ICMP_Spoofer(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_icmp *icmp;

	// const char *payload;                    /* Packet payload */

	int size_ip;
	int size_icmp;

	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);

	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	icmp = (struct sniff_icmp*)(packet + SIZE_ETHERNET + size_ip);

	int i;
	int sd; 
	struct sockaddr_in sin;

	char buffer[1024];

	sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if(sd < 0) {
		perror("socket() error"); exit(-1);
	}

	sin.sin_family = AF_INET;

	struct iphdr *ip_header = (struct iphdr *) buffer;
	struct icmphdr *icmp_header = (struct icmphdr *) (buffer + sizeof(struct iphdr));
	create_IP_Header(ip_header, ip);	
	create_ICMP_Header(icmp_header,icmp);

	if(sendto(sd, buffer, ip_header->tot_len, 0, (struct sockaddr *)&sin, 
		sizeof(sin)) < 0) {

		perror("sendto() error"); exit(-1);
	}
	printf("Sent out a spoofed ICMP packet.\n");
	// close(sd);
}

int main(int argc, char **argv)
{
	char *dev = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	char filter_exp[] = "icmp and src net 192.168.15.5";		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int num_packets = 1;			/* number of packets to capture */

	/* check for capture device name on command-line */
	if (argc == 2) {
		dev = argv[1];
	}
	else if (argc > 2) {
		fprintf(stderr, "error: unrecognized command-line options\n\n");
		print_app_usage();
		exit(EXIT_FAILURE);
	}
	else {
		/* find a capture device if not specified on command-line */
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n",
			    errbuf);
			exit(EXIT_FAILURE);
		}
	}
	
	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* print capture info */
	printf("Device: %s\n", dev);
	printf("Number of packets: %d\n", num_packets);
	printf("Filter expression: %s\n", filter_exp);

	// while (1) {
		/* open capture device */
		handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
			exit(EXIT_FAILURE);
		}

		/* make sure we're capturing on an Ethernet device [2] */
		if (pcap_datalink(handle) != DLT_EN10MB) {
			fprintf(stderr, "%s is not an Ethernet\n", dev);
			exit(EXIT_FAILURE);
		}

		/* compile the filter expression */
		if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
			fprintf(stderr, "Couldn't parse filter %s: %s\n",
			    filter_exp, pcap_geterr(handle));
			exit(EXIT_FAILURE);
		}

		/* apply the compiled filter */
		if (pcap_setfilter(handle, &fp) == -1) {
			fprintf(stderr, "Couldn't install filter %s: %s\n",
			    filter_exp, pcap_geterr(handle));
			exit(EXIT_FAILURE);
		}

		/* now we can set our callback function */
		pcap_loop(handle, -(num_packets), ICMP_Spoofer, NULL);

		/* cleanup */
		pcap_freecode(&fp);
		pcap_close(handle);
	// }

	printf("\nSniff-and-Spoof complete.\n");

return 0;
}

