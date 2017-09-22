/* 6bed4/peer.c -- Peer-to-Peer IPv6-anywhere with 6bed4 -- peer.c
 *
 * This is an implementation of neighbour and router discovery over a
 * tunnel that packs IPv6 inside UDP/IPv4.  This tunnel mechanism is
 * so efficient that the server administrators need not mind if it is
 * distributed widely.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <fcntl.h>
#include <time.h>

#include <syslog.h>
#ifndef LOG_PERROR
#define LOG_PERROR LOG_CONS		/* LOG_PERROR is non-POSIX, LOG_CONS is */
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/select.h>
#include <sys/ioctl.h>

#include <net/if.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>

#include <asm/types.h>
//#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/if_ether.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

/* The following will initially fail, due to an IANA obligation to avoid
 * default builds with non-standard options.
 */
#include "nonstd.h"


#define MTU 1280
#define PREFIX_SIZE 114

typedef enum {
	METRIC_LOW,
	METRIC_MEDIUM,
	METRIC_HIGH
} metric_t;

/*
 * The HAVE_SETUP_TUNNEL variable is used to determine whether absense of
 * the -d option leads to an error, or to an attempt to setup the tunnel.
 * The setup_tunnel() function used for that is defined per platform, such
 * as for LINUX.  Remember to maintain the manpage's optionality for -d.
 */
#undef HAVE_SETUP_TUNNEL


/* Global variables */

char *program;

int rtsox = -1;
int v4sox = -1;
int v6sox = -1;
int v4mcast = -1;

uint8_t v4qos = 0;		/* Current QoS setting on UDP/IPv4 socket */
uint32_t v6tc = 0;		/* Current QoS used by the IPv6 socket */
uint8_t v4ttl = 64;		/* Default TTL setting on UDP/IPv4 socket */
int v4ttl_mcast = -1;		/* Multicast TTL for LAN explorations */

char *v4server = NULL;
char *v6server = NULL;
char v6prefix [INET6_ADDRSTRLEN];
uint8_t v6lladdr [6];

const uint8_t v6listen_linklocal [16] = { 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
uint8_t v6listen_linklocal_complete [16] = { 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

struct sockaddr_nl rtname;
struct sockaddr_nl rtkernel;

struct sockaddr_in  v4name;
struct sockaddr_in  v4peer;
struct sockaddr_in6 v6name;

struct sockaddr_in v4bind;
struct sockaddr_in v4allnodes;

struct in6_addr v6listen;
//TODO:NEEDNOT// struct in6_addr v6listen_complete;
struct in_addr  v4listen;


struct {
	struct ethhdr eth;
	union {
		struct {
			struct ip6_hdr v6hdr;
			uint8_t data [MTU - sizeof (struct ip6_hdr)];
		} idata;
		struct {
			struct ip6_hdr v6hdr;
			struct icmp6_hdr v6icmphdr;
		} ndata;
	} udata;
} __attribute__((packed)) v4data6;

#define v4ether 	(v4data6.eth)
#define v4data		((uint8_t *) &v4data6.udata)
#define v4hdr6		(&v4data6.udata.idata.v6hdr)
#define v4src6		(&v4data6.udata.idata.v6hdr.ip6_src)
#define v4dst6		(&v4data6.udata.idata.v6hdr.ip6_dst)

#define v4v6plen	(v4data6.udata.ndata.v6hdr.ip6_plen)
#define v4v6nexthdr	(v4data6.udata.ndata.v6hdr.ip6_nxt)
#define v4v6hoplimit	(v4data6.udata.ndata.v6hdr.ip6_hops)

#define v4icmp6		(&v4data6.udata.ndata.v6icmphdr)
#define v4v6icmpdata	(v4data6.udata.ndata.v6icmphdr.icmp6_data8)
#define v4v6icmptype	(v4data6.udata.ndata.v6icmphdr.icmp6_type)
#define v4v6icmpcode	(v4data6.udata.ndata.v6icmphdr.icmp6_code)
#define v4v6icmpcksum	(v4data6.udata.ndata.v6icmphdr.icmp6_cksum)
#define v4v6ndtarget	(&v4data6.udata.ndata.v6icmphdr.icmp6_data8 [4])


struct {
	struct ethhdr eth;
	union {
		uint8_t data [MTU];
		struct {
			struct ip6_hdr v6hdr;
			struct icmp6_hdr v6icmp;
		} __attribute__((packed)) ndata;
	} udata;
}  __attribute__((packed)) v6data6;

#define v6ether		(v6data6.eth)
#define v6data		(v6data6.udata.data)
#define v6hdr6		(&v6data6.udata.ndata.v6hdr)
#define v6hops		(v6data6.udata.ndata.v6hdr.ip6_hops)
#define v6type		(v6data6.udata.ndata.v6hdr.ip6_nxt)
#define v6plen		(v6data6.udata.ndata.v6hdr.ip6_plen)
#define v6src6		(&v6data6.udata.ndata.v6hdr.ip6_src)
#define v6dst6		(&v6data6.udata.ndata.v6hdr.ip6_dst)
#define v6icmp6type	(v6data6.udata.ndata.v6icmp.icmp6_type)
#define v6icmp6code	(v6data6.udata.ndata.v6icmp.icmp6_code)
#define v6icmp6data	(v6data6.udata.ndata.v6icmp.icmp6_data8)
#define v6icmp6csum	(v6data6.udata.ndata.v6icmp.icmp6_cksum)
#define v6ndtarget	(&v6data6.udata.ndata.v6icmp.icmp6_data16[2])


/* Structure for tasks in neighbor discovery queues
 */
struct ndqueue {
	struct ndqueue *next;
	struct timeval tv;
	struct in6_addr source;
	struct in6_addr target;
	uint8_t source_lladdr [6];
	uint8_t todo_lancast, todo_direct;
};

/* Round-robin queue for regular tasks, starting at previous value */
struct ndqueue *ndqueue = NULL;
struct ndqueue *freequeue = NULL;
uint32_t freequeue_items = 100;

/* The time for the next scheduled maintenance: routersol or keepalive.
 * The milliseconds are always 0 for maintenance tasks.
 */
time_t maintenance_time_sec;
time_t maintenance_time_cycle = 0;
time_t maintenance_time_cycle_max = 30;
bool got_lladdr = false;
time_t keepalive_period = 30;
time_t keepalive_ttl = -1;

/* The network packet structure of a 6bed4 Router Solicitation */

uint8_t ipv6_router_solicitation [] = {
	// IPv6 header
	0x60, 0x00, 0x00, 0x00,
	16 >> 8, 16 & 0xff, IPPROTO_ICMPV6, 255,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,		 // unspecd src
	0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, // all-rtr tgt
	// ICMPv6 header: router solicitation
	ND_ROUTER_SOLICIT, 0, 0x7a, 0xae,	// Checksum courtesy of WireShark :)
	// ICMPv6 body: reserved
	0, 0, 0, 0,
	// ICMPv6 option: source link layer address 0x0001 (end-aligned)
	0x01, 0x01, 0, 0, 0, 0, 0x00, 0x01,
};

uint8_t ipv6_defaultrouter_neighbor_advertisement [] = {
	// IPv6 header
	0x60, 0x00, 0x00, 0x00,
	32 >> 8, 32 & 0xff, IPPROTO_ICMPV6, 255,
	0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,	// src is default router
	0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,// dst is all-nodes multicast, portable?
	// ICMPv6 header: neighbor solicitation
	ND_NEIGHBOR_ADVERT, 0, 0x36, 0xf2,		// Checksum courtesy of WireShark :)
	// ICMPv6 Neighbor Advertisement: flags
	0x40, 0, 0, 0,
	// Target: fe80::
	0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,	// the targeted neighbor
	// ICMPv6 option: target link layer address
	2, 1,
	UDP_PORT_6BED4 & 0xff, UDP_PORT_6BED4 >> 8,
	SERVER_6BED4_IPV4_INT0, SERVER_6BED4_IPV4_INT1, SERVER_6BED4_IPV4_INT2, SERVER_6BED4_IPV4_INT3
};

uint8_t router_linklocal_address [] = {
	0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x00,
};

//TODO// Complete with the if-id of the 6bed4 Router:
uint8_t router_linklocal_address_complete [] = {
	0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x00,
};

uint8_t client1_linklocal_address [] = {
	0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x01,
};

uint8_t allnodes_linklocal_address [] = {
	0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x01,
};

uint8_t allrouters_linklocal_address [] = {
	0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x02,
};

uint8_t solicitednodes_linklocal_prefix [13] = {
	0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xff
};

bool default_route = false;

bool foreground = false;

bool log_to_stderr = false;

bool multicast = true;


/*
 *
 * Driver routines
 *
 */

#ifdef LINUX
#define HAVE_SETUP_TUNNEL
static struct ifreq ifreq;
static bool have_tunnel = false;
/* Implement the setup_tunnel() command for Linux.
 * Return true on success, false on failure.
 */
bool setup_tunnel (void) {
	if (v6sox == -1) {
		v6sox = open ("/dev/net/tun", O_RDWR);
	}
	if (v6sox == -1) {
		syslog (LOG_ERR, "%s: Failed to access tunnel driver on /dev/net/tun: %s\n", program, strerror (errno));
		return 0;
	}
	bool ok = true;
	int flags = fcntl (v6sox, F_GETFL, 0);
	if (flags == -1) {
		syslog (LOG_CRIT, "Failed to retrieve flags for the tunnel file descriptor: %s\n", strerror (errno));
		ok = false;
	}
	if (!have_tunnel) {
		memset (&ifreq, 0, sizeof (ifreq));
		strncpy (ifreq.ifr_name, "6bed4", IFNAMSIZ);
		ifreq.ifr_flags = IFF_TAP | IFF_NO_PI;
		if (ok && (ioctl (v6sox, TUNSETIFF, (void *) &ifreq) == -1)) {
			syslog (LOG_CRIT, "Failed to set interface name: %s\n", strerror (errno));
			ok = false;
		} else {
			have_tunnel = ok;
		}
		ifreq.ifr_name [IFNAMSIZ] = 0;
		ifreq.ifr_ifindex = if_nametoindex (ifreq.ifr_name);
syslog (LOG_DEBUG, "Found Interface Index %d for name %s\n", ifreq.ifr_ifindex, ifreq.ifr_name);
		ok = ok & (ifreq.ifr_ifindex != 0);
	}
	char cmd [512+1];
	snprintf (cmd, 512, "/sbin/sysctl -q -w net.ipv6.conf.%s.forwarding=0", ifreq.ifr_name);
	if (ok && system (cmd) != 0) {
		ok = false;
	}
	snprintf (cmd, 512, "/sbin/sysctl -q -w net.ipv6.conf.%s.accept_dad=0", ifreq.ifr_name);
	if (ok && system (cmd) != 0) {
		ok = false;
	}
	if (!ok) {
		close (v6sox);	/* This removes the tunnel interface */
		v6sox = -1;
	}
	return ok;
}
bool setup_tunnel_address (void) {
	bool ok = have_tunnel;
	char cmd [512+1];

	snprintf (cmd, 512, "/sbin/sysctl -q -w net.ipv6.conf.%s.autoconf=0", ifreq.ifr_name);
	if (ok && system (cmd) != 0) {
		ok = 0;
	}
#ifdef TODO_NO_LLADDR_FOR_NOW
	snprintf (cmd, 512, "/sbin/ip link set %s address %02x:%02x:%02x:%02x:%02x:%02x", ifreq.ifr_name, v6lladdr [0], v6lladdr [1], v6lladdr [2], v6lladdr [3], v6lladdr [4], v6lladdr [5]);
	if (ok && system (cmd) != 0) {
syslog (LOG_CRIT, "Bad news!\n");
		ok = false;
	}
#endif
	snprintf (cmd, 512, "/sbin/ip link set %s up mtu %d", ifreq.ifr_name, MTU);
	if (ok && system (cmd) != 0) {
		ok = false;
	}
	snprintf (cmd, 512, "/sbin/ip -6 addr add %s/114 dev %s", v6prefix, ifreq.ifr_name);
	if (ok && system (cmd) != 0) {
		ok = false;
	}
	if (default_route) {
		snprintf (cmd, 512, "/sbin/ip -6 route add default via fe80:: dev %s", ifreq.ifr_name);
		if (ok && system (cmd) != 0) {
			ok = false;
		}
	}
	return ok;
}
#endif /* LINUX */


/*
 *
 * Utility functions
 *
 */



/* Produce an IPv6 address following the 6bed4 structures.
 *  - The top half is taken from v6listen
 *  - The bottom contains IPv4 address and port from v4name
 *  - The last 14 bits are filled with the lanip parameter
 */
void addr_6bed4 (struct in6_addr *dst_ip6, uint16_t lanip) {
	memcpy (&dst_ip6->s6_addr [0], &v6listen, 8);
	dst_ip6->s6_addr32 [2] = v4name.sin_addr.s_addr;
	dst_ip6->s6_addr16 [6] = v4name.sin_port;
	dst_ip6->s6_addr  [14] = ((dst_ip6->s6_addr [8] & 0x03) << 6)
	                       | ((lanip >> 8) & 0x3f);
	dst_ip6->s6_addr  [15] = (lanip & 0xff);
	dst_ip6->s6_addr  [8] &= 0xfc;
}

/* Look for an entry in the 50ms-cycled Neighbor Discovery queue.
 * Match the target address.  Return the entry found, or NULL.
 */
struct ndqueue *findqueue (struct in6_addr *target) {
	struct ndqueue *ndq = ndqueue;
	if (ndq) {
		do {
			if (memcmp (target, &ndq->target, 16) == 0) {
				return ndq;
			}
			ndq = ndq->next;
		} while (ndq != ndqueue);
	}
	return NULL;
}

/* Enter an item in the 50ms-cycled Neighbor Discovery queue.
 * Retrieve its storage space from the free queue.
 * TODO: Avoid double entries by looking up entries first -> "requeue?"
 */
static int TODO_qlen;
void enqueue (struct in6_addr *target, struct in6_addr *v6src, uint8_t *source_lladdr) {
	//
	// Refuse to create double entries
	if (findqueue (target)) {
		return;
	}
	//
	// Allocate a free item to enqueue
	struct ndqueue *new = freequeue;
	if (!new) {
		// Temporarily overflown with ND -> drop the request
		return;
	}
char tgt [INET6_ADDRSTRLEN]; inet_ntop (AF_INET6, target, tgt, sizeof (tgt));
syslog (LOG_DEBUG, "Queue++ => %d, looking for %s\n", ++TODO_qlen, tgt);
	freequeue = freequeue->next;
	//
	// Setup the new entry with target details
	memcpy (&new->target, target, sizeof (new->target));
	memcpy (&new->source, v6src, sizeof (new->source));
	memcpy (&new->source_lladdr, source_lladdr, sizeof (new->source_lladdr));
	new->todo_lancast = (v4mcast == -1)? 0: 2;
	new->todo_direct = 3;
	//
	// Time the new item to run instantly
	new->tv.tv_sec = 0;
	//
	// Enqueue the new item in front of the queue
	if (ndqueue) {
		new->next = ndqueue->next;
		ndqueue->next = new;
	} else {
		new->next = new;
		ndqueue = new;
	}
}

/* Remove an item from the 50ms-cycled Neighbor Discovery queue.
 * Enter its storage space in the free queue.
 */
void dequeue (struct ndqueue *togo) {
	struct ndqueue *prev = ndqueue;
	do {
		if (prev->next == togo) {
			if (togo->next != togo) {
				prev->next = togo->next;
				if (ndqueue == togo) {
					ndqueue = togo->next;
				}
			} else {
				// Must be the only queued item
				ndqueue = NULL;
			}
			togo->next = freequeue;
			freequeue = togo;
syslog (LOG_DEBUG, "Queue-- => %d\n", --TODO_qlen);
			return;
		}
		prev = prev->next;
	} while (prev != ndqueue);
}


/*
 * Calculate the ICMPv6 checksum field
 */
uint16_t icmp6_checksum (uint8_t *ipv6hdr, size_t payloadlen) {
	uint16_t plenword = htons (payloadlen);
	uint16_t nxthword = htons (IPPROTO_ICMPV6);
	uint16_t *areaptr [] = { (uint16_t *) &ipv6hdr [8], (uint16_t *) &ipv6hdr [24], &plenword, &nxthword, (uint16_t *) &ipv6hdr [40], (uint16_t *) &ipv6hdr [40 + 4] };
	uint8_t areawords [] = { 8, 8, 1, 1, 1, payloadlen/2 - 2 };
	uint32_t csum = 0;
	u_int8_t i, j;
	for (i=0; i < 6; i++) {
		uint16_t *area = areaptr [i];
		for (j=0; j<areawords [i]; j++) {
			csum += ntohs (area [j]);
		}
	}
	csum = (csum & 0xffff) + (csum >> 16);
	csum = (csum & 0xffff) + (csum >> 16);
	csum = htons (~csum);
	return csum;
}


/*
 * Send a Redirect reply.  This is in response to a v4v6data message,
 * and is directed straight at the origin's address but sent with a
 * lower metric.
 *
 * Note: Although the packet arrived in v4data6, the reply is built
 *       in v6data6 and sent from there as though it had come from
 *       the IPv6 stack.
 */
void redirect_reply (uint8_t *ngbc_llremote, metric_t ngbc_metric) {
	void handle_6to4_plain_unicast (const ssize_t pktlen, const uint8_t *lladdr);
	v6icmp6type = ND_REDIRECT;
	v6icmp6code = 0;
	v6icmp6data [0] =
	v6icmp6data [1] =
	v6icmp6data [2] =
	v6icmp6data [3] = 0;		// Reserved
	memcpy (v6icmp6data + 4, &v6listen, 16);
					// Target IPv6 address
	switch (ngbc_metric) {
					// Destination Address suggestion
	case METRIC_LOW:
		//
		// Redirect to the local-subnet IPv4 address
		memcpy (v6icmp6data + 4 + 16, v6listen_linklocal, 8);
		v6icmp6data [4 + 16 + 8 ] = v4peer.sin_port & 0x00ff;
		v6icmp6data [4 + 16 + 9 ] = v4peer.sin_port >> 8;
		memcpy (v6icmp6data + 4 + 16 + 12, &v4peer.sin_addr, 4);
		v6icmp6data [4 + 16 + 10] = v4v6icmpdata [4 + 16 + 12];
		v6icmp6data [4 + 16 + 11] = 0xff;
		v6icmp6data [4 + 16 + 12] = 0xfe;
		break;
	case METRIC_MEDIUM:
		memcpy (v6icmp6data + 4 + 16, v6listen_linklocal_complete, 16);
		break;
	case METRIC_HIGH:
	default:
		return;		/* no cause for Redirect, drop */
	}
	v6type = IPPROTO_ICMPV6;
	v6plen = htons (8 + 16 + 16);
	memcpy (v6src6, &v6listen, 16);
	memcpy (v6dst6, v4src6, 16);
	v6icmp6csum = icmp6_checksum ((uint8_t *) v4hdr6, 8 + 16 + 16);
	handle_6to4_plain_unicast (sizeof (struct ethhdr) + 40 + 8 + 16 + 16, ngbc_llremote);
} 


/* Append the current prefix to an ICMPv6 message.  Incoming optidx
 * and return values signify original and new offset for ICMPv6 options.
 * The endlife parameter must be set to obtain zero lifetimes, thus
 * instructing the tunnel client to stop using an invalid prefix.
 */
size_t icmp6_prefix (size_t optidx, uint8_t endlife) {
	v6icmp6data [optidx++] = 3;	// Type
	v6icmp6data [optidx++] = 4;	// Length
	v6icmp6data [optidx++] = 114;	// This is a /114 prefix
#ifndef COMPENSATE_FOR_AUTOCONF
	v6icmp6data [optidx++] = 0xc0;	// L=1, A=1, Reserved1=0
#else
	//TODO// Temporary fix: "ip -6 addr add .../64 dev 6bed4"
	v6icmp6data [optidx++] = 0x80;	// L=1, A=0, Reserved1=0
#endif
	memset (v6icmp6data + optidx, endlife? 0x00: 0xff, 8);
	optidx += 8;
					// Valid Lifetime: Zero / Infinite
					// Preferred Lifetime: Zero / Infinite
	memset (v6icmp6data + optidx, 0, 4);
	optidx += 4;
					// Reserved2=0
	addr_6bed4 ((struct in6_addr *) (v6icmp6data + optidx), 0);
					// Set IPv6 prefix
	optidx += 16;
	return optidx;
}


/*
 * Construct a Neighbor Advertisement message, providing the
 * Public 6bed4 Service as the link-local address.
 *
 * This is done immediately when the IPv6 stack requests the link-local
 * address for fe80:: through Router Solicition.  In addition, it is the
 * fallback response used when attempts to contact the remote peer at its
 * direct IPv4 address and UDP port (its 6bed4 address) fails repeatedly.
 *
 * This routine is called with info==NULL to respond to an fe80::
 * Neighbor Solicitation, otherwise with an info pointer containing
 * a target IPv6 address to service.
 */
void advertise_6bed4_public_service (struct ndqueue *info) {
	if (info) {
		memcpy (v6ether.h_dest, info->source_lladdr, 6);
	} else {
		memcpy (v6ether.h_dest, v6ether.h_source, 6);
	}
	memcpy (v6ether.h_source, SERVER_6BED4_PORT_IPV4_MACSTR, 6);
	memcpy (v6data, ipv6_defaultrouter_neighbor_advertisement, 8);
	if (info) {
		memcpy (v6dst6, &info->source, 16);
	} else {
		memcpy (v6dst6, v6src6, 16);
	}
	if (info) {
		memcpy (v6src6, &info->target, 16);
	} else {
		memcpy (v6src6, router_linklocal_address_complete, 16);
	}
	//TODO:OVERWROTE// memcpy (v6data + 8, ipv6_defaultrouter_neighbor_advertisement + 8, 16);
	memcpy (v6data + 8 + 16 + 16, ipv6_defaultrouter_neighbor_advertisement + 8 + 16 + 16, sizeof (ipv6_defaultrouter_neighbor_advertisement) - 8 - 16 - 16);
	if (info) {
		// Overwrite target only for queued requests
		memcpy (&v6icmp6data [4], &info->target, 16);
	}
	v6icmp6csum = icmp6_checksum ((uint8_t *) v6hdr6, 32);
	int sent = write (v6sox, &v6data6, sizeof (struct ethhdr) + sizeof (ipv6_defaultrouter_neighbor_advertisement));
	if (info) {
		syslog (LOG_DEBUG, "TODO: Neighbor Discovery failed to contact directly -- standard response provided\n");
	} else {
		syslog (LOG_DEBUG, "TODO: Neighbor Discovery for Public 6bed4 Service -- standard response provided\n");
	}
}


/*
 * Validate the originator's IPv6 address.  It should match the
 * UDP/IPv4 coordinates of the receiving 6bed4 socket.  Also,
 * the /64 prefix (but not the /114 prefix!) must match v6listen.
 */
bool validate_originator (struct in6_addr *ip6) {
	uint32_t addr;
	//
	// Communication from the configured router is welcomed
	//TODO// Why should we trust the ip6 address at face value?
	if ((v4name.sin_addr.s_addr == v4peer.sin_addr.s_addr)
			&& (v4name.sin_port == v4peer.sin_port)) {
		return true;
	}
	//
	// Require non-local top halves to match our v6listen_linklocal address
	//TODO// When do we receive local top halves?
	//TODO// We should really be more flexible and allow fallback addrs
	if (memcmp (ip6, v6listen_linklocal, 8) != 0) {
		if (memcmp (&v6listen, ip6->s6_addr, 8) != 0) {
			return false;
		}
	}
	//
	// Require the sender port to appear in its IPv6 address
	if (v4name.sin_port != ip6->s6_addr16 [6]) {
		return false;
	}
	//
	// Require the sender address to appear in its IPv6 address
	addr = ntohl (ip6->s6_addr32 [2]) & 0xfcffffff;
	addr |= ((uint32_t) (ip6->s6_addr [14] & 0xc0)) << (24-6);
	if (addr != ntohl (v4name.sin_addr.s_addr)) {
		return false;
	}
	//
	// We passed with flying colours
	return true;
}


/*
 * Translate a Link-Local Address to its metric.  The metrics are
 * numbered so that a higher number indicates a more costly path
 * over which to connect.  The values of the metric should not be
 * published, but be treated as an opaque value with a complete
 * ordering (that is: <, <=, >=, > relations) defined on it.
 */
metric_t lladdr_metric (uint8_t *lladdr) {
	uint32_t ipv4 = * (uint32_t *) (lladdr + 2);
	//
	// Metric 2: The 6bed4 Router address
	if (ipv4 == v4peer.sin_addr.s_addr) {
		return METRIC_HIGH;
	}
	//
	// Metric 0: Private Addresses, as per RFC 1918
	if ((ipv4 & 0xff000000) == 0x0a000000) {
		return METRIC_LOW;	/* 10.0.0./8 */
	}
	if ((ipv4 & 0xffff0000) == 0xc0a80000) {
		return METRIC_LOW;	/* 192.168.0.0/16 */
	}
	if ((ipv4 & 0xfff00000) == 0xac100000) {
		return METRIC_LOW;	/* 172.16.0.0/12 */
	}
	//
	// Metric 1: Direct IPv4 contact is any other address
	//           Correctness should be checked elsewhere
	return METRIC_MEDIUM;
}


/*
 * Retrieve the Link-Local Address, if any, for a given 6bed4 Peer.
 * Return true on success, false on failure to find it.  The lladdr
 * parameter is only overwritten in case of success.
 *
 * Obviously, there is a point where it is more efficient to not
 * lookup the cache for every request, but to cache it locally
 * and limit the lookup frequency.  This low-traffic optimal version
 * is used here for initial simplicity, and because this is a peer
 * daemon and a reference implementation.  But who knows what people
 * will submit as patches...
 *
 * Note: This code is specific to Linux, but note that BSD also has a
 *       NetLink concept, so it may port without needing to resort to
 *       shell commands running slowly in separate processes.
 * Note: The interface for Linux is under-documented.  Work may be
 *       needed to handle exception situations, such as going over
 *       invisible boundaries on the number of neighbours.  Similarly,
 *       the use of alignment macros is rather unclear.  This is not
 *       how I prefer to write code, but it's the best I can do now.
 */
bool lookup_neighbor (uint8_t *ipv6, uint8_t *lladdr) {
	struct mymsg {
		struct nlmsghdr hd;
		struct ndmsg nd;
		uint8_t arg [16384];
	} msg;
	memset (&msg, 0, sizeof (struct nlmsghdr) + sizeof (struct ndmsg));
	msg.hd.nlmsg_len = NLMSG_LENGTH (sizeof (msg.nd));
	msg.hd.nlmsg_type = RTM_GETNEIGH;
	msg.hd.nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT /* | NLM_F_MATCH */;
	msg.hd.nlmsg_pid = rtname.nl_pid;
	msg.nd.ndm_family = AF_INET6;
	msg.nd.ndm_state = NUD_REACHABLE | NUD_DELAY | NUD_PROBE | NUD_PERMANENT | NUD_STALE;	// Ignored by the kernel?
	msg.nd.ndm_ifindex = ifreq.ifr_ifindex;	// Ignored by the kernel?
	// How to select an IPv6 address?  Ignored by the kernel?
#if 0
	struct rtattr *ra1 = (struct rtattr *) (((char *) &msg) + sizeof (struct nlmsghdr) + sizeof (struct ndmsg));
	ra1->rta_type = NDA_DST;	// lookup IPv6 address
	ra1->rta_len = RTA_LENGTH(16);
	msg.hd.nlmsg_len = NLMSG_ALIGN (msg.hd.nlmsg_len) + RTA_LENGTH (16);
	memcpy (RTA_DATA (ra1), ipv6, 16);
#endif
	if (send (rtsox, &msg, msg.hd.nlmsg_len, MSG_DONTWAIT) == -1) {
		return false;
	}
	ssize_t recvlen;
	uint16_t pos = 0;
{ char buf [INET6_ADDRSTRLEN]; inet_ntop (AF_INET6, ipv6, buf, sizeof (buf)); syslog (LOG_DEBUG, "Looking up v6addr %s\n", buf); }
	while (recvlen = recv (rtsox, ((char *) &msg) + pos, sizeof (msg) - pos, MSG_DONTWAIT), recvlen > 0) {
syslog (LOG_DEBUG, "Message of %zd bytes from neighbor cache, total is now %zd\n", recvlen, pos + recvlen);
		recvlen += pos;
		pos = 0;
		struct mymsg *resp;
		while (resp = (struct mymsg *) (((char *) &msg) + pos),
				(pos + sizeof (struct nlmsghdr) <= recvlen) &&
				(pos + resp->hd.nlmsg_len <= recvlen)) {
			bool ok = true, match = false;
			uint8_t *result = NULL;
			if (resp->hd.nlmsg_type == NLMSG_DONE) {
				return false;
			} else if (resp->hd.nlmsg_type != RTM_NEWNEIGH) {
				syslog (LOG_ERR, "Kernel sent an unexpected nlmsg_type 0x%02x, ending neighbor interpretation\n", resp->hd.nlmsg_type);
				ok = false;
			} else if (resp->nd.ndm_ifindex != ifreq.ifr_ifindex) {
				ok = false;
			} else if (resp->nd.ndm_family != AF_INET6) {
				syslog (LOG_ERR, "Kernel reported unknown neighbor family %d\n", resp->nd.ndm_family);
				ok = false;
			} else
			if (!(resp->nd.ndm_state & (NUD_REACHABLE | NUD_DELAY | NUD_PROBE | NUD_PERMANENT | NUD_STALE))) {
				ok = false;
			}
			struct rtattr *ra = (struct rtattr *) ((char *) &resp + pos + sizeof (struct nlmsghdr) + sizeof (struct ndmsg) + 8);
			ssize_t rapos = 0;
			while (ok && (rapos + ra->rta_len <= resp->hd.nlmsg_len)) {
				switch (ra->rta_type) {
				case NDA_DST:
{ char buf [INET6_ADDRSTRLEN]; inet_ntop (AF_INET6, RTA_DATA (ra), buf, sizeof (buf)); syslog (LOG_DEBUG, "Comparing against %s\n", buf); }
					if (memcmp (ipv6, RTA_DATA (ra), 16) == 0) {
						match = true;
					}
					break;
				case NDA_LLADDR:
					result = RTA_DATA (ra);
					break;
				case NDA_PROBES:
				case NDA_CACHEINFO:
				default:
					break;	/* not of interest, skip */
				}
				rapos += ((ra->rta_len - 1) | 0x00000003) + 1;
				ra = (struct rtattr *) (((char *) ra) + (((ra->rta_len - 1) | 0x0000003) + 1));
			}
			if (ok && match && result) {
				memcpy (lladdr, result, 6);
				return true;	/* Yippy! Erfolg! */
			}
			pos += resp->hd.nlmsg_len;
		}
		// Copy remaining partial message to the beginning, continue from there
		memcpy (&msg, ((char *) &msg) + pos, recvlen - pos);
		pos = recvlen - pos;
	}
	return false;
}


/*
 * Major packet processing functions
 */


/* Handle the IPv4 message pointed at by msg, checking if (TODO:HUH?) the IPv4:port
 * data matches the lower half of the IPv6 sender address.  Drop silently
 * if this is not the case.  TODO: or send ICMP?
 */
void handle_4to6_plain (ssize_t v4datalen, struct sockaddr_in *sin) {
	//
	// Send the unwrapped IPv6 message out over v6sox
	v4ether.h_proto = htons (ETH_P_IPV6);
	memcpy (v4ether.h_dest,   v6lladdr, 6);
	v4ether.h_source [0] = ntohs (sin->sin_port) & 0xff;
	v4ether.h_source [1] = ntohs (sin->sin_port) >> 8;
	memcpy (v4ether.h_source + 2, &sin->sin_addr, 4);
syslog (LOG_INFO, "Writing IPv6, result = %zd\n",
	write (v6sox, &v4data6, sizeof (struct ethhdr) + v4datalen)
)
	;
}


/* Handle the IPv4 message pointed at by msg as a neighbouring command.
 *
 * Type	Code	ICMPv6 meaning			Handling
 * ----	----	-----------------------------	----------------------------
 * 133	0	Router Solicitation		Ignore
 * 134	0	Router Advertisement		Setup Tunnel with Prefix
 * 135	0	Neighbour Solicitation		Send Neighbour Advertisement
 * 136	0	Neighbour Advertisement		Ignore
 * 137	0	Redirect			Ignore
 */
void handle_4to6_nd (struct sockaddr_in *sin, ssize_t v4ngbcmdlen) {
	uint16_t srclinklayer;
	uint8_t *destprefix = NULL;
#ifdef TODO_DEPRECATED
	uint8_t *destlladdr = NULL;
#endif
	struct ndqueue *ndq;
	if (v4ngbcmdlen < sizeof (struct ip6_hdr) + sizeof (struct icmp6_hdr)) {
		return;
	}
	//
	if (v4v6icmpcode != 0) {
		return;
	}
	if (icmp6_checksum (v4data, v4ngbcmdlen - sizeof (struct ip6_hdr)) != v4v6icmpcksum) {
		return;
	}
	//
	// Approved.  Perform neighbourly courtesy.
	switch (v4v6icmptype) {
	case ND_ROUTER_SOLICIT:
		return;		/* this is not a router, drop */
	case ND_ROUTER_ADVERT:
		//
		// Validate Router Advertisement
		if (ntohs (v4v6plen) < sizeof (struct icmp6_hdr) + 16) {
			return;   /* strange length, drop */
		}
		if (v4v6icmpdata [1] & 0x80 != 0x00) {
			return;   /* indecent proposal to use DHCPv6, drop */
		}
		if (memcmp (&v4src6->s6_addr, router_linklocal_address, 16) != 0) {
			return;   /* not from router, drop */
		}
		if (memcmp (&v4dst6->s6_addr, client1_linklocal_address, 8) != 0) {
			if (memcmp (&v4dst6->s6_addr, allnodes_linklocal_address, 16) != 0) {
				return;   /* no address setup for me, drop */
			}
		}
		if (v4dst6->s6_addr [8] & 0x01) {
			syslog (LOG_WARNING, "TODO: Ignoring (by accepting) an odd public UDP port revealed in a Router Advertisement -- this could cause confusion with multicast traffic\n");
		}
		size_t rdofs = 12;
		//TODO:+4_WRONG?// while (rdofs <= ntohs (v4v6plen) + 4) { ... }
		while (rdofs + 4 < ntohs (v4v6plen)) {
			if (v4v6icmpdata [rdofs + 1] == 0) {
				return;   /* zero length option */
			}
#ifdef TODO_DEPRACATED
			if ((v4v6icmpdata [rdofs + 0] == ND_OPT_DESTINATION_LINKADDR) && (v4v6icmpdata [rdofs + 1] == 1)) {
				if (v4v6icmpdata [rdofs + 2] & 0x01) {
					syslog (LOG_WARNING, "TODO: Ignoring an odd UDP port offered in a Router Advertisement over 6bed4\n");
				}
				syslog (LOG_INFO, "TODO: Set tunnel link-local address to %02x:%02x:%02x:%02x:%02x:%02x\n", v4v6icmpdata [rdofs + 2], v4v6icmpdata [rdofs + 3], v4v6icmpdata [rdofs + 4], v4v6icmpdata [rdofs + 5], v4v6icmpdata [rdofs + 6], v4v6icmpdata [rdofs + 7]);
				destlladdr = &v4v6icmpdata [rdofs + 2];
				/* continue with next option */
			} else
#endif
			if (v4v6icmpdata [rdofs + 0] != ND_OPT_PREFIX_INFORMATION) {
				/* skip to next option */
			} else if (v4v6icmpdata [rdofs + 1] != 4) {
				return;   /* bad length field */
			} else if (rdofs + (v4v6icmpdata [rdofs + 1] << 3) > ntohs (v4v6plen) + 4) {
				return;   /* out of packet length */
			} else if (v4v6icmpdata [rdofs + 3] & 0xc0 != 0xc0) {
				/* no on-link autoconfig prefix */
			} else if (v4v6icmpdata [rdofs + 2] != PREFIX_SIZE) {
				/* not a /114 prefix, so no 6bed4 offer */
				return;
			} else {
				destprefix = &v4v6icmpdata [rdofs + 16];
			}
			rdofs += (v4v6icmpdata [rdofs + 1] << 3);
		}
		if (destprefix) {
			memcpy (v6listen.s6_addr + 0, destprefix, 16);
			v6listen.s6_addr [14] &= 0xc0;
			v6listen.s6_addr [15]  = 0x01;	// choose client 1
			int prefixBits = PREFIX_SIZE;
			int i;
			for (i = 0; prefixBits >= 8; i++) {
				v6listen_linklocal_complete [i] = v6listen_linklocal [i];
				prefixBits -= 8;
			}
			if (prefixBits > 0) {
				int mask = (1 << (8 - prefixBits)) - 1;
				v6listen_linklocal_complete [i] = v6lladdr [i] = (v6listen_linklocal [i] & ~mask) | (v6listen.s6_addr [i] & mask);
				i++;
			}
			while (i < 16) {
				v6listen_linklocal_complete [i] = v6lladdr [i] = v6listen.s6_addr [i];
				i++;
			}

//			memcpy (v6listen_linklocal_complete+0,
//					v6listen_linklocal, 8);
//			memcpy (v6listen_linklocal_complete+8,
//					v6listen.s6_addr+8, 8);
//			memcpy (v6lladdr, v6listen_linklocal_complete+8, 8);
			//TODO// Is v6lladdr useful?  Should it include lanip?
			v6lladdr [0] &= 0xfc;
			v6lladdr [0] |= (v6listen_linklocal_complete [14] >> 6);
			inet_ntop (AF_INET6,
				&v6listen,
				v6prefix,
				sizeof (v6prefix));
			syslog (LOG_INFO, "%s: Assigning address %s to tunnel\n", program, v6prefix);
			setup_tunnel_address ();  //TODO// parameters?
			got_lladdr = true;
			maintenance_time_cycle = maintenance_time_cycle_max;
			maintenance_time_sec = time (NULL) + maintenance_time_cycle;
		}
		return;
	case ND_NEIGHBOR_SOLICIT:
		//
		// Validate Neigbour Solicitation (trivial)
		//
		// Replicate the message over the IPv6 Link (like plain IPv6)
		if (v4ngbcmdlen < 24) {
			return;		/* too short, drop */
		}
		syslog (LOG_DEBUG, "%s: Replicating Neighbor Solicatation from 6bed4 to the IPv6 Link\n", program);
char buf [INET6_ADDRSTRLEN]; uint8_t ll [6]; if ((memcmp (v4src6, v6listen_linklocal, 8) != 0) && (memcmp (v4src6, &v6listen, 8) != 0)) { inet_ntop (AF_INET6, v4src6, buf, sizeof (buf)); syslog (LOG_DEBUG, "Source IPv6 address %s from wrong origin\n", buf); } else { uint8_t pfaddr [16]; memcpy (pfaddr, v6listen.s6_addr, 8); memcpy (pfaddr + 8, v4src6->s6_addr + 8, 8); inet_ntop (AF_INET6, pfaddr, buf, sizeof (buf)); if (lookup_neighbor (pfaddr, ll)) { syslog (LOG_DEBUG, "Source IPv6 %s has Link-Local Address %02x:%02x:%02x:%02x:%02x:%02x with metric %d\n", buf, ll [0], ll [1], ll [2], ll [3], ll [4], ll [5], lladdr_metric (ll)); } else { syslog (LOG_DEBUG, "Source IPv6 %s is unknown to me\n", buf); } }
uint8_t optofs = 4 + 16;
#if 0
uint8_t *srcll = NULL;	/* TODO -- use 6bed4 Network sender instead! */
while ((40 + 4 + optofs + 2 < v4ngbcmdlen) && (40 + 4 + optofs + 8 * v4v6icmpdata [optofs + 1] <= v4ngbcmdlen)) {
if (v4v6icmpdata [optofs] == 1) {
srcll = v4v6icmpdata + optofs + 2;
}
optofs += 8 * v4v6icmpdata [optofs + 1];
}
if (srcll) { syslog (LOG_DEBUG, "ND-contained Source Link-Layer Address %02x:%02x:%02x:%02x:%02x:%02x has metric %d\n", srcll [0], srcll [1], srcll [2], srcll [3], srcll [4], srcll [5], lladdr_metric (srcll)); }
#endif
		//
		// We should attach a Source Link-Layer Address, but
		// we cannot automatically trust the one provided remotely.
		// Also, we want to detect if routes differ, and handle it.
		//
		// 0. if no entry in the ngb.cache
		//    then use 6bed4 server in ND, initiate ngb.sol to src.ll
		//         impl: use 6bed4-server lladdr, set highest metric
		// 1. if metric (ngb.cache) < metric (src.ll)
		//    then retain ngb.cache, send Redirect to source
		// 2. if metric (ngb.cache) > metric (src.ll)
		//    then retain ngb.cache, initiate ngb.sol to src.ll
		// 3. if metric (ngb.cache) == metric (src.ll)
		//    then retain ngb.cache
		//
		uint8_t src_lladdr [6];
		src_lladdr [0] = ntohs (v4name.sin_port) & 0x00ff;
		src_lladdr [1] = ntohs (v4name.sin_port) >> 8;
		memcpy (src_lladdr + 2, &v4name.sin_addr, 4);
		metric_t src_metric = lladdr_metric (src_lladdr);
		v4v6icmpdata [4+16+0] = 1;	/* Option: Source LLaddr */
		v4v6icmpdata [4+16+1] = 1;	/* Length: 1x 8 bytes */
		uint8_t *ngbc_lladdr = v4v6icmpdata + 4+16+2;
		uint8_t ngbc_ipv6 [16];
		if (memcmp (v4src6, v6listen_linklocal, 8)) {
			memcpy (ngbc_ipv6 + 0, &v6listen, 8);
			memcpy (ngbc_ipv6 + 8, v4src6 + 8, 8);
		} else {
			memcpy (ngbc_ipv6, v4src6, 16);
		}
		bool ngbc_cached = lookup_neighbor (ngbc_ipv6, ngbc_lladdr);
		metric_t ngbc_metric;
		if (ngbc_cached) {
			ngbc_metric = lladdr_metric (ngbc_lladdr);
		} else {
			ngbc_metric = METRIC_HIGH; /* trigger local ngbsol */
			memcpy (ngbc_lladdr, SERVER_6BED4_PORT_IPV4_MACSTR, 6);
syslog (LOG_DEBUG, "Failed to find neighbor in cache, initialising it with the high metric\n");
		}
		syslog (LOG_DEBUG, "Metric analysis: source lladdr %02x:%02x:%02x:%02x:%02x:%02x metric %d, neighbor cache lladdr %02x:%02x:%02x:%02x:%02x:%02x metric %d\n", src_lladdr [0], src_lladdr [1], src_lladdr [2], src_lladdr [3], src_lladdr [4], src_lladdr [5], src_metric, ngbc_lladdr [0], ngbc_lladdr [1], ngbc_lladdr [2], ngbc_lladdr [3], ngbc_lladdr [4], ngbc_lladdr [5], ngbc_metric);
		//
		// Replicate the ngb.sol with the selected ngbc-lladdr
		v4v6icmpcksum = icmp6_checksum ((uint8_t *) v4hdr6, 8 + 16 + 8);
		handle_4to6_plain (40 + 24 + 8, &v4name);
		//
		// If needed, initiate Neigbor Solicitation to the source
		// Note: Also when !ngbc_cached as the router is then cached
		if (ngbc_metric > src_metric) {
syslog (LOG_DEBUG, "Trying to find the more direct route that the remote peer seems to be using\n");
			enqueue ((struct in6_addr *) v4src6, &v6listen, v6lladdr);
		}
		//
		// If needed, ask the source to redo Neighbor Solicitation
		if (ngbc_metric < src_metric) {
syslog (LOG_DEBUG, "Redirecting the remote peer to the more efficient route that I am using\n");
			redirect_reply (ngbc_lladdr, ngbc_metric);
		}
		return;
	case ND_NEIGHBOR_ADVERT:
		//
		// Process Neighbor Advertisement coming in over 6bed4
		// First, make sure it is against an item in the ndqueue
		ndq = findqueue ((struct in6_addr *) v4v6ndtarget);
		if (!ndq) {
			// Ignore advertisement -- it may be an attack
			return;
		}
		// Remove the matching item from the ndqueue
		dequeue (ndq);
		// Replicate the Neigbor Advertisement over the IPv6 Link (like plain IPv6)
		v4v6icmpdata [0] |= 0xe0;	/* Router, Solicited, Override */
		v4v6icmpdata [20] = 2;		/* Target Link-Layer Address */
		v4v6icmpdata [21] = 1;		/* Length: 1x 8 bytes */
		v4v6icmpdata [22] = ntohs (v4name.sin_port) & 0xff;
		v4v6icmpdata [23] = ntohs (v4name.sin_port) >> 8;
		memcpy (v4v6icmpdata + 24, &v4name.sin_addr, 4);
		v4v6plen = htons (24 + 8);
		v4v6icmpcksum = icmp6_checksum ((uint8_t *) v4hdr6, 24 + 8);
		handle_4to6_plain (sizeof (struct ip6_hdr) + 24 + 8, &v4name);
		return;
	case ND_REDIRECT:
		//
		// Redirect indicates that a more efficient bypass exists than
		// the currently used route.  The remote peer has established
		// this and wants to share that information to retain a
		// symmetric communication, which is helpful in keeping holes
		// in NAT and firewalls open.
		//
		//TODO// BE EXTREMELY SELECTIVE BEFORE ACCEPTING REDIRECT!!!
		//TODO:NOTYET// enqueue ((struct in6_addr *) v4v6ndtarget, &v6listen, v6lladdr);
		return;
	}
}


/* Receive a tunnel package, and route it to either the handler for the
 * tunnel protocol, or to the handler that checks and then unpacks the
 * contained IPv6.
 */
void handle_4to6 (int v4in) {
	uint8_t buf [1501];
	ssize_t buflen;
	socklen_t adrlen = sizeof (v4name);
	//
	// Receive IPv4 package, which may be tunneled or a tunnel request
	buflen = recvfrom (v4in,
			v4data, MTU,
			MSG_DONTWAIT,
			(struct sockaddr *) &v4name, &adrlen
		);
	if (buflen == -1) {
		syslog (LOG_INFO, "%s: WARNING: Error receiving IPv4-side package: %s\n",
				program, strerror (errno));
		return;		/* receiving error, drop */
	}
	if (buflen <= sizeof (struct ip6_hdr)) {
		return;		/* received too little data, drop */
	}
	if ((v4data [0] & 0xf0) != 0x60) {
		return;		/* not an IPv6 packet, drop */
	}
	if (!validate_originator (v4src6)) {
		return;		/* source appears fake, drop */
	}
	/*
	 * Distinguish types of traffic:
	 * Non-plain, Plain Unicast, Plain Multicast
	 */
	if ((v4v6nexthdr == IPPROTO_ICMPV6) &&
			(v4v6icmptype >= 133) && (v4v6icmptype <= 137)) {
		//
		// Not Plain: Router Adv/Sol, Neighbor Adv/Sol, Redirect
		if (v4v6hoplimit != 255) {
			return;
		}
		handle_4to6_nd (&v4name, buflen);
	} else {
		//
		// Plain Unicast or Plain Multicast (both may enter)
		if (v4v6hoplimit-- <= 1) {
			return;
		}
		handle_4to6_plain (buflen, &v4name);
	}
}


/*
 * Relay an IPv6 package to 6bed4, using the link-local address as it
 * is found in the Ethernet header.  Trust the local IPv6 stack to have
 * properly obtained this destination address through Neighbor Discovery
 * over 6bed4.
 */
void handle_6to4_plain_unicast (const ssize_t pktlen, const uint8_t *lladdr) {
	struct sockaddr_in v4dest;
	memset (&v4dest, 0, sizeof (v4dest));
	v4dest.sin_family = AF_INET;
	v4dest.sin_port = htons (lladdr [0] | (lladdr [1] << 8));
	memcpy (&v4dest.sin_addr, lladdr + 2, 4);
	if (v6tc != (v6hdr6->ip6_vfc & htonl (0x0ff00000))) {
		v6tc = v6hdr6->ip6_vfc & htonl (0x0ff00000);
		v4qos = (ntohl (v6hdr6->ip6_vfc) & 0x0ff00000) >> 24;
		if (setsockopt (v4sox, IPPROTO_IP, IP_TOS, &v4qos, sizeof (v4qos)) == -1) {
			syslog (LOG_ERR, "Failed to switch IPv4 socket to QoS setting 0x%02x\n", v4qos);
		}
	}
	syslog (LOG_DEBUG, "%s: Sending IPv6-UDP-IPv4 to %d.%d.%d.%d:%d, result = %zd\n", program,
	((uint8_t *) &v4dest.sin_addr.s_addr) [0],
	((uint8_t *) &v4dest.sin_addr.s_addr) [1],
	((uint8_t *) &v4dest.sin_addr.s_addr) [2],
	((uint8_t *) &v4dest.sin_addr.s_addr) [3],
	ntohs (v4dest.sin_port),
		sendto (v4sox,
				v6data,
				pktlen - sizeof (struct ethhdr),
				MSG_DONTWAIT,
				(struct sockaddr *) &v4dest,
				sizeof (struct sockaddr_in))
	)
				;
}


/*
 * Handle a request for Neighbor Discovery over the 6bed4 Link.
 */
void handle_6to4_nd (ssize_t pktlen) {
	uint8_t lldest [6];
	//
	// Validate ICMPv6 message -- trivial, trust local generation
	//
	// Handle the message dependent on its type
	switch (v6icmp6type) {
	case ND_ROUTER_SOLICIT:
		v6icmp6type = ND_ROUTER_ADVERT;
		v6icmp6code = 0;
		v6icmp6data [0] = 0;		// Cur Hop Limit: unspec
		v6icmp6data [1] = 0x18;		// M=0, O=0,
						// H=0, Prf=11=Low
						// Reserved=0
		//TODO: wire says 0x44 for router_adv.flags
		size_t writepos = 2;
		memset (v6icmp6data + writepos,
				default_route? 0xff: 0x00,
				2);		// Router Lifetime
		writepos += 2;
		memcpy (v6icmp6data + writepos,
				"\x00\x00\x80\x00",
				4);		// Reachable Time: 32s
		writepos += 4;
		memcpy (v6icmp6data + writepos,
				"\x00\x00\x01\x00",
				4);		// Retrans Timer: .25s
		writepos += 4;
		writepos = icmp6_prefix (writepos, 0);
		v6plen = htons (4 + writepos);
		memcpy (v6dst6, v6src6, 16);
		memcpy (v6src6, v6listen_linklocal_complete, 16);
		v6icmp6csum = icmp6_checksum ((uint8_t *) v6hdr6, 4 + writepos);
		v6ether.h_proto = htons (ETH_P_IPV6);
		memcpy (v6ether.h_dest, v6ether.h_source, 6);
		memcpy (v6ether.h_source, v6lladdr, 6);
		syslog (LOG_INFO, "Replying Router Advertisement to the IPv6 Link, result = %zd\n",
			write (v6sox, &v6data6, sizeof (struct ethhdr) + sizeof (struct ip6_hdr) + 4 + writepos)
		)
			;
		break;
	case ND_ROUTER_ADVERT:
		return;		/* the IPv6 Link is no router, drop */
	case ND_NEIGHBOR_SOLICIT:
		//
		// Neighbor Solicitation is treated depending on its kind:
		//  - the 6bed4 Router address is answered immediately
		//  - discovery for the local IPv6 address is dropped
		//  - discovery for fe80::/64 addresses is answered
		//  - other peers start a process in the ndqueue
		if ((memcmp (v6ndtarget, router_linklocal_address, 16) == 0) ||
		    (memcmp (v6ndtarget, router_linklocal_address_complete, 16) == 0)) {
			advertise_6bed4_public_service (NULL);
		} else if (memcmp (v6ndtarget, &v6listen, 16) == 0) {
			return;		/* yes you are unique, drop */
		} else if (memcmp (v6ndtarget, v6listen_linklocal, 8) == 0) {
			//
			// Construct response for fe80::/64
			v6icmp6type = ND_NEIGHBOR_ADVERT;
			v6icmp6data [0] = 0x60;	/* Solicited, Override */
			v6icmp6data [20] = 2;	/* Target Link-Layer Address */
			v6icmp6data [21] = 1;	/* Length is 1x 8 bytes */
			v6icmp6data [22] = v6icmp6data [12] ^ 0x02;
			v6icmp6data [23] = v6icmp6data [13];
			v6icmp6data [24] = v6icmp6data [14];
			v6icmp6data [25] = v6icmp6data [17];
			v6icmp6data [26] = v6icmp6data [18];
			v6icmp6data [27] = v6icmp6data [19];
			v6plen = htons (4 + 28);
			memcpy (v6dst6, v6src6, 16);
			memcpy (v6src6, &v6listen, 16);
			memcpy (v6ether.h_dest, v6ether.h_source, 6);
			memcpy (v6ether.h_source, v6lladdr, 6);
			v6icmp6csum = icmp6_checksum ((uint8_t *) v6hdr6, 4 + 28);
syslog (LOG_DEBUG, "Sending trivial reply to fe80::/64 type query\n");
			write (v6sox, &v6data6, sizeof (struct ethhdr) + sizeof (struct ip6_hdr) + 4 + 28);
			return;
		} else {
			enqueue ((struct in6_addr *) v6ndtarget, (struct in6_addr *) v6src6, v6ether.h_source);
		}
		break;
	case ND_NEIGHBOR_ADVERT:
		lldest [0] = v6dst6->s6_addr [8] ^ 0x02;
		lldest [1] = v6dst6->s6_addr [9];
		lldest [2] = v6dst6->s6_addr [10];
		lldest [3] = v6dst6->s6_addr [13];
		lldest [4] = v6dst6->s6_addr [14];
		lldest [5] = v6dst6->s6_addr [15];
		handle_6to4_plain_unicast (pktlen, lldest);
		break;
	case ND_REDIRECT:
		//TODO:NOT_IMPLEMENTED_YET:ND_REDIRECT_FROM_6BED4//
		//
		// Redirect indicates that a more efficient bypass exists than
		// the currently used route.  The remote peer has established
		// this and wants to share that information to retain a
		// symmetric communication, which is helpful in keeping holes
		// in NAT and firewalls open.
		//
		return;
	}
}


/*
 * Receive an IPv6 package, check its address and pickup IPv4 address and
 * port, then package it as a tunnel message and forward it to IPv4:port.
 * Rely on the proper formatting of the incoming IPv6 packet, as it is
 * locally generated.
 */
void handle_6to4 (void) {
	//
	// Receive the IPv6 package and ensure a consistent size
	size_t rawlen = read (v6sox, &v6data6, sizeof (v6data6));
	if (rawlen == -1) {
		return;		/* failure to read, drop */
	}
	if (rawlen < sizeof (struct ethhdr) + sizeof (struct ip6_hdr) + 1) {
		return;		/* packet too small, drop */
	}
	if (v6ether.h_proto != htons (ETH_P_IPV6)) {
		return;		/* not IPv6, drop */
	}
//TODO// syslog (LOG_DEBUG, "Packet from IPv6 stack, target %02x:%02x:%02x:%02x:%02x:%02x\n", v6ether.h_dest [0], v6ether.h_dest [1], v6ether.h_dest [2], v6ether.h_dest [3], v6ether.h_dest [4], v6ether.h_dest [5]);
	//
	// Ignore messages from the IPv6 stack to itself
	if (memcmp (v6ether.h_dest, v6ether.h_source, 6) == 0) {
		syslog (LOG_DEBUG, "TODO: Self-to-self messaging in IPv6 stack ignored\n");
		return;
	}
	/*
	 * Distinguish types of traffic:
	 * Non-plain, Plain Unicast, Plain Multicast
	 */
	if ((v6type == IPPROTO_ICMPV6) &&
			(v6icmp6type >= 133) && (v6icmp6type <= 137)) {
		//
		// Not Plain: Router Adv/Sol, Neighbor Adv/Sol, Redirect
syslog (LOG_DEBUG, "Forwarding non-plain unicast from IPv6 to 6bed4\n");
		handle_6to4_nd (rawlen);
	} else if ((v6dst6->s6_addr [0] != 0xff) && !(v6dst6->s6_addr [8] & 0x01)) {
		//
		// Plain Unicast
		if (v6hops-- <= 1) {
			return;
		}
syslog (LOG_DEBUG, "Forwarding plain unicast from IPv6 to 6bed4\n");
		handle_6to4_plain_unicast (rawlen, v6ether.h_dest);
	} else {
		//
		// Plain Multicast
		//TODO:IGNORE_MULTICAST//
		//TODO// syslog (LOG_DEBUG, "%s: Plain multicast from 6bed4 Link to 6bed4 Network is not supported\n", program);
	}
}


/*
 * Send a single Neighbor Solicitation message over 6bed4.  This will
 * be sent to the given 6bed4 address, and is usually part of a series
 * of attempts to find a short-cut route to the 6bed4 peer.
 */
void solicit_6bed4_neighbor (const struct ndqueue *info, const uint8_t *addr6bed4) {
	memcpy (v6src6, &info->source, 16);
	memcpy (v6dst6, &info->target, 16);
	v6type = IPPROTO_ICMPV6;
	v6hops = 255;
	v6icmp6type = ND_NEIGHBOR_SOLICIT;
	v6icmp6code = 0;
	v6icmp6data [0] =
	v6icmp6data [1] =
	v6icmp6data [2] =
	v6icmp6data [3] = 0x00;
	memcpy (v6icmp6data + 4, &info->target, 16);
	v6icmp6data [20] = 1;	// option type is Source Link-Layer Address
	v6icmp6data [21] = 1;	// option length is 1x 8 bytes
	memcpy (v6icmp6data + 22, v6lladdr, 6);
	uint16_t pktlen = sizeof (struct ip6_hdr) + 4 + 28;
	//OLD// v6icmp6csum = icmp6_checksum ((uint8_t *) v6hdr6, 28 + 8);
	v6plen = htons (4 + 28);
	v6icmp6csum = icmp6_checksum ((uint8_t *) v6hdr6, 4 + 28);
	handle_6to4_plain_unicast (sizeof (struct ip6_hdr) + 8 + 28 + 10, addr6bed4);
	//TODO// Why these +8 and +10 are needed, I don't know yet!
}


/*
 * Find a neighbor's 6bed4 address.  This is coordinated by the ndqueue,
 * which schedules such tasks and makes them repeat.  Furthermore, a few
 * attempts may be scheduled on the local network before attempts
 * shift to the direct target IPv4/UDP addresses.  Of course the local
 * network will only be scheduled if the public IPv4 address matches
 * the one for the local node.
 *
 * This process is dequeued by reverse Neighbor Advertisements.  If none
 * comes back in spite of the various Neighbor Solicitations sent, then
 * the final action is to send a Neighbor Advertisement to the host with
 * the Public 6bed4 Service as its target of last resort.  In case of
 * this last resort, the process is not continued any further; the
 * return value indicates whether the queue entry should be kept for
 * another round.
 */
bool chase_neighbor_6bed4_address (struct ndqueue *info) {
	uint8_t addr6bed4 [6];
	static const uint8_t addr6bed4_lancast [8] = {
		UDP_PORT_6BED4 & 0xff, UDP_PORT_6BED4 >> 8,
		224, 0, 0, 1
	};
	if (info->todo_lancast > 0) {
		// Attempt 1. Send to LAN multicast address (same public IP)
		info->todo_lancast--;
		solicit_6bed4_neighbor (info, addr6bed4_lancast);
		return true;
	} else if (info->todo_direct > 0) {
		// Attempt 2. Send to target's direct IP address / UDP port
		info->todo_direct--;
		addr6bed4 [0] = info->target.s6_addr [8] ^ 0x02;
		addr6bed4 [1] = info->target.s6_addr [9];
		addr6bed4 [2] = info->target.s6_addr [10];
		addr6bed4 [3] = info->target.s6_addr [13];
		addr6bed4 [4] = info->target.s6_addr [14];
		addr6bed4 [5] = info->target.s6_addr [15];
		solicit_6bed4_neighbor (info, addr6bed4);
		return true;
	} else {
		// Attempt 3. Respond with Public 6bed4 Service
		syslog (LOG_INFO, "%s: Failed to find a bypass, passing back the 6bed4 Router\n", program);
		advertise_6bed4_public_service (info);
		return false;
	}
}


/*
 * Perform Router Solicitation.  This is the usual mechanism that is used
 * on ethernet links as well, except that the 6bed4 permits fixed interface
 * identifiers; for this client, the interface identifier will be 0x0001.
 * The router always has interface identifier 0x0000 but it will now be
 * addressed at the all-routers IPv6 address 0xff02::2 with the general
 * source IPv6 address ::
 */
void solicit_router (void) {
	v4name.sin_family = AF_INET;
	memcpy (&v4name.sin_addr.s_addr, &v4listen, 4);
	v4name.sin_port = htons (UDP_PORT_6BED4);
	int done = 0;
	int secs = 1;
// syslog (LOG_DEBUG, "%s: Sending RouterSolicitation-IPv6-UDP-IPv4 to %d.%d.%d.%d:%d, result = %d\n", program,
// ((uint8_t *) &v4name.sin_addr.s_addr) [0],
// ((uint8_t *) &v4name.sin_addr.s_addr) [1],
// ((uint8_t *) &v4name.sin_addr.s_addr) [2],
// ((uint8_t *) &v4name.sin_addr.s_addr) [3],
// ntohs (v4name.sin_port),
(
	sendto (v4sox,
			ipv6_router_solicitation,
			sizeof (ipv6_router_solicitation),
			MSG_DONTWAIT,
			(struct sockaddr *) &v4name, sizeof (v4name)));
}


/*
 * Send a KeepAlive message.  This is an UDP/IPv4 message with no contents.
 * The router will not respond, but that is okay; outgoing traffic is the
 * way to keep holes in NAT and firewalls open.
 */
void keepalive (void) {
	v4name.sin_family = AF_INET;
	memcpy (&v4name.sin_addr.s_addr, &v4listen, 4);
	v4name.sin_port = htons (UDP_PORT_6BED4);
	int done = 0;
	int secs = 1;
	setsockopt (v4sox, IPPROTO_IP, IP_TTL, &keepalive_ttl, sizeof (keepalive_ttl));
	sendto (v4sox,
			"",
			0,
			MSG_DONTWAIT,
			(struct sockaddr *) &v4name, sizeof (v4name));
	setsockopt (v4sox, IPPROTO_IP, IP_TTL, &v4ttl, sizeof (v4ttl));
}


/* Regular maintenance is a routine that runs regularly to do one of two
 * generic tasks: either it sends Router Solicitation messages to the
 * Public 6bed4 Service, or it sends an empty UDP message somewhat in its
 * direction to keep NAT/firewall holes open.
 */
void regular_maintenance (void) {
	if (!got_lladdr) {
		solicit_router ();
		maintenance_time_cycle <<= 1;
		maintenance_time_cycle += 1;
		if (maintenance_time_cycle > maintenance_time_cycle_max) {
			maintenance_time_cycle = maintenance_time_cycle_max;
		}
		syslog (LOG_INFO, "Sent Router Advertisement to Public 6bed4 Service, next attempt in %ld seconds\n", maintenance_time_cycle);
	} else {
		syslog (LOG_INFO, "Sending a KeepAlive message (empty UDP) to the 6bed4 Router\n");
		keepalive ();
		maintenance_time_cycle = maintenance_time_cycle_max;
	}
	maintenance_time_sec = time (NULL) + maintenance_time_cycle;
}


/* Run the daemon core code, passing information between IPv4 and IPv6 and
 * responding to tunnel requests if so requested.
 */
void run_daemon (void) {
	fd_set io;
	bool keep;
	maintenance_time_sec = 0;	// trigger Router Solicitation
	FD_ZERO (&io);
	FD_SET (v4sox, &io);
	FD_SET (v6sox, &io);
	int nfds = (v4sox < v6sox)? (v6sox + 1): (v4sox + 1);
	if (v4mcast != -1) {
		FD_SET (v4mcast, &io);
		if (v4mcast >= nfds) {
			nfds = v4mcast + 1;
		}
	}
	while (1) {
		struct timeval tout;
		struct timeval now;
		gettimeofday (&now, NULL);
		if (maintenance_time_sec <= now.tv_sec) {
			regular_maintenance ();
		}
		tout.tv_sec = maintenance_time_sec - now.tv_sec;
		tout.tv_usec = 0;
		while (ndqueue && (
				((ndqueue->next->tv.tv_sec == now.tv_sec)
				  && (ndqueue->next->tv.tv_usec <= now.tv_usec))
				|| (ndqueue->next->tv.tv_sec < now.tv_sec))) {
			//
			// Run the entry's handler code
			syslog (LOG_DEBUG, "Queue at %ld.%03ld: Timed for %ld.%03ld", now.tv_sec, now.tv_usec / 1000, ndqueue->next->tv.tv_sec, ndqueue->next->tv.tv_usec / 1000);
			keep = chase_neighbor_6bed4_address (ndqueue->next);
			if (!keep) {
				dequeue (ndqueue->next);
				continue;
			}
			//
			// Make ndqueue point to the entry to run
			ndqueue = ndqueue->next;
			//
			// Add 50ms to the running time
			if (now.tv_usec < 950000) {
				ndqueue->tv.tv_usec = now.tv_usec +   50000;
				ndqueue->tv.tv_sec  = now.tv_sec  + 0;
			} else {
				ndqueue->tv.tv_usec = now.tv_usec -  950000;
				ndqueue->tv.tv_sec  = now.tv_sec  + 1;
			}
		}
		if (ndqueue && ((ndqueue->next->tv.tv_sec - now.tv_sec) < tout.tv_sec)) {
			tout.tv_sec  = ndqueue->next->tv.tv_sec  - now.tv_sec ;
			tout.tv_usec = ndqueue->next->tv.tv_usec - now.tv_usec;
			if (tout.tv_usec < 0) {
				tout.tv_usec += 1000000;
				tout.tv_sec  -= 1;
			}
		}
		if (select (nfds, &io, NULL, NULL, &tout) == -1) {
			syslog (LOG_ERR, "Select failed: %s\n", strerror (errno));
		}
		if (FD_ISSET (v4sox, &io)) {
syslog (LOG_DEBUG, "Got unicast input\n");
			handle_4to6 (v4sox);
		} else {
			FD_SET (v4sox, &io);
		}
		if (FD_ISSET (v6sox, &io)) {
			handle_6to4 ();
		} else {
			FD_SET (v6sox, &io);
		}
		if (v4mcast != -1) {
			if (FD_ISSET (v4mcast, &io)) {
syslog (LOG_DEBUG, "WOW: Got multicast input\n");
				handle_4to6 (v4mcast);
			} else {
				FD_SET (v4mcast, &io);
			}
		}
//fflush (stdout);
	}
}


/* Option descriptive data structures */

char *short_opt = "s:t:dl:p:r:k:feh";

struct option long_opt [] = {
	{ "v4server", 1, NULL, 's' },
	{ "tundev", 1, NULL, 'd' },
	{ "default-route", 0, NULL, 'r' },
	{ "listen", 1, NULL, 'l' },
	{ "port", 1, NULL, 'p' },
	{ "ttl", 1, NULL, 't' },
	{ "foreground", 0, NULL, 'f' },
	{ "fork-not", 0, NULL, 'f' },
	{ "keepalive", 1, NULL, 'k' },
	{ "keepalive-period-ttl", 1, NULL, 'k' },
	{ "error-console", 0, NULL, 'e' },
	{ "help", 0, NULL, 'h' },
	{ NULL, 0, NULL, 0 }	/* Array termination */
};


/* Parse commandline arguments (and start to process them).
 * Return 1 on success, 0 on failure.
 */
int process_args (int argc, char *argv []) {
	int ok = 1;
	int help = 0;
	int done = 0;
	unsigned long tmpport;
	char *endarg;
	default_route = false;
	while (!done) {
		switch (getopt_long (argc, argv, short_opt, long_opt, NULL)) {
		case -1:
			done = 1;
			if (optind != argc) {
				fprintf (stderr, "%s: Extra arguments not permitted: %s...\n", program, argv [optind]);
				ok = 0;
			}
			break;
		case 's':
			if (v4sox != -1) {
				ok = 0;
				fprintf (stderr, "%s: You can only specify a single server address\n", program);
				continue;
			}
			v4server = optarg;
			if (inet_pton (AF_INET, optarg, &v4peer.sin_addr) <= 0) {
				ok = 0;
				fprintf (stderr, "%s: Failed to parse IPv4 address %s\n", program, optarg);
				break;
			}
			memcpy (&v4listen, &v4peer.sin_addr, 4);
			v4sox = socket (AF_INET, SOCK_DGRAM, 0);
			if (v4sox == -1) {
				ok = 0;
				fprintf (stderr, "%s: Failed to allocate UDPv4 socket: %s\n", program, strerror (errno));
				break;
			}
			break;
		case 'd':
			if (v6sox != -1) {
				ok = 0;
				fprintf (stderr, "%s: Multiple -d arguments are not permitted\n", program);
				break;
			}
			v6sox = open (optarg, O_RDWR);
			if (v6sox == -1) {
				ok = 0;
				fprintf (stderr, "%s: Failed to open tunnel device %s: %s\n", program, optarg, strerror (errno));
				break;
			}
			break;
		case 'r':
			if (default_route) {
				fprintf (stderr, "%s: You can only request default route setup once\n", program);
				exit (1);
			}
			default_route = true;
			break;
		case 'l':
			if (inet_pton (AF_INET, optarg, &v4bind.sin_addr.s_addr) != 1) {
				fprintf (stderr, "%s: IPv4 address %s is not valid\n", program, optarg);
				exit (1);
			}
			break;
		case 'p':
			tmpport = strtoul (optarg, &endarg, 10);
			if ((*endarg) || (tmpport > 65535)) {
				fprintf (stderr, "%s: UDP port number %s is not valid\n", program, optarg);
				exit (1);
			}
			if (tmpport & 0x0001) {
				fprintf (stderr, "%s: UDP port number %ld is odd, which is not permitted\n", program, tmpport);
				exit (1);
			}
			v4bind.sin_port = htons (tmpport);
			break;
		case 'f':
			if (foreground) {
				fprintf (stderr, "%s: You can only request foreground operation once\n", program);
				exit (1);
			}
			foreground = true;
			break;
		case 'e':
			if (log_to_stderr) {
				fprintf (stderr, "%s: You can only specify logging to stderr once\n", program);
				exit (1);
			}
			log_to_stderr = true;
			break;
		case 't':
			if (v4ttl_mcast != -1) {
				fprintf (stderr, "%s: You can set the ttl for multicast once\n", program);
				exit (1);
			}
			char *zero;
			long setting = strtol(optarg, &zero, 10);
			if (*zero || (setting < 0) || (setting > 255)) {
				fprintf (stderr, "%s: Multicast radius must be a number in the range 0 to 255, inclusive, not %s\n", program, optarg);
				exit (1);
			}
			v4ttl_mcast = setting;
			break;
		case 'k':
			if (keepalive_ttl != -1) {
				fprintf (stderr, "%s: You can only set the keepalive period and TTL once\n", program);
				exit (1);
			}
			char *rest;
			keepalive_period = strtol (optarg, &rest, 10);
			if (*rest == ',') {
				rest++;
				keepalive_ttl = strtol (rest, &rest, 10);
				if ((keepalive_ttl < 0) || (keepalive_ttl > 255)) {
					fprintf (stderr, "%s: The keepalive TTL must be in the range 0 to 255, inclusive\n", program);
					exit (1);
				}
			} else {
				keepalive_ttl = 3;
			}
			if (*rest) {
				fprintf (stderr, "%s: The format for keepalive configuration is 'period,ttl' or just 'period', but not %s\n", program, optarg);
				exit (1);
			}
			break;
		default:
			ok = 0;
			help = 1;
			/* continue into 'h' to produce usage information */
		case 'h':
			help = 1;
			break;
		}
		if (help || !ok) {
			done = 1;
		}
	}
	if (help) {
#ifdef HAVE_SETUP_TUNNEL
		fprintf (stderr, "Usage: %s [-r] [-d /dev/tunX]\n       %s -h\n", program, program);
#else
		fprintf (stderr, "Usage: %s [-r] -d /dev/tunX\n       %s -h\n", program, program);
#endif
		return 0;
	}
	if (!ok) {
		return 0;
	}
	if (keepalive_ttl != -1) {
		maintenance_time_cycle_max = keepalive_period;
	} else {
		keepalive_ttl = 3;
	}
#ifdef HAVE_SETUP_TUNNEL
	if (v6sox == -1) {
		if (geteuid () != 0) {
			fprintf (stderr, "%s: You should be root, or use -d to specify an accessible tunnel device\n", program);
			return false;
		} else {
			return setup_tunnel ();
		}
	}
#else /* ! HAVE_SETUP_TUNNEL */
	if (v6sox == -1) {
		fprintf (stderr, "%s: You must specify a tunnel device with -d that is accessible to you\n", program);
		return 0;
	}
#endif /* HAVE_SETUP_TUNNEL */
	return ok;
}


/* The main program parses commandline arguments and forks off the daemon
 */
int main (int argc, char *argv []) {
	//
	// Initialise
	program = strrchr (argv [0], '/');
	if (program) {
		program++;
	} else {
		program = argv [0];
	}
	memset (&v4name, 0, sizeof (v4name));
	memset (&v4peer, 0, sizeof (v4peer));
	memset (&v6name, 0, sizeof (v6name));
	v4name.sin_family  = AF_INET ;
	v4peer.sin_family  = AF_INET ;
	v6name.sin6_family = AF_INET6;
	// Fixed public server data, IPv4 and UDP:
	v4server = SERVER_6BED4_IPV4_TXT;
	v4peer.sin_addr.s_addr = htonl (SERVER_6BED4_IPV4_INT32);
	v4name.sin_port = htons (UDP_PORT_6BED4);
	v4peer.sin_port = htons (UDP_PORT_6BED4);
	memcpy (&v4listen, &v4peer.sin_addr, 4);
	memset (&v4bind, 0, sizeof (v4bind));
	v4bind.sin_family = AF_INET;
	//
	// Parse commandline arguments
	if (!process_args (argc, argv)) {
		exit (1);
	}
	//
	// Construct the 6bed4 Router's complete link-layer address
	router_linklocal_address_complete [8] = (ntohs (v4peer.sin_port) & 0xff) ^ 0x02;
	router_linklocal_address_complete [9] = ntohs (v4peer.sin_port) >> 8;
	router_linklocal_address_complete [10] = ntohl (v4peer.sin_addr.s_addr) >> 24;
	router_linklocal_address_complete [11] = 0xff;
	router_linklocal_address_complete [12] = 0xfe;
	memcpy (router_linklocal_address_complete + 13, &((uint8_t *) &v4peer.sin_addr) [1], 3);
	//
	// Open the syslog channel
	openlog (program, LOG_NDELAY | LOG_PID | ( log_to_stderr? LOG_PERROR: 0), LOG_DAEMON);
	//
	// Create memory for the freequeue buffer
	freequeue = calloc (freequeue_items, sizeof (struct ndqueue));
	if (!freequeue) {
		syslog (LOG_CRIT, "%s: Failed to allocate %d queue items\n", program, freequeue_items);
		exit (1);
	}
	int i;
	for (i = 1; i < freequeue_items; i++) {
		freequeue [i].next = &freequeue [i-1];
	}
	freequeue = &freequeue [freequeue_items - 1];
	//
	// Create socket for normal outgoing (and return) 6bed4 traffic
	if (v4sox == -1) {
		v4sox = socket (AF_INET, SOCK_DGRAM, 0);
		if (v4sox == -1) {
			syslog (LOG_CRIT, "%s: Failed to open a local IPv4 socket -- does your system still support IPv4?\n", program);
			exit (1);
		}
	}
	struct sockaddr_in tmpaddr;
	memset (&tmpaddr, 0, sizeof (tmpaddr));
	tmpaddr.sin_family = AF_INET;
	srand (getpid ());
	uint16_t portn = rand () & 0x3ffe;
	uint16_t port0 = portn + 16384;
	//TODO// Move port iteration + allocation to separate function
	while (portn < port0) {
		tmpaddr.sin_port = htons ((portn & 0x3ffe) + 49152);
		if (bind (v4sox, (struct sockaddr *) &tmpaddr, sizeof (tmpaddr)) == 0) {
			break;
		}
		portn += 2;
	}
	if (portn < port0) {
		syslog (LOG_DEBUG, "Bound to UDP port %d\n", ntohs (tmpaddr.sin_port));
	} else {
		fprintf (stderr, "%s: All even dynamic ports rejected binding: %s\n", program, strerror (errno));
		exit (1);
	}
	//
	// Setup fragmentation, QoS and TTL options
	u_int yes = 1;
	u_int no = 0;
#ifdef IP_DONTFRAG
	if (setsockopt (v4sox, IPPROTO_IP, IP_DONTFRAG, no, sizeof (no)) == -1) {
		syslog (LOG_ERR, "Failed to permit fragmentation -- not all peers may be accessible with MTU 1280");
	}
#else
#warning "Target system lacks support for controlling packet fragmentation"
#endif
	socklen_t soxlen = sizeof (v4qos);
	if (getsockopt (v4sox, IPPROTO_IP, IP_TOS, &v4qos, &soxlen) == -1) {
		syslog (LOG_ERR, "Quality of Service is not supported by the IPv4-side socket");
		v4qos = 0;
	}
	v6tc = htonl (v4qos << 20);
	soxlen = sizeof (v4ttl);
	if (getsockopt (v4sox, IPPROTO_IP, IP_TTL, &v4ttl, &soxlen) == -1) {
		syslog (LOG_ERR, "Time To Live cannot be varied on the IPv4 socket");
		v4ttl = 64;
	}
	//
	// Bind to the IPv4 all-nodes local multicast address
	memset (&v4allnodes, 0, sizeof (v4allnodes));
	v4allnodes.sin_family = AF_INET;
	v4allnodes.sin_port = htons (UDP_PORT_6BED4);
	v4allnodes.sin_addr.s_addr = htonl ( INADDR_ANY );
	if (multicast) {
		v4mcast = socket (AF_INET, SOCK_DGRAM, 0);
		if (v4mcast != -1) {
			struct ip_mreq mreq;
			mreq.imr_multiaddr.s_addr = htonl ( (224L << 24) | 1L);
			mreq.imr_multiaddr.s_addr = htonl ( INADDR_ANY );
			if (bind (v4mcast, (struct sockaddr *) &v4allnodes, sizeof (v4allnodes)) != 0) {
				close (v4mcast);
				v4mcast = -1;
				syslog (LOG_ERR, "No LAN bypass: Failed to bind to IPv4 all-nodes: %s\n", strerror (errno));
			} else if (setsockopt (v4mcast, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof (yes)) == -1) {
				close (v4mcast);
				v4mcast = -1;
				syslog (LOG_ERR, "No LAN bypass: Failed to share multicast port: %s\n", strerror (errno));
			} else if (setsockopt (v4mcast, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof (mreq)) == -1) {
				close (v4mcast);
				v4mcast = -1;
				syslog (LOG_ERR, "No LAN bypass: Failed to setup multicast: %s\n", strerror (errno));
			} else if ((v4ttl_mcast != -1) && (setsockopt (v4mcast, IPPROTO_IP, IP_MULTICAST_TTL, &v4ttl_mcast, sizeof (v4ttl_mcast)) == -1)) {
				close (v4mcast);
				v4mcast = -1;
				syslog (LOG_ERR, "No LAN bypass: Failed to configure the multicast radius: %s\n", strerror (errno));
			}
#if 0
			if (bind (v4mcast, (struct sockaddr *) &v4allnodes, sizeof (v4allnodes)) != 0) {
				close (v4mcast);
				v4mcast = -1;
				syslog (LOG_ERR, "%s: No LAN bypass: Failed to bind to IPv4 all-nodes\n", program);
			} else if (listen (v4mcast, 10) != 0) {
				close (v4mcast);
				v4mcast = -1;
				syslog (LOG_ERR, "%s: No LAN bypass: Failed to listen to IPv4 all-nodes\n", program);
			}
#endif
		}
	} else {
		syslog (LOG_INFO, "%s: No LAN bypass: Not desired\n", program);
	}
	//
	// Construct an rtnetlink socket for neighbor cache interaction
	rtsox = socket (PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (rtsox == -1) {
		syslog (LOG_CRIT, "Failed to gain access to the neighbor cache: %s\n", strerror (errno));
		exit (1);
	}
	memset (&rtname,   0, sizeof (rtname  ));
	memset (&rtkernel, 0, sizeof (rtkernel));
	rtname.nl_family = rtkernel.nl_family = AF_NETLINK;
	rtname.nl_pid = getpid ();
	if (bind (rtsox, (struct sockaddr *) &rtname, sizeof (rtname)) == -1) {
		syslog (LOG_CRIT, "Failed to bind to the neighbor cache socket: %s\n", strerror (errno));
		exit (1);
	}
	if (connect (rtsox, (struct sockaddr *) &rtkernel, sizeof (rtkernel)) == -1) {
		syslog (LOG_CRIT, "Failed to connect to the neighbor cachr in the kernel; %s\n", strerror (errno));
		exit (1);
	}
{ uint8_t testll [6];
uint8_t test_address [] = { 0xfe, 0x80, 0,0,0,0,0,0, 0xc2, 0x25, 0x06, 0xff, 0xfe, 0xb0, 0x7e, 0xa6 };
if (lookup_neighbor (test_address, testll)) {
syslog (LOG_INFO, "Successfully retrieved LL: %02x:%02x:%02x:%02x:%02x:%02x\n", testll [0], testll [1], testll [2], testll [3], testll [4], testll [5]);
} else { syslog (LOG_INFO, "Failed to find LL\n"); } }
	//
	// If port and/or listen arguments were provided, bind to them
	if ((v4bind.sin_addr.s_addr != INADDR_ANY) || (v4bind.sin_port != 0)) {
		if (bind (v4sox, (struct sockaddr *) &v4bind, sizeof (v4bind)) != 0) {
			syslog (LOG_CRIT, "%s: Failed to bind to local socket -- did you specify both address and port?\n", program);
			exit (1);
		}
	}
	//
	// Run the daemon
	if (foreground) {
		run_daemon ();
	} else {
		if (setsid () != -1) {
			syslog (LOG_CRIT, "%s: Failure to detach from parent session: %s\n", program, strerror (errno));
			exit (1);
		}
		switch (fork ()) {
		case -1:
			syslog (LOG_CRIT, "%s: Failure to fork daemon process: %s\n", program, strerror (errno));
			exit (1);
		case 0:
			close (0);
			if (! log_to_stderr) {
				close (1);
				close (2);
			}
			run_daemon ();
			break;
		default:
			break;
		}
	}
	//
	// Report successful creation of the daemon
	closelog ();
	exit (0);
}

