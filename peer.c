/* 6bed4/client.c -- IPv6-anywhere client for 6bed4
 *
 * This is an implementation of neighbour and router discovery over a
 * tunnel that packs IPv6 inside UDP/IPv4.  This tunnel mechanism is
 * so efficient that the server administrators need not mind if it is
 * distributed widely.  The server address SERVER_6BED4_xxx is
 * hard-coded into this client code, as it is considered "well-known".
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

#include <syslog.h>
#ifndef LOG_PERROR
#define LOG_PERROR LOG_CONS		/* LOG_PERROR is non-POSIX, LOG_CONS is */
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/select.h>
#include <sys/ioctl.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>

#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/if_ether.h>


/* The following will initially fail, due to an IANA obligation to avoid
 * default builds with non-standard options.
 */
#include "nonstd.h"



#define MTU 1280

/*
 * The HAVE_SETUP_TUNNEL variable is used to determine whether absense of
 * the -t option leads to an error, or to an attempt to setup the tunnel.
 * The setup_tunnel() function used for that is defined per platform, such
 * as for LINUX.  Remember to maintain the manpage's optionality for -t.
 */
#undef HAVE_SETUP_TUNNEL


/* Global variables */

char *program;

int v4sox = -1;
int v6sox = -1;
int v4mcast = -1;

char *v4server = NULL;
char *v6server = NULL;
char v6prefix [INET6_ADDRSTRLEN];
uint8_t v6lladdr [6];

const uint8_t v6listen_linklocal [16] = { 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
uint8_t v6listen_linklocal_complete [16] = { 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

struct sockaddr_in  v4name;
struct sockaddr_in  v4peer;
struct sockaddr_in6 v6name;

struct sockaddr_in v4bind;
struct sockaddr_in v4allnodes;

struct in6_addr v6listen;
struct in6_addr v6listen_complete;
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
time_t maintenance_time_cycle = 1;
time_t maintenance_time_cycle_max = 30;
bool got_lladdr = false;

/* The network packet structure of a 6bed4 Router Solicitation */

uint8_t ipv6_router_solicitation [] = {
	// IPv6 header
	0x60, 0x00, 0x00, 0x00,
	16 / 256, 16 % 256, IPPROTO_ICMPV6, 255,
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
	32 / 256, 32 % 256, IPPROTO_ICMPV6, 255,
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
	UDP_PORT_6BED4 % 256, UDP_PORT_6BED4 / 256,
	SERVER_6BED4_IPV4_INT0, SERVER_6BED4_IPV4_INT1, SERVER_6BED4_IPV4_INT2, SERVER_6BED4_IPV4_INT3
};

uint8_t router_linklocal_address [] = {
	0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x00,
};

//TODO// Complete with the if-id of the 6bed4 Router:
uint8_t router_linklocal_address_complete [] = {
	0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x00,
};

uint8_t democlient_linklocal_address [] = {
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
static int have_tunnel = 0;
/* Implement the setup_tunnel() command for Linux.
 * Return 1 on success, 0 on failure.
 */
int setup_tunnel (void) {
	if (v6sox == -1) {
		v6sox = open ("/dev/net/tun", O_RDWR);
	}
	if (v6sox == -1) {
		syslog (LOG_ERR, "%s: Failed to access tunnel driver on /dev/net/tun: %s\n", program, strerror (errno));
		return 0;
	}
	int ok = 1;
	if (!have_tunnel) {
		memset (&ifreq, 0, sizeof (ifreq));
		strncpy (ifreq.ifr_name, "6bed4", IFNAMSIZ);
		ifreq.ifr_flags = IFF_TAP | IFF_NO_PI;
		if (ok && (ioctl (v6sox, TUNSETIFF, (void *) &ifreq) == -1)) {
			ok = 0;
		} else {
			have_tunnel = 1;
		}
		ifreq.ifr_name [IFNAMSIZ] = 0;
	}
	char cmd [512+1];
	snprintf (cmd, 512, "/sbin/ip addr add fe80::1 dev %s scope link", ifreq.ifr_name);
	if (ok && system (cmd) != 0) {
		ok = 0;
	}
	// snprintf (cmd, 512, "/sbin/ifconfig %s hw ether 98:1e:53:a4:cf:6e", ifreq.ifr_name, MTU);
	snprintf (cmd, 512, "/sbin/ip link set %s address 98:1e:53:a4:cf:6e", ifreq.ifr_name, MTU);
	if (ok && system (cmd) != 0) {
syslog (LOG_CRIT, "Bad news!\n");
		ok = 0;
	}
	snprintf (cmd, 512, "/sbin/ip link set %s up mtu %d", ifreq.ifr_name, MTU);
	if (ok && system (cmd) != 0) {
		ok = 0;
	}
	snprintf (cmd, 512, "/sbin/ip -6 route add 2001:610:188:2001::/64 mtu 1280 dev %s", ifreq.ifr_name);
	if (ok && system (cmd) != 0) {
		ok = 0;
	}
	if (!ok) {
		close (v6sox);	/* This removes the tunnel interface */
		v6sox = -1;
	}
	return ok;
}
int setup_tunnel_address (void) {
	int ok = have_tunnel;
	char cmd [512+1];
	snprintf (cmd, 512, "/sbin/ip -6 addr add %s/64 dev %s", v6prefix, ifreq.ifr_name);
	if (ok && system (cmd) != 0) {
		ok = 0;
	}
	if (default_route) {
		snprintf (cmd, 512, "/sbin/ip -6 route add default via fe80:: dev %s", ifreq.ifr_name);
		if (ok && system (cmd) != 0) {
			ok = 0;
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

/* Enter an item in the 10ms-cycled Neighbor Discovery queue.
 * Retrieve its storage space from the free queue.
 */
void enqueue (struct in6_addr *target, struct in6_addr *v6src, uint8_t *source_lladdr) {
	//
	// Allocate a free item to enqueue
	struct ndqueue *new = freequeue;
	if (!new) {
		// Temporarily overflown with ND -> drop the request
		return;
	}
	freequeue = freequeue->next;
	//
	// Setup the new entry with target details
	memcpy (&new->target, target, sizeof (new->target));
	memcpy (&new->source, v6src, sizeof (new->source));
	memcpy (&new->source_lladdr, source_lladdr, sizeof (new->source_lladdr));
	new->todo_lancast = 2;
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

/* Remove an item from the 10ms-cycled Neighbor Discovery queue.
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
			freequeue->next = togo;
			return;
		}
		prev = prev->next;
	} while (prev != ndqueue);
}


/* Calculate the ICMPv6 checksum field
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


/* Send an ICMPv6 reply.  This is constructed at the tunnel end, from
 * the incoming message.  The parameter indicates how many bytes the
 * ICMPv6 package counts after the ICMPv6 header.  It must be 4 (mod 8).
 *
 * Actions: v4/udp/v6 src becomes dest, set v4/udp/v6 src, len, cksum, send.
 */
void icmp6_reply (size_t icmp6bodylen) {
	size_t v6iphdr_msglen = sizeof (struct ip6_hdr) + sizeof (struct icmp6_hdr) + icmp6bodylen;
	size_t v4iphdr_msglen = sizeof (struct iphdr) + sizeof (struct udphdr) + v6iphdr_msglen;
	v4v6hoplimit = 255;
	icmp6bodylen += 4;
	icmp6bodylen >>= 3;
	; //TODO: icmp6 reply construction (src==any => tgt=multicast-node)
printf ("Sending ICMPv6-IPv6-UDP-IPv4 to %d.%d.%d.%d:%d, result = %d\n",
((uint8_t *) &v4name.sin_addr.s_addr) [0],
((uint8_t *) &v4name.sin_addr.s_addr) [1],
((uint8_t *) &v4name.sin_addr.s_addr) [2],
((uint8_t *) &v4name.sin_addr.s_addr) [3],
ntohs (v4name.sin_port),
	sendto (v4sox,
			v4data,
			sizeof (struct ip6_hdr) + 4 + icmp6bodylen,
			MSG_DONTWAIT,
			(struct sockaddr *) &v4name, sizeof (v4name)));
}


/* Append the current prefix to an ICMPv6 message.  Incoming optidx
 * and return values signify original and new offset for ICMPv6 options.
 * The endlife parameter must be set to obtain zero lifetimes, thus
 * instructing the tunnel client to stop using an invalid prefix.
 */
size_t icmp6_prefix (size_t optidx, uint8_t endlife) {
	v6icmp6data [optidx++] = 3;	// Type
	v6icmp6data [optidx++] = 4;	// Length
	v6icmp6data [optidx++] = 64;	// This is a /64 prefix
#ifdef TODO_HWADDR_SETS_PROPERLY_THANKS_TO_EVEN_UDP_PORT_REGIME
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
	memcpy (v6icmp6data + optidx + 0, &v6listen, 8);
	memset (v6icmp6data + optidx + 8, 0, 8);
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
	memcpy (v6data + 8, ipv6_defaultrouter_neighbor_advertisement + 8, 16);
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
 * Test if the provided IPv6 address matches the prefix used for 6bed4.
 */
static inline bool prefix_6bed4 (struct in6_addr *ip6) {
	return memcmp (&v6listen, ip6->s6_addr, 8) == 0;
}


/*
 * Validate the originator's IPv6 address.  It should match the
 * UDP/IPv4 coordinates of the receiving 6bed4 socket.  Also,
 * the /64 prefix must match that of v6listen.
 */
bool validate_originator (struct sockaddr_in *sin, struct in6_addr *ip6) {
	uint16_t port = ntohs (sin->sin_port);
	uint32_t addr = ntohl (sin->sin_addr.s_addr);
	if (memcmp (router_linklocal_address, ip6, 16) == 0) {
		//TODO// Temp test, needed for Router Advertisement
		return true;
	}
	if (!prefix_6bed4 (ip6)) {
		return false;
	}
	if ((port % 256) != (ip6->s6_addr [8] ^ 0x02)) {
		return false;
	}
	if ((port / 256) != ip6->s6_addr [9]) {
		return false;
	}
	if ((addr >> 24) != ip6->s6_addr [10]) {
		return false;
	}
	if ((addr & 0x00ffffff) != (htonl (ip6->s6_addr32 [3]) & 0x00ffffff)) {
		return false;
	}
	return true;
}


/*
 * Major packet processing functions
 */


/* Handle the IPv4 message pointed at by msg, checking if the IPv4:port
 * data matches the lower half of the IPv6 sender address.  Drop silently
 * if this is not the case.  TODO: or send ICMP?
 */
void handle_4to6_plain (ssize_t v4datalen, struct sockaddr_in *sin) {
	//
	// Send the unwrapped IPv6 message out over v6sox
	v4ether.h_proto = htons (ETH_P_IPV6);
	memcpy (v4ether.h_dest,   v6lladdr, 6);
	v4ether.h_source [0] = ntohs (sin->sin_port) % 256;
	v4ether.h_source [1] = ntohs (sin->sin_port) / 256;
	memcpy (v4ether.h_source + 2, &sin->sin_addr, 4);
syslog (LOG_INFO, "Writing IPv6, result = %d\n",
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
	uint8_t *target;
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
		if (memcmp (v4src6, router_linklocal_address, 16) != 0) {
			return;   /* not from router, drop */
		}
		if (memcmp (v4dst6, democlient_linklocal_address, 8) != 0) {
			return;   /* no address setup for me, drop */
		}
		if ((v4dst6->s6_addr [11] != 0xff) || (v4dst6->s6_addr [12] != 0xfe)) {
			return;   /* funny interface identifier, drop */
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
			} else if (v4v6icmpdata [rdofs + 2] != 64) {
				return;
			} else {
				destprefix = &v4v6icmpdata [rdofs + 16];
			}
			rdofs += (v4v6icmpdata [rdofs + 1] << 3);
		}
#ifdef TODO_DEPRECATED
		if (destprefix && destlladdr) {
			memcpy (v6lladdr, destlladdr, 6);
			memcpy (&v6listen.s6_addr [0], destprefix, 8);
			v6listen.s6_addr [8] = destlladdr [0] ^ 0x02;
			v6listen.s6_addr [9] = destlladdr [1];
			v6listen.s6_addr [10] = destlladdr [2];
			v6listen.s6_addr [11] = 0xff;
			v6listen.s6_addr [12] = 0xfe;
			v6listen.s6_addr [13] = destlladdr [3];
			v6listen.s6_addr [14] = destlladdr [4];
			v6listen.s6_addr [15] = destlladdr [5];
			inet_ntop (AF_INET6,
				&v6listen,
				v6prefix,
				sizeof (v6prefix));
			syslog (LOG_INFO, "%s: Assigning new-style address %s to tunnel\n", program, v6prefix);
			setup_tunnel_address ();
			got_lladdr = true;
		}
#else
		if (destprefix) {
			memcpy (v6listen.s6_addr + 0, destprefix, 8);
			memcpy (v6listen.s6_addr + 8, v4dst6->s6_addr + 8, 8);
			memcpy (v6listen_linklocal_complete, v4dst6, 16);
			v6lladdr [0] = v6listen_linklocal_complete [8] ^ 0x02;
			v6lladdr [1] = v6listen_linklocal_complete [9];
			v6lladdr [2] = v6listen_linklocal_complete [10];
			v6lladdr [3] = v6listen_linklocal_complete [13];
			v6lladdr [4] = v6listen_linklocal_complete [14];
			v6lladdr [5] = v6listen_linklocal_complete [15];
			inet_ntop (AF_INET6,
				&v6listen,
				v6prefix,
				sizeof (v6prefix));
			syslog (LOG_INFO, "%s: Assigning new-style address %s to tunnel\n", program, v6prefix);
			setup_tunnel_address ();  //TODO// parameters?
			got_lladdr = true;
		}
#endif
		return;
	case ND_NEIGHBOR_SOLICIT:
		//
		// Validate Neigbour Solicitation (trivial)
		//
		// Replicate the message over the IPv6 Link (like plain IPv6)
		syslog (LOG_DEBUG, "%s: Replicating Neighbor Solicatation from 6bed4 to the IPv6 Link\n", program);
		handle_4to6_plain (v4ngbcmdlen, &v4name);
		return;
	case ND_NEIGHBOR_ADVERT:
		//
		// Process Neighbor Advertisement coming in over 6bed4
		// First, make sure it is against an item in the ndqueue
		target = v4v6ndtarget;
		bool found = false;
		if (ndqueue) {
			ndq = ndqueue;
			do {
				if (memcmp (target, &ndq->target, 16) == 0) {
					found = true;
					break;
				}
				ndq = ndq->next;
			} while (ndq != ndqueue);
		}
		if (!found) {
			// Ignore advertisement -- it may be an attack
			return;
		}
		// Remove the matching item from the ndqueue
		dequeue (ndq);
		// Replicate the Neigbor Advertisement over the IPv6 Link (like plain IPv6)
		handle_4to6_plain (v4ngbcmdlen, &v4name);
		return;
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
	if (!validate_originator (&v4name, v4src6)) {
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
void handle_6to4_plain_unicast (ssize_t pktlen) {
	struct sockaddr_in v4dest;
	memset (&v4dest, 0, sizeof (v4dest));
	v4dest.sin_family = AF_INET;
	v4dest.sin_port = htons (v6ether.h_dest [0] | (v6ether.h_dest [1] << 8));
	memcpy (&v4dest.sin_addr, v6ether.h_dest + 2, 4);
	syslog (LOG_DEBUG, "%s: Sending IPv6-UDP-IPv4 to %d.%d.%d.%d:%d, result = %d\n", program,
	((uint8_t *) &v4peer.sin_addr.s_addr) [0],
	((uint8_t *) &v4peer.sin_addr.s_addr) [1],
	((uint8_t *) &v4peer.sin_addr.s_addr) [2],
	((uint8_t *) &v4peer.sin_addr.s_addr) [3],
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
	//
	// Validate ICMPv6 message -- trivial, trust local generation
	//
	// Handle the message dependent on its type
	switch (v6icmp6type) {
	case ND_ROUTER_SOLICIT:
		v6icmp6type = ND_ROUTER_ADVERT;
		v6icmp6data [0] = 0;		// Cur Hop Limit: unspec
		v6icmp6data [1] = 0x18;		// M=0, O=0,
						// H=0, Prf=11=Low
						// Reserved=0
		//TODO: wire says 0x44 for router_adv.flags
		size_t writepos = 2;
		memset (v6icmp6data + writepos, 0xff, 2+4+4);
						// Router Lifetime: max, 18.2h
						// Reachable Time: max
						// Retrans Timer: max
		writepos += 2+4+4;
		writepos = icmp6_prefix (writepos, 0);
		v6plen = htons (4 + writepos);
		memcpy (v6dst6, v6src6, 16);
		memcpy (v6src6, v6listen_linklocal_complete, 16);
		v6icmp6csum = icmp6_checksum ((uint8_t *) v6hdr6, 4 + writepos);
		v6ether.h_proto = htons (ETH_P_IPV6);
		memcpy (v6ether.h_dest, v6ether.h_source, 6);
		memcpy (v6ether.h_source, v6lladdr, 6);
		syslog (LOG_INFO, "Replying Router Advertisement to the IPv6 Link, result = %d\n",
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
		//  - other peers start a process in the ndqueue
		if ((memcmp (v6ndtarget, router_linklocal_address, 16) == 0) ||
		    (memcmp (v6ndtarget, router_linklocal_address_complete, 16))) {
			advertise_6bed4_public_service (NULL);
		} else if (memcmp (v6ndtarget, &v6listen, 16) == 0) {
			return;		/* yes you are unique, drop */
		} else {
			enqueue ((struct in6_addr *) v6ndtarget, (struct in6_addr *) v6src6, v6ether.h_source);
		}
		break;
	case ND_NEIGHBOR_ADVERT:
		handle_6to4_plain_unicast (pktlen);
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
syslog (LOG_DEBUG, "TODO: Packet from IPv6 stack, target %02x:%02x:%02x:%02x:%02x:%02x\n", v6ether.h_dest [0], v6ether.h_dest [1], v6ether.h_dest [2], v6ether.h_dest [3], v6ether.h_dest [4], v6ether.h_dest [5]);
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
		handle_6to4_nd (rawlen);
	} else if ((v6dst6->s6_addr [0] != 0xff) && !(v6dst6->s6_addr [8] & 0x01)) {
		//
		// Plain Unicast
		if (v6hops-- <= 1) {
			return;
		}
syslog (LOG_DEBUG, "TODO: Forwarding plain unicast from IPv6 to 6bed4\n");
		handle_6to4_plain_unicast (rawlen);
	} else {
		//
		// Plain Multicast
		//TODO:IGNORE_MULTICAST//
		syslog (LOG_DEBUG, "%s: Multicast from 6bed4 Link to 6bed4 Network is not supported\n", program);
	}
}


/*
 * Send a single Neighbor Solicitation message over 6bed4.  This will
 * be sent to the given 6bed4 address, and is usually part of a series
 * of attempts to find a short-cut route to the 6bed4 peer.
 */
void solicit_6bed4_neighbor (const struct ndqueue *info, const uint8_t *addr6bed4) {
	v4v6icmptype = ND_NEIGHBOR_SOLICIT;
	v4v6icmpcode = 0;
	v4v6icmpdata [0] =
	v4v6icmpdata [1] =
	v4v6icmpdata [2] =
	v4v6icmpdata [3] = 0x00;
	memcpy (v4v6icmpdata + 4, &info->target, 16);
	v4v6icmpdata [20] = 1;	// option type is Source Link-Layer Address
	v4v6icmpdata [21] = 1;	// option length is 1x 8 bytes
	memcpy (v4v6icmpdata + 22, v6lladdr, 6);
	uint16_t pktlen = sizeof (struct ip6_hdr) + sizeof (struct icmp6_hdr) + 28;
	icmp6_checksum ((uint8_t *) v4hdr6, pktlen);
	handle_6to4_plain_unicast (pktlen);
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
		UDP_PORT_6BED4 % 256, UDP_PORT_6BED4 / 256,
		224, 0, 0, 1
	};
	if (info->todo_lancast > 0) {
		// Attempt 1. Send to LAN multicast address (same public IP)
		info->todo_lancast--;
		solicit_6bed4_neighbor (info, addr6bed4_lancast);
	} else if (info->todo_direct > 0) {
		// Attempt 2. Send to target's direct IP address / UDP port
		info->todo_direct--;
		addr6bed4 [0] = info->target.s6_addr [0] ^ 0x02;
		addr6bed4 [1] = info->target.s6_addr [1];
		addr6bed4 [2] = info->target.s6_addr [2];
		addr6bed4 [3] = info->target.s6_addr [5];
		addr6bed4 [4] = info->target.s6_addr [6];
		addr6bed4 [5] = info->target.s6_addr [7];
		solicit_6bed4_neighbor (info, addr6bed4);
	} else {
		// Attempt 3. Respond with Public 6bed4 Service
		syslog (LOG_INFO, "%s: Failed to find a bypass, passing back the 6bed4 Router\n", program);
		advertise_6bed4_public_service (info);
	}
}


/* Perform Router Solicitation.  This is the usual mechanism that is used
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


/* Regular maintenance is a routine that runs regularly to do one of two
 * generic tasks: either it sends Router Solicitation messages to the
 * Public 6bed4 Service, or it sends an empty UDP message somewhat in its
 * direction to keep NAT/firewall holes open.
 */
void regular_maintenance (void) {
	if (!got_lladdr) {
		solicit_router ();
		maintenance_time_cycle <<= 1;
		if (maintenance_time_cycle > maintenance_time_cycle_max) {
			maintenance_time_cycle = maintenance_time_cycle_max;
		}
		syslog (LOG_INFO, "Sent Router Advertisement to Public 6bed4 Service, next attempt in %d seconds\n", maintenance_time_cycle);
	} else {
		syslog (LOG_INFO, "This would be a nice time for KeepAlive\n");
		maintenance_time_cycle = maintenance_time_cycle_max;
	}
	maintenance_time_sec = time () + maintenance_time_cycle;
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
	if (v4mcast != -1) {
		FD_SET (v4mcast, &io);
	}
	int nfds = (v4sox < v6sox)? (v6sox + 1): (v4sox + 1);
	while (1) {
		struct timeval tout;
		struct timeval now;
		gettimeofday (&now, NULL);
		if (maintenance_time_sec <= now.tv_sec) {
			regular_maintenance ();
		}
		tout.tv_sec = maintenance_time_sec;
		tout.tv_usec = 0;
		while (ndqueue && (
				((ndqueue->next->tv.tv_sec == now.tv_sec)
				  && (ndqueue->next->tv.tv_usec < now.tv_usec))
				|| (ndqueue->next->tv.tv_sec < now.tv_sec))) {
			//
			// Run the entry's handler code
			keep = chase_neighbor_6bed4_address (ndqueue->next);
			if (!keep) {
				dequeue (ndqueue->next);
				continue;
			}
			//
			// Make ndqueue point to the entry to run
			ndqueue = ndqueue->next;
			//
			// Add 10ms to the running time
			if (ndqueue->tv.tv_usec < 990000) {
				ndqueue->tv.tv_usec +=   10000;
			} else {
				ndqueue->tv.tv_usec -=  990000;
				ndqueue->tv.tv_sec  += 1      ;
			}
		}
		if (ndqueue && (ndqueue->next->tv.tv_sec < tout.tv_sec)) {
			tout.tv_sec  = now.tv_sec  - ndqueue->next->tv.tv_sec ;
			tout.tv_usec = now.tv_usec - ndqueue->next->tv.tv_usec;
			if (tout.tv_usec < 0) {
				tout.tv_usec += 1000000;
				tout.tv_sec  -= 1;
			}
		}
		select (nfds, &io, NULL, NULL, &tout);
		if (FD_ISSET (v4sox, &io)) {
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
printf ("WOW: Got multicast input\n");
				handle_4to6 (v4mcast);
			} else {
				FD_SET (v4mcast, &io);
			}
		}
//fflush (stdout);
	}
}


/* Option descriptive data structures */

char *short_opt = "s:t:dl:p:femh";

struct option long_opt [] = {
	{ "v4server", 1, NULL, 's' },
	{ "tundev", 1, NULL, 't' },
	{ "default-route", 0, NULL, 'd' },
	{ "listen", 1, NULL, 'l' },
	{ "port", 1, NULL, 'p' },
	{ "foreground", 0, NULL, 'f' },
	{ "fork-not", 0, NULL, 'f' },
	{ "error-console", 0, NULL, 'e' },
	{ "mistrust", 0, NULL, ',' },
	{ "multicast-not", 0, NULL, 'm' },
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
				fprintf (stderr, "%s: You can only specify a single server address\n");
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
			if (connect (v4sox, (struct sockaddr *) &v4peer, sizeof (v4peer)) != 0) {
				ok = 0;
				fprintf (stderr, "%s: Failed to connect to UDPv4 %s:%d: %s\n", program, optarg, ntohs (v4peer.sin_port), strerror (errno));
				break;
			}
			break;
		case 't':
			if (v6sox != -1) {
				ok = 0;
				fprintf (stderr, "%s: Multiple -t arguments are not permitted\n");
				break;
			}
			v6sox = open (optarg, O_RDWR);
			if (v6sox == -1) {
				ok = 0;
				fprintf (stderr, "%s: Failed to open tunnel device %s: %s\n", program, optarg, strerror (errno));
				break;
			}
			break;
		case 'd':
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
		case 'm':
			if (!multicast) {
				fprintf (stderr, "%s: You can only request skipping multicast once\n", program);
				exit (1);
			}
			multicast = false;
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
		fprintf (stderr, "Usage: %s [-d] [-t /dev/tunX]\n       %s -h\n", program, program);
#else
		fprintf (stderr, "Usage: %s [-d] -t /dev/tunX\n       %s -h\n", program, program);
#endif
		return 0;
	}
	if (!ok) {
		return 0;
	}
#ifdef HAVE_SETUP_TUNNEL
	if (v6sox == -1) {
		if (geteuid () != 0) {
			fprintf (stderr, "%s: You should be root, or use -t to specify an accessible tunnel device\n", program);
			return 0;
		} else {
			setup_tunnel ();
		}
	}
#else /* ! HAVE_SETUP_TUNNEL */
	if (v6sox == -1) {
		fprintf (stderr, "%s: You must specify a tunnel device with -t that is accessible to you\n", program);
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
	// Open the syslog channel
	openlog (program, LOG_NDELAY | LOG_PID | ( log_to_stderr? LOG_PERROR: 0), LOG_DAEMON);
	//
	// Create memory for the freequeue buffer
	freequeue = calloc (freequeue_items, sizeof (struct ndqueue));
	if (!freequeue) {
		syslog (LOG_CRIT, "%d: Failed to allocate %d queue items\n", program, freequeue_items);
		exit (1);
	}
	//
	// Create socket for normal outgoing (and return) 6bed4 traffic
	if (v4sox == -1) {
		v4sox = socket (AF_INET, SOCK_DGRAM, 0);
		if (v4sox == -1) {
			syslog (LOG_CRIT, "%s: Failed to open a local IPv4 socket -- does your system still support IPv4?\n", program);
			exit (1);
		}
	}
	//
	// Bind to the IPv4 all-nodes local multicast address
	memset (&v4allnodes, 0, sizeof (v4allnodes));
	v4allnodes.sin_family = AF_INET;
	v4allnodes.sin_port = htons (UDP_PORT_6BED4);
	v4allnodes.sin_addr.s_addr = htonl ( (224L << 24) | 1L );
	if (multicast) {
		v4mcast = socket (AF_INET, SOCK_DGRAM, 0);
		if (v4mcast != -1) {
			if (bind (v4mcast, (struct sockaddr *) &v4allnodes, sizeof (v4allnodes)) != 0) {
				close (v4mcast);
				v4mcast = -1;
				syslog (LOG_ERR, "%s: No LAN bypass: Failed to bind to IPv4 all-nodes\n", program);
#if 0
			} else if (listen (v4mcast, 10) != 0) {
				close (v4mcast);
				v4mcast = -1;
				syslog (LOG_ERR, "%s: No LAN bypass: Failed to listen to IPv4 all-nodes\n", program);
#endif
			}
		}
	} else {
		syslog (LOG_INFO, "%s: No LAN bypass: Not desired\n");
	}
	//
	// If port and/or listen arguments were provided, bind to them
	if ((v4bind.sin_addr.s_addr != INADDR_ANY) || (v4bind.sin_port != 0)) {
		if (bind (v4sox, (struct sockaddr *) &v4bind, sizeof (v4bind)) != 0) {
			syslog (LOG_CRIT, "%s: Failed to bind to local socket -- did you specify both address and port?\n", program);
			exit (1);
		}
	}
	//
	// Setup connection to the public server
	if (connect (v4sox, (struct sockaddr *) &v4peer, sizeof (v4peer)) != 0) {
		syslog (LOG_CRIT, "%s: Failed to connect over UDPv4: %s\n", program, strerror (errno));
		exit (1);
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

