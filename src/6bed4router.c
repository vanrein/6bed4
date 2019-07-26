/* 6bed4/router.c -- traffic forwarding daemon for public TSP service
 *
 * This is an implementation of the profile that makes TSP service publicly
 * usable, that is without authentication.  However to avoid abuse of such
 * a service, it is not anonymous -- IPv6 addresses contain the IPv4 address
 * and port.
 *
 * This is an implementation of neighbour and router discovery over a
 * tunnel that packs IPv6 inside UDP/IPv4.  This tunnel mechanism is
 * targeted specifically at embedded devices that are to function on
 * any network, including IPv4-only, while being designed as IPv6-only
 * devices with a fallback to this tunnel.
 *
 * Interestingly, as a side-effect of this design the router daemon can be
 * stateless.  Any further requirements that are stateful are most likely
 * filtering, and that can be solved in stateful firewall configuration.
 *
 * The intention of TSP is to enable IPv4-only hosts to connecto to
 * IPv6 services; the public TSP profile adds to that the ability to
 * do it in a temporary manner.
 *
 * TODO: Should we translate ICMPv4 --> ICMPv6?
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>

#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/select.h>
#include <sys/ioctl.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
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
 * the -d option leads to an error, or to an attempt to setup the tunnel.
 * The setup_tunnel() function used for that is defined per platform, such
 * as for LINUX.  Remember to maintain the manpage's optionality for -d.
 */
#undef HAVE_SETUP_TUNNEL


/* Global variables */

/* SCTP structures are far from standardised, so we define our own header */
struct my_sctphdr {
	uint16_t source, dest;
	uint32_t vtag;
	uint32_t cksum;
};

char *program;

int v4sox = -1;
int v6sox = -1;

char *v4server = NULL;
char *v6server = NULL;
char *v6prefix = NULL;

const uint8_t v6listen_linklocal [16] = { 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
uint8_t v6listen_linklocal_complete [16] = { 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

uint8_t lladdr_6bed4 [6];

struct sockaddr_in  v4name;
struct sockaddr_in6 v6name;

struct in6_addr v6listen;
struct in6_addr v6listen_complete;
struct in_addr  v4listen;


struct {
	struct tun_pi tun;
	union {
		struct {
			struct ip6_hdr v6hdr;
			uint8_t data [MTU - sizeof (struct ip6_hdr)];
		} idata;
		struct v4frame {
			struct ip6_hdr v6hdr;
			union {
				struct icmp6_hdr  v6icmphdr;
				struct my_sctphdr v6sctphdr;
				struct tcphdr     v6tcphdr ;
				struct udphdr     v6udphdr ;
				struct {
					struct udphdr     v6udphdr;
					struct my_sctphdr v6sctphdr;
				} tdata;
			} adata;
		} ndata;
	} udata;
} v4data6;

#define v4tunpi6 	( v4data6.tun)
#define v4data		((uint8_t *) &v4data6.udata)
#define v4hdr6		(&v4data6.udata.idata.v6hdr)
#define v4src6		(&v4data6.udata.idata.v6hdr.ip6_src)
#define v4dst6		(&v4data6.udata.idata.v6hdr.ip6_dst)

#define v4v6payload	((uint16_t *) &v4data6.udata.ndata.adata)
#define v4v6plen	( v4data6.udata.ndata.v6hdr.ip6_plen)
#define v4v6nexthdr	( v4data6.udata.ndata.v6hdr.ip6_nxt)
#define v4v6hoplimit	( v4data6.udata.ndata.v6hdr.ip6_hops)

#define v4v6icmpdata	( v4data6.udata.ndata.adata.v6icmphdr.icmp6_data8)
#define v4v6icmptype	( v4data6.udata.ndata.adata.v6icmphdr.icmp6_type)
#define v4v6icmpcode	( v4data6.udata.ndata.adata.v6icmphdr.icmp6_code)
#define v4v6icmpcksum	( v4data6.udata.ndata.adata.v6icmphdr.icmp6_cksum)

#define v4v6sctpofs	(offsetof (struct v4frame,adata.v6sctphdr))
#define v4v6sctpsrcport	( v4data6.udata.ndata.adata.v6sctphdr.source)
#define v4v6sctpdstport	( v4data6.udata.ndata.adata.v6sctphdr.dest)
#define v4v6sctpcksum	( v4data6.udata.ndata.adata.v6sctphdr.cksum)

#define v4v6tunsctpofs	(offsetof (struct v4frame,adata.tdata.v6sctphdr))
#define v4v6tunsctpsrcport ( v4data6.udata.ndata.adata.tdata.v6sctphdr.source)
#define v4v6tunsctpdstport ( v4data6.udata.ndata.adata.tdata.v6sctphdr.dest)
#define v4v6tunsctpcksum   ( v4data6.udata.ndata.adata.tdata.v6sctphdr.cksum)

#define v4v6tcpsrcport	( v4data6.udata.ndata.adata.v6tcphdr.source)
#define v4v6tcpdstport	( v4data6.udata.ndata.adata.v6tcphdr.dest)
#define v4v6tcpcksum	( v4data6.udata.ndata.adata.v6tcphdr.check)

#define v4v6udpsrcport	( v4data6.udata.ndata.adata.v6udphdr.source)
#define v4v6udpdstport	( v4data6.udata.ndata.adata.v6udphdr.dest)
#define v4v6udpcksum	( v4data6.udata.ndata.adata.v6udphdr.check)

#define v4ngbsoltarget	(&v4data6.udata.ndata.adata.v6icmphdr.icmp6_data8 [4])


struct {
	struct tun_pi tun;
	union {
		uint8_t data [MTU];
		struct v6frame {
			struct ip6_hdr v6hdr;
			union {
				struct icmp6_hdr  v6icmphdr;
				struct my_sctphdr v6sctphdr;
				struct tcphdr     v6tcphdr ;
				struct udphdr     v6udphdr ;
				struct {
					struct udphdr     v6udphdr;
					struct my_sctphdr v6sctphdr;
				} tdata;
			} adata;
		} ndata;
	} udata;
	uint8_t zero;
} v6data6;

#define v6tuncmd	( v6data6.tun)
#define v6data		( v6data6.udata.data)
#define v6hdr6		(&v6data6.udata.ndata.v6hdr)
#define v6src6		(&v6data6.udata.ndata.v6hdr.ip6_src)
#define v6dst6		(&v6data6.udata.ndata.v6hdr.ip6_dst)
#define v6hoplimit	( v6data6.udata.ndata.v6hdr.ip6_hops)
#define v6nexthdr	( v6data6.udata.ndata.v6hdr.ip6_nxt)

#define v6icmptype	( v6data6.udata.ndata.adata.v6icmphdr.icmp6_type)
#define v6icmpcksum	( v6data6.udata.ndata.adata.v6icmphdr.icmp6_cksum)

#define v6sctpcksum	( v6data6.udata.ndata.adata.v6sctphdr.cksum)
#define v6tunsctpcksum	( v6data6.udata.ndata.adata.tdata.v6sctphdr.cksum)

#define v6sctpofs	(offsetof(struct v6frame,adata.v6sctphdr))
#define v6tunsctpofs	(offsetof(struct v6frame,adata.tdata.v6sctphdr))

#define v6tcpcksum	( v6data6.udata.ndata.adata.v6tcphdr.check)

#define v6udpcksum	( v6data6.udata.ndata.adata.v6udphdr.check)
#define v6udpdstport	( v6data6.udata.ndata.adata.v6udphdr.dest)
#define v6udpsrcport	( v6data6.udata.ndata.adata.v6udphdr.source)


uint8_t router_linklocal_address [] = {
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



#ifndef MAXNUM_MASQHOST
#define MAXNUM_MASQHOST 4
#endif

uint16_t num_masqhost = 0;
uint8_t masqhost [MAXNUM_MASQHOST][16];

// ports for 's', 't', 'u' -- SCTP, TCP, UDP have increasing numbers

#ifndef MAXNUM_PORTPAIRS
#define MAXNUM_PORTPAIRS 10
#endif

// masqportpairs holds triples <lowport,highport,masqhostnr>
uint16_t num_masqportpairs [3] = { 0, 0, 0 };
uint16_t masqportpairs [3][3*MAXNUM_PORTPAIRS];

// same for ICMPv6
uint16_t icmp_num_portpairs = 0;
uint16_t icmp_portpairs [3] = { 1, 1, 0 };



/*
 *
 * Driver routines
 *
 */

#ifndef INTERFACE_NAME_6BED4
#define INTERFACE_NAME_6BED4 "6bed4"
#endif

#ifdef LINUX
#define HAVE_SETUP_TUNNEL
/* Implement the setup_tunnel() command for Linux.
 * Return 1 on success, 0 on failure.
 */
int setup_tunnel (void) {
	v6sox = open ("/dev/net/tun", O_RDWR);
	if (v6sox == -1) {
		fprintf (stderr, "%s: Failed to access tunnel driver on /dev/net/tun: %s\n", program, strerror (errno));
		return 0;
	}
	int ok = 1;
	struct ifreq ifreq;
	memset (&ifreq, 0, sizeof (ifreq));
	strncpy (ifreq.ifr_name, INTERFACE_NAME_6BED4, IFNAMSIZ);
	ifreq.ifr_flags = IFF_TUN;
	if (ok && (ioctl (v6sox, TUNSETIFF, (void *) &ifreq) == -1)) {
		ok = 0;
	}
	ifreq.ifr_name [IFNAMSIZ] = 0;
	char cmd [512+1];
	snprintf (cmd, 512, "/sbin/ip -6 addr flush dev %s", ifreq.ifr_name);
	if (ok && system (cmd) != 0) {
		ok = 0;
	}
	snprintf (cmd, 512, "/sbin/ip addr add fe80::0 dev %s scope link", ifreq.ifr_name);
	if (ok && system (cmd) != 0) {
		ok = 0;
	}
	snprintf (cmd, 512, "/sbin/ip -6 addr add %s dev %s", v6prefix, ifreq.ifr_name);
	if (ok && system (cmd) != 0) {
		ok = 0;
	}
	snprintf (cmd, 512, "/sbin/ip link set %s up mtu 1280", ifreq.ifr_name);
	if (ok && system (cmd) != 0) {
		ok = 0;
	}
	if (!ok) {
		close (v6sox);	/* This removes the tunnel interface */
		fprintf (stderr, "Failed to setup tunnel \"%s\"\n", INTERFACE_NAME_6BED4);
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

/* Calculate the ICMPv6 checksum field
 */
uint16_t icmp6_checksum (struct in6_addr *src6, struct in6_addr *dst6,
				uint16_t *payload, size_t payloadlen) {
	uint16_t plenword = htons (payloadlen);	// our ICMPv6 is small
	uint16_t nxthword = htons (IPPROTO_ICMPV6);
	uint16_t *area [] = { src6->s6_addr16, dst6->s6_addr16,
				&plenword, &nxthword,
				payload, &payload [2] };
	uint8_t areawords [] = { 8, 8, 1, 1, 1, (payloadlen >> 1) - 2 };
	uint32_t csum = 0;
	u_int8_t i, j;
	for (i=0; i < 6; i++) {
		for (j=0; j<areawords [i]; j++) {
			csum += ntohs (area [i] [j]);
		}
	}
	csum = (csum & 0xffff) + (csum >> 16);
	csum = (csum & 0xffff) + (csum >> 16);
	csum = htons (~csum);
	return csum;
}


/* Mangle a packet by replacing an IPv6 address, correcting the checksum.
 * In all of ICMPv6, UDPv6, TCPv6, SCTPv6, the checksumming is a 1's cpl
 * of a sum of 16-bit words; the position of the words don't matter and
 * we can subtract the old address' words and add the new address' words.
 * Or, as a result of the one's complement, the opposite.  There is some
 * inclusion of the top half of a 32-bit sum, but that is also neutral.
 */
void masquerade_address (struct in6_addr *var,
			const struct in6_addr *new,
			uint16_t *csum_field) {
	int32_t csum = ntohs (~*csum_field);
	uint8_t i;
	for (i=0; i<8; i++) {
		csum -= ntohs (var->s6_addr16 [i]);
		var->s6_addr16 [i] = new->s6_addr16 [i];
		csum += ntohs (var->s6_addr16 [i]);
	}
	csum = (csum & 0xffff) + (csum >> 16);
	csum = (csum & 0xffff) + (csum >> 16);
	*csum_field = htons (~csum);
}


/* Send an ICMPv6 reply.  This is constructed at the tunnel end, from
 * the incoming message.  The parameter indicates how many bytes the
 * ICMPv6 package counts after the ICMPv6 header.  It must be 4 (mod 8).
 *
 * Actions: v4/udp src becomes dest, set v4/udp/v6 src, len, cksum, send.
 *          reply is always to v4src6, except that if it starts with
 *	    0x00,0x00 it will be replaced with allnodes_linklocal_address.
 */
void icmp6_reply (size_t icmp6bodylen) {
	v4v6hoplimit = 255;
	if ((icmp6bodylen & 0x07) != 4) {
		return;   /* illegal length, drop */
	}
	v4v6plen = htons (icmp6bodylen + 4);
	memcpy (v4dst6,
		(v4src6->s6_addr16 [0])
			? (uint8_t *) v4src6
			: allnodes_linklocal_address,
		16);
	memcpy (v4src6, router_linklocal_address, 16);
	v4v6icmpcksum = icmp6_checksum (v4src6, v4dst6,
				v4v6payload, ntohs (v4v6plen));
	//
	// Send the message to the IPv4 originator port
printf ("Sending ICMPv6-IPv6-UDP-IPv4 to %d.%d.%d.%d:%d, result = %zd\n",
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
	v4v6icmpdata [optidx++] = 3;	// Type
	v4v6icmpdata [optidx++] = 4;	// Length
	v4v6icmpdata [optidx++] = 114;	// This is a /114 prefix
	v4v6icmpdata [optidx++] = 0xc0;	// L=1, A=1, Reserved1=0
	memset (v4v6icmpdata + optidx, endlife? 0x00: 0xff, 8);
	optidx += 8;
					// Valid Lifetime: Zero / Infinite
					// Preferred Lifetime: Zero / Infinite
	memset (v4v6icmpdata + optidx, 0, 4);
	optidx += 4;
					// Reserved2=0
	addr_6bed4 ((struct in6_addr *) (v4v6icmpdata + optidx), 0);
					// Set IPv6 prefix
	optidx += 16;
	return optidx;
}


/*
 * TODO: DEPRECATED
 *
 * Append a Destination Link-Layer Address Option to an ICMPv6
 * message.  The address is comprised from the remote's UDP port
 * and IPv4 address, as seen by the router.  They are supplied
 * in that order, in network byte order.  The resulting address
 * is 6 bytes, but even though that makes it look like a MAC
 * address, it really is another beast.
 * Note that no effort is made in the router to recognise the
 * "illegal port number" 0x3333 -- the client needs a message
 * and will recognise it and act on it.
 */
size_t icmp6_dest_linkaddr (size_t optidx) {
	uint8_t typelen [2] = { ND_OPT_DESTINATION_LINKADDR, 1 };
	memcpy (v4v6icmpdata + optidx + 0, &typelen, 2);
	v4v6icmpdata [optidx + 2] = ntohs (v4name.sin_port) & 0xff;
	v4v6icmpdata [optidx + 3] = ntohs (v4name.sin_port) >> 8;
	memcpy (v4v6icmpdata + optidx + 4, &v4name.sin_addr, 4);
	optidx += 8;
	return optidx;
}


/*
 * Test if an address is a local override.  This function is compiled-in
 * to support hosts with a /64 from their own ISP and nothing more; they
 * need to access local IPv6 addresses.  We rely on the 6bed4 port being
 * 0 to decide that an address cannot be anything but a local override.
 * Define LOCAL_OVERRIDES_PORT0 to enable this feature.
 */
#ifdef LOCAL_OVERRIDES_PORT0
static inline bool is_local_override (struct in6_addr *ip6) {
	return (ip6->s6_addr16 [6] == 0) && (memcmp (ip6->s6_addr, &v6listen, 8) == 0);
}
#else
#define is_local_override(_) false
#endif


/*
 * Test if the provided IPv6 address matches the prefix used for 6bed4.
 *TODO: This is oversimplistic, it only cares for the Hetzner /64
 */
static inline bool is_6bed4 (struct in6_addr *ip6) {
	return memcmp (&v6listen, ip6->s6_addr, 8) == 0;
}

/* Test if the provided IPv6 address matches the fc64::/16 prefix.
 * If so, the traffic may be bounced using 6bed4 traffic, but it
 * must not be relayed to the native IPv6 side.
 * TODO: Perhaps allow only configured <netid>, so fc64:<netid>::/32
 */
static inline bool is_fc64 (struct in6_addr *ip6) {
	return ip6->s6_addr16 [0] == htons (0xfc64);
}

/* Test if the src and destination share the same /114 and the destination
 * fills up the rest with zero bits; in other words, test that this is a
 * package targeted from a 6bed4peer node to its 6bed4router.  This is used
 * to distinguish special ICMPv6 messages, as well as masquerading targets.
 */
static inline bool is_mine (struct in6_addr *src6, struct in6_addr *dst6) {
	return ((dst6->s6_addr [15] == 0x00)
		&& ((dst6->s6_addr [14] & 0x3f) == 0x00)
		&& (memcmp (dst6->s6_addr, src6->s6_addr, 14) == 0));
}


/*
 * Validate the originator's IPv6 address.  It should match the
 * UDP/IPv4 coordinates of the receiving 6bed4 socket.  Also,
 * the /64 prefix (but not the /114 prefix!) must match v6listen.
 */
bool validate_originator (struct in6_addr *ip6) {
	uint32_t addr;
	//
	// Require non-local top halves to match our v6listen_linklocal address
	// We will enforce our own fallback address (and fc64:<netid>::/32)
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
 * Major packet processing functions
 */


/*
 * Respond to a Router Solicitation received over the 6bed4 Network.
 */
void handle_6bed4_router_solicit (void) {
	struct in6_addr observed;
	v4v6icmptype = ND_ROUTER_ADVERT;
	v4v6icmpdata [0] = 0;			// Cur Hop Limit: unspec
	v4v6icmpdata [1] = 0x18;		// M=0, O=0
						// H=0, Prf=11=Low
						// Reserved=0
// TODO: wire says 0x44 for router_adv.flags
	size_t writepos = 2;
	memset (v4v6icmpdata+writepos, 0xff, 2+4+4);
					// Router Lifetime: max, 18.2h
					// Reachable Time: max
					// Retrans Timer: max
	writepos += 2+4+4;
	writepos = icmp6_prefix (writepos, 0);
	icmp6_reply (writepos);
}


/* Handle the IPv4 message pointed at by msg as a neighbouring command.
 *
 * Type	Code	ICMPv6 meaning			Handling
 * ----	----	-----------------------------	----------------------------
 * 133	0	Router Solicitation		Send Router Advertisement
 * 134	0	Router Advertisement		Ignore
 * 135	0	Neighbour Solicitation		Send Neighbour Advertisement
 * 136	0	Neighbour Advertisement		Ignore
 * 137	0	Redirect			Ignore
 */
void handle_4to6_nd (ssize_t v4ngbcmdlen) {
	uint16_t srclinklayer;
	if (v4ngbcmdlen < sizeof (struct ip6_hdr) + sizeof (struct icmp6_hdr)) {
		return;
	}
	if (v4v6icmpcode != 0) {
		return;
	}
	if (icmp6_checksum (v4src6, v4dst6,
				v4v6payload, v4ngbcmdlen-sizeof (struct ip6_hdr)
			) != v4v6icmpcksum) {
		return;
	}
	//
	// Approved.  Perform neighbourly courtesy.
	switch (v4v6icmptype) {
	case ND_ROUTER_SOLICIT:
		//
		// Validate Router Solicitation
		srclinklayer = 0;
		if (v4ngbcmdlen == sizeof (struct ip6_hdr) + 8 + 8) {
			// One option is possible, the source link-layer address
			if (v4v6icmpdata [4] != 1 || v4v6icmpdata [5] != 1) {
				break;   /* bad opton, ignore */
			}
			// The source link-layer address is end-aligned
			srclinklayer = (v4v6icmpdata [10] << 8) | v4v6icmpdata [11];
			if (srclinklayer == 0) {
				break;   /* illegal, ignore */
			}
		} else if (v4ngbcmdlen == sizeof (struct ip6_hdr) + 8) {
			srclinklayer = 0;   /* set for latter filling */
		} else {
			break;   /* illegal length, drop */
		}
		//
		// Having accepted the Router Advertisement, respond
		handle_6bed4_router_solicit ();
		break;
	case ND_NEIGHBOR_SOLICIT:
		//
		// Validate Neigbour Solicitation
		if (!validate_originator (v4src6)) {
			break;	/* bad source address, drop */
		}
		if ((v4ngbcmdlen != sizeof (struct ip6_hdr) + 24) &&
		    (v4ngbcmdlen != sizeof (struct ip6_hdr) + 24 + 8)) {
			break;   /* funny length, drop */
		}
		if ((memcmp (v4ngbsoltarget, v6listen_linklocal, 16) != 0) &&
                    (memcmp (v4ngbsoltarget, v6listen_linklocal_complete, 16) != 0) &&
                    (memcmp (v4ngbsoltarget, &v6listen_complete, 16) != 0)) {
			break;	/* target not known here, drop */
		}
		//
		// Construct Neigbour Advertisement
		v4v6icmptype = ND_NEIGHBOR_ADVERT;
		v4v6icmpdata [0] = 0xc0;
		v4v6icmpdata [1] =
		v4v6icmpdata [2] =
		v4v6icmpdata [3] = 0x00;	// R=1, S=1, O=1, Reserved=0
		memcpy (v4v6icmpdata +  4, &v6listen_complete, 16);
		// Append option: the target link-layer address
		// Note: wire does not include target link-layer address
		v4v6icmpdata [20] = 2;		// Type: Target Link-Layer Addr
		v4v6icmpdata [21] = 1;		// Length: 1x 8 bytes
		memcpy (v4v6icmpdata + 22, lladdr_6bed4, 6);
		icmp6_reply (28);	// 28 is the ICMPv6 response length
		break;
	case ND_ROUTER_ADVERT:
	case ND_NEIGHBOR_ADVERT:
	case ND_REDIRECT:
		break;   /* drop */
	}
}


/*
 * Forward a message to the masquerading target, or drop it.  This is done
 * with non-6bed4 packets that are sent from a 6bed4peer node to its
 * 6bed4router address; see is_mine() for the definition.  The general idea
 * is that the address that is to be masqueraded can later be reconstructed
 * from the 6bed4peer's address.
 */
void handle_4to6_masquerading (ssize_t v4datalen) {
	fprintf (stderr, "Traffic to 6bed4router may be fit for masquerading\n");
	uint16_t *portpairs = NULL;
	uint16_t numpairs = 0;
	uint16_t port = 0;
	uint16_t *csum_field = NULL;
	uint16_t sctp_offset = 0;
	uint16_t skip_csum;
	switch (v4v6nexthdr) {
	case IPPROTO_SCTP:
		portpairs = masqportpairs [0];	// 's'
		numpairs  = num_masqportpairs [0];
		port = ntohs (v4v6sctpdstport);
		csum_field = &skip_csum;
		sctp_offset = v4v6sctpofs;
		break;
	case IPPROTO_TCP:
		portpairs = masqportpairs [1];	// 't'
		numpairs  = num_masqportpairs [1];
		port = ntohs (v4v6tcpdstport);
		csum_field = &v4v6tcpcksum;
		break;
	case IPPROTO_UDP:
		portpairs = masqportpairs [2];	// 'u'
		numpairs  = num_masqportpairs [2];
		port = ntohs (v4v6udpdstport);
		csum_field = &v4v6udpcksum;
		if ((port == 9899) && (v4v6udpsrcport == v4v6udpdstport)) {
			// SCTP tunneled over UDP (keep csum_field)
			portpairs = masqportpairs [0];
			numpairs = num_masqportpairs [0];
			port = ntohs (v4v6tunsctpdstport);
			sctp_offset = v4v6tunsctpofs;
		}
		break;
	case IPPROTO_ICMPV6:
		portpairs = icmp_portpairs;
		numpairs = icmp_num_portpairs;
		port = icmp_portpairs [0];
		csum_field = &v4v6icmpcksum;
		break;
	default:
		return;
	}
	fprintf (stderr, "DEBUG: Looking for masquerading of port %d in %d entries\n", port, numpairs);
	while (numpairs-- > 0) {
		if ((port >= portpairs [0]) && (port <= portpairs [1])) {
			//
			// Replace masqueraded address by 6bed4router's
			fprintf (stderr, "DEBUG: Passing traffic to masquerading address number %d\n", portpairs [2]);
			masquerade_address (v4dst6,
				(struct in6_addr *) masqhost [portpairs [2]],
				csum_field);
			if (sctp_offset > 0) {
				//TODO// Recompute SCTP's CRC-32 checksum
				// recompute_sctp_checksum (ip6hdr, sctp_offset, framelen);
				//BUT: SCTP checksum does not use pseudo IPhdr
				//SO:  Address masquerading goes undetected :-D
			}
			//
			// Forward immediately, and return from this function
printf ("Writing Masqueraded IPv6, result = %zd\n",
			write (v6sox, &v4data6, sizeof (struct tun_pi) + v4datalen));
			return;
		}
		portpairs += 3;
	}
	//
	// Silently skip the offered packet
}


/* 
 * Forward a message received over the 6bed4 Network over IPv6.
 * Note that existing checksums will work well, as only the
 * Hop Limit has been altered, and this is not part of the
 * checksum calculations.
 */
void handle_4to6_plain_unicast (ssize_t v4datalen) {
printf ("Writing IPv6, result = %zd\n",
	write (v6sox, &v4data6, sizeof (struct tun_pi) + v4datalen));
}


/*
 * Forward a 6bed4 message to another 6bed4 destination address.
 * Local address prefixes fc64:<netid>:<ipv4>::/64 are also relayed.
 * Note that existing checksums will work well, as only the
 * Hop Limit has been altered, and this is not part of the
 * checksum calculations.
 */
void relay_4to4_plain_unicast (uint8_t* data, ssize_t v4datalen, struct in6_addr *ip6) {
	v4name.sin_port = htons (ip6->s6_addr [12] << 8 | ip6->s6_addr [13]);
	uint8_t *addr = (uint8_t *) &v4name.sin_addr.s_addr;
	addr [0] = (ip6->s6_addr [8] & 0xfc) | ip6->s6_addr [14] >> 6;
	memcpy (addr + 1, ip6->s6_addr + 9, 3);
printf ("Relaying over 6bed4 Network to %d.%d.%d.%d:%d, result = %zd\n",
((uint8_t *) &v4name.sin_addr.s_addr) [0],
((uint8_t *) &v4name.sin_addr.s_addr) [1],
((uint8_t *) &v4name.sin_addr.s_addr) [2],
((uint8_t *) &v4name.sin_addr.s_addr) [3],
ntohs (v4name.sin_port),
	sendto (v4sox,
			data, v4datalen,
			MSG_DONTWAIT,
			(struct sockaddr *) &v4name, sizeof (v4name)));
}


/* Receive a tunnel package, and route it to either the handler for the
 * tunnel protocol, or to the handler that checks and then unpacks the
 * contained IPv6.
 */
void handle_4to6 (void) {
	uint8_t buf [1501];
	ssize_t buflen;
	socklen_t adrlen = sizeof (v4name);
	//
	// Receive IPv4 package, which may be tunneled or a tunnel request
	buflen = recvfrom (v4sox,
			v4data, MTU,
			MSG_DONTWAIT,
			(struct sockaddr *) &v4name, &adrlen
		);
	if (buflen == -1) {
		printf ("%s: Error receiving IPv4-side package: %s",
				program, strerror (errno));
		return;
	}
	if (buflen < sizeof (struct ip6_hdr)) {
		return;
	}
	if ((v4data [0] & 0xf0) != 0x60) {
		// Not an IPv6 packet
		return;
	}
	//
	// Handle the tunneled IPv6 package (dependent on its class)
	if ((v4v6nexthdr == IPPROTO_ICMPV6) &&
			(v4v6icmptype >= 133) && (v4v6icmptype <= 137)) {
		//
		// Not Plain: Router Adv/Sol, Neighbor Adv/Sol, Redirect
		if (v4v6hoplimit != 255) {
			return;
		}
		handle_4to6_nd (buflen);
	} else if (is_mine (v4src6, v4dst6)) {
		handle_4to6_masquerading (buflen);
	} else if ((v4dst6->s6_addr [0] != 0xff) && !(v4dst6->s6_addr [8] & 0x01)) {
		//
		// Plain Unicast
		if (is_local_override (v4dst6)) {
			handle_4to6_plain_unicast (buflen);
		} else if (validate_originator (v4src6)) {
			if (v4v6hoplimit-- <= 1) {
				return;
			}
			if (is_6bed4 (v4dst6) || is_fc64 (v4dst6)) {
				relay_4to4_plain_unicast (v4data, buflen, v4dst6);
			} else {
				handle_4to6_plain_unicast (buflen);
			}
		} else if (is_6bed4 (v4src6)) {
			// The sender must not have kept NAT/firewall holes
			// open and should be instructed about a change in
			// its 6bed4 Link-Local Address.
			handle_6bed4_router_solicit ();
		}
	} else {
		//
		// Plain Multicast
		//OPTIONAL// validate_originator, hoplimit, relay_mcast.
		return;
	}
}


/* Receive an IPv6 package, check its address and pickup IPv4 address and
 * port, then package it as a tunnel message and forward it to IPv4:port.
 */
void handle_6to4 (void) {
	uint16_t mqh;
	//
	// Receive the IPv6 package and ensure a consistent size
	size_t rawlen = read (v6sox, &v6data6, sizeof (v6data6));
	if (rawlen == -1) {
		return;		/* error reading, drop */
	}
	if (rawlen < sizeof (struct tun_pi) + sizeof (struct ip6_hdr) + 1) {
		return;		/* too small, drop */
	}
	if (v6tuncmd.proto != htons (ETH_P_IPV6)) {
		return;		/* no IPv6, drop */
	}
	if ((v6nexthdr == IPPROTO_ICMPV6) &&
			(v6icmptype >= 133) && (v6icmptype <= 137)) {
		return;		/* not plain IPv6, drop */
	}
	if (v6hoplimit-- <= 1) {
		// TODO: Send back an ICMPv6 error message
		return;		/* hop limit exceeded, drop */
	}
	if ((v6dst6->s6_addr [0] == 0xff) /* TODO:UDP_PORT_NOT_YET_FORCED_TO_EVEN || (v6dst6->s6_addr [8] & 0x01) */ ) {
printf ("Received multicast IPv6 data, flags=0x%04x, proto=0x%04x\n", v6tuncmd.flags, v6tuncmd.proto);
		//OPTIONAL// handle_6to4_plain_multicast ()
		return;		/* multicast, drop */
	}
printf ("Received plain unicast IPv6 data, flags=0x%04x, proto=0x%04x\n", v6tuncmd.flags, v6tuncmd.proto);
	//
	// Replace masqueraded addresses configured with -m and its default ::1
	//TODO// Better use the port number to find the find the masqhost
	for (mqh=0; mqh<num_masqhost; mqh++) {
		if (memcmp (v6src6, masqhost [mqh], 16) == 0) {
printf ("Masqueraded sender address in 6to4 set to the client's 6bed4router address\n");
			uint16_t *csum_field = NULL;
			uint16_t fake_csum;
			struct in6_addr masq_src;
			uint16_t sctp_offset = 0;
			switch (v6nexthdr) {
			case IPPROTO_SCTP:
				csum_field = &fake_csum;
				sctp_offset = v6sctpofs;
				break;
			case IPPROTO_TCP:
				csum_field = &v6tcpcksum;
				break;
			case IPPROTO_UDP:
				csum_field = &v6udpcksum;
				if ((v6udpsrcport == v6udpdstport) &&
						(v6udpsrcport == htons (9899))) {
					// SCTP tunneled over UDP
					sctp_offset = v6tunsctpofs;
				}
				break;
			case IPPROTO_ICMPV6:
				csum_field = &v6icmpcksum;
				break;
			default:
				continue;
			}
			//
			// Construct v6src6 from v6dst6, ending in 14 zero bits
			memcpy (&masq_src, v6dst6, 16);
			masq_src.s6_addr16 [7] &= htons (0xc000);
			fprintf (stderr, "Masquerading cksum.old = 0x%04x, ", ntohs (*csum_field));
			masquerade_address (v6src6, &masq_src, csum_field);
			if (sctp_offset > 0) {
				//TODO// Recompute SCTP's CRC-32 checksum
				// recompute_sctp_checksum (ip6hdr, sctp_offset, framelen);
				//BUT: SCTP checksum does not use pseudo IPhdr
				//SO:  Address masquerading goes undetected :-D
			}
			fprintf (stderr, "cksum.new = 0x%04x\n", ntohs (*csum_field));
			break;
		}
	}
	//
	// Ensure that the incoming IPv6 address is properly formatted
	// Note that this avoids access to ::1/128, fe80::/10, fec0::/10
#ifndef TODO_PERMIT_BOUNCE_FOR_32BIT_PREFIX
	if (memcmp (v6dst6, &v6listen, 8) != 0) {
		return;
	}
#else
	if (v6dst6->s6_addr32 [0] != v6listen.s6_addr32 [0]) {
		// Mismatch /32 so this is not going to fly (anywhere)
		return;
	} else if (v6dst6->s6_addr32 [1] != v6listen.s6_addr32 [1]) {
		// Match /32 but mismatch /64 -- relay to proper fallback
		// that fc64::/16 is not welcome in 6to4 processing
		//TODO//OVER_6bed4// relay_6to6_plain_unicast (v6data, rawlen - sizeof (struct tun_pi), v6dst6);
	}
#endif
	//
	// Harvest socket address data from destination IPv6, then send
	relay_4to4_plain_unicast (v6data, rawlen - sizeof (struct tun_pi), v6dst6);
}


/* Run the daemon core code, passing information between IPv4 and IPv6 and
 * responding to tunnel requests if so requested.
 */
void run_daemon (void) {
	fd_set io;
	FD_ZERO (&io);
	FD_SET (v4sox, &io);
	FD_SET (v6sox, &io);
	int nfds = (v4sox < v6sox)? (v6sox + 1): (v4sox + 1);
	while (1) {
		select (nfds, &io, NULL, NULL, NULL);
		if (FD_ISSET (v4sox, &io)) {
			handle_4to6 ();
		} else {
			FD_SET (v4sox, &io);
		}
		if (FD_ISSET (v6sox, &io)) {
			handle_6to4 ();
		} else {
			FD_SET (v6sox, &io);
		}
fflush (stdout);
	}
}


/* Option descriptive data structures */

char *short_opt = "l:L:d:hit:u:s:m:";

struct option long_opt [] = {
	{ "v4listen", 1, NULL, 'l' },
	{ "v6prefix", 1, NULL, 'L' },
	{ "tundev", 1, NULL, 'd' },
	{ "help", 0, NULL, 'h' },
	{ "icmp", 0, NULL, 'i' },
	{ "tcp", 1, NULL, 't' },
	{ "udp", 1, NULL, 'u' },
	{ "sctp", 1, NULL, 's' },
	{ "masqhost", 1, NULL, 'm' },
	// { "fallback4", 1 NULL, 'f' },
	// { "fallback6", 1, NULL, 'F' },
	{ NULL, 0, NULL, 0 }	/* Array termination */
};

/* Parse commandline arguments (and start to process them).
 * Return 1 on success, 0 on failure.
 */
int process_args (int argc, char *argv []) {
	int ok = 1;
	int help = (argc == 1);
	int done = 0;
	int opt;
	while (!done) {
		switch (opt = getopt_long (argc, argv, short_opt, long_opt, NULL)) {
		case -1:
			done = 1;
			if (optind != argc) {
				fprintf (stderr, "%s: Extra arguments not permitted: %s...\n", program, argv [optind]);
				ok = 0;
			}
			break;
		case 'l':
			if (v4sox != -1) {
				ok = 0;
				fprintf (stderr, "%s: Only one -l argument is permitted\n", program);
				break;
			}
			v4server = optarg;
			if (inet_pton (AF_INET, optarg, &v4name.sin_addr) <= 0) {
				ok = 0;
				fprintf (stderr, "%s: Failed to parse IPv4 address %s\n", program, optarg);
				break;
			}
			memcpy (&v4listen, &v4name.sin_addr, 4);
			v4sox = socket (AF_INET, SOCK_DGRAM, 0);
			if (v4sox == -1) {
				ok = 0;
				fprintf (stderr, "%s: Failed to allocate UDPv4 socket: %s\n", program, strerror (errno));
				break;
			}
			if (bind (v4sox, (struct sockaddr *) &v4name, sizeof (v4name)) != 0) {
				ok = 0;
				fprintf (stderr, "%s: Failed to bind to UDPv4 %s:%d: %s\n", program, optarg, ntohs (v4name.sin_port), strerror (errno));
				break;
			}
			break;
		case 'L':
			if (v6server) {
				ok = 0;
				fprintf (stderr, "%s: Only one -L argument is permitted\n", program);
				break;
			}
			char *slash64 = strchr (optarg, '/');
			if (!slash64 || strcmp (slash64, "/64") != 0) {
				ok = 0;
				fprintf (stderr, "%s: The -L argument must be an explicit /64 prefix and not %s\n", program, slash64? slash64: "implied");
				break;
			}
			*slash64 = 0;
			v6server = strdup (optarg);
			*slash64 = '/';
			v6prefix = optarg;
			if (!v6server || (inet_pton (AF_INET6, v6server, &v6listen) <= 0)) {
				ok = 0;
				fprintf (stderr, "%s: Failed to parse IPv6 prefix %s\n", program, optarg);
				break;
			}
			if (v6listen.s6_addr32 [2] || v6listen.s6_addr32 [3]) {
				ok = 0;
				fprintf (stderr, "%s: IPv6 prefix contains bits beyond its /64 prefix: %s\n", program, optarg);
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
		case 's':
		case 't':
		case 'u':
		case 'i':
			// Masqueraded port (range) for SCTP, TCP, UDP
			//TODO// Should we support ICMPv6 as well? [honeypots]
			if (num_masqhost == 0) {
				//TODO// Reference v6listen instead of ::1
				inet_pton (AF_INET6, "::1", masqhost [0]);
				num_masqhost = 1;
			}
			// Temporary variables in local scope
			if (opt == 'i') {
				if (icmp_num_portpairs > 0) {
					fprintf (stderr, "%s: Only one ICMP masquerading setting is possible\n", program);
					ok = 0;
					break;
				}
				icmp_portpairs [2] = num_masqhost - 1;
				icmp_num_portpairs++;
			} else {
				unsigned long fromport, toport;
				uint16_t *portpairs;
				errno = 0;
				if (*optarg != ':') {
					fromport = strtoul (optarg, &optarg, 10);
				} else {
					fromport = 1;
				}
				if (*optarg != ':') {
					toport = fromport;
				} else if (*++optarg) {
					toport = strtoul (optarg, &optarg, 10);
				} else {
					toport = 65535;
				}
				if (errno || *optarg) {
					fprintf (stderr, "%s: Failed to parse port or port:port\n", program);
					ok = 0;
					break;
				}
				if ((fromport < 1) || (fromport > toport) || (toport > 65535)) {
					fprintf (stderr, "%s: Invalid port or port range\n", program);
					ok = 0;
					break;
				}
				if (++num_masqportpairs [opt-'s'] >= MAXNUM_PORTPAIRS) {
					fprintf (stderr, "%s: You cannot define so many ports / port pairs\n", program);
					ok = 0;
					break;
				}
				portpairs = &masqportpairs [opt-'s'][3*(num_masqportpairs [opt-'s']-1)];
				portpairs [0] = fromport;
				portpairs [1] = toport;
				portpairs [2] = num_masqhost-1;
			}
			break;
		case 'm':
			// Masqueraded host for TCP, UDP, SCTP (default is ::1)
			if (++num_masqhost >= MAXNUM_MASQHOST) {
				fprintf (stderr, "%s: No more than %d masquering hosts can be specified\n", program, MAXNUM_MASQHOST);
				ok = 0;
				break;
			}
			if (inet_pton (AF_INET6, optarg, masqhost [num_masqhost]) != 1) {
				fprintf (stderr, "%s: Unsupported masquerading host \"%s\"\n", program, optarg);
				ok = 0;
				break;
			}
			num_masqhost++;
			break;
		// case 'f':
		// case 'F':
		// 	// Fallback addresses for IPv4, IPv6
		// 	ok = 0;	//TODO:IMPLEMENT//
		// 	help = 1;
		// 	break;
		default:
			ok = 0;
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
		fprintf (stderr, "Usage: %s [-d /dev/tunX] -l <v4server> -L <v6prefix>/64\n       %s -h\n", program, program);
		fprintf (stderr, "\tUse -s|-t|-u to masquerade a port (range) to last -m host or ::1\n");
#else
		fprintf (stderr, "Usage: %s -d /dev/tunX -l <v4server> -L <v6prefix>/64\n       %s -h\n", program, program);
		fprintf (stderr, "\tUse -s|-t|-u to masquerade a port (range) to last -m host of ::1\n");
#endif
		return ok;
	}
	if (!ok) {
		return 0;
	}
	if (v4sox == -1) {
		fprintf (stderr, "%s: Use -l to specify an IPv4 address for the tunnel interface\n", program);
		return 0;
	}
	if (!v6server) {
		fprintf (stderr, "%s: Use -L to specify a /64 prefix on the IPv6 side\n", program);
		return 0;
	}
#ifdef HAVE_SETUP_TUNNEL
	if (v6sox == -1) {
		if (geteuid () != 0) {
			fprintf (stderr, "%s: You should be root, or use -d to specify an accessible tunnel device\n", program);
			return 0;
		}
		ok = setup_tunnel ();
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
	program = argv [0];
	memset (&v4name, 0, sizeof (v4name));
	memset (&v6name, 0, sizeof (v6name));
	v4name.sin_family  = AF_INET ;
	v6name.sin6_family = AF_INET6;
	v4name.sin_port = htons (UDP_PORT_6BED4);   /* 6BED4 standard port */
	v4tunpi6.flags = 0;
	v4tunpi6.proto = htons (ETH_P_IPV6);
	//
	// Parse commandline arguments
	if (!process_args (argc, argv)) {
		exit (1);
	}
	//
	// Setup a few addresses for later comparison/reproduction
	//  * lladdr_6bed4 is the 6bed4 Link-Local Address
	//  * v6listen_complete is the router's full IPv6 address (with if-id)
	//  * v6listen_linklocal_complete is fe80::/64 plus the router's if-id
	// A few others have already been setup at this time
	//  * v6listen is the router's 6bed4 prefix ending in 64 zero bits
	//  * v6listen_linklocal is the address fe80::/128
	//
	lladdr_6bed4 [0] = UDP_PORT_6BED4 & 0xff;
	lladdr_6bed4 [1] = UDP_PORT_6BED4 >> 8;
	memcpy (lladdr_6bed4 + 2, (uint8_t *) &v4name.sin_addr, 4);
	addr_6bed4 (&v6listen_complete, 0);

	memcpy (v6listen_linklocal_complete, v6listen_linklocal, 8);
	memcpy (v6listen_linklocal_complete + 8, &v6listen_complete.s6_addr [8], 8);
printf ("LISTEN lladdr_6bed4 = %02x:%02x:%02x:%02x:%02x:%02x\n", lladdr_6bed4 [0], lladdr_6bed4 [1], lladdr_6bed4 [2], lladdr_6bed4 [3], lladdr_6bed4 [4], lladdr_6bed4 [5]);
printf ("LISTEN v6listen = %x:%x:%x:%x:%x:%x:%x:%x\n", htons (v6listen.s6_addr16 [0]), htons (v6listen.s6_addr16 [1]), htons (v6listen.s6_addr16 [2]), htons (v6listen.s6_addr16 [3]), htons (v6listen.s6_addr16 [4]), htons (v6listen.s6_addr16 [5]), htons (v6listen.s6_addr16 [6]), htons (v6listen.s6_addr16 [7]));
printf ("LISTEN v6listen_complete = %x:%x:%x:%x:%x:%x:%x:%x\n", htons (v6listen_complete.s6_addr16 [0]), htons (v6listen_complete.s6_addr16 [1]), htons (v6listen_complete.s6_addr16 [2]), htons (v6listen_complete.s6_addr16 [3]), htons (v6listen_complete.s6_addr16 [4]), htons (v6listen_complete.s6_addr16 [5]), htons (v6listen_complete.s6_addr16 [6]), htons (v6listen_complete.s6_addr16 [7]));
printf ("LISTEN v6listen_linklocal = %x:%x:%x:%x:%x:%x:%x:%x\n", htons (((uint16_t *) v6listen_linklocal) [0]), htons (((uint16_t *) v6listen_linklocal) [1]), htons (((uint16_t *) v6listen_linklocal) [2]), htons (((uint16_t *) v6listen_linklocal) [3]), htons (((uint16_t *) v6listen_linklocal) [4]), htons (((uint16_t *) v6listen_linklocal) [5]), htons (((uint16_t *) v6listen_linklocal) [6]), htons (((uint16_t *) v6listen_linklocal) [7]));
printf ("LISTEN v6listen_linklocal_complete = %x:%x:%x:%x:%x:%x:%x:%x\n", htons (((uint16_t *) v6listen_linklocal_complete) [0]), htons (((uint16_t *) v6listen_linklocal_complete) [1]), htons (((uint16_t *) v6listen_linklocal_complete) [2]), htons (((uint16_t *) v6listen_linklocal_complete) [3]), htons (((uint16_t *) v6listen_linklocal_complete) [4]), htons (((uint16_t *) v6listen_linklocal_complete) [5]), htons (((uint16_t *) v6listen_linklocal_complete) [6]), htons (((uint16_t *) v6listen_linklocal_complete) [7]));
	//
	// Start the main daemon process
#ifdef SKIP_TESTING_KLUDGE_IN_FOREGROUND
	switch (fork ()) {
	case -1:		/* Error forking */
		fprintf (stderr, "%s: Failed to fork: %s\n", program, strerror (errno));
		exit (1);
	case 0:			/* Child process */
		close (0);
		//TODO: tmp.support for ^printf// close (1);
		close (2);
		setsid ();
		run_daemon ();
		break;
	default:		/* Parent process */
		close (v4sox);
		close (v6sox);
		break;
	}
#else
	run_daemon ();
#endif
	//
	// Report successful creation of the daemon
	return 0;
}
