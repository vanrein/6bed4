/* 6bed4/democlient.c -- IPv6-anywhere demo-only client for 6bed4
 *
 * This is an implementation of neighbour and router discovery over a
 * tunnel that packs IPv6 inside UDP/IPv4.  This tunnel mechanism is
 * targeted specifically at embedded devices that are to function on
 * any network, including IPv4-only, while being designed as IPv6-only
 * devices with a fallback to this tunnel.
 *
 * Because of the emphasis on embedded devices, this code or derivatives
 * SHOULD NOT be distributed as a desktop application.  Variations are
 * possible for network providers who intend to host IPv6 support as a
 * local network service, available on a non-standard IPv4 address and
 * a non-standard IPv6 /64 prefix.
 *
 * The software is ONLY available for experimentation purposes, and as
 * a foundation for embedded code.  This status will only be changed
 * when the tunnel hosting parties agree that desktop use of their
 * tunnels is permitted.  This may happen when the tunnels are widely
 * spread accross the Internet, like 6to4 is now.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
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
#include <netinet/udp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>

#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/if_ether.h>


struct tsphdr {
	uint32_t seqnum;
	uint32_t timestamp;
};


#define TUNNEL_CAPABILITIES "CAPABILITY TUNNEL=V6UDPV4 AUTH=ANONYMOUS"

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

char *v4server = NULL;
char *v6server = NULL;
char v6prefix [INET6_ADDRSTRLEN];

const char v6listen_linklocal [16] = { 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

struct sockaddr_in  v4name;
struct sockaddr_in  v4peer;
struct sockaddr_in6 v6name;

struct in6_addr v6listen;
struct in_addr  v4listen;


struct {
	struct tun_pi tun;
	union {
		struct {
			struct tsphdr tsp;
			uint8_t cmd [MTU];
			uint8_t zerobyte;
		} cdata;
		struct {
			struct ip6_hdr v6hdr;
			uint8_t data [MTU];
		} idata;
		struct {
			struct ip6_hdr v6hdr;
			struct icmp6_hdr v6icmphdr;
		} ndata;
	} udata;
} v4data6;

#define v4tunpi6 	(v4data6.tun)
#define v4data		((uint8_t *) &v4data6.udata)
#define v4tsphdr	(&v4data6.udata.cdata.tsp)
#define v4tspcmd	(v4data6.udata.cdata.cmd)
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


struct {
	struct tun_pi tun;
	union {
		uint8_t data [MTU];
		struct ip6_hdr v6hdr;
	} udata;
	uint8_t zero;
} v6data6;

#define v6data		(v6data6.udata.data)
#define v6tuncmd	(v6data6.tun)
#define v6hdr6		(&v6data6.udata.v6hdr)
#define v6src6		(&v6data6.udata.v6hdr.ip6_src)
#define v6dst6		(&v6data6.udata.v6hdr.ip6_dst)


uint8_t ipv6_router_solicitation [] = {
	// IPv6 header
	0x60, 0x00, 0x00, 0x00,
	16 / 256, 16 % 256, IPPROTO_ICMPV6, 255,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,		 // unspecd src
	0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, // all-rtr tgt
	// ICMPv6 header: router solicitation
	ND_ROUTER_SOLICIT, 0, 0x7a, 0xae,	// Checksum from WireShark :)
	// ICMPv6 body: reserved
	0, 0, 0, 0,
	// ICMPv6 option: source link layer address 0x0001 (end-aligned)
	0x01, 0x01, 0, 0, 0, 0, 0x00, 0x01,
};

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


/*
 *
 * Driver routines
 *
 */

#ifdef LINUX
#define HAVE_SETUP_TUNNEL
/* Implement the setup_tunnel() command for Linux.
 * Return 1 on success, 0 on failure.
 */
int setup_tunnel (void) {
	if (v6sox == -1) {
		v6sox = open ("/dev/net/tun", O_RDWR);
	}
	if (v6sox == -1) {
		fprintf (stderr, "%s: Failed to access tunnel driver on /dev/net/tun: %s\n", program, strerror (errno));
		return 0;
	}
	int ok = 1;
	static struct ifreq ifreq;
	static int have_tunnel = 0;
	if (!have_tunnel) {
		memset (&ifreq, 0, sizeof (ifreq));
		ifreq.ifr_flags = IFF_TUN;
		if (ok && (ioctl (v6sox, TUNSETIFF, (void *) &ifreq) == -1)) {
			ok = 0;
		} else {
			have_tunnel = 1;
		}
		ifreq.ifr_name [IFNAMSIZ] = 0;
	}
	char cmd [512+1];
	snprintf (cmd, 512, "/sbin/ip -6 addr flush dev %s", ifreq.ifr_name);
	if (ok && system (cmd) != 0) {
		ok = 0;
	}
	snprintf (cmd, 512, "/sbin/ip -6 route flush dev %s", ifreq.ifr_name);
	if (ok && system (cmd) != 0) {
		ok = 0;
	}
	snprintf (cmd, 512, "/sbin/ip addr add fe80::1 dev %s scope link", ifreq.ifr_name);
	if (ok && system (cmd) != 0) {
		ok = 0;
	}
	if (* (uint16_t *) v6prefix != htons (0x0000)) {
		snprintf (cmd, 512, "/sbin/ip -6 addr add %s dev %s", v6prefix, ifreq.ifr_name);
		if (ok && system (cmd) != 0) {
			ok = 0;
		}
		snprintf (cmd, 512, "/sbin/ip -6 route add %s/112 mtu 1280 dev %s", v6prefix, ifreq.ifr_name);
		if (ok && system (cmd) != 0) {
			ok = 0;
		}
#if 0
		snprintf (cmd, 512, "/sbin/ip -6 rule add from %s/112 table 64", v6prefix);
		if (ok && system (cmd) != 0) {
			ok = 0;
		}
#endif
		snprintf (cmd, 512, "/sbin/ip -6 route flush table 64");
		if (ok && system (cmd) != 0) {
			ok = 0;
		}
		snprintf (cmd, 512, "/sbin/ip -6 route add table 64 default via %s dev %s metric 512", v6prefix, ifreq.ifr_name);
		if (ok && system (cmd) != 0) {
			ok = 0;
		}
	}
	snprintf (cmd, 512, "/sbin/ip link set %s up mtu 1280", ifreq.ifr_name);
	if (ok && system (cmd) != 0) {
		ok = 0;
	}
	if (!ok) {
		close (v6sox);	/* This removes the tunnel interface */
	}
	return ok;
}
#endif /* LINUX */


/*
 *
 * Command functions
 *
 */


/* Calculate the ICMPv6 checksum field
 */
uint16_t icmp6_checksum (size_t payloadlen) {
	uint16_t plenword = htons (payloadlen);
	uint16_t nxthword = htons (IPPROTO_ICMPV6);
	uint16_t *area [] = { (uint16_t *) v4src6, (uint16_t *) v4dst6, &plenword, &nxthword, (uint16_t *) v4icmp6, (uint16_t *) v4v6icmpdata };
	uint8_t areawords [] = { 8, 8, 1, 1, 1, payloadlen/2 - 2 };
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
}


/* Append the current prefix to an ICMPv6 message.  Incoming optidx
 * and return values signify original and new offset for ICMPv6 options.
 * The endlife parameter must be set to obtain zero lifetimes, thus
 * instructing the tunnel client to stop using an invalid prefix.
 */
size_t icmp6_prefix (size_t optidx, uint8_t endlife) {
	v4v6icmpdata [optidx++] = 3;	// Type
	v4v6icmpdata [optidx++] = 4;	// Length
	v4v6icmpdata [optidx++] = 112;	// This is a /112 prefix
	v4v6icmpdata [optidx++] = 0x40;	// L=0, A=1, Reserved1=0
	memset (v4v6icmpdata + optidx, endlife? 0x00: 0xff, 8);
	optidx += 8;
					// Valid Lifetime: Zero / Infinite
					// Preferred Lifetime: Zero / Infinite
	memset (v4v6icmpdata + optidx, 0, 4);
	optidx += 4;
					// Reserved2=0
	memcpy (v4v6icmpdata + optidx +  0, &v6listen, 8);
	memcpy (v4v6icmpdata + optidx +  8, &v4listen, 4);
	//memcpy (v4v6icmpdata + optidx + 12, &v4port,   2);
	* ((uint16_t *) (v4v6icmpdata + optidx + 12)) = htons (3653);
	memset (v4v6icmpdata + optidx + 14, 0,         2);
					// Set IPv6 prefix
	optidx += 16;
	return optidx;
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
void handle_4to6_ngb (ssize_t v4ngbcmdlen) {
	uint16_t srclinklayer;
	//
	// Ensure that the packet is large enough
	if (v4ngbcmdlen < sizeof (struct ip6_hdr) + sizeof (struct icmp6_hdr)) {
		return;
	}
	//
	// Ensure that the packet is an ICMPv6 packet is otherwise okay
	if (v4v6nexthdr != IPPROTO_ICMPV6 || v4v6icmpcode != 0 || v4v6hoplimit < 255) {
		return;
	}
	if (icmp6_checksum (v4ngbcmdlen - sizeof (struct ip6_hdr)) != v4v6icmpcksum) {
		return;
	}
	//
	// TODO? Ensure that the packet hops indicate that it is local traffic
	//
	// Approved.  Perform neighbourly courtesy.
	switch (v4v6icmptype) {
	case ND_ROUTER_ADVERT:
		//
		// Validate Router Advertisement
		if (memcmp (v4src6, router_linklocal_address, 16) != 0) {
			return;   /* not from router, ignore */
		}
		if (memcmp (v4dst6, democlient_linklocal_address, 16) != 0 &&
		    memcmp (v4dst6,   allnodes_linklocal_address, 16) != 0) {
			return;   /* not for me, ignore */
		}
		if (v4v6hoplimit != 255) {
			return;   /* hops made, ignore */
		}
		if (ntohs (v4v6plen) < sizeof (struct icmp6_hdr) + 16) {
			return;   /* strange length, return */
		}
		if (v4v6icmpdata [1] & 0x80 != 0x00) {
			return;   /* indecent proposal: DHCPv6 */
		}
		size_t rdofs = 12;
		while (rdofs <= ntohs (v4v6plen) + 4) {
			if (v4v6icmpdata [rdofs + 1] == 0) {
				return;   /* zero length option */
			}
			if (v4v6icmpdata [rdofs + 0] != 3) {
				break;    /* skip to next option */
			} else if (v4v6icmpdata [rdofs + 1] != 4) {
				return;   /* bad length field */
			} else if (rdofs + (v4v6icmpdata [rdofs + 1] << 3) > ntohs (v4v6plen) + 4) {
				return;   /* out of packet length */
			} else if (v4v6icmpdata [rdofs + 3] & 0xc0 != 0xc0) {
				break;    /* no on-link autoconfig prefix */
			} else if (v4v6icmpdata [rdofs + 2] != 112) {
				break;    /* wrong prefix length */
			} else {
				//
				// Process prefix Information option
				memcpy (&v6listen, v4v6icmpdata + rdofs+16, 16);
				v6listen.s6_addr16 [7] = htons (0x0001);
				inet_ntop (AF_INET6,
					&v6listen,
					v6prefix,
					sizeof (v6prefix));
				printf ("Assigning address %s to tunnel\n", v6prefix);
				setup_tunnel ();
			}
			rdofs += (v4v6icmpdata [rdofs + 1] << 3);
		}
	case ND_NEIGHBOR_SOLICIT:
		//
		// Validate Neigbour Solicitation
		if (v4dst6->s6_addr16 [0] == htons (0xff02)) {
			break;   /* drop */
		}
		if (v4src6->s6_addr16 [9] == htons (0x0000)) {
			// TODO: 24 ---> 24 + bytes_voor_srclinklayaddr
			if (v4ngbcmdlen != sizeof (struct ip6_hdr) + 24) {
				break;   /* drop */
			}
		} else {
			if (v4ngbcmdlen != sizeof (struct ip6_hdr) + 24) {
				break;   /* drop */
			}
		}
		//
		// Construct Neigbour Advertisement
		v4v6icmptype = ND_NEIGHBOR_ADVERT;
		v4v6icmpdata [0] = 0xc0;
		v4v6icmpdata [1] =
		v4v6icmpdata [2] =
		v4v6icmpdata [3] = 0x00;	// R=1, S=1, O=1, Reserved=0
		memcpy (v4v6icmpdata +  4, &v6listen, 8);        // prefix /64
		memcpy (v4v6icmpdata + 12, &v4name.sin_addr, 4); // IPv4
		memcpy (v4v6icmpdata + 16, &v4name.sin_port, 2); // UDPport
		v4v6icmpdata [18] =
		v4v6icmpdata [19] = 0x00;			 // router if-id
		// Append option: the target link-layer address
		// Note: wire does not include target link-layer address
		v4v6icmpdata [20] = 2;		// Type: Target Link-Layer Addr
		v4v6icmpdata [21] = 1;		// Length: 1x 8 bytes
		memset (v4v6icmpdata + 22, 0x00, 6); // Link-layer addr is 0
		// Total length of ICMPv6 body is 28 bytes
		icmp6_reply (28);
		break;
	default:
		break;   /* drop */
	}
}


/* Handle the IPv4 message pointed at by msg, checking if the IPv4:port
 * data matches the lower half of the IPv6 sender address.  Drop silently
 * if this is not the case.  TODO: or send ICMP?
 */
void handle_4to6_payload (ssize_t v4datalen) {
	//
	// Ensure that the lower half of the IPv6 sender address is ok
#if 0
	if (v4dst6->s6_addr32 [2] != v4peer.sin_addr.s_addr) {
		return;
	}
	if (v4dst6->s6_addr16 [6] != v4peer.sin_port) {
		return;
	}
#endif
	if (v4dst6->s6_addr16 [7] == htons (0x0000)) {
		return;
	}
	//
	// Ensure that the top half of the IPv6 address is ok
	// Note that this implies rejection of ::1/128, fe80::/10 and fec0::/10
	if (memcmp (v4dst6, &v6listen, 8) != 0) {
		return;
	}
	if (v4dst6->s6_addr32 [0] != v6listen.s6_addr32 [0]) {
		return;
	}
	if (v4dst6->s6_addr32 [1] != v6listen.s6_addr32 [1]) {
		return;
	}
	//
	// Send the unwrapped IPv6 message out over v6sox
	memcpy (&v6name.sin6_addr, v4dst6, sizeof (v6name.sin6_addr));
printf ("Writing IPv6, result = %d\n",
	write (v6sox, &v4data6, sizeof (struct tun_pi) + v4datalen));
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
			v4data, sizeof (struct tsphdr) + MTU,
			MSG_DONTWAIT,
			(struct sockaddr *) &v4name, &adrlen
		);
	if (buflen == -1) {
		printf ("%s: Error receiving IPv4-side package: %s\n",
				program, strerror (errno));
		return;
	}
	if (buflen < sizeof (struct tsphdr)) {
		return;
	}
	/* Handle as a tunneled IPv6 package */
	if (buflen > sizeof (struct ip6_hdr) + 1) {
		uint16_t dst = v4src6->s6_addr16 [0];
		if ((v4dst6->s6_addr16 [0] == htons (0xff02)) ||
		    (v4dst6->s6_addr16 [0] == htons (0xfe80))) {
			handle_4to6_ngb (buflen);
		} else {
			handle_4to6_payload (buflen);
		}
	}
}


/* Receive an IPv6 package, check its address and pickup IPv4 address and
 * port, then package it as a tunnel message and forward it to IPv4:port.
 */
void handle_6to4 (void) {
	//
	// Receive the IPv6 package and ensure a consistent size
	size_t rawlen = read (v6sox, &v6data6, sizeof (v6data6));
	if (rawlen == -1) {
		return;
	}
	if (rawlen < sizeof (struct tun_pi) + sizeof (struct ip6_hdr) + 1) {
		return;
	}
	if (v6tuncmd.proto != htons (ETH_P_IPV6)) {
		return;
	}
printf ("Received IPv6 data, flags=0x%04x, proto=0x%04x\n", v6tuncmd.flags, v6tuncmd.proto);
	//
	// Ensure that the incoming IPv6 address is properly formatted
	// Note that this avoids access to ::1/128, fe80::/10, fec0::/10
	// TODO: v6src6 or v6dst6?!?
	if (memcmp (v6src6, &v6listen, 8) != 0) {
		return;
	}
	if (v6src6->s6_addr32 [0] != v6listen.s6_addr32 [0]) {
		return;
	}
	if (v6src6->s6_addr32 [1] != v6listen.s6_addr32 [1]) {
		return;
	}
	if (v6src6->s6_addr16 [7] == htons (0x0000)) {
		return;
	}
	//
	// Harvest socket address data from destination IPv6, then send
socklen_t v4namelen = sizeof (v4name);
printf ("Sending IPv6-UDP-IPv4 to %d.%d.%d.%d:%d, result = %d\n",
((uint8_t *) &v4peer.sin_addr.s_addr) [0],
((uint8_t *) &v4peer.sin_addr.s_addr) [1],
((uint8_t *) &v4peer.sin_addr.s_addr) [2],
((uint8_t *) &v4peer.sin_addr.s_addr) [3],
ntohs (v4peer.sin_port),
	send (v4sox,
			v6data,
			rawlen - sizeof (struct tun_pi),
			MSG_DONTWAIT));
}


/* Perform router solicitation.  This is the usual mechanism that is used
 * on ethernet links as well, except that the 6bed4 permits fixed interface
 * identifiers; for this client, the interface identifier will be 0x0001.
 * The router always has interface identifier 0x0000 but it will now be
 * addressed at the all-routers IPv6 address 0xff02::2 with the general
 * source IPv6 address ::
 */
void solicit_routers (void) {
	v4name.sin_family = AF_INET;
	memcpy (&v4name.sin_addr.s_addr, &v4listen, 4);
	v4name.sin_port = htons (3653);
	int done = 0;
	int secs = 1;
	while (!done) {
printf ("Sending RouterSolicitation-IPv6-UDP-IPv4 to %d.%d.%d.%d:%d, result = %d\n",
((uint8_t *) &v4name.sin_addr.s_addr) [0],
((uint8_t *) &v4name.sin_addr.s_addr) [1],
((uint8_t *) &v4name.sin_addr.s_addr) [2],
((uint8_t *) &v4name.sin_addr.s_addr) [3],
ntohs (v4name.sin_port),
		sendto (v4sox,
				ipv6_router_solicitation,
				sizeof (ipv6_router_solicitation),
				MSG_DONTWAIT,
				(struct sockaddr *) &v4name, sizeof (v4name)));
		fd_set wait4me;
		FD_ZERO (&wait4me);
		FD_SET (v4sox, &wait4me);
		struct timeval tout = { secs, 0 };
		done = select (v4sox+1, &wait4me, NULL, NULL, &tout) > 0;
		if (secs < 60) {
			secs <<= 1;
		}
	}
	printf ("Got a response, liberally assuming it is an offer\n");
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

char *short_opt = "s:t:h";

struct option long_opt [] = {
	{ "v4server", 1, NULL, 's' },
	{ "tundev", 1, NULL, 't' },
	{ "help", 0, NULL, 'h' },
	{ NULL, 0, NULL, 0 }	/* Array termination */
};

/* Parse commandline arguments (and start to process them).
 * Return 1 on success, 0 on failure.
 */
int process_args (int argc, char *argv []) {
	int ok = 1;
	int help = (argc == 1);
	int done = 0;
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
				fprintf (stderr, "%s: Only one -s argument is permitted\n");
				break;
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
				fprintf (stderr, "%s: Failed to bind to UDPv4 %s:%d: %s\n", program, optarg, ntohs (v4peer.sin_port), strerror (errno));
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
		fprintf (stderr, "Usage: %s [-t /dev/tunX] -s <v4server>\n       %s -h\n", program, program);
#else
		fprintf (stderr, "Usage: %s -t /dev/tunX -s <v4server>\n       %s -h\n", program, program);
#endif
		return 0;
	}
	if (!ok) {
		return 0;
	}
	if (v4sox == -1) {
		fprintf (stderr, "%s: Use -s to specify an IPv4 address for the tunnel interface\n", program);
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
	program = argv [0];
	memset (&v4name, 0, sizeof (v4name));
	memset (&v4peer, 0, sizeof (v4peer));
	memset (&v6name, 0, sizeof (v6name));
	v4name.sin_family  = AF_INET ;
	v4peer.sin_family  = AF_INET ;
	v6name.sin6_family = AF_INET6;
	v4name.sin_port = htons (3653); /* TSP standard port */
	v4peer.sin_port = htons (3653); /* TSP standard port */
	v4tunpi6.flags = 0;
	v4tunpi6.proto = htons (ETH_P_IPV6);
	//
	// Parse commandline arguments
	if (!process_args (argc, argv)) {
		exit (1);
	}
	//
	// Inform the user about the DEMO-ONLY status of this tool
	if (!isatty (fileno (stdin)) || !isatty (fileno (stdout))) {
		fprintf (stderr, "This tool can only be started with terminal I/O\n");
		exit (1);
	}
	printf ("\nThis tunnel client is ONLY FOR DEMONSTRATION PURPOSES.\n\nUntil there are plenty of tunnels and tunnel hosting parties agree, it is\nnot permitted to rolll out this application on desktops.  Please acknowledge\nthat by entering the word demonstrate to the following prompt.\n\nExceptions are made for roll-outs on local networks, where the tunnel service\nis used from a non-standard IPv4 address and IPv6 /64 prefix.\n\nType the word from the text to proceed: ");
	fflush (stdout);
	char demobuf [100];
	if (fgets (demobuf, sizeof (demobuf)-1, stdin) == NULL
	    || strcmp (demobuf, "demonstrate\n") != 0) {
		fprintf (stderr, "Please read the instructions and try again.\n");
		exit (1);
	}
	//
	// Start the main daemon process
	solicit_routers ();	// DEMO -- only once
	run_daemon ();
	//
	// Report successful creation of the daemon
	return 0;
}
