/* pubTSP/router.c -- traffic forwarding daemon for public TSP service
 *
 * This is an implementation of the profile that makes TSP service publicly
 * usable, that is without authentication.  However to avoid abuse of such
 * a service, it is not anonymous -- IPv6 addresses contain the IPv4 address
 * and port.
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


#include <stdlib.h>
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
#include <arpa/inet.h>

#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/if_ether.h>


struct tsphdr {
	u_int32_t seqnum;
	u_int32_t timestamp;
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
#ifdef LINUX
#  define HAVE_SETUP_TUNNEL
#endif


/* Global variables */

char *program;

int v4sox = -1;
int v6sox = -1;

char *v4server = NULL;
char *v6server = NULL;
char *v6prefix = NULL;

struct sockaddr_in  v4name;
struct sockaddr_in6 v6name;

struct in6_addr v6listen;


struct {
	struct tun_pi tun;
	union {
		struct {
			struct tsphdr tsp;
			u_int8_t cmd [MTU];
			u_int8_t zerobyte;
		} cdata;
		struct {
			struct ip6_hdr v6hdr;
			u_int8_t data [MTU];
		} idata;
	} udata;
} v4data6;

#define v4tunpi6 	(v4data6.tun)
#define v4data		((u_int8_t *) &v4data6.udata)
#define v4tsphdr	(&v4data6.udata.cdata.tsp)
#define v4tspcmd	(v4data6.udata.cdata.cmd)
#define v4hdr6		(&v4data6.udata.idata.v6hdr)
#define v4src6		(&v4data6.udata.idata.v6hdr.ip6_src)
#define v4dst6		(&v4data6.udata.idata.v6hdr.ip6_dst)


struct {
	struct tun_pi tun;
	union {
		u_int8_t data [MTU];
		struct ip6_hdr v6hdr;
	} udata;
	u_int8_t zero;
} v6data6;

#define v6data		(v6data6.udata.data)
#define v6tuncmd	(v6data6.tun)
#define v6hdr6		(&v6data6.udata.v6hdr)
#define v6src6		(&v6data6.udata.v6hdr.ip6_src)
#define v6dst6		(&v6data6.udata.v6hdr.ip6_dst)


/*
 *
 * Driver routines
 *
 */

#ifdef LINUX
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
	ifreq.ifr_flags = IFF_TUN;
	if (ok && ioctl (v6sox, TUNSETIFF, (void *) &ifreq) == -1) {
		ok = 0;
	}
	ifreq.ifr_name [IFNAMSIZ] = 0;
	char cmd [512+1];
	snprintf (cmd, 512, "/sbin/ip -6 addr add %s dev %s", v6prefix, ifreq.ifr_name);
	if (ok && system (cmd) != 0) {
		ok = 0;
	}
	snprintf (cmd, 512, "/sbin/ip link set %s up", ifreq.ifr_name);
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


/* Send a reply to a tunnel command back to the most recent sender.
 * This is a textual protocol, so reply is a NUL-terminated string
 * and "\r\n" will be postfixed.
 */
void tspcmd_reply (char *reply) {
	if (reply != (char *) v4tspcmd) {
		strncpy (v4tspcmd, reply, MTU-1);
	} else {
		v4tspcmd [MTU-1] = 0;
	}
	strncat (v4tspcmd, "\r\n", MTU+1);
printf ("Reply =%s=\n", v4tspcmd);
	sendto (v4sox, v4data, sizeof (struct tsphdr) + strlen (v4tspcmd),			MSG_DONTWAIT, (struct sockaddr *) &v4name, sizeof (v4name));
}


/* Send an info message, in response to a creation request on the
 * tunnel.  The contents of this message are constant, in support of
 * the stateless implementation of this daemon.  The address and port
 * of the IPv4 sender are taken into account, but the information sent
 * over XML is not.
 */
void tspcmd_create (void) {
	char v4client [INET_ADDRSTRLEN];
	char v6client [INET6_ADDRSTRLEN+1];
	inet_ntop (AF_INET, &v4name.sin_addr, v4client, sizeof (v4client));
	snprintf (v6client, sizeof (v6client)-1,
		"%x:%x:%x:%x:%x:%x:%x::",
			ntohs (v6listen.s6_addr16 [0]),
			ntohs (v6listen.s6_addr16 [1]),
			ntohs (v6listen.s6_addr16 [2]),
			ntohs (v6listen.s6_addr16 [3]),
			ntohl (v4name.sin_addr.s_addr) >> 16,
			ntohl (v4name.sin_addr.s_addr) & 0x0000ffff,
			ntohs (v4name.sin_port));
	snprintf (v4tspcmd, MTU-1,
"Content-length: 0000\r\n"
"200 OK\r\n"
"<tunnel action=\"info\" type=\"v6udpv4\" lifetime=\"86400\">\r\n"
"  <server>\r\n"
"    <address type=\"ipv4\">%s</address>\r\n"
"    <address type=\"ipv6\">%s</address>\r\n"
"  </server>\r\n"
"  <client>\r\n"
"    <address type=\"ipv4\">%s</address>\r\n"
"    <address type=\"ipv6\">%s</address>\r\n"
"    <keepalive interval=\"30\">\r\n"
"      <address type=\"ipv6\">%s</address>\r\n"
"    </keepalive>\r\n"
"  </client>\r\n"
"</tunnel>"
		, v4server, v6server, v4client, v6client, v6server);
	char contlen [6];
	snprintf (contlen, 5, "%04d", strlen (v4tspcmd) - 22);
printf ("strlen = %d, contlen = \"%s\"\n", strlen (v4tspcmd), contlen);
	memcpy (v4tspcmd + 16, contlen, 4);
	tspcmd_reply (v4tspcmd);
}


/* Handle the IPv4 message pointed at by msg as a tunnel command.
 */
void handle_4to6_tspcmd (ssize_t v4tspcmdlen) {
	//
	// Tunnel data is textual, append '\0' and ensure that's all
	v4tspcmd [v4tspcmdlen] = 0;
	if (strlen (v4tspcmd) != v4tspcmdlen) {
		// Tricky package contains '\0' -- drop silently
		return;
	}
	//
	// Handle VERSION= interaction
printf ("CMD=%s=\n", v4tspcmd);
	if (strncmp (v4tspcmd, "VERSION=", 8) == 0) {
		if (strcmp (v4tspcmd + 8, "2.0.0\r\n") == 0) {
			tspcmd_reply (TUNNEL_CAPABILITIES);
		} else {
			tspcmd_reply ("302 Unsupported client version");
		}
	}
	//
	// Handle AUTHENTICATE command
	else if (strncmp (v4tspcmd, "AUTHENTICATE ", 13) == 0) {
		if (strcmp (v4tspcmd + 13, "ANONYMOUS\r\n") == 0) {
			tspcmd_reply ("200 Success\r\n");
		} else {
			tspcmd_reply ("300 Only ANONYMOUS authentication supported");
		}
	}
	//
	// Handle XML prefixed with "content-length:"
	else if (strncasecmp (v4tspcmd, "content-length:", 15) == 0) {
		// Hoping to get away with not parsing XML:
		if (strstr (v4tspcmd, "create")) {
			tspcmd_create ();
		} else {
			tspcmd_reply ("200 Success");
		}
	}
	//
	// Reject any further commands loudly
	else {
		tspcmd_reply ("310 Go away");
	}
}


/* Handle the IPv4 message pointed at by msg, checking if the IPv4:port
 * data matches the lower half of the IPv6 sender address.  Drop silently
 * if this is not the case.  TODO: or send ICMP?
 */
void handle_4to6_payload (ssize_t v4datalen) {
	//
	// Ensure that the lower half of the IPv6 sender address is ok
	if (v4src6->s6_addr32 [2] != v4name.sin_addr.s_addr) {
		return;
	}
	if (v4src6->s6_addr16 [6] != v4name.sin_port) {
		return;
	}
#if 0
	if (v4src6->s6_addr16 [7] != htons (0x0000)) {
		return;
	}
#endif
	//
	// Ensure that the top half of the IPv6 address is ok
	// Note that this implies rejection of ::1/128, fe80::/10 and fec0::/10
	if (memcmp (v4src6, &v6listen, 8) != 0) {
		return;
	}
	if (v4src6->s6_addr32 [0] != v6listen.s6_addr32 [0]) {
		return;
	}
	if (v4src6->s6_addr32 [1] != v6listen.s6_addr32 [1]) {
		return;
	}
	//
	// Send the unwrapped IPv6 message out over v6sox
	memcpy (&v6name.sin6_addr, v4dst6, sizeof (v6name.sin6_addr));
printf ("Sending IPv6, result = %d\n",
	sendto (v6sox,
			&v4data6, sizeof (struct tun_pi) + v4datalen,
			MSG_DONTWAIT,
			(struct sockaddr *) &v6name, sizeof (v6name)));
printf ("Writing IPv6, result = %d\n",
	write (v6sox, &v4data6, sizeof (struct tun_pi) + v4datalen));
}

/* Receive a tunnel package, and route it to either the handler for the
 * tunnel protocol, or to the handler that checks and then unpacks the
 * contained IPv6.
 */
void handle_4to6 (void) {
	u_int8_t buf [1501];
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
		printf ("%s: Error receiving IPv4-side package: %s",
				program, strerror (errno));
		return;
	}
	if (buflen < sizeof (struct tsphdr)) {
		return;
	}
	int flag = v4data [0] & 0xf0;
	switch (flag) {
	case 0xf0:
		/* Handle as a tunnel command package */
		if (buflen > sizeof (struct tsphdr) + 1) {
			handle_4to6_tspcmd (buflen - sizeof (struct tsphdr));
		}
		return;
	case 0x60:
		/* Handle as a tunneled IPv6 package */
		if (buflen > sizeof (struct iphdr) + sizeof (struct udphdr) + sizeof (struct ip6_hdr) + 1) {
			handle_4to6_payload (buflen);
		}
		return;
	default:
		/* Silently ignore wrong types of packages */
		return;
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
	if (memcmp (v6dst6, &v6listen, 8) != 0) {
		return;
	}
	if (v6dst6->s6_addr32 [0] != v6listen.s6_addr32 [0]) {
		return;
	}
	if (v6dst6->s6_addr32 [1] != v6listen.s6_addr32 [1]) {
		return;
	}
#if 0
	if (v6dst6->s6_addr16 [7] != htons (0x0000)) {
		return;
	}
#endif
	//
	// Harvest socket address data from destination IPv6, then send
	v4name.sin_family = AF_INET;
	v4name.sin_addr.s_addr = v6dst6->s6_addr32 [2];
	v4name.sin_port = v6dst6->s6_addr16 [6];
printf ("Sending IPv6-UDP-IPv4 to %d.%d.%d.%d:%d, result = %d\n",
((u_int8_t *) &v4name.sin_addr.s_addr) [0],
((u_int8_t *) &v4name.sin_addr.s_addr) [1],
((u_int8_t *) &v4name.sin_addr.s_addr) [2],
((u_int8_t *) &v4name.sin_addr.s_addr) [3],
ntohs (v4name.sin_port),
	sendto (v4sox,
			v6data,
			rawlen - sizeof (struct tun_pi),
			MSG_DONTWAIT,
			(struct sockaddr *) &v4name, sizeof (v4name)));
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

char *short_opt = "l:L:t:h";

struct option long_opt [] = {
	{ "v4listen", 1, NULL, 'l' },
	{ "v6prefix", 1, NULL, 'L' },
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
		case 'l':
			if (v4sox != -1) {
				ok = 0;
				fprintf (stderr, "%s: Only one -l argument is permitted\n");
				break;
			}
			v4server = optarg;
			if (inet_pton (AF_INET, optarg, &v4name.sin_addr) <= 0) {
				ok = 0;
				fprintf (stderr, "%s: Failed to parse IPv4 address %s\n", program, optarg);
				break;
			}
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
				fprintf (stderr, "%s: Only one -L argument is permitted\n");
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
			if (!v6server || inet_pton (AF_INET6, v6server, &v6listen) <= 0) {
				ok = 0;
				fprintf (stderr, "%s: Failed to parse IPv6 prefix %s\n", optarg);
				break;
			}
			if (v6listen.s6_addr32 [2] || v6listen.s6_addr32 [3]) {
				ok = 0;
				fprintf (stderr, "%s: IPv6 prefix contains bits beyond its /64 prefix: %s\n", program, optarg);
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
		fprintf (stderr, "Usage: %s [-t /dev/tunX] -l <v4server> -L <v6prefix>/64\n       %s -h\n", program, program);
#else
		fprintf (stderr, "Usage: %s -t /dev/tunX -l <v4server> -L <v6prefix>/64\n       %s -h\n", program, program);
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
			fprintf (stderr, "%s: You should be root, or use -t to specify an accessible tunnel device\n", program);
			return 0;
		}
		ok = setup_tunnel ();
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
	memset (&v6name, 0, sizeof (v6name));
	v4name.sin_family  = AF_INET ;
	v6name.sin6_family = AF_INET6;
	v4name.sin_port = htons (3653); /* TSP standard port */
	v4tunpi6.flags = 0;
	v4tunpi6.proto = htons (ETH_P_IPV6);
	//
	// Parse commandline arguments
	if (!process_args (argc, argv)) {
		exit (1);
	}
	//
	// Start the main daemon process
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
	//
	// Report successful creation of the daemon
	return 0;
}
