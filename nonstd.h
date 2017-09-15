/* The error line below is here to satisfy RFC requirements: We cannot
 * distribute code that has non-standard protocol numbers built in as
 * defaults.  So you must read this and understand that you are running
 * a non-compliant, experimental code version.  When you agree, please
 * change the error directives to warnings -- then, the code will build.
 *
 * Sincerely, Rick van Rein, OpenFortress.
 */

#error "Build uses experimental Neighbor Discovery Option Type 253 for Destination Link-Layer Address"

#define ND_OPT_DESTINATION_LINKADDR 253


#error "Build uses experimental UDP port number 27629 or 0x6bed"

#define UDP_PORT_6BED4 25788


#warning "Build uses temporary IPv4 address information"

#define SERVER_6BED4_IPV4_TXT			"145.100.190.242"
#define SERVER_6BED4_IPV4_INT32			( (145L << 24) | (100L << 16) | (190L << 8) | 242L )
#define SERVER_6BED4_IPV4_INT0			145
#define SERVER_6BED4_IPV4_INT1			100
#define SERVER_6BED4_IPV4_INT2			190
#define SERVER_6BED4_IPV4_INT3			242
#define SERVER_6BED4_IPV4_BINSTR		"\x91\x64\xbe\xf2"

#define SERVER_6BED4_PORT_TXT			"25788"
#define SERVER_6BED4_PORT_BINSTR		"\xbc\x64"

#define SERVER_6BED4_IPV4_PORT_TXT		"145.100.190.242:27629"
#define SERVER_6BED4_PORT_IPV4_ADDRSTR		"\xbe\x64\x91\x64\xbe\xf2"
#define SERVER_6BED4_PORT_IPV4_MACSTR		"\xbc\x64\x91\x64\xbe\xf2"

/* Define LOCAL_OVERRIDES_PORT0 to forcefully detect 6bed4 port 0 as an
 * override to a local address.  This is used when a host uses its own /64
 * and has no other addresses available.
 */
#define LOCAL_OVERRIDES_PORT0 yes
