6BED4 PREFIXES AND PROMISES
===========================

> *6bed4 works over a globally registered prefix TBD1 and a standard
> UDP port TBD2.  But there can be alternatives that route through the
> same 6bed4 infrastructure.*


Facilitation by 6bed4
---------------------

The 6bed4 facilities are as follows:

  * The prefix of the address may or may not be globally routable.  This is
    impartial to 6bed4, but not necessarily for its users.  Locally routable
    addresses can serve internal purposes (which is a vague term) including
    (potentially large) peer-to-peer networks.  Global routability means that
    anyone can route to the IPv6 endpoing addresses of 6bed4 peers, possibly
    going through the 6bed4router.

  * The prefix may also help to learn about the capability of an address for
    opportunistic peering.  This capability must apply to both the sender and
    recipient for a frame, because any NAT traversal must be kept open, thus
    requiring a bidirectional UDP stream.  Note that no assumptions may be
    made in general about remote nodes, other than the recognition of globally
    defined prefix capabilities.

  * The top-half of the address contains a fallback server, which can be used
    when direct contact between peers is not possible.  Without this, it is
    still possible to communicate with a configured fallback server, but peers
    will only keep NAT open towards their own fallback server.  As a result,
    the fallback server is a necessary hop between peers, and not finding a
    peer's fallback server in their IPv6 address top half could lead to failure
    to connect.  Because of this, communication can only be done locally.

  * The lower half of the address contains a peer's public IPv4 address and
    UDP port.  This information can be used for opportunistic peering, with
    the option of the fallback server to deal with unroutable situations
    between direct peers.  Port numbers 0 in the lower half can never be
    used meaningfully in a 6bed4 address, so their handling is undefined.

So, when the top-half has no room for the fallback server's IP address, then
it can only be used on one 6bed4router (or on a cluster, but certainly not
globally).


Candidate Prefixes
------------------

The following prefixes spring to mind for use with 6bed4:

  * TBD1::/32 is the perfect prefix for 6bed4.  It supports the top-half and
    bottom-half structures, and is globally defined to do so.

  * fc64:<netid>:<ipv4>::/64 may be used for 6bed4 as well.  The <netid> could
    be varied to indicate different applications, so the prefix is as for 6bed4,
    the fc64:<netid>::/32 prefix.  The fc00::/8 prefix indicates locally unique
    addresses.  Since this also limits the scope, any connection between such
    nets may be read as an indication that they are on the same local net and
    the interpretation may therefore be assumed.  This is true for all fc00::/8
    addresses, but we suggest leaving room for other uses by setting fc64::/8
    specifically for the 6bed4 interpretation of the remainder of the address.
    Note that fd00::/8 also covers unique local addresses, but it is followed
    by random bits, so no policy can be applied without breaking standards
    (and software).  Note that fc00::/8 is a local scoped name space, but it
    is possible to connect 6bed4peers behind different fallback servers.  It
    is simply a matter of distribution of addresses whether two peers will be
    able to communicate.  We believe this scheme is perfect for peer-to-peer
    operations, especially with the use of IPsec.

  * Native IPv6 /48 or /64 prefixes may be used, but they will not facilitate
    the top-half.  Sometimes the native use of native addresses may compete
    with use in a 6bed4router; this is especially true when only one /64 is
    available.  In this case, the undefined behaviour of port 0 in the lower
    half may be used to bypass native traffic to a natively connected service.
    Other than this, any 6bed4peer collecting these addresses can do anything;
    native addresses can be reached, opportunistic connections to peers are
    possible and even the native services using port 0 would work.  The one
    thing that is impossible, as with fc64::/16, is that independent
    6bed4router processes can serve the same prefix and have their 6bedpeer
    clients reach each other; this is due to the lacking fallback server in
    the top half.

  * 2002:<ipv4>::/48 is based on the 6to4 prefix 2002::/16, but instead of
    using the peer's address and relying on the ability to pass IPv6 directly
    over IPv4, the 6bed4router can be used as an intermediate.  The place of
    the <ipv4> address is different than after the /32 of normal 6bed4
    addresses, but this is easily inferred from the prefix.  So, it is quite
    possible to interpret <ipv4> as the fallback server.  What is not safe
    to assume though, is that the underlying portion is a 6bed4 address.  To
    allow for that, we define a "special SLA value" be64, as a hint that the
    lower half may be interpreted for opportunistic peering.
    TODO: This breaks with traditions... NOT FIT FOR A FORMAL SPEC



Implementation
--------------

The 6bed4router accepts multiple prefixes, simply by issuing more than one
`-L` prefix.  Each of these will be provided to the 6bed4peers in Router
Advertisements, after having completed them to a /114 prefix length.
When a 6bed4peer receives such prefixes, it should configure them all,
after setting its preference(s) of <lanip> in the last 14 bits.

The sizes of the various prefixes vary.  The following things are added
when possible:

  * the fallback server IPv4 address, when at least 32 bits are available;
  * the literal value be64, to fill up any remaining 16 bits

This format works for prefixes of sizes 16, 32, 48 and 64:

  * xxxx::/16 becomes top half xxxx:<ipv4>:be64::/64
  * xxxx:yyyy::/32 becomes top half xxxx:yyyy:<ipv4>::/64
  * xxxx:yyyy:zzzz::/48 becomes top half xxxx:yyyy:zzzz:be64::/64
  * xxxx:yyyy:zzzz:wwww::/64 is unaltered

Specifically for the indicated candidate prefixes:

  * TBD1::/32 becomes top half TBD1:<ipv4>::/64
  * fc64:<netid>::/32 becomes top half fc64:<netid>:<ipv4>::/64
  * xxxx:yyyy:zzzz::/48 becomes top half xxxx:yyyy:zzzz:be64::/64
  * xxxx:yyyy:zzzz:wwww::/64 is unaltered
  * 2002::/16 becomes top half 2002:<ipv4>:be64::/64

These do all support routing based on the bottom half.  Furthermore:

  * The fallback server appearing as <ipv4> in the top half enables unrelated 6bed4router connectivity
  * The rules for global routing determine whether the addresses can communicate with native IPv6 addresses

