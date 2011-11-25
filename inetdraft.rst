============================================
IPv6 tunnelling for embedded devices (6bed4)
============================================

::

        From: Rick van Rein <rick@openfortress.nl>

The current set of transitioning techniques provide no suitable mechanism
for embedded devices that wish to support IPv6.  Given the limitation on
resources in most embedded applications, dual-stack solutions are not
usually possible, so a mechanism is needed that supports the transition
from IPv4-only to IPv6-only.

If an embedded device is to be IPv6-only, and if it is to work without
effort in that mode, it requires a method to access IPv6 from any
current network, including IPv4-only networks behind NAT routers.
The nature of these applications makes it desirable that such access
can happen without configuration of credentials for access to the
IPv6 network.  At the same time, the mechanism must support tracing
of abusers based on their IPv6 network use.


Protocol description
====================

The 6bed4 mechanism is a tunnel that encapsulates IPv6 packets in
UDP, and then into IPv4.  The mechanism assumes a remote tunnel service
at a well-known IPv4 address and UDP port, effectively making the tunnel
independent of DNS, and capable of traversing NAT.  The local IPv4 address
is acquired through common techniques such as DHCPv4, and the local
UDP port can be picked in any way that makes sense locally.

The tunnel service can be implemented at many locations, each announcing a
route to their well-known IPv4 address over BGP,
basically following the anycast principle.  The routing infrastructure
will then forward tunnel traffic to a nearby instance of that service.

Embedded devices obtain a routeable IPv6 address over the tunnel through
autoconfiguration.  The router, always with interface identifier 0,
can be reached on the fixed link-local IPv6 address fe80:: or on the
all-routers address ff02::2 or on the all-nodes address ff02::1.  The
tunnel client, which is the only other participant in the tunnel, can
pick non-zero interface identifiers at will to complete autoconfiguration.

The routeable prefix offered over the tunnel includes the IPv4 address
and UDP port as seen from the Internet.  Any NAT layer crossed by the
tunnel may influence the client-side IPv4 address and UDP port, which is
why the tunnel server will provide this data.  Autoconfiguration serves
to learn how the tunnel client looks from the perspective of the Internet.



Well-known addresses
====================

The setup described here allocates a number of well-known numbers for
addressing.  These numbers can be fixated into an embedded device, and
serve to address an anycast-published tunnel as a fallback for local
IPv6 facilities.

IPv4 address for the remote tunnel service:	TODO
IPv6 prefix for the remote tunnel service:	TODO::/64
UDP port for the remote tunnel service:		TODO

The well-known UDP port is only needed for routing UDP traffic
tofor the well-known IPv4 address of the remote tunnel service.



Link-local profile for 6bed4 tunnels
====================================

The 6bed4 tunnels add detail with respect to the autoconfiguration
mechanism described in RFC 2462.  Most importantly, the parameter
N for the number of bits in the interface identifier is 16.  The
preceeding 112 bits are filled with a /64 prefix for the IPv6-side
of the tunnel service, 32 bits worth of IPv4 address and 16 bits
of UDP port number::

  +-------------------------------+---------------+-------+-------+
  |      IPv6-side /64 PREFIX     | Public v4addr |UDPport| if-id |
  +-------------------------------+---------------+-------+-------+

Or, seen from the tunnel client perspective::

  +-------------------------------------------------------+-------+
  |                 IPv6-side /112 PREFIX                 | if-id |
  +-------------------------------------------------------+-------+

The interface identifier for the router is always 0 and only 0, which
means that it can always be reached at its link-local address fe80::/128.
The tunnel client can choose its own interface identifier(s) at will from
the range 1-65535.  The tunnel client MAY fixate the interface identifier
in its firmware.

The point-to-point nature makes it possible for tunnel clients and
servers to ignore the interface identifier altogether without
malfunctioning.  Upon sending however, a node MUST use a valid
interface identifier to accommodate peers that do check it.

The value of DupAddrDetectTransmits defaults to 0 for this kind of link,
meaning that no neighbour discovery is required for 6bed4 links.
This is possible because of the static allocation of interface
identifiers to endpoint.  Note that RFC 2462 requires the tunnel client
and server provide a facility for overriding this setting.  For this
reason, the tunnel endpoints MUST support neighbouring requests.


Tunnelling traffic
==================

The following describes how to pass traffic down from the IPv6-side
of the tunnel to the IPv4-tunnelled side; how to pass it up in the
opposite direction; and, as an optimisation, how a tunnel may
directly connect two tunnels by bouncing traffic to the other side.


Handling traffic sent down the tunnel
-------------------------------------

Traffic that is to be sent down through the tunnel, is routed to a
tunnel server by routing to its IPv6 /64 prefix.  If this is the
well-known prefix, then many BGP speakers may be announcing it; the
routing infrastructure would then find a suitable tunnel server
nearby the IPv6 sender.

If an entering IPv6 packet has a destination address with a different
/64 prefix than the prefix setup for the tunnel, then that packet MUST
be dropped or rejected with an ICMPv6 message.

If an IPv6 packet is passed down through the tunnel, its time-to-live
MUST be decremented.  If this is not possible because the time-to-live
is already 0, then the packet MUST be rejected with TODO:ICMPv6-TTL.

The IPv6 address to which the message is sent contains an IPv4 address
right after its /64 prefix, followed by 16 bits of client UDP port.
The distination side of an UDP header and IPv4 header can be reconstructed
from that, and the source side can be filled with the well-known values
that have been defined for 6bed4.  At some point before shipping this
message, the last 16 bits of the address, holding the interface identifier,
MUST be checked to be non-zero.  If the value is zero, the incoming
traffic MUST be silently dropped.


Handling traffic sent up the tunnel
-----------------------------------

The embedded device can send IPv6 packets through a tunnel as soon as it
has an assigned IPv6 address.  To do this, it will prefix an UDP header
with the well-known UDP port as a destination and the UDP port used
locally for the tunnel as a source.  It will then prefix an IPv4 header,
containing the well-known IPv4 address of the tunnel as destination,
and the classically obtained local IPv4 address as the sender.

This is shipped over the IPv4 network, may pass NAT routers, and will
arrive on the tunnel server with possibly altered sender information in
the IPv4 and UDP headers.

When traffic is sent to the all-routers multicast address ff02::2, the
all-nodes multicast address ff02::1 or to the router's link-local
address fe80::/128 it is subject to local handling according to RFC 2461
and RFC 2462.  If however, the time-to-live is not 255, the packet
MUST be dropped or rejected with ICMPv6:TTL.  Specifically, router
sollication will result in sending a router advertisement, and neighbour
sollicitations are handled as usual.

Before passing traffic through the tunnel, the time-to-live in the IPv6
packet MUST be decremented.  If this is not possible because it is already
0, then the packet MUST be rejected and an ICMPv6:TTL sent in response.

The tunnel server then verifies the correctness of the sending IPv6 address:
The first 64 bits should match the fixed prefix assigned to the tunnel
server; the following 32 bits should match the IPv4 address according
to the incoming message; the following 16 bits should match the UDP
port from which the incoming message came; the final 16 bits with the
interface identifier may not be zero, as that is always the tunnel
server's address.

If the match is good, the IPv6 payload will be taken out of its
IPv4/UDP wrapper, and forwarded as normal traffic over the IPv6
network.  A few exceptional forms of deliver (local, or IPv4) are
handled in later sections of this specification.

If the match is false, the tunnel server will send an unsollicited
router advertisement.  This advertisement will revoke the prefix
used by the tunnel client by setting its preferred and valid lifetimes
to 0.  In the same message, it will advertise the new prefix that
holds the external IPv4 address and UDP port of the client, and
assign it an infinite preferred and valid lifetime value 0xffffffff.

Upon reception of a router advertisement, the tunnel client MUST
immediately update its IPv6 addresses and it MUST NOT send out
any further messages using the old IPv6 address.  It MAY resend
any unacknowledged messages that are being processed.


Bouncing traffic on the tunnel's IPv4 side
------------------------------------------

If a tunnel receives a tunnelled package destined for an IPv6
address that begins with the tunnel's well-known IPv6 /64 prefix,
it MAY optimise the flow of traffic by forwarding it as
tunnelled traffic to the IPv4 address and UDP port found in the
remainder of the IPv6 destination address.

In doing so, it MUST NOT bypass the comparison of the IPv6 prefix,
IPv4 address and UDP port as mentioned in the source IPv6 address.
If this comparison fails, the traffic MUST be treated as traffic
trying to pass up through the tunnel with an incorrectly set
IPv6 address.


Tunnel service profiles
=======================

Two different service profiles are expcted to be useful for this tunnel
mechanism.  The first is public, available to users anywhere in the World.
The other profile is local, intended to serve only a part of the Internet,
such as the network of a particular provider.


Public tunnel server profile
----------------------------

The public tunnel server profile is announced over BGP and MUST be made
available to all partners that are allowed to route general traffic
through the autonomous system announcing the tunnel server.  The
announcement over BGP of the tunnel service SHOULD publish both sides
of the service, that is the IPv4 address as well as the IPv6 /64 prefix.

The traffic flowing through the tunnel server MUST NOT be logged or
analysed for any other reason than the correct functioning of networks.
That includes blockage of abusive patterns, but traffic MUST NOT be
logged for reasons of packet inspection by/for government policies.
If a policy exists that mandates any such forms of inspection then,
as a result of the anycast mechanism, the risk could arise that foreign
privacy-depriving laws would be applied to parties that communicate
from a region that is subject to more privacy.

Under the public profile, the tunnel server MUST use the well-known IPv6
prefix for this tunnel service.  This makes the tunnel servers fully
replace each other.


Local tunnel server profile
---------------------------

Under the local tunnel server profile, the well-known IPv4 address for
this server is not exported to non-local parts of the network.  In the
local part of the network, all traffic sent to the well-known IPv4 address
is handled by an internal tunnel server.

The IPv6 prefix used for this tunnel server MUST NOT be the well-known
prefix; it is allocated with the intention of direct routeability
to the local network.  The service provider MUST register an abuse
contact address for the IPv6 /64 prefix, and MAY explain how abuse can
be traced to IPv4 abusers, in the regional internet registry's whois
database.


En-route translation profile
----------------------------

Any public router connected to both IPv4 and IPv6 protocols can perform
the translations specified in this document.  It could perform this
function en route, so on traffic that happens to pass through it.  This
means that the least possible energy and effort is required to support
IPv6 to the embedded devices targeted by 6bed4.  The vital distinction
between such a 6bed4 profile and the public tunnel server profile is
that the translation services are not announced over BGP.

The major advantage of en-route translation is that it avoids any
diversion of the traffic to a 6bed4 tunnel server.  Instead of routing
the traffic through an intermediary, it can be kept on the fastest
route available, which is good for the routing budget of the Internet
as a whole; furthermore, it can save on the budget of the en-route
party if it has less need to steer traffic through core routers.

It is possible to perform only one side of this translation en-route;
a consumer-level ISP might want to support old IPv4-only routers and
any 6bed4-based devices behind it.  Similarly, a hosting provider
could offer the service of translating the IPv6 side traffic to IPv4.

An ISP wishing to provide this service to its own network but not to
the whole world could implement such en-route translation, in order





NAT traversal issues
====================

Very often, a 6bed4 tunnel will have to pass through a layer of
netwerk address translation, or NAT.  This layer will rewrite IPv4
and UDP source addresses.  The 6bed4 tunnel protocol has been designed
to accommodate that situation.

A problem with NAT for UDP is that it has no connection status, and
its translation must therefore be flushed at some point.  Although the
tunnel itself will recover quickly if that happens, the higher protocols
may not be as accommodating; notably, TCP connections over IPv6 would
break if the translation changed suddenly.

For this reason, it may be needed to send messages for the purpose
of keeping the address translation active in any on-route NAT routers.  
This can either be achieved by an actively communicating protocol, or by
explicit keep-alive messages.

Explicit keep-alive messages MAY be complete neighbour discovery messages
sent to the tunnel service, but there usually is no need to go that far.
Any such messages MUST NOT be sent if there is no application need for
keeping the same IPv6 address on which the tunnel client can be reached;
and in any case it MUST NOT be sent more often than once in 30 seconds.
Furthermore, randomization of the keep-alive message interval is important
so as to offload the tunnel server from synchronisation of keep-alives
after things like power outages.

In general, it suffices to send messages to the first IPv4 router with an
address that is not defined in RFC TODO for local use.  This address can
be easily obtained by using the traceroute procedure: send UDP traffic
with increasing TTL values and wait for the ICMP return traffic that
reveal router addresses.  A tunnel client SHOULD attempt to obtain this
nearer-by address and use it for explicit keep-alive messages, so as to
offload the Internet and specifically the 6bed4 service.

Note that a device MAY use other means to achieve the longevity of an
open link.  If it can communicate its wish for an open UDP port directed
to its local endpoint directly, this is a much simpler method.  The only
disadvantage of this approach is usually that it cannot be relied upon
as a general mechanism; but if it does, it will save energy and bandwidth,
so it is certainly recommended.


IANA Issues
===========

Well-known IPv4 address, well-known IPv6 /64 prefix.
Requested: IPv4 address 192.64.64.1/24 and IPv6 prefix 2001:6bed:4:0::/64.

Possibly also, the well-known UDP port.
Since this port is only bound to a well-known IPv4 address, the port
could be anything.  We suggest sharing the UDP port for TSP, which is
3653.


Privacy issues
==============

Tunnel servers can attract traffic, and especially the use of an anycast
address means that the tunnel service provider is not easily known.
As a result, there may be privacy issues when the traffic enters a
jurisdiction that requires more excessive tapping and law enforcement
than is assumed by communicating partners.

For this reason, in jurisdictions where tapping, inspection and/or
storage of traffic can be enforced by law, the BGP announcements of either
or both well-known address prefixes MUST NOT reach jurisdictions where
more more relaxed tapping requirements exist.

A disadvantage of this requirement is that the use of 6bed4 with its
well-known addresses is impaired in countries that enforce tapping of
traffic at the routing level.  The result may be slower performance,
with a real impact on realtime media exchange.  The economic impact
that this could have is outside the scope of this specification.


Security issues
===============

Any party that can convince a network of being the router for a given
range of addresses will be able to attract the traffic for 6bed4 tunnels.
This could open up such protocols for man-in-the-middle attacks.

The foreseeable means of doing this are either through BGP advertisements
on the Internet, or through router advertisements on a local network.
The issue of BGP advertisements is a general problem and is not generally
thought of as being hazardous; notwithstanding that, work is being done
to solve the general problems at that level.  At the local level, the
problem is not much different from DHCP hijacking, a risk that is usually
dealt with locally by monitoring nodes to behave as clients, or by strict
control over network accessibility.

Although symmetric signatures are possible over neighbour discovery
protocols, this is not usable for the 6bed4 system, because it is a
global protocol and includes too many parties to be able to protect
te secret keys used.  Any signature mechanism for 6bed4 would have
to be asymmetrical.

