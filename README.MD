# IPv6 Everywhere with 6bed4

> *The 6bed4 tunnel and peer-to-peer toolkit enables IPv6 everywhere.
> It connects programs and hosts over UDP/IPv4.  It tries hard to setup
> connections as direct peer-to-peer connections, but may fall back to
> a server failing this.*

The intention of 6bed4 is to assure protocol designers of the availability
of IPv6 on all nodes that run their protocol.  For instance, a designer
of a peer-to-peer search application should be able to connect to peers
over IPv6, thereby bypassing many problems resulting from NAT.  One might
say that IPv6 is used to encapsulate all problems with NAT traversal.


## Status

This code is **WORK IN PROGRESS**, while we are finalising our 6bed4
Internet Draft.


## Programs

The `6bed4peer` program runs an interface over which IPv6 routing is
available, and for which up to 16383 local extensions can be allocated
and made available over a tunnel interface.

The `6bed4node` program is an extended `6bed4peer` in that it does not
provide a network interface but a network service that offers IPv6
addresses over a standard network interface, though this requires a few
extra programs like `radvd` and possibly a DHCPv6 server.  In this case,
programs can use native IPv6 network stacks.  A typical use case for the
`6bed4node` is on a network router, such as one of the OpenWRT routers.

The `6bed4router` program runs as a fallback router.  Even when it could
be considered a server program, it is faithful to the idea of peer-to-peer
communication in the sense that multiple of these routers can collaborate
to connect `6bed4peer` programs.  A user can choose which router to use,
although this
[depends on the prefix](PREFIXES.MD)
used.  We have arranged for public 6bed4 service at 145.136.0.1 port 25790.

**TODO:** 6bed4node remains to be done.

**TODO:** A socket-replacing library would be useful.

For use with Java, we have **TODO:** Android6bed4 and Socket6bed4.


## Usage

TODO
