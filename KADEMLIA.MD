Kademlia Routing with Standard Protocols
========================================

On top of the standard prefix TBD1::/32 for 6bed4, a list of alternative
prefixes was proposed, including `fc64::/16` for local interpretation
as `fc64:<netid>:<ipv4>::/64`, a variant of the globally acceptable
interpretation of `TBD1:<ipv4>::/32`.

A highly interesting option is the `fd00::/8` prefix, which is extended
to a /48 by adding 40 random bits.  Or, as we tend to do, with 56 random
bits to form a prefix `fdXX:XXXX:XXXX:XXXX::/64`.  This is an interesting
notation for a network node that might be routed under local policy, for
instance using a Kademlia variant.


Kademlia Routing
----------------

Kademlia is a peer-to-peer protocol, and it routes over varying and possibly
pervasive infrastructure.  A variant to Kademlia is found in GNUnet, which
precedes a Kademlia address with a few extra bits that scatter messages out
over random routes before they recollect and find their way to the intended
recipient.

Kademlia nodes have an address, and so do their peers.  By computing the
exclusive or between a targeted destination address and its own address,
Kademlia can find progressive paths to close in on the destination.  The
trick is that it favours the longest prefix, and only stores those that
start their exclusive or pattern with zeroes and a single one bit.  In
other words, Kademlia looks one level down from its own address, at every
prefix length.

The scattering that initiates this search in GNUnet is easily added by
prefixing the target address with random bits, and treating those
addresses as proper recipient addresses to route.


Kademlia and the fdXX::/16 Prefix
---------------------------------

As explained, we add 56 random bits to the `fd00::/8` prefix to find a
node address.  Usually, this node address will be stable, so as to not
disservice clients and neighbours on the network.

When a packet arrives that is targeted at an address under a different
prefix, say `fdYY:YYYY:YYYY:YYYY::/64`, we can look for overlap with
the local nodes' `fdXX:XXXX:XXXX:XXXX::/64` and find the nodes that
service it one step down.

To add initial scatter in the style of GNUnet, we might choose to distort
the initial 8 bits of the address, but only after having made the routing
decision to enter Kademlia.  This scattering would turn the address prefix
into `ZZYY:YYYY:YYYY:YYYY::/64`, which must only be done upon entry of the
Kademlia system, and only within a networking namespace that tolerates such
random initiations and searches for them in the Kademlia network.  In fact,
the local node uses a somewhat more random prefix `XXXX:XXXX:XXXX:XXXX::/64`
and the target uses `YYYY:YYYY:YYYY:YYYY::/64` as its prefix.

We now have a routing key of 64 bits; the initial 8 bits scatter as well
as the `ZZ` are random, and the following 56 bits `YY:YYYY:YYYY:YYYY` close
in on the target, but only after having reached the scattered address.
The routing key is now treated as customary under Kademlia.

The router is assumed to have tunnels to the various nodes in the network.
In fact, there is usually a bag of multiple nodes to connect to, as part
of the resilient design of Kademlia.  (It is worth investigating if the
initial scatter makes this less of a requisite.)

We can use any standard linking mechanism; since we are now in server land
we may choose a simple mechanism such as IP-in-IP or GRE.  Indeed, it would
be useful to benefit from dual-stack routing, and support routes going over
IPv4 as well as over IPv6.

The storage required to perform this routing is simply this: for each of
the 64 address bits a bucket of (say 20) routers that may be contacted as
a remote tunnel endpoint.  This setup is highly dynamic, and therefore less
practical to do in kernel space.


Building the Routing Table
--------------------------

**TODO: WORK IN PROGRESS**

Routing may be doable, but we still need to build the routing table.  All
this starts with one or more seeds that allow entry into the Kademlia
network; those seeds define the realm that we enter.  These seeds do not
exercise control of any kind; any node in the network may serve as a seed
and control quickly passes on to the other nodes.

As it turns out, standard ICMPv6 messages suffice, together with the notion
of link-local addresses that can store up to 64 bits of addressing information
with a link-specific interpretation.

The link-local addresses used to convey Kademlia peers are not the usual
`fe80::/64` addresses, but they are 6bed4 address.  Depending on the
[prefix and its promises](PREFIXES.MD), there may be a globally routable
IPv6 address or not; there may or may not be an IPv4 address in the top
half address.  In any case, the lower half of the address can be interpreted
for 6bed4 peering, so this will lead to an IPv4 address and an UDP port.
It is not important if this lower half information points to an end user
or a Kademlia node; as long as it is usable for routing purposes.

This is perhaps the vital part of peer-to-peer routing, the ability of
end users to perform routing.  To this end, they should be clear about
their reachability, which usually hinges on either local port forwarding
or a fallback server that is reachable under an IPv4 address.

Note how the routability of an IPv6 prefix is not dependent on the
actual presence of a native IPv6 route to the Kademlia node; we created
6bed4 precisely to overcome that obstacle.  And `fc64::/16` is also
usable for the same purposes, as this clearly defines a local network
to be used.  When a routable IPv6 prefix is provided, especially when it
is a native one, then connectivity over IPv6 is also arranged, which
is desirable as an alternative to IPv4-based routing (using 6bed4).

At some point in the future, we may not be able to rely on IPv4 as a
routing layer; by then, the address 0.0.0.0 will be used in the lower
half of the address to indicate that situation.

Kademlia uses a limited number of
[protocol messages](https://en.wikipedia.org/wiki/Kademlia#Protocol_messages):

  * `ping` to verify that a node is alive.  This may be done using an ICMPv6
    message sent to the address that we know lives on the other end.
  * `store` to pass a mapping from an `fd00::/8` prefix to a routing address
    to another node.  This may be done using Router Advertisement.
  * **TODO:** `find_node` and `find_value` map to Router Solicitation.


Client Resiliency
-----------------

It is important to understand that the client is not forced to depend solely
on one hosted node.  There is an option of diverging to other routers, albeit
that this changes the client's address.  The lower part of the address does
not always change, but that is not a reliable assumption due to the diverse
nature of NAT.

Clients however, can have more than one address and can switch as they like,
thereby changing the upstream party that they rely on.

**TODO:** We might also exploit diversity through scattering, but only when
the client can be sure to sit on just a peer-to-peer network, without any
native routing or other prefixes being used than `fd00::/8`.

**TODO:** Clients can route between networks if they like (and be present
on each of the connected networks).  Challenge is to swap encryption while
moving from one network to another.  ECDH may be part of the solution, or
the router may take do this for egress/ingress "local" network frames.


Privacy and Security
--------------------

Nodes should communicate securely, and the best way to do this is through
IPsec; use AH for just authentication, or ESP for both authentication and
encryption of traffic.

It is worth noting that a UDP port has been
[set aside](https://tools.ietf.org/html/rfc3948) for ESP operation,
namely port 4500.  When sending, both sender and recipient ports are
set to 4500, though on arrival it may only be set to 4500 for the recipient
port, due to NAT traversal.

The same port is used for both ESP encapsulation and IKE, so there are no
issues of any kind with NAT traversal.

**TODO:** All this does not matter much; we need to see the IPv6 header,
and only the layers after that can be protected with ESP.  This is common.
What it does say however, is that we are not in search for an ESP transport,
but for an IPv6 transport.  We end up wanting 6bed4... which we started with
anyway `;-)`

It is strongly advised to protect the layers beyond IPv6 in a generic manner,
that is, using ESP.  It is up to the application how to use ESP &mdash; in
tunnel mode, transport mode, or as part of the Host Identity Protocol.

It is very common in peer-to-peer networks to consider a public key as the
identity of a client.  This is the private substitute for an email address.


Client Address Privacy
----------------------

**TODO:** This is probably overkill.  It was worth a shot, but leads to
a chaotic design of everything involved.  In general, join a group that
you trust, and want to contact directly.  Join many groups if you like.
Route between groups and make your concealment efforts at that point.

When working on a client's privacy, we should not reveal their address to
the world.  And since the lower half of the address is only up for
interpretation by others using the same /64 prefix, this defines a good
privacy method.

The node offering the `fdXX:XXXX:XXXX:XXXX::/64` prefix should apply a
form of encryption to the lower half that is unwrapped when it sends
traffic over IPv4/UDP using the 6bed4 protocol.  The encryption would
be reapplied when passing it on to another Kademlia node.  The top half
of the address (plus, possibly, time) define the encryption applied.

This leaves a client address visible to other clients under the same
`fdXX:XXXX:XXXX:XXXX::/64` prefix, which may be acceptable (for a
company's node) or not (for a public server node).  The client can
choose to always use another prefix than that in use by a targeted
peer.  This is always possible for a peer with at least two prefixes.

Interestingly, when we designed 6bed4 we set the purpose of avoiding
trapezium-shaped routing and instead we preferred direct peering.
In a peer-to-peer network there may be choices that prefer to go
through at least two fallback routers; one to encrypt our own
lower address half, and another to decrypt the target's lower half.
And the opposite on reply traffic, of course.

A much better solution to this problem is possible on a server.  This
recognises that the normal extension of `fd00::/8` is up to a /48
prefix, and that this is already considered sufficient protection from
clashes.  So, a server might reserve a few of the last bits of its /64
prefix for an index.  This might look like `fdXX:XXXX:XXXX:XXXA::/64`
and `fdXX:XXXX:XXXX:XXXB::/64` and perhaps more.  Kademlia routing
will make it easy to pickup on both addresses on the same node.
The trick is now to look at the addresses shown to a client and
make sure that a the source and destination address never come from
the same prefix.  It is easy enough for the router to bounce traffic
between its clients with altered encryption, if so desired.

**TODO:** Another task would be to control the visibility of addresses
in non-IP protocols such as DNS.  This may be more challenging, though
not undoable either, if this is the only way to find addresses.  The
problem probably is that this is not the case; all sorts of protocols
may pass around peer addresses and we might end up re-inventing NAT...

