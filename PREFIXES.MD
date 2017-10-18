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

  * `TBD1::/32` and its extension `TBD1:<ipv4>::/64` are the perfect prefixes
    for 6bed4.  They support the top-half and bottom-half structures, and are
    globally defined to do so.

  * `fc64:<netid>:<ipv4>::/64` may be used for 6bed4 as well.  The `<netid>` could
    be varied to indicate different applications, so the prefix is as for 6bed4,
    the `fc64:<netid>::/32` prefix.  The `fc00::/8` prefix indicates locally unique
    addresses.  Since this also limits the scope, any connection between such
    nets may be read as an indication that they are on the same local net and
    the interpretation may therefore be assumed.  This is true for all `fc00::/8`
    addresses, but we suggest leaving room for other uses by setting `fc64::/8`
    specifically for the 6bed4 interpretation of the remainder of the address.
    Note that `fd00::/8` also covers unique local addresses, but it is followed
    by random bits, so no policy can be applied without breaking standards
    (and software).  Note that `fc00::/8` is a local scoped name space, but it
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
    thing that is impossible, as with `fc64::/16`, is that independent
    6bed4router processes can serve the same prefix and have their 6bedpeer
    clients reach each other; this is due to the lacking fallback server in
    the top half.

  * `fdXX:XXXX:XXXX::/48` prefixes are based on randomly assigned bits.  We
    shall expand this to a /64, and it should be clear that these IPv6
    addresses cannot be interpreted to hold an IPv4 address in their top half.
    Local convention however, may dictate the interpretation of the lower half
    for purposes of 6bed4 direct peering, provided that the other peer's
    top half is the same.  This is a local convention, not in any way
    different from one for a native IPv6 /48 or /64 prefix, but without
    global routing.

  * `2002:<ipv4>::/48` is based on the 6to4 prefix `2002::/16`, but instead of
    using the peer's address and relying on the ability to pass IPv6 directly
    over IPv4, the 6bed4router can be used as an intermediate.  The place of
    the `<ipv4>` address is different than after the /32 of normal 6bed4
    addresses, but this is quickly inferred from the prefix.  So, given a
    prefix `2002:<ipv4>:<netid>::/64` it is theoretically possible to interpret
    `<ipv4>` as the fallback server, even for foreign networks.  The problem
    with this is concluding that the lower half of the address contains the
    information typical for a 6bed4 peer.  This would lead to routing errors,
    and this assumption should only be made for prefixes announced over
    6bed4 in Router Advertisements.  In other words, the
    `2002:<ipv4>:<netid>::/64` prefix is no different to the 6bed4 peer than
    a native IPv6 prefix; direct peering is only done under the same /64.
    Still, this leaves users with an option to have IPv6 addresses routed
    over a NAT-piercing protocol from a server that should have no trouble
    receiving proto-41 traffic.  Do note however, that 6to4 popularity is
    in demise.


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
  * network identities, to fill up any remaining 16 bits

This format works for prefixes of sizes 16, 32, 48 and 64:

  * `xxxx::/16` becomes top half `xxxx:<ipv4>:<netid>::/64` or `xxxx:<netid>:<ipv4>::/64`
  * `xxxx:yyyy::/32` becomes top half `xxxx:yyyy:<ipv4>::/64`
  * `xxxx:yyyy:zzzz::/48` becomes top half `xxxx:yyyy:zzzz:<netid>::/64`
  * `xxxx:yyyy:zzzz:wwww::/64` is unaltered

Specifically for the indicated candidate prefixes:

  * `TBD1::/32` becomes top half `TBD1:<ipv4>::/64`
  * `fc64:<netid>::/32` becomes top half `fc64:<netid>:<ipv4>::/64`
  * `fc64::/16` becomes top half `fc64:<netid>:<ipv4>::/64`
  * `fdXX:XXXX:XXXX::/48` becomes top half `fdXX:XXXX:XXXX:<netid>::/64`
  * `fdXX:XXXX:XXXX:XXXX::/64` is unaltered
  * `2002::/16` becomes top half `2002:<ipv4>:<netid>::/64`
  * `2002:<ipv4>::/48` becomes top half `2002:<ipv4>:<netid>::/64`
  * `xxxx:yyyy:zzzz::/48` becomes top half `xxxx:yyyy:zzzz:<netid>::/64`
  * `xxxx:yyyy:zzzz:wwww::/64` is unaltered

These do all support routing based on the bottom half.  Furthermore:

  * The fallback server appearing as <ipv4> in the top half enables unrelated 6bed4router connectivity
  * The rules for global routing determine whether the addresses can communicate with native IPv6 addresses


Routing Local Addresses
-----------------------

As explained, some prefixes can be routed globally:

  * `TBD1::/32`
  * `TBD1:<ipv4>::/64`

Other prefixes are defined by local addressing policy and can only be
directly peered to peers that match the prefix:

  * Native IPv6 /48 prefixes
  * Native IPv6 /64 prefixes
  * `fc64:<netid>:<ipv4>::/64`
  * `fdXX:XXXX:XXXX::/48`
  * `fdXX:XXXX:XXXX:XXXX::/64`
  * `2002:<ipv4>::/48`
  * `2002:<ipv4>:<netid>::/64`

Having to relay all traffic the fallback router is not necessarily the end
of the (networking) world, however.  There are still options for routing.

Even the local addressing schemes for `fc64::/16` and `fd00::/8` are local
in the sense of convention, but the addresses are thought and hoped to be
globally unique, thus allowing them to spread out without a risk of clashes.

What this means is that the router may be *explicitly configured* to connect
to other server nodes with the same interpretation policy.  It is even possible
to mix `fc64:<netid>` with different `<netid>` values and treat them as one
network; the only concern is the interpretation of the address format should
match.  Now, wasn't Linux visionary when it defined the wonderful notion of
[network namespaces](https://blog.scottlowe.org/2013/09/04/introducing-linux-network-namespaces/)?

It is in fact strongly advised to do any routing for non-global prefixes in
a namespace that is separate from any native routing.  This helps to avoid
leaking local traffic over a default route, which is always a bad idea.
Likewise, local traffic should not be inserted so easily and accidentally
by an upstream router.  We recommend that you partition your network
to separate out the local namespaces `fc64::/16` and `fd00::/8`.

If you do not partition into netwok namespaces, you can instead ensure that
any prefix cannot get out or in across the scope of interpretation, which
usually means the primary network interface of a machine:

```
shell$ ip6tables -A OUTPUT -s fc00::/7 -j DROP
shell$ ip6tables -A OUTPUT -d fc00::/7 -j DROP
shell$ ip6tables -A  INPUT -s fc00::/7 -j DROP
shell$ ip6tables -A  INPUT -d fc00::/7 -j DROP
```

Having made sure that no *default traffic* for local addresses are exchanged
with an outside that interprets those addresses differently, we can now add
*explicit routes* between servers that have the same interpretation of the
addresses.  This can be done through tunnels, of any kind you like.  Since
the fallback router is supposed to control its routing and firewalling more
professionally than home/office nodes, the UDP layer is no longer required.

Among the many options that now arise are:

  * IPIP tunnels, packing IPv6 in IPv4 or IPv6 in IPv6.  These lead to a
    different `ip link` for each tunnel.
  * L2TP tunnels, which allow for more management, and may be constructed
    dynamically or statically.  L2TP is often used with IPsec protection,
    though that might not add much if the 6bed4 usage patterns did not.
    L2TP is also used as a backend protocol for such things as PPPoE,
    and it may be statically configured using `ip link` or dynamically
    using [extensive management tools](http://openl2tp.org).  L2TPv2
    handles 2 level of 16-bit identities, L2TPv3 uses 32-bit identities.
  * GRE, which can send traffic with 32-bit keys.  GRE over IPv6 in Linux
    may not scale well, but over IPv4 it does.  This is a simple technical
    matter of adding hash tables to the IPv6 implementation as it has been
    done for the IPv4 counterpart.

The reason for emphasising the 32-bit identities in the above is that this
might be used to automate tunneling to a given IPv4 address.  Note that the
remarks about scope of interpretation applies when this is done.  This is
not a good idea for `fd00::/8` adresses, which really ought to be filled
with random data, without any opportunity of interpretation.  Interesting
about `fd00::/8` however is that it defines a /48 prefix and the remainder
may be interpreted locally, for instance as a 16-bit identity for an L2TP
protocol.  All these are just options to simplify automation.


Peer-to-Peer Networking
-----------------------

We emphasised the value of global routing, but this is not always desired.
Specifically for peer-to-peer networks, this requirement is not useful at
all.  In fact, such networks may even use the ORCHID address range, which
introduces 96 bits from a hash over a public key as a hint to a host's
identifying key.  Note that ORCHID leaves no room for us to interpret the
lower half of the address for 6bed4, so it cannot be used for our purposes.

A peer-to-peer network can however be based on 6bed4 addresses such as
`fc64::/16` ranges, or even a network-specific `fdXX:XXXX:XXXX::/48` or
`fdXX:XXXX:XXXX:XXXX::/64` prefix and the 6bed4 interpretation for the
lower half of the address.

It may sound like a contradiction to combine hosting with peer-to-peer
networking.  The trick however, is that connected hosts allow the peer
to choose a hosting party that suits his goals in terms of control,
jurisdiction and privacy.  This may in fact be a hosting provider that
intentionally protects their customer's privacy, possibly in return
for payment (which is a way of being sure that the contract needs to be
consistently lived by, a property that "free" services do not offer).

Also note that many setups with 6bed4 allow peers to connect directly.
This is even true with shared prefixes from a local-address range.
As a result, the user still has full control, and may only need to
fallback to the server to detect their address, and/or as a fallback
route.  When setup completely (usually with port forwarding in one's
NAT router) the fallback server can be completely abolished; this
however, would be the "extra-value" option for die-hards, but not a
strict necessity for those who are just getting started on the network.

There are also benefits in a technical sense.  Where peer-to-peer networks
employ clever techniques to make routing less dependent on infrastructure,
there still is a need for a lot of communication in service of others on
the network; this results from multi-hop routing in the overlay network.
If an average of 10 hops are needed, then count on an average of 9 frames
to route for a single frame that you send.  It can be attractive to bundle
such responsibilities in a hosted server, whose traffic is usually cheaper,
whose connectivity is more stable and whose routing may benefit multiple
tenants of the peer-to-peer network.  Many who have tried peer-to-peer
systems on their mobile phone would agree that the unpredictably elevated
cost of traffic is unattractive.

All this constitutes choices to be made by designers of a peer-to-peer
network.  They are however saved a lot of trouble passing through NAT
when they adopt the 6bed4 mechanism, so it is probably worthwhile to
consider.  Among the choices is the address prefix that will be used;
`fc64:<netid>:<ipv4>::/64` is helpful because of the embedded IPv4
address that can be interpreted as a hosting endpoint; on the other hand,
`fdXX:XXXX:XXXX:XXXX::/64` introduces a kind of *network identity*
in the random bits, and strictly relies on the interpretation of the
lower half where all the opportunistic peering takes place, and it will
never step out to someone else's router, which can happen when `fc64::/16`
is used.  Abundant choices, but they are all good (in their own way).

As an example: fallback serers may each use their own `fd00::/8` prefix
with a random continuation that differs between fallback servers.
Some mechanism of the network informs such servers about their joint
action as a peer-to-peer network.  The fallback servers use the random
bits to route using a mechanism like Kademlia, possibly after some initial
randomisation as proposed by GNUnet.  This means that the fallback servers
form a peer-to-peer network.  As far as the 6bed4 clients know, they can
link to other `fd00::/8` local addresses, and route them up to their
fallback server if the complete /64 differs from another that they might
like to contact.

