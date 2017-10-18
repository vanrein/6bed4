# Using 6bed4router under a Native /64 Prefix

> *Your ISP gave you a natively routed /64 prefix, and you want to use the
> 6bed4router as a tunnel.  The clients of that tunnel might be a mobile
> device or a home network.*

Following are instructions to setup for this.  We use the Linux command line
because it is the most general.  Your distribution may have clever ways of
automating the configuration, perhaps even graphically.  If you desire such
instructions, please use a forum for your distribution.


## Assumptions

We assume that your hosting provider gave you a Linux virtual machine with
root privileges.  We assume that its primary network interface is named
`eth0` with MAC address `a8:bb:cc:00:11:22`.  The IPv6 prefix awarded to
you will be assumed to be `2001:db8:9:10::/64`.

When your `eth0` interface goes up, it automatically configures a link-local
address, meant for communication on the link (to the router of your hosting
provider).  It will start fall under `fe80::/10` and in this case should be
`fe80::aabb:ccff:fe00:1122`.  You can see that it contains a mangled form
of the MAC address of the interface.

Without explicitly adding an IPv6 address with a global scope, you already
have this link-scoped address configured:

```
shell# ip -6 addr show dev eth0
0: eth0: <...> ...
    inet6 fe80::aabb:ccff:fe00:1122/64 scope link
```

The upstream router could use `ping6` to reach you at this address, and so
could you from this virtual machine.  However, this being a link-scoped
address, nobody else could reach the IPv6 address.


## Example Setup

First, the IPv6 default route is set to the address of the upstream router
of the hosting provider, something like

```
shell$ ip -6 route add default via fe80::aabb:ccff:fedd:eeff dev eth0
shell$ ip -6 route show
default via fe80::aabb:ccff:fedd:eeff dev eth0 metric 1024 mtu 1500 ...
```

Most people configure their hosted machine like they would do with a
machine on their home network.  So, we shall add a few IPv6 addresses:

```
shell# ip -6 addr add 2001:db8:9:10::11/64 dev eth0
shell# ip -6 addr add 2001:db8:9:10::30/64 dev eth0
shell# ip -6 addr show dev eth0
0: eth0: <...> ...
    inet6 2001:db8:9:10::30/64 scope global
    inet6 2001:db8:9:10::11/64 scope global
    inet6 fe80::aabb:ccff:fe00:1122/64 scope link
```

Note how the new addresses are setup with global scope.  Indeed, anyone on
the Internet should now be able to `ping6` you on that address.  You are
online!

You can now configure programs like a webserver to listen to one or both
of these addresses.  Inasfar as they are already listening to all addresses
they will immediately pickup on the newly added addresses.  This applies
to `ping6` but also to most installations of `sshd`:

```
shell# netstat -ptnl6
9378/sshd   0   0   :::22   ...
```

It would be confusing to parse due to the colon between the address and port,
but `:::22` indicates address `::` and port 22.  In other words, `sshd` with
pid 9378 listens to all addresses and will respond to the newly added IPv6
addresses.


## Enter 6bed4router

When you are using `6bed4router`, chances are it's the first time you start
to think of your virtual host as a router.  This is indeed the added value of
the vast array of addresses that you get with IPv6.

The example setup sketched before is common, but from a router's viewpoint
it is flawed.  Just look at this:

```
shell# ip -6 route show
2001:db8:9:10::/64 dev eth0 ...
fe80::/64 dev eth0 ...
default via fe80::aabb:ccff:fedd:eeff dev eth0 ...
```

Note how silly this is &mdash; you are directing your assigned native /64
prefix back to the router of your hosting provider.  This is the result of
your use of a `/64` prefix when you setup your two addresses on `eth0`.

When your `eth0` is attached to a LAN, this setup makes sense; the LAN
has numerous hosts under this /64 prefix, and so your networking stack should
consider anything under the prefix local to the `eth0` link.  The prefix
is attached to the LAN by a router that connects the LAN to the rest of the
IPv6 internet.

In your hosting setup, this is usually not how things are done.  Here, the
`eth0` interface is a direct link to an upstream router whose sole purpose
it is to relay your prefix to your `eth0` interface.  There are no other
hosts residing under the same /64 prefix.  Still, as long as you enumerate
all actual IPv6 addresses in use on the `eth0` interface, this is going
to work.

But now you want to add `6bed4router`, which means you have entered the
realm of routing yourself.  Now what do you do?  If you let it, the
`6bed4router` creates a `6bed4` network interface with the same /64 prefix,
and your system might get confused.

The solution is simple.  You can use `eth0` for inbound traffic for your
/64 prefix, even when it does not have local addresses assigned.  All you
need to ensure is that it forwards frames that it cannot handle on the
interface itself.

```
shell# sysctl -w net.ipv6.conf.eth0.ip_forwarding=1
shell# sysctl net.ipv6.conf.eth0.ip_forwarding
net.ipv6.conf.eth0.ip_forwarding = 1
```

and, if you intend to support multicast as well, perhaps even

```
shell# sysctl -w net.ipv6.conf.eth0.ip_mc_forwarding=1
shell# sysctl net.ipv6.conf.eth0.ip_mc_forwarding
net.ipv6.conf.eth0.ip_mc_forwarding = 1
```

You could now remove the IPv6 addresses to pass all the traffic, for insance
to the 6bed4 interface, which is not desirable if you intend to run servers
under your /64 as well.  But this is how it would be done:

```
shell# ip -6 addr del 2001:db8:9:10::11/64 dev eth0
shell# ip -6 addr del 2001:db8:9:10::30/64 dev eth0
shell# ip -6 addr show dev eth0
0: eth0: <...> ...
    inet6 fe80::aabb:ccff:fe00:1122/64 scope link
shell# ip -6 route show
fe80::/64 dev eth0 ...
```

The trick is to redefine the addresses with a longer prefix than /64.  With
the /64 assigned to the `6bed4` interface, the longer prefix is a better match
for some packets, which are then not forwarded over `6bed4`.

There is explicit support in the 6bed4 design for this approach, and that is
by being utterly uninterested in certain addresses.  The one-but-last word
in the address structure of 6bed4 represents an UDP port, and since port 0
is never permitted, there is a whole range of IPv6 addresses that can be
bypassed for other uses &mdash; such as running a server locally.  There just
have to take a format `xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:0000:xxxx` to be clearly
distinguishable from 6bed4 addresses.  In our case, we can use the addresses
ending in `::11` and `::30` without confusing with 6bed4.  A decent prefix
to use would be either /128 for an exact match with the address or, if we
wish to offload the routing tables, a /112 prefix that is certain to hold
at least the port number.

The next question is where the addresses should go.  For /128 prefixes, the
`eth0` interface would be quite good, so it can match the addresses locally
and refrain from further routing.  This is also pleasant if there is a
preference to route IPv4 and IPv6 over the same interfaces (though that is
a subject desire).  Aside from the already-coded removal of the old
addresses, the procedure would be:


```
shell# ip -6 addr add 2001:db8:9:10::11/128 dev eth0
shell# ip -6 addr add 2001:db8:9:10::30/128 dev eth0
shell# ip -6 addr show dev eth0
0: eth0: <...> ...
    inet6 2001:db8:9:10::30/128 scope global
    inet6 2001:db8:9:10::11/128 scope global
    inet6 fe80::aabb:ccff:fe00:1122/128 scope link
```

Where the option of one or more /112 prefixes is preferred, we might instead
do that on `eth0`, or choose to not send packets for the smaller network
ranges back upstream by creating a virtual network interface.  It may be
helpful to create a "dummy" network interface, which holds your
local IPv6 addresses and has them routed through the loopback interface,

```
shell# ip -6 link add dumbo0 type dummy
shell# ip -6 link set dumbo0 up
shell# ip -6 link show dev dumbo0
1: dumbo0: <...> ...
    link/ether 11:22:33:44:55:66 brd ff:ff:ff:ff:ff:ff
```

Variations on this are many...

 1. You could create virtuel ethernet devices
    to link directly to others, possibly in another
    [networking name space](https://blog.scottlowe.org/2013/09/04/introducing-linux-network-namespaces/)
    or [container](https://linuxcontainers.org), and so on.
 2. You could setup a tunnel with a tool like
    [socat](http://www.dest-unreach.org/socat/)
    to relay traffic to another network, where you unleash the
    address range via
    [Router Advertisements](http://www.litech.org/radvd/) and
    [DHCPv6](https://www.sixxs.net/wiki/Configuring_ISC_DHCPv6_Server).
 3. You could setup a
    [translation](http://openhip.sourceforge.net) to logical addresses using the
    [Host Identity Protocol](https://en.wikipedia.org/wiki/Host_Identity_Protocol).
 4. You could export an address range over a
    [DNS tunnel](http://code.kryo.se/iodine/).
 5. You could run [L2TP](http://openl2tp.org)
    to connect networks based on the /112 IPv6 prefix, possibly
    as a backend to PPPoE clients.  Add IPsec and you have a nice,
    standards-compliant VPN.

And you could mix in any way you like, by assigning different /112
prefixes to each interface.  Given the port-0 assumption, you have 4294967296
of those ranges for a total of 281474976710656 hosts, we hope that you will
agree that 6bed4 leaves you some room to play.

Again, we should ensure forwarding:

```
shell# sysctl -w net.ipv6.conf.eth0.ip_forwarding=1
shell# sysctl net.ipv6.conf.eth0.ip_forwarding
net.ipv6.conf.eth0.ip_forwarding = 1
```

and possibly

```
shell# sysctl -w net.ipv6.conf.eth0.ip_mc_forwarding=1
shell# sysctl net.ipv6.conf.eth0.ip_mc_forwarding
net.ipv6.conf.eth0.ip_mc_forwarding = 1
```

Now we can proceed by adding the IPv6 addresses again, but this time with a
/112 prefix and to the `dumbo0` device:

```
shell# ip -6 addr add 2001:db8:9:10::11/112 dev dumbo0
shell# ip -6 addr add 2001:db8:9:10::30/112 dev dumbo0
shell# ip -6 addr show dev dumbo0
0: dumbo0: <...> ...
    inet6 fe80::aabb:ccff:fe00:1122/64 scope link
    inet6 2001:db8:9:10::30/112 scope global
    inet6 2001:db8:9:10::11/112 scope global
```

Do not forget to remove the /64 prefixes from `eth0`, as coded above.

You can now run `6bed4router` without further problems.

## Poorly Configured Upstreams

Now that you are running a router, you may be assuming that your uplink
does, too.  This may not always be true.  For instance:

  * You may be running the `6bed4router` on an ethernet LAN
  * Your upstream may not be configured with your link-local address
    for your IPv6 range

In these cases, you may be subjected to Neighbor Solicitation requests
for the various IPv6 addresses that make up 6bed4.  This is a pitty, as
the variety of addresses may be a bit much for the upstream.  So if you
can, tell your upstream to do something like

```
shell$ ip -6 route add 2001:db9:9:10::/64 via fe80::aa:bb:cc:ff:fe::dd:ee:ff/64 dev eth0
```

If this is not an option, for instance because the router is managed
by another party that does not respond to such inquiries, you may have to
[Proxy Neighbor Discovery](https://github.com/DanielAdolfsson/ndppd/)
instead.  Once it runs, your connections should magically come alive.

