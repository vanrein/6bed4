IPv6-only networks: Add NAT64, DNS64 and 6bed4

> *Imagine a new server setup with only IPv6.  Less complexity,
> plenty of address space, global uniqueness and not the dual
> nature that confuses debugging.  But how to deal with IPv4
> clients?*


There are a few translation mechanisms for IPv4/IPv6, and the
stateless translation of address headers with NAT64 is perhaps
the simplest.  Generally put, IPv4 addresses receive a /96
prefix that makes them into IPv6 addresses, and local routing
brings traffic back to the NAT64 router for translating back
and delivery over IPv4 of the response.

NAT64 works in conjunction with DNS64, which translates A
query output to AAAA query output (if no direct addresses are
usable).  The /96 prefix used there is set to the same value
as the one added by NAT64, so the forged AAAA records pass
out through the translator and end up in the right IPv4
address.  DNS64 conflicts with DNSSEC, but its mapping may
be applied after secure query processing.

Given the small space available in IPv4, there are likely to
be more multiplexing mechanisms, such as based on SRV records,
hostnames such as in HTTP or Server Name Indications such as
in TLS.  This may be done after the translation by NAT64 into
the IPv6 space, so redirection can be made to one of the many
addresses then available.

IPv4 does need NAT, and certainly on clients it is commonly
employed.  This means that port numbers can change between
the client and server end points, and so peer-to-peer traffic
is not as reliable as on IPv6, where addresses and ports are
transparant, and only firewall-based filtering is used.
This gives much more reliable peer-to-peer performance, and
is preferred for the more advanced use cases.

NAT64 will not be helpful for such situations, but 6bed4 is.
The ability to send an IPv6 address in end-to-end communication,
based on prior contact to a server, should help to build up
reliable communication even if it actually runs over IPv4 and
UDP.  The UDP port will not get renumbered; if that is the only
option, the 6bed4 system falls back to relaying through the
server that originally saw the IPv4 address and UDP port.  This
would be rare, but it is a reassurance that it exists.  With
6bed4 it should therefore be possible to engage in full-blown
peer-to-peer operations, and almost always enjoy the benefits
of direct communication between the peers.

In a scenario where a server employs NAT64 and 6bed4 service
at the entrance, this is even more straightforward, as the
6bed4 service would use its own IPv4 address in its endpoint
address, and mention it again in the low half to hint that
direct contact is the proper mechanism to use.  The peering
does get possible when the protocol connects parties that
connect through these addresses, but if it fails then the
server will be available for bouncing traffic between peers.

DNS64 plays no role in the 6bed4 scenario.  Servers that
exhibit 6bed4 service announce their IPv6 address for the
6bed4 service end point as an AAAA record.

**Summary:** NAT64+DNS64 is useful for backward compatibility
with client-server mode; for peer-to-peer operation however,
6bed4 is a more reliable form.  Clients can upgrade to the
more reliable service by installing the 6bed4peer, but they
are free to try a service without that explicit action.

