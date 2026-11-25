# IPv6 Neighbor Discovery Responder

`ndpresponder` listens for ICMPv6 Neighbor Solicitations on a specified interface. It responds with a Neighbor Advertisement when the solicitation target falls within one of the configured IPv6 subnets.

## Usage

```bash
sudo ndpresponder -i eth0 -n 2001:db8:1234::/64
```

- `-i` selects the network interface.
- `-n` specifies an IPv6 subnet to answer for. Repeat `-n` to add more subnets.
