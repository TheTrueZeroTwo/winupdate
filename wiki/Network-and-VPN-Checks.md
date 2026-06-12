# Network and VPN Checks

Use menu option **Network/VPN connectivity check** when a user can connect to the internet but cannot reach a VPN, RDP host, domain controller, file share, printer, or line-of-business service.

The script asks for IPs or hostnames. Good targets include:

- VPN gateway IP or DNS name;
- firewall LAN IP;
- domain controller IP;
- file server IP;
- RDP host IP;
- printer IP;
- known public IP such as `1.1.1.1`;
- a public DNS name such as `microsoft.com`.

The check reviews active adapters, VPN-like adapters, IP configuration, default routes, DNS servers, ICMP ping, common TCP ports, and optional trace route output.

Useful port examples:

- `443` for HTTPS/VPN portals;
- `3389` for RDP;
- `445` for SMB/file shares;
- `53` for DNS;
- `80` for HTTP fallback testing.
