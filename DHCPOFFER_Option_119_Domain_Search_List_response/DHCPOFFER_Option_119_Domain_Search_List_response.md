# BusyBox udhcpc: DNS Search Domain Hijacking via DHCP Option 119

## 1. Summary

BusyBox udhcpc unconditionally accepts and writes DNS search domains provided via DHCP Option 119 (Domain Search List, RFC 3397) into `/etc/resolv.conf`. A rogue DHCP server on the same Layer 2 segment can inject attacker-controlled domain search suffixes into the victim's resolver configuration. Once written, all short/relative hostname lookups are appended with the attacker's domain suffixes.

This differs from DNS server hijacking (Option 6) in that:
- The DNS server IP remains unchanged
- Only bare/short hostnames are affected (FQDNs are unaffected)
- DHCP monitoring tools that check for rogue DNS servers typically do not check for search domain changes

Verified on BusyBox udhcpc 1.36.1 (Alpine 3.19). The malicious search domains are written directly to `/etc/resolv.conf` via the udhcpc default script.

## 2. Affected Software

| Software | Version Tested | Result |
|----------|---------------|--------|
| **BusyBox udhcpc** | 1.36.1 (Alpine 3.19) | Malicious search domains written to `/etc/resolv.conf` |

All versions of udhcpc that support the `search` option (Option 119 / RFC 3397) are expected to be affected. Given BusyBox's widespread deployment in embedded systems, IoT devices, and containers, the potential impact scope is significant.

## 3. Vulnerability Details

### 3.1 Attack Flow

1. Victim's udhcpc sends a broadcast DHCPDISCOVER or DHCPREQUEST
2. Attacker on the same L2 segment responds with a forged DHCPACK containing:
   - Option 119 with attacker-controlled search domains (e.g., `corp.evil.com`, `evil.internal`)
   - Option 6 set to the **legitimate** DNS server IP (to avoid detection)
3. udhcpc passes the search domains to its default script (`/usr/share/udhcpc/default.script`)
4. The script writes them to `/etc/resolv.conf` as `search` entries
5. All short hostname lookups now append the attacker's domains

### 3.2 Distinction from CVE-2020-7461

CVE-2020-7461 is a heap buffer overflow in FreeBSD's dhclient when parsing Option 119 — a memory safety bug. This report describes a different issue: udhcpc correctly parses Option 119 per RFC 3397, but the default script unconditionally trusts and applies the search domains from unauthenticated DHCP responses.

### 3.3 Relation to CVE-2024-3661 (TunnelVision)

CVE-2024-3661 demonstrated DHCP Option 121 (Classless Static Routes) injection. This is the same attack class — unauthenticated DHCP option injection — but targets a different option (119 vs 121) and attack surface (DNS resolution vs routing).

## 4. Verified Results

### Test Environment

- Rogue DHCP server: Scapy (Python 3) on shared L2 segment (Docker bridge 10.100.0.0/24)
- Injected Option 119 domains: `corp.evil.com`, `evil.internal`

### udhcpc 1.36.1 Output

```
udhcpc: broadcasting discover
udhcpc: broadcasting select for 10.100.0.50, server 10.100.0.2
udhcpc: lease of 10.100.0.50 obtained from 10.100.0.2, lease time 300
[udhcpc-script] === DHCP lease bound on eth0 ===
[udhcpc-script]   IP:      10.100.0.50/24
[udhcpc-script]   Router:  10.100.0.1
[udhcpc-script]   DNS:     10.100.0.2
[udhcpc-script]   Domain:  legit.local
[udhcpc-script]   Search:  corp.evil.com evil.internal
```

System configuration:
```
$ cat /etc/resolv.conf
search corp.evil.com evil.internal
nameserver 10.100.0.2
```

The DNS server IP remained legitimate (`10.100.0.2`), while the attacker's search domains were applied.

## 5. Security Impact

- All short hostname lookups (`intranet`, `mail`, `repo`) resolve via attacker-controlled domains
- The effect persists for the entire DHCP lease duration
- Every application on the device is affected
- Particularly impactful for embedded/IoT devices running BusyBox, which often lack additional security layers
- The DNS server IP is unchanged, making this harder to detect than Option 6 hijacking

## 6. Suggested Mitigations

1. **Search domain change notification**: The default udhcpc script could log a warning when search domains change compared to the previous lease
2. **Search domain pinning**: Provide a mechanism (e.g., a configuration variable in the script) to ignore DHCP-provided search domains when static search domains are configured
3. **Search domain validation**: Optionally validate that provided search domains match a configured allowlist
4. **Documentation**: Note in BusyBox documentation that DHCP-provided search domains are applied without validation

## 7. Reproduction

### Steps

```bash
docker compose up -d

docker cp DHCPOFFER_Option_119_Domain_Search_List_response/rogue_dns_search.py \
    rogue-dhcp-server:/poc/

docker exec rogue-dhcp-server bash -c \
    'cd /poc && python3 rogue_dns_search.py 30 10.100.0.2' &
sleep 3

docker exec client-udhcpc sh -c \
    'ip addr flush dev eth0 && udhcpc -i eth0 -f -v -S -O search -n -q'

docker exec client-udhcpc cat /etc/resolv.conf
# Expected: search corp.evil.com evil.internal
```

### Files

| File | Description |
|------|-------------|
| `rogue_dns_search.py` | Scapy-based rogue DHCP server injecting Option 119 |
| `run_poc.sh` | Orchestration script |
| `logs/dhcp_client-udhcpc.log` | udhcpc client output |
| `logs/rogue_client-udhcpc.log` | Rogue server log |
| `logs/opt119_client-udhcpc.pcap` | Packet capture |

## 8. References

- RFC 2131: Dynamic Host Configuration Protocol
- RFC 3397: Dynamic Host Configuration Protocol (DHCP) Domain Search Option
- RFC 1035: Domain Names — Implementation and Specification
- CVE-2020-7461: FreeBSD dhclient Option 119 heap overflow (different vulnerability class)
- CVE-2024-3661: TunnelVision — DHCP Option 121 routing injection (same attack class, different option)
