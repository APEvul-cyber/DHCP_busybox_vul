# BusyBox udhcpc: Hidden Option Injection via DHCP Option 52 (Overload) sname Field

## 1. Summary

BusyBox udhcpc fully implements DHCP Option 52 (Option Overload, RFC 2131 §4.1), parsing and applying DHCP options encoded in the BOOTP `sname` field when instructed to do so by Option 52. A rogue DHCP server can exploit this to deliver network configuration (DNS server, default gateway, domain name) hidden in the `sname` field rather than the standard DHCP options area.

This creates a practical concern: DHCP security monitoring tools (snooping, IDS/IPS) that only inspect the standard options area will not detect the injected configuration. The standard options area of the attack packet appears benign (no DNS, no router, no domain), while the actual malicious configuration is encoded in the `sname` field.

Verified on BusyBox udhcpc 1.36.1 (Alpine 3.19). DNS server, router, and domain name encoded in the overloaded `sname` field were fully parsed, applied to system configuration, and written to `/etc/resolv.conf`.

## 2. Affected Software

| Software | Version Tested | Result |
|----------|---------------|--------|
| **BusyBox udhcpc** | 1.36.1 (Alpine 3.19) | Options from overloaded sname parsed and applied to `/etc/resolv.conf` and system routing |

All versions of udhcpc implementing RFC 2131 §4.1 Option Overload are expected to be affected.

## 3. Vulnerability Details

### 3.1 Mechanism

When a DHCPACK includes Option 52 = 2 ("sname field contains DHCP options"), udhcpc:
1. Detects Option 52 in the standard options area
2. Parses the 64-byte `sname` field as an additional DHCP options area
3. Merges the options found in sname with those from the standard area
4. Applies all merged options to system configuration

A rogue DHCP server can place critical network configuration exclusively in the `sname` field:

| Standard Options Area (visible to monitoring) | Overloaded sname (invisible to most monitoring) |
|-----------------------------------------------|--------------------------------------------------|
| Option 53 = ACK | Option 6 = attacker DNS |
| Option 54 = server ID | Option 3 = attacker gateway |
| Option 51 = lease time | Option 15 = attacker domain |
| Option 1 = subnet mask | Option 255 = end |
| Option 52 = 2 (overload) | |
| No DNS, no router, no domain | |

### 3.2 Why This Is Concerning

- Legitimate use of Option 52 is very rare in modern networks
- Most DHCP monitoring and security tools do not parse sname/file as options areas even when Option 52 is present
- The standard options area of the attack packet looks like an incomplete but not malicious DHCP response
- udhcpc's widespread deployment in embedded/IoT/container environments amplifies the impact

## 4. Verified Results

### 4.1 Option Overload (Option 52 = 2)

Injected options in sname field (hex):
```
06 04 0a640002              → Option 6  (DNS Server)    = 10.100.0.2
03 04 0a640002              → Option 3  (Router)        = 10.100.0.2
0f 09 6576696c2e636f7270    → Option 15 (Domain Name)   = evil.corp
ff                          → Option 255 (End)
```

udhcpc output:
```
[udhcpc-script]   Router:  10.100.0.2       ← from overloaded sname
[udhcpc-script]   DNS:     10.100.0.2       ← from overloaded sname
[udhcpc-script]   Domain:  evil.corp        ← from overloaded sname
[udhcpc-script]   Boot:    sname=           ← sname consumed as options
```

System configuration:
```
$ cat /etc/resolv.conf
search evil.corp
nameserver 10.100.0.2
```

All three options (DNS, router, domain) were parsed from the overloaded sname and applied.

### 4.2 sname as PXE Server Hostname (Option 52 absent, for reference)

When Option 52 is not present, the sname field carries its normal BOOTP meaning:
```
[udhcpc-script]   Boot:    file= siaddr=10.100.0.2 sname=evil-pxe.attacker.local
```

udhcpc accepted the attacker-controlled server hostname.

## 5. Security Impact

| Scenario | Description |
|----------|-------------|
| DNS hijack | Attacker DNS in sname → all name resolution controlled |
| Gateway hijack | Attacker router in sname → all traffic intercepted (MitM) |
| Domain suffix | Attacker domain in sname → short hostname phishing |
| Combined | Multiple options fit in 64 bytes → full network config takeover |

The monitoring evasion aspect makes this particularly concerning: an attacker can perform DNS and gateway hijacking while evading DHCP-layer security tools.

## 6. Suggested Mitigations

1. **Log Option 52 usage**: When Option Overload is detected, log it as a notable event — legitimate use is extremely rare
2. **Conflict detection**: If options in the overloaded sname conflict with options in the standard area, prefer the standard area values or warn
3. **Configuration option to disable overload**: Allow administrators to disable Option 52 processing in security-sensitive deployments
4. **Documentation**: Note in BusyBox documentation that Option 52 processing can be used to deliver hidden configuration

## 7. Reproduction

### Steps

```bash
docker compose up -d

docker cp DHCPOFFER_sname_response/rogue_sname_server.py \
    rogue-dhcp-server:/poc/

# Option Overload test (Case B)
docker exec rogue-dhcp-server bash -c \
    'cd /poc && python3 rogue_sname_server.py 20 10.100.0.2 B' &
sleep 3

docker exec client-udhcpc sh -c \
    'ip addr flush dev eth0 && udhcpc -i eth0 -f -v -S -O search -n -q'

docker exec client-udhcpc cat /etc/resolv.conf
# Expected: search evil.corp / nameserver 10.100.0.2
```

### Files

| File | Description |
|------|-------------|
| `rogue_sname_server.py` | Scapy-based rogue server (mode A: sname hostname, mode B: Option Overload) |
| `run_poc.sh` | Orchestration script |
| `logs/dhcp_caseA.log` | Case A client output |
| `logs/dhcp_caseB.log` | Case B client output |
| `logs/rogue_caseA.log` | Rogue server log (Case A) |
| `logs/rogue_caseB.log` | Rogue server log (Case B) |
| `logs/sname_caseA.pcap` | Packet capture (Case A) |
| `logs/sname_caseB.pcap` | Packet capture (Case B) |

## 8. References

- RFC 2131 §4.1: Dynamic Host Configuration Protocol — Option Overloading
- RFC 2132 §9.3: DHCP Options — Option 52 (Option Overload)
- CVE-2024-3661: TunnelVision — DHCP Option 121 routing injection (same attack class)

## 9. Related Reports

- **This repository**: https://github.com/APEvul-cyber/DHCP_busybox_vul
- Option 52 detection gap — Snort: https://github.com/APEvul-cyber/DHCP_snort_vul
- Option 52 detection gap — Suricata: https://github.com/APEvul-cyber/DHCP_suricata_vul
- Option 119 search domain hijack (also in this repo): https://github.com/APEvul-cyber/DHCP_busybox_vul/tree/main/DHCPOFFER_Option_119_Domain_Search_List_response
