# BusyBox udhcpc applies DHCP Option 119 search domains from a rogue server

**Affected:** BusyBox udhcpc 1.36.1 (Alpine 3.19); default script writes `search` to `/etc/resolv.conf`.  
**CWE:** CWE-345

Option 119 (RFC 3397) is applied unconditionally. A rogue DHCPACK can keep Option 6 (real DNS) and still inject search suffixes. Short names append the attacker domain.

Same class as TunnelVision (CVE-2024-3661). udhcpc implements the option; attackers on L2 use it.

**Impact:** relative lookups (`www`, `vpn`, `ntp`) go to attacker-controlled FQDNs. Option 6 monitors miss it.

## Reproduce

`rogue_dns_search.py` / `run_poc.sh`.

**Actual:** `/etc/resolv.conf` contains the rogue `search` list.  
**Expected:** ignore Option 119 unless configured; or require a static search list.

## Fix

Do not write DHCP search by default on untrusted L2. Document Option 119 as equivalent risk to Option 6 / 121.

## References

- RFC 3397
- CVE-2024-3661
- https://github.com/APEvul-cyber/DHCP_busybox_vul/tree/main/option-119-search
