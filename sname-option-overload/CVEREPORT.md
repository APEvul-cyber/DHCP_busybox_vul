# BusyBox udhcpc applies Option 52 overload from `sname`

**Affected:** BusyBox udhcpc 1.36.1 (Alpine 3.19).  
**CWE:** CWE-20

RFC 2131 §4.1: Option 52=2 means the 64-byte `sname` field is more DHCP options. udhcpc does this and writes the result (DNS, router, domain) to `/etc/resolv.conf`.

That is spec-correct. The useful part: the standard options area can look empty of DNS/router while those values sit in `sname`. Snort/Suricata rules that only walk the options area after the magic cookie miss it.

Not a memory-safety bug. Report is for maintainers who want a log/disable switch, and as the client half of the IDS gap.

## Reproduce

Rogue DHCPACK: Option 52=2; Option 6/3/15 only in `sname`. See `rogue_sname_server.py` mode B.

**Actual:** `resolv.conf` has the attacker DNS/search.  
**Expected (hardening):** log Option 52; optional ignore-overload.

## References

- RFC 2131 §4.1, RFC 2132 §9.3
- https://github.com/APEvul-cyber/DHCP_snort_vul
- https://github.com/APEvul-cyber/DHCP_suricata_vul
- https://github.com/APEvul-cyber/DHCP_busybox_vul/tree/main/sname-option-overload
