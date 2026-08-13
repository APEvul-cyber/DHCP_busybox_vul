# udhcpc writes rogue DHCP Option 119 into resolv.conf

A rogue ACK with Option 119 (Option 6 left legit) becomes `search` in `/etc/resolv.conf`. Short names append the attacker suffix.

## Reproduce

`rogue_dns_search.py`.

**Expected:** do not apply Option 119 unless the user asked for it.

https://github.com/APEvul-cyber/DHCP_busybox_vul/tree/main/option-119-search
