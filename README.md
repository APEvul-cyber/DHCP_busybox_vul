# DHCP_busybox_vul

| Dir | Issue |
|---|---|
| `sname-option-overload` | udhcpc applies DHCP options from BOOTP `sname` when Option 52=2 (RFC 2131). IDS that only parse the options area miss this. |