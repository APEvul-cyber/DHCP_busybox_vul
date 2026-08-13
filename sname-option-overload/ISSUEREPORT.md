# udhcpc: Option 52 overload from `sname` is applied with no log

RFC 2131 Option 52=2: parse `sname` as options. udhcpc 1.36.1 does this. DNS/router/domain in `sname` land in `/etc/resolv.conf`.

Please log Option 52 (it is rare) and consider a compile/runtime switch to ignore overload.

PoC: `rogue_sname_server.py` mode B.