This is regular hping2 with a few extra features:

* `-6` - required for ipv6 destinations
* `--pps`
* `--bps` - set outgoing pps/bps rates. Return packets are not processed in these modes.

Example:

    root@koszik-vps:~# ./hping6 ns1.atw.hu -6 -2 -p 53 -k  -s 1583 --traceroute
    HPING ns1.atw.hu (eth0 2a01:270:0:2::11): udp mode set, 48 headers + 0 data bytes
    hop=1 TTL 0 during transit from ip=2a00:1f40:2::1 name=2a00-1f40-2--1.pool6.giganet.hu hoprtt=0.9 ms
    hop=2 TTL 0 during transit from ip=2a00:1f40:1:bb00::2:1 name=UNKNOWN hoprtt=1005.7 ms
    hop=3 TTL 0 during transit from ip=2001:7f8:35::2:9278:2 name=UNKNOWN hoprtt=2011.2 ms
    hop=4 TTL 0 during transit from ip=2a02:730:c:b01:b03:0:1:1 name=UNKNOWN hoprtt=3006.7 ms
    hop=5 TTL 0 during transit from ip=2a01:270:c:c04:103::1 name=UNKNOWN hoprtt=4007.1 ms
    hop=6 TTL 0 during transit from ip=2a01:270:c:c02:c04::1 name=UNKNOWN hoprtt=5007.7 ms
    hop=7 TTL 0 during transit from ip=2a01:270:c:106::42 name=UNKNOWN hoprtt=6007.3 ms
    ^C
    --- ns1.atw.hu hping statistic ---
    12 packets transmitted, 7 packets received, 42% packet loss
    round-trip min/avg/max = 0.9/3006.7/6007.3 ms
