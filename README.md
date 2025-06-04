# dns-proxy
a tiny dns to socks5 tunnel program for transparent proxy.
it can be used as upstream server for dnsmasq in openwrt.
include Makefile for openwrt.
usage:
~~~
                        in gfwlist                             gfw
  dns request ->dnsmasq ----------> dns-proxy -> socks5 server ---> remove server ---> turst dns server(8.8.8.8 as default)--->add resolve back in to nftset/ipset
                        | not in gfwlist
                        |--------->  isp dns server

                 in nftset                                     gfw
  internet access -------->tproxy to ipt2socks -> socks5 server ---> remote server ---> internet
                 | not in gfwlist
                 |------->intranet
~~~
999-add-sem_clockwait.patch just add an clockwait semaphore function to musl. because almost all openwrt device don't have RTC, so NTP time sync may cause problem. 
just put the file into toolchain/musl/patches. or revert the commit to use sem_timewait.
