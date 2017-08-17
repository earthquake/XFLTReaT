# XFLTReaT #
This is just one thing of many things that was missing from the Internet. If you got tired of trying several tunnelling tools for each protocols, this must be your ~~tool~~^W framework.

### Available modules ###

* TCP
* UDP
* ICMP
* SOCKS v4, 4a, 5
* HTTP CONNECT
* DNS (A/CNAME, PRIVATE, NULL) - Proof of Concept

### Available versions ###

At the moment there are two different branches of the framework. The master branch is a somewhat stable version (v0.1) without the DNS module. The other branch is called next-version and that has the newer version (v0.2), which includes DNS support for a few records (A/CNAME, PRIVATE, NULL). This branch has not been tested thoroughly yet, please respect that before making an opinion about the source code and framework.

To have a somewhat stable release (without DNS), please use:
\# git clone https://github.com/earthquake/xfltreat/

To get the DNS support from the next version branch (which was not tested thoroughly, please keep that in mind):
\# git clone https://github.com/earthquake/xfltreat/
\# cd xfltreat
\# git checkout -b next-version v0.2
To configure DNS please check the DNS_notes.md.

### Setup ###
* \# git clone https://github.com/earthquake/xfltreat/
* \# pip install -r requirements.txt
* edit xfltreat.conf
* \# server side: python xfltreat.py
* \# client side: python xfltreat.py --client

### Set up your linux box as a server ###
Enable IP forwarding as **root** by using either:  
\# sysctl -w net.ipv4.ip_forward=1  
or  
\# echo 1 > /proc/sys/net/ipv4/ip_forward  

then set up iptables to do the NAT'ing for you:  
\# iptables -t nat -A POSTROUTING â€“s 10.9.0.0/24 -o eth0 -j MASQUERADE

### a few things to note ###
* python 2.7
* Linux only
* root privs needed

### side notes to expand ##
* server and check functionality can handle all modules enabled in the config.
* client should have only one enabled.

### DISCLAMER ###
The tool is not yet production grade, edge cases (and not that edge cases) are might not handled very well. There can be security issues in the code that has not been fixed. In case you manage to identify any, please contact me in private or create an issue on the Github page. 
Mail: xfltreat _at_ rycon.hu
