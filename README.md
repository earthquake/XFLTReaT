# XFLTReaT #
This is just one thing of many things that was missing from the Internet. If you got tired of trying several tunnelling tools for each protocols, this must be your ~~tool~~^W framework.

### Available modules ###

* TCP
* UDP
* ICMP
* SOCKS v4, 4a, 5
* HTTP CONNECT

### Setup ###
* \# git clone https://bitbucket.org/eqarmada/xfltreat/
* \# pip install -r requirements.txt
* \# edit xfltreat.conf
* \# server side: python xfltreat.py
* \# client side: python xfltreat.py --client

### Set up your linux box as a server ###
Enable IP forwarding as **root** by using either:  
\# sysctl -w net.ipv4.ip_forward=1  
or  
\# echo 1 > /proc/sys/net/ipv4/ip_forward  

then set up iptables to do the NAT'ing for you:  
\# iptables -t nat -A POSTROUTING –s 10.9.0.0/24 -o eth0 -j MASQUERADE

### a few things to note ###
* python 2.7
* Linux only
* root privs needed

### side notes to expand ##
* server and check functionality can handle all modules enabled in the config.
* client should have only one enabled.