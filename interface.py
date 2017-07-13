import sys

if "interface.py" in sys.argv[0]:
	print "[-] Instead of poking around just try: python xfltreat.py --help"
	sys.exit(-1)


import socket
import struct
import fcntl
import time
import os

import pyroute2

import common

class Interface():

	ip = pyroute2.IPRoute()

	IFF_TUN = 0x0001
	IFF_TAP = 0x0002
	IFF_NO_PI = 0x1000

	CLONEDEV = "/dev/net/tun"
	TUNSETIFF = 0x400454ca
	SIOCSIFADDR = 0x8916
	SIOCSIFNETMASK = 0x891C
	SIOCSIFMTU = 0x8922

	orig_default_gw = None

	def tun_alloc(self, dev, flags):
		try:
			tun = os.open(Interface.CLONEDEV, os.O_RDWR|os.O_NONBLOCK, 0)
			ifr = struct.pack('16sH', dev, flags)
			fcntl.ioctl(tun, self.TUNSETIFF, ifr)

		except IOError:
			common.internal_print("Error: Cannot create tunnel. Is {0} in use?".format(dev), -1)
			sys.exit(-1)
		
		return tun

	def set_mtu(self, dev, mtu):
		s = socket.socket(type=socket.SOCK_DGRAM)
		ifr = struct.pack('<16sH', dev, mtu) + '\x00'*14
		try:
			ifs = fcntl.ioctl(s, self.SIOCSIFMTU, ifr)
		except Exception, s:
			common.internal_print("Cannot set MTU ({0}) on interface".format(mtu), -1)
			sys.exit(-1)

		return

	def set_ip_address(self, dev, ip, netmask):
		idx = self.ip.link_lookup(ifname=dev)[0]
		self.ip.addr('add', index=idx, address=ip, mask=int(netmask))
		self.ip.link('set', index=idx, state='up')

		return

	def close_tunnel(self, tun):
		try:
			os.close(tun)
		except:
			pass

		return

	def set_default_route(self, serverip, ip):
		'''
		TODO
	 	awfully choose the first of the default routes and don't care 
	 	about the rest. This could lead to serious problems.
	 	'''
	 	for attrs in self.ip.get_default_routes()[0]['attrs']:
	 		if attrs[0] == "RTA_GATEWAY":
				self.orig_default_gw = attrs[1]
		self.ip.route('delete', gateway=self.orig_default_gw, dst="0.0.0.0")
		self.ip.route('add', gateway=ip, dst="0.0.0.0")
		self.ip.route('add', gateway=self.orig_default_gw, dst=serverip, mask=32)
		
		return

	def set_proxy_route(self, serverip, proxyip):
		common.internal_print("Changing route table for proxy")
		self.ip.route('delete', gateway=self.orig_default_gw, dst=serverip, mask=32)
		self.ip.route('add', gateway=self.orig_default_gw, dst=proxyip, mask=32)

	def restore_routes(self, serverip):
		common.internal_print("Restoring default route")
		self.ip.route('delete', gateway=self.orig_default_gw, dst=serverip, mask=32)
		self.ip.route('add', gateway=self.orig_default_gw, dst="0.0.0.0")

		return
