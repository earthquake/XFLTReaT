# MIT License

# Copyright (c) 2017 Balazs Bucsay

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

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

	# allocating tunnel, clonde device and name it
	def tun_alloc(self, dev, flags):
		try:
			tun = os.open(Interface.CLONEDEV, os.O_RDWR|os.O_NONBLOCK, 0)
			ifr = struct.pack('16sH', dev, flags)
			fcntl.ioctl(tun, self.TUNSETIFF, ifr)

		except IOError:
			common.internal_print("Error: Cannot create tunnel. Is {0} in use?".format(dev), -1)
			sys.exit(-1)
		
		return tun

	# setting MTU on the interface
	def set_mtu(self, dev, mtu):
		s = socket.socket(type=socket.SOCK_DGRAM)
		ifr = struct.pack('<16sH', dev, mtu) + '\x00'*14
		try:
			ifs = fcntl.ioctl(s, self.SIOCSIFMTU, ifr)
		except Exception, s:
			common.internal_print("Cannot set MTU ({0}) on interface".format(mtu), -1)
			sys.exit(-1)

		return

	# setting IP address + netmask on the interface
	def set_ip_address(self, dev, ip, netmask):
		idx = self.ip.link_lookup(ifname=dev)[0]
		self.ip.addr('add', index=idx, address=ip, mask=int(netmask))
		self.ip.link('set', index=idx, state='up')

		return

	# closing tunnel file descriptor
	def close_tunnel(self, tun):
		try:
			os.close(tun)
		except:
			pass

		return

	# check if more than one or no default route is present
	def check_default_route(self):
	 	if len(self.ip.get_default_routes()) < 1:
			common.internal_print("No default route. Please set up your routing before executing the tool", -1)
			sys.exit(-1)
	 	if len(self.ip.get_default_routes()) > 1:
			common.internal_print("More than one default route. This should be reviewed before executing the tool.", -1)
			sys.exit(-1)	

	# automatic routing set up.
	# check for multiple default routes, if there are then print error message
	# - save default route address
	# - delete default route
	# - add default route, route all packets into the XFLTReaT interface
	# - last route: server IP address routed over the original default route
	def set_default_route(self, serverip, ip):
		#TODO tunnel thru a tunnel
		found = False
		routes = self.ip.get_routes()

		self.check_default_route()
		# looking for the the remote server in the route table
	 	for attrs in self.ip.get_default_routes()[0]['attrs']:
	 		if attrs[0] == "RTA_GATEWAY":
				self.orig_default_gw = attrs[1]

		for r in routes:
			i = -1
			j = -1
			for a in range(0, len(r["attrs"])):
				if r["attrs"][a][0] == "RTA_DST":
					i = a
				if r["attrs"][a][0] == "RTA_GATEWAY":
					j = a
			if (i > -1) and (j > -1):
				if (r["attrs"][i][1] == serverip) and (r["attrs"][j][1] == self.orig_default_gw):
					# remote server route was already added
					found = True

		self.ip.route('delete', gateway=self.orig_default_gw, dst="0.0.0.0")
		self.ip.route('add', gateway=ip, dst="0.0.0.0")
		if not found:
			# remote server route was not in the table, adding to it
			self.ip.route('add', gateway=self.orig_default_gw, dst=serverip, mask=32)
		
		return

	# setting up intermediate route
	# when the module needs an intermediate hop (DNS server, Proxy server)
	# then all encapsulated packet should be sent to the intermediate server
	# instead of the XFLTReaT server
	def set_intermediate_route(self, serverip, proxyip):
		common.internal_print("Changing route table for intermediate hop")
		self.ip.route('delete', gateway=self.orig_default_gw, dst=serverip, mask=32)
		self.ip.route('add', gateway=self.orig_default_gw, dst=proxyip, mask=32)

		return

	# restoring default route
	def restore_routes(self, serverip):
		common.internal_print("Restoring default route")
		self.ip.route('delete', gateway=self.orig_default_gw, dst=serverip, mask=32)
		self.ip.route('add', gateway=self.orig_default_gw, dst="0.0.0.0")

		return
