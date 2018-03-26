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
# For the Windows support credit goes to: Thomas Watteyne @thomaswatteyne
# https://openwsn.atlassian.net/wiki/spaces/OW/pages/5373971/tun+tap+in+Windows

import sys

if "interface.py" in sys.argv[0]:
	print("[-] Instead of poking around just try: python xfltreat.py --help")
	sys.exit(-1)


import socket
import struct
import time
import os
import subprocess

import common

class Interface():
	orig_default_gw = None

	def __init__(self):
		OSFP_table = {
		# OS type 			: [__init__(), tun_alloc(), set_ip_address(),
		#		set_mtu(), close_tunnel(), check_default_route(),
		#		set_default_route(), set_intermediate_route(), restore_routes()]
		common.OS_LINUX		: [self.lin_init, self.lin_tun_alloc,
			self.lin_set_ip_address, self.lin_set_mtu, self.lin_close_tunnel,
			self.lin_check_default_route, self.lin_set_default_route,
			self.lin_set_intermediate_route, self.lin_restore_routes,
			self.lin_set_split_route, self.lin_del_split_route],
		common.OS_MACOSX	: [self.mac_init, self.mac_tun_alloc,
			self.mac_set_ip_address, self.mac_set_mtu, self.mac_close_tunnel,
			self.mac_check_default_route, self.mac_set_default_route,
			self.mac_set_intermediate_route, self.mac_restore_routes,
			self.mac_set_split_route, self.mac_del_split_route],
		common.OS_WINDOWS	: [self.win_init, self.win_tun_alloc,
			self.win_set_ip_address, self.win_set_mtu, self.win_close_tunnel,
			self.win_check_default_route, self.win_set_default_route,
			self.win_set_intermediate_route, self.win_restore_routes,
			self.win_set_split_route, self.win_del_split_route],
		}
		os_type = common.get_os_type()
		if not (os_type in OSFP_table):
			common.internal_print("Your operating system is not supported yet. (interface.py)", -1)
			sys.exit(-1)

		# calling OS specific __init__()
		OSFP_table[os_type][0]()

		# replacing placeholders with OS specific calls

		# allocating tunnel, clonde device and name it
		self.tun_alloc 				= OSFP_table[os_type][1]
		# setting IP address + netmask on the interface
		self.set_ip_address 		= OSFP_table[os_type][2]
		# setting MTU on the interface
		self.set_mtu 				= OSFP_table[os_type][3]
		# closing tunnel file descriptor
		self.close_tunnel 			= OSFP_table[os_type][4]
		# check if more than one or no default route is present
		self.check_default_route 	= OSFP_table[os_type][5]
		# automatic routing set up.
		# check for multiple default routes, if there are then print error message
		# - save default route address
		# - delete default route
		# - add default route, route all packets into the XFLTReaT interface
		# - last route: server IP address routed over the original default route
		self.set_default_route 		= OSFP_table[os_type][6]
		# setting up intermediate route
		# when the module needs an intermediate hop (DNS server, Proxy server)
		# then all encapsulated packet should be sent to the intermediate server
		# instead of the XFLTReaT server
		self.set_intermediate_route = OSFP_table[os_type][7]
		# restoring default route
		self.restore_routes 		= OSFP_table[os_type][8]
		# set split routes
		self.set_split_route 		= OSFP_table[os_type][9]
		# del split routes
		self.del_split_route 		= OSFP_table[os_type][10]


	# LINUX #########################################################
	IFF_TUN = 0x0001
	IFF_TAP = 0x0002
	IFF_NO_PI = 0x1000

	LINUX_CLONEDEV = "/dev/net/tun"
	IOCTL_LINUX_TUNSETIFF = 0x400454ca
	IOCTL_LINUX_SIOCSIFADDR = 0x8916
	IOCTL_LINUX_SIOCSIFNETMASK = 0x891C
	IOCTL_LINUX_SIOCSIFMTU = 0x8922

	IOCTL_MACOSX_SIOCSIFADDR = 0x8020690c
	IOCTL_MACOSX_SIOCSIFNETMASK = 0x80206916
	IOCTL_MACOSX_SIOCSIFMTU = 0x80206934
	IOCTL_MACOSX_SIOCSIFFLAGS = 0x80206910
	IOCTL_MACOSX_SIOCAIFADDR = 0x8040691A


	# __init__()
	def lin_init(self):
		global pyroute2
		global fcntl

		import pyroute2
		import fcntl
		self.ip = pyroute2.IPRoute()

	def lin_tun_alloc(self, dev, flags):
		try:
			tun = os.open(Interface.LINUX_CLONEDEV, os.O_RDWR|os.O_NONBLOCK, 0)
			ifr = struct.pack('16sH', dev, flags)
			fcntl.ioctl(tun, self.IOCTL_LINUX_TUNSETIFF, ifr)

		except IOError:
			common.internal_print("Error: Cannot create tunnel. Is {0} in use?".format(dev), -1)
			sys.exit(-1)

		return tun

	def lin_set_ip_address(self, dev, ip, serverip, netmask):
		idx = self.ip.link_lookup(ifname=dev)[0]
		self.ip.addr('add', index=idx, address=ip, mask=int(netmask))
		self.ip.link('set', index=idx, state='up')

		return

	def lin_set_mtu(self, dev, mtu):
		s = socket.socket(type=socket.SOCK_DGRAM)
		try:
			ifr = struct.pack('<16sH', dev, mtu) + '\x00'*14
			fcntl.ioctl(s, self.IOCTL_LINUX_SIOCSIFMTU, ifr)
		except Exception as e:
			common.internal_print("Cannot set MTU ({0}) on interface".format(mtu), -1)
			sys.exit(-1)

		return

	def lin_close_tunnel(self, tun):
		try:
			os.close(tun)
		except:
			pass

		return

	def lin_check_default_route(self):
		if len(self.ip.get_default_routes()) < 1:
			common.internal_print("No default route. Please set up your routing before executing the tool", -1)
			sys.exit(-1)
		if len(self.ip.get_default_routes()) > 1:
			common.internal_print("More than one default route. This should be reviewed before executing the tool.", -1)
			sys.exit(-1)

		return

	def lin_set_default_route(self, serverip, clientip, ip):
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
			try:
				self.ip.route('add', gateway=self.orig_default_gw, dst=serverip, mask=32)
			except:
				common.internal_print("Error: Something is not quite right with your route table. Please check.", -1)
				sys.exit(-1)

		return

	def lin_set_intermediate_route(self, serverip, proxyip):
		common.internal_print("Changing route table for intermediate hop")
		self.ip.route('delete', gateway=self.orig_default_gw, dst=serverip, mask=32)
		self.ip.route('add', gateway=self.orig_default_gw, dst=proxyip, mask=32)

		return

	def lin_restore_routes(self, serverip, clientip, ip):
		common.internal_print("Restoring default route")
		self.ip.route('delete', gateway=self.orig_default_gw, dst=serverip, mask=32)
		self.ip.route('add', gateway=self.orig_default_gw, dst="0.0.0.0")

		return

	def lin_set_split_route(self, scope, ip):
		for entry in scope:
			self.ip.route('add', gateway=ip, dst=entry[0], mask=int(entry[2]))

		return

	def lin_del_split_route(self, scope, ip):
		return


	# MAC OS (X) ####################################################
	MACOS_UTUN_CONTROL_NAME = "com.apple.net.utun_control"
	MACOS_PF_SYSTEM = 32
	MACOS_AF_SYSTEM = 32
	MACOS_SYSPROTO_CONTROL = 2
	MACOS_AF_SYS_CONTROL = 2
	MACOS_UTUN_OPT_IFNAME = 2
	MACOS_MAX_KCTL_NAME = 96
	MACOS_CTLIOCGINFO = 0xc0644e03
	MACOS_temp = None # TODO, do we really need to declare this?

	# __init__()
	def mac_init(self):
		global fcntl
		import fcntl

	def mac_tun_alloc(self, dev, flags):
		'''
		# before utun, tun/tap driver had to be used. utun support was
		# added to MacOS 10.7+ so there is no need for tun/tap ext.
		if common.get_os_release() == '13.4.0':
			#TODO loop to look for an interface that is not busy
			for i in range(0, 16):
				self.iface_name = "tun{0}".format(i)
				try:
					tun = os.open("/dev/"+self.iface_name, os.O_EXCL|os.O_RDWR, 0)
					print tun
				except Exception as exception:
					if exception.args[0] == 16:
						continue
					else:
						print exception
						sys.exit(-1)
				break
		else:
		'''
		# MacOS utun support
		# direct calls to libc are needed, because otherwise it could not
		# done.
		import ctypes
		import ctypes.util

		self.iface_name = "\x00"*10
		libc_name = ctypes.util.find_library('c')
		libc = ctypes.CDLL(libc_name, use_errno=True)

		# special socket to poke MacOS(X)' soul
		s = socket.socket(self.MACOS_PF_SYSTEM, socket.SOCK_DGRAM, self.MACOS_SYSPROTO_CONTROL)

		# magic to make utun alive
		info = struct.pack("<I{0}s".format(self.MACOS_MAX_KCTL_NAME), 0, self.MACOS_UTUN_CONTROL_NAME)
		ctl_id = struct.unpack("<I{0}s".format(self.MACOS_MAX_KCTL_NAME), fcntl.ioctl(s, self.MACOS_CTLIOCGINFO, info))[0]

		# setting up the address, because the python lib does not
		# support this type of address type...
		# setting the interface number to 0 to let the kernel allocate
		addr = struct.pack("<BBHIIIIIIII", 32, self.MACOS_AF_SYSTEM, self.MACOS_AF_SYS_CONTROL, ctl_id, 0, 0, 0, 0, 0, 0, 0)
		err = libc.connect(s.fileno(), addr, 32)
		if err < 0:
			err = ctypes.get_errno()
			raise OSError(err, os.strerror(err))

		# get interface name into the self.iface_name
		err = libc.getsockopt(s.fileno(), self.MACOS_SYSPROTO_CONTROL, self.MACOS_UTUN_OPT_IFNAME, ctypes.c_char_p(self.iface_name), ctypes.byref(ctypes.c_int(10)))
		if err < 0:
			err = ctypes.get_errno()
			raise OSError(err, os.strerror(err))

		# setting flags on interface/fd
		fcntl.fcntl(s, fcntl.F_SETFL, os.O_NONBLOCK)
		fcntl.fcntl(s, fcntl.F_SETFD, fcntl.FD_CLOEXEC)

		# saving the socket, otherwise it will be destroyed. with the iface
		self.MACOS_temp = s
		return s.fileno()

	def mac_set_ip_address(self, dev, ip, serverip, netmask):
		ifr = struct.pack('<16sBBHIIIBBHIIIBBHIII',
			self.iface_name,
			16, socket.AF_INET, 0, struct.unpack('<L', socket.inet_pton(socket.AF_INET, ip))[0], 0, 0,
			16, socket.AF_INET, 0, struct.unpack('<L', socket.inet_pton(socket.AF_INET, serverip))[0], 0, 0,
			16, 0, 0, struct.unpack('<L', socket.inet_pton(socket.AF_INET, "255.255.255.255"))[0], 0, 0)
		try:
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			fcntl.ioctl(sock, self.IOCTL_MACOSX_SIOCAIFADDR, ifr)
		except Exception as e:
			common.internal_print("Something went wrong with setting up the interface.", -1)
			print(e)
			sys.exit(-1)

		# adding new route for forwarding packets properly.
		integer_ip = struct.unpack(">I", socket.inet_pton(socket.AF_INET, serverip))[0]
		rangeip = socket.inet_ntop(socket.AF_INET, struct.pack(">I", integer_ip & ((2**int(netmask))-1)<<32-int(netmask)))
		ps = subprocess.Popen(["route", "add", "-net", rangeip+"/"+netmask, serverip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		(stdout, stderr) = ps.communicate()
		if stderr:
			if not "File exists" in stderr:
				common.internal_print("Error: adding client route: {0}".format(stderr), -1)
				sys.exit(-1)

		return

	def mac_set_mtu(self, dev, mtu):
		s = socket.socket(type=socket.SOCK_DGRAM)
		try:
			ifr = struct.pack('<16sH', self.iface_name, 1350)+'\x00'*14
			fcntl.ioctl(s, self.IOCTL_MACOSX_SIOCSIFMTU, ifr)
		except Exception as e:
			common.internal_print("Cannot set MTU ({0}) on interface".format(mtu), -1)
			sys.exit(-1)

		return

	def mac_close_tunnel(self, tun):
		try:
			os.close(tun)
		except:
			pass

		return

	def mac_check_default_route(self):
		# get default gateway
		ps = subprocess.Popen(["route", "-n", "get", "default"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		(stdout, stderr) = ps.communicate()

		# is there a default gateway entry?
		if "not in table" in stderr:
			common.internal_print("No default route. Please set up your routing before executing the tool", -1)
			sys.exit(-1)
		# check for multiple default routes
		# is this even possible on MacOS(X)?

		return

	def mac_set_default_route(self, serverip, clientip, ip):
		# https://developer.apple.com/documentation/kernel/rt_msghdr?language=objc
		# s = socket(PF_ROUTE, SOCK_RAW, 0)
		# not sure which is the better way, calling external tools like
		# 'route' or implementing the messaging...

		# get default gateway
		ps = subprocess.Popen(["route", "-n", "get", "default"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		(stdout, stderr) = ps.communicate()

		# is there a default gateway entry?
		if "not in table" in stderr:
			common.internal_print("No default route. Please set up your routing before executing the tool", -1)
			sys.exit(-1)

		self.orig_default_gw = stdout.split("gateway: ")[1].split("\n")[0]

		# is it an ipv4 address?
		if not common.is_ipv4(self.orig_default_gw):
			common.internal_print("Default gateway is not an IPv4 address.", -1)
			sys.exit(-1)

		ps = subprocess.Popen(["route", "add", "-net", serverip, self.orig_default_gw, "255.255.255.255"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		(stdout, stderr) = ps.communicate()
		if stderr:
			if not "File exists" in stderr:
				common.internal_print("Error: adding server route: {0}".format(stderr), -1)
				sys.exit(-1)

		ps = subprocess.Popen(["route", "delete", "default"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		(stdout, stderr) = ps.communicate()
		if stderr:
			common.internal_print("Error: deleting default route: {0}".format(stderr), -1)
			sys.exit(-1)

		ps = subprocess.Popen(["route", "add", "default", ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		(stdout, stderr) = ps.communicate()
		if stderr:
			common.internal_print("Error: adding new default route: {0}".format(stderr), -1)
			sys.exit(-1)

		'''
		# keeping this, in case I can test with tun, not utun
		ps = subprocess.Popen(["route", "add", "-net", clientip, serverip, "255.255.255.255"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		(stdout, stderr) = ps.communicate()
		if stderr:
			if not "File exists" in stderr:
				common.internal_print("Error: adding new route: {0}".format(stderr), -1)
				sys.exit(-1)
		'''

		return

	def mac_set_intermediate_route(self, serverip, proxyip):
		common.internal_print("Changing route table for intermediate hop")

		ps = subprocess.Popen(["route", "delete", serverip, self.orig_default_gw], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		(stdout, stderr) = ps.communicate()
		if stderr:
			common.internal_print("Error: delete old route: {0}".format(stderr), -1)
			sys.exit(-1)

		ps = subprocess.Popen(["route", "add", "-net", proxyip, self.orig_default_gw, "255.255.255.255"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		(stdout, stderr) = ps.communicate()
		if stderr:
			if not "File exists" in stderr:
				common.internal_print("Error: adding server route: {0}".format(stderr), -1)
				sys.exit(-1)
		return

	def mac_restore_routes(self, serverip, clientip, ip):
		common.internal_print("Restoring default route")

		ps = subprocess.Popen(["route", "delete", serverip, self.orig_default_gw], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		(stdout, stderr) = ps.communicate()
		if stderr:
			common.internal_print("Error: delete old route: {0}".format(stderr), -1)
			sys.exit(-1)

		'''
		# keeping this, in case I can test with tun, not utun
		ps = subprocess.Popen(["route", "delete", clientip, serverip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		(stdout, stderr) = ps.communicate()
		if stderr:
			common.internal_print("Error: delete old server route: {0}".format(stderr), -1)
			sys.exit(-1)
		'''

		ps = subprocess.Popen(["route", "delete", "default"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		(stdout, stderr) = ps.communicate()
		if stderr:
			if not "not in table" in stderr:
				common.internal_print("Error: deleting default route: {0}".format(stderr), -1)
				sys.exit(-1)

		ps = subprocess.Popen(["route", "add", "default", self.orig_default_gw], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		(stdout, stderr) = ps.communicate()
		if stderr:
			if not "File exists" in stderr:
				common.internal_print("Error: adding server route: {0}".format(stderr), -1)
				sys.exit(-1)

		return

	def mac_set_split_route(self, scope, ip):
		for entry in scope:
			ps = subprocess.Popen(["route", "add", "{0}/{1}".format(entry[0], entry[2]), ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			(stdout, stderr) = ps.communicate()
			if stderr:
				common.internal_print("Error: adding new split route: {0}".format(stderr), -1)
				sys.exit(-1)
		return

	def mac_del_split_route(self, scope, ip):
		return



	# WINDOWS #######################################################
	WINDOWS_ADAPTER_KEY = "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}"
	TUNTAP_COMPONENT_ID = "tap0901"

	def win_init(self):
		global registry, win32file

		import _winreg as registry
		import win32file

		return


	# get GUID of tap device from registry (Windows)
	def WIN_get_device_guid(self):

		try:
			regkey = registry.OpenKey(registry.HKEY_LOCAL_MACHINE, self.WINDOWS_ADAPTER_KEY)
			for i in xrange(10000):
				key_name = registry.EnumKey(regkey, i)
				try:
					regsubkey = registry.OpenKey(regkey, key_name)
					component_id = registry.QueryValueEx(regsubkey, "ComponentId")[0]
					if component_id == self.TUNTAP_COMPONENT_ID:
						return registry.QueryValueEx(regsubkey, 'NetCfgInstanceId')[0]
				except WindowsError as e:
					pass
					continue
		except Exception as e:
			pass
			return None

		return None

	def WIN_get_subinterface_name(self):
		IFACE_NAME_KEY = "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\"
		NetCfgInstanceId = self.WIN_get_device_guid()

		try:
			regkey = registry.OpenKey(registry.HKEY_LOCAL_MACHINE, IFACE_NAME_KEY+NetCfgInstanceId+"\\Connection\\")
			iface_name = registry.QueryValueEx(regkey, "Name")[0]
		except WindowsError as e:
			common.internal_print("Cannot get interface name. Registry key cannot be found: {0}".format(e), -1)
			sys.exit(-1)

		return iface_name

	def WIN_get_interface_index(self):
		iface_name = self.WIN_get_subinterface_name()
		ps = subprocess.Popen(["netsh", "interface", "ipv4", "show", "interfaces"], stdout=subprocess.PIPE,
			stderr=subprocess.PIPE)
		(stdout, stderr) = ps.communicate()


		if stderr != "":
			common.internal_print("Show interfaces. netsh failed: {0}".format(stdout), -1)
			sys.exit(-1)

		for line in stdout.split("\n"):
			if iface_name in line:
				i = 0
				while line[i:i+1] == " ":
					i += 1
				return int(line[i:].split(" ")[0])

		return -1

	def WIN_CTL_CODE(self, device_type, function, method, access):
	    return (device_type << 16) | (access << 14) | (function << 2) | method;

	def WIN_TAP_CONTROL_CODE(self, request, method):
	    return self.WIN_CTL_CODE(34, request, method, 0)


	def win_tun_alloc(self, dev, flags):
		TAP_IOCTL_SET_MEDIA_STATUS 	= self.WIN_TAP_CONTROL_CODE(6, 0)

		guid = self.WIN_get_device_guid()
		if not guid:
			common.internal_print("Please install OpenVPN's Windows TAP driver (NDIS 6) to use XFLTReaT\r\nhttps://openvpn.net/index.php/open-source/downloads.html", -1)
			sys.exit(-1)

		# create a win32file for manipulating the TUN/TAP interface
		self.wintun = win32file.CreateFile("\\\\.\\Global\\{0}.tap".format(guid),
			win32file.GENERIC_READ | win32file.GENERIC_WRITE,
			win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE,
			None, win32file.OPEN_EXISTING,
			win32file.FILE_ATTRIBUTE_SYSTEM | win32file.FILE_FLAG_NO_BUFFERING | win32file.FILE_FLAG_OVERLAPPED,
			None)

		# have Windows consider the interface now connected
		win32file.DeviceIoControl(self.wintun, TAP_IOCTL_SET_MEDIA_STATUS, '\x01\x00\x00\x00', 1, None)

		return self.wintun

	def win_set_ip_address(self, dev, ip, serverip, netmask):
		TAP_WIN_IOCTL_CONFIG_TUN = self.WIN_TAP_CONTROL_CODE(10, 0)
		TAP_WIN_IOCTL_CONFIG_DHCP_MASQ = self.WIN_TAP_CONTROL_CODE(7, 0)

		integer_ip = struct.unpack(">I", socket.inet_aton(ip))[0]
		integer_network = struct.pack(">I", integer_ip & ((2**int(netmask))-1)<<32-int(netmask))
		integer_netmask = struct.pack(">I", ((2**int(netmask))-1)<<32-int(netmask))
		settings = socket.inet_aton(ip) + integer_network + integer_netmask

		win32file.DeviceIoControl(self.wintun, TAP_WIN_IOCTL_CONFIG_TUN,
			settings, 1, None)

		lease = '\x10\x0e\x00\x00'
		settings = socket.inet_aton(ip) + integer_netmask + socket.inet_aton(ip) + lease

		iface_name = self.WIN_get_subinterface_name()
		integer_netmask = struct.pack(">I", ((2**int(netmask))-1)<<32-int(netmask))
		netmask = socket.inet_ntoa(integer_netmask)

		# server mode
		if serverip == ip:
			ps = subprocess.Popen(["netsh", "interface", "ipv4", "set", "address", "name={0}".format(iface_name),
				"source=static", "address={0}".format(ip), "mask={0}".format(netmask)], stdout=subprocess.PIPE,
				stderr=subprocess.PIPE)
			(stdout, stderr) = ps.communicate()

			if stderr != "":
				common.internal_print("Cannot set IP. netsh failed: {0}".format(stdout), -1)
				sys.exit(-1)

		# client mode
		else:
			ps = subprocess.Popen(["netsh", "interface", "ipv4", "set", "address", "name={0}".format(iface_name),
				"source=static", "address={0}".format(ip), "mask={0}".format(netmask),"gateway={0}".format(serverip)],
				stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			(stdout, stderr) = ps.communicate()

			if stderr != "":
				common.internal_print("Cannot set IP. netsh failed: {0}".format(stdout), -1)
				sys.exit(-1)

		return

	def win_set_mtu(self, dev, mtu):
		iface_name = self.WIN_get_subinterface_name()

		ps = subprocess.Popen(["netsh", "interface", "ipv4", "set", "subinterface", iface_name,
			"mtu={0}".format(mtu), "store=active"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		(stdout, stderr) = ps.communicate()

		if "Ok." not in stdout:
			common.internal_print("Cannot set MTU. netsh failed: {0}".format(stdout), -1)
			sys.exit(-1)

		return


	def win_close_tunnel(self, tun):
		try:
			win32file.CloseHandle(self.wintun)
		except:
			pass

		return


	def win_check_default_route(self):
		# get default gateway
		ps = subprocess.Popen(["route", "-4", "PRINT", "0.0.0.0"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		(stdout, stderr) = ps.communicate()
		if stderr:
			common.internal_print("Checking default route failed: {0}".format(stderr), -1)
			sys.exit(-1)

		# count default routes
		default_routes = 0
		for line in stdout[0:stdout.find("Persistent Routes:")].split("\n"):
			if "0.0.0.0" in line:
				default_routes += 1

		if not default_routes:
			common.internal_print("No default route. Please set up your routing before executing the tool", -1)
			sys.exit(-1)

		return

	def win_set_default_route(self, serverip, clientip, ip):
		self.win_check_default_route()

		# get default gateway lines
		ps = subprocess.Popen(["route", "-4", "PRINT", "0.0.0.0"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		(stdout, stderr) = ps.communicate()
		if stderr:
			common.internal_print("Get default route failed: {0}".format(stderr), -1)
			sys.exit(-1)

		# parse and get default gw - no persistent routes
		for line in stdout[0:stdout.find("Persistent Routes:")].split("\n"):
			if "0.0.0.0" in line:
				elements = line.split(" ")
				while "" in elements:
					elements.remove("")

				# save original default route
				if elements[2] != ip:
					self.orig_default_gw = elements[2]
					break

		ps = subprocess.Popen(["route", "DELETE", "0.0.0.0", self.orig_default_gw], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		(stdout, stderr) = ps.communicate()
		if stderr:
			common.internal_print("Delete default route failed: {0}".format(stderr), -1)
			sys.exit(-1)

		ps = subprocess.Popen(["route", "ADD", serverip, "MASK", "255.255.255.255", self.orig_default_gw], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		(stdout, stderr) = ps.communicate()
		if stderr:
			common.internal_print("Add route to server failed: {0}".format(stderr), -1)
			sys.exit(-1)

		return

	def win_set_intermediate_route(self, serverip, proxyip):
		common.internal_print("Changing route table for intermediate hop")
		# delete original default route
		ps = subprocess.Popen(["route", "DELETE", serverip, self.orig_default_gw], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		(stdout, stderr) = ps.communicate()
		if stderr:
			common.internal_print("Delete server route failed: {0}".format(stderr), -1)
			sys.exit(-1)

		# add intermediate route
		ps = subprocess.Popen(["route", "ADD", proxyip, "MASK", "255.255.255.255", self.orig_default_gw], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		(stdout, stderr) = ps.communicate()
		if stderr:
			common.internal_print("Add intermediate route failed: {0}".format(stderr), -1)
			sys.exit(-1)

		return

	def win_restore_routes(self, serverip, clientip, ip):
		common.internal_print("Restoring default route")

		ps = subprocess.Popen(["route", "DELETE", serverip, self.orig_default_gw], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		(stdout, stderr) = ps.communicate()
		if stderr:
			common.internal_print("Delete server route failed: {0}".format(stderr), -1)
			sys.exit(-1)

		ps = subprocess.Popen(["route", "-p", "DELETE", "0.0.0.0", ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		(stdout, stderr) = ps.communicate()
		if stderr:
			common.internal_print("Delete default route failed: {0}".format(stderr), -1)
			sys.exit(-1)

		ps = subprocess.Popen(["route", "ADD", "0.0.0.0", "MASK", "0.0.0.0", self.orig_default_gw], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		(stdout, stderr) = ps.communicate()
		if stderr:
			common.internal_print("Add original default route failed: {0}".format(stderr), -1)
			sys.exit(-1)

		return

	def win_set_split_route(self, scope, ip):
		iface_idx = self.WIN_get_interface_index()
		ps = subprocess.Popen(["route", "-p", "DELETE", "0.0.0.0", ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		(stdout, stderr) = ps.communicate()
		if stderr:
			common.internal_print("Delete default route failed: {0}".format(stderr), -1)
			sys.exit(-1)

		for entry in scope:
			ps = subprocess.Popen(["route", "ADD", entry[0], "MASK", entry[1], ip, "IF", "{0}".format(iface_idx)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			(stdout, stderr) = ps.communicate()
			if stderr:
				common.internal_print("Add split route to server failed: {0}".format(stderr), -1)
				sys.exit(-1)
		return

	def win_del_split_route(self, scope, ip):
		for entry in scope:
			ps = subprocess.Popen(["route", "DELETE", entry[0], ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			(stdout, stderr) = ps.communicate()
			if stderr:
				common.internal_print("Delete split route to server failed: {0}".format(stderr), -1)
				sys.exit(-1)
		return