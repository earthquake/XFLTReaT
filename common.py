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

if "common.py" in sys.argv[0]:
	print("[-] Instead of poking around just try: python xfltreat.py --help")
	sys.exit(-1)

import struct
import random
import socket
import os
import re
import platform
import pkgutil

DATA_CHANNEL_BYTE	 = "\x00"
CONTROL_CHANNEL_BYTE = "\x80"

CONTROL_CHECK 			= "XFLT>CHECK!"
CONTROL_CHECK_RESULT 	= "XFLT>CHECK_RESULT"
CONTROL_INIT 			= "XFLT>INIT!"
CONTROL_INIT_DONE		= "XFLT>INIT_DONE"
CONTROL_LOGOFF			= "XFLT>LOGOFF!"
CONTROL_DUMMY_PACKET 	= "XFLT>DUMMY_PACKET"
# TODO DEL AUTH
CONTROL_AUTH 			= "XFLT>AUTH!"
CONTROL_AUTH_OK 		= "XFLT>AUTH_OK"
CONTROL_AUTH_NOTOK 		= "XFLT>AUTH_NOTOK"


# Multi Operating System support values
OS_UNKNOWN	= 0
OS_LINUX 	= 1
OS_MACOSX	= 2
OS_WINDOWS	= 4
OS_FREEBSD	= 8
OS_OPENBSD	= 16
OS_WHATNOT	= 32

OS_SUPPORTED = OS_LINUX | OS_MACOSX | OS_WINDOWS

# print severity levels:
# 	0	always
#	1	verbose (common.VERBOSE)
#	2	debug   (common.DEBUG)
# print feedback levels:
#	-1	negativ
#	0	neutral
#	1	positive
colour = True
VERBOSE = 1
DEBUG   = 2
def internal_print(message, feedback = 0, verbosity = 0, severity = 0):
	debug = ""
	if severity == 2:
		debug = "DEBUG: "
	if verbosity >= severity:
		if feedback == -1:
			if colour:
				prefix = "\033[91m[-]"
			else:
				prefix = "[-]"
		if feedback == 0:
			if colour:
				prefix = "\033[39m[*]"
			else:
				prefix = "[*]"
		if feedback == 1:
			if colour:
				prefix = "\033[92m[+]"
			else:
				prefix = "[+]"
		if colour:
			print("{0} {1}{2}\033[39m".format(prefix, debug, message))
		else:
			print("{0} {1}{2}".format(prefix, debug, message))

# check if the OS is supported
def os_support():
	if OS_SUPPORTED & get_os_type():
		return True
	else:
		internal_print("Sorry buddy, I am afraid that your OS is not yet supported", -1)
		return False

# check if the requirements are met
def check_modules_installed():
	reqs = []
	os_type = get_os_type()

	# reqs = [["module_name", "package_name"], [...]]
	if os_type == OS_LINUX:
		reqs = [["cryptography", "cryptography"], ["pyroute2","pyroute2"], ["sctp","pysctp"]]
	if os_type == OS_MACOSX:
		reqs = [["cryptography", "cryptography"]]
	if os_type == OS_WINDOWS:
		reqs = [["cryptography", "cryptography"], ["win32file","pywin32"]]

	allinstalled = True
	for m in reqs:
		if not pkgutil.find_loader(m[0]):
			allinstalled = False
			internal_print("The following python modules were not installed: {0}".format(m[1]), -1)

	return allinstalled


# get os type. No need to import 'platform' in every module this way.
def get_os_type():
	os_type = platform.system()
	if os_type == "Linux":
		return OS_LINUX

	if os_type == "Darwin":
		return OS_MACOSX

	if os_type == "Windows":
		return OS_WINDOWS

	if os_type == "FreeBSD":
		return OS_FREEBSD

	if os_type == "OpenBSD":
		return OS_OPENBSD

	return OS_UNKNOWN

# get the release of the OS
def get_os_version():
	return platform.version()

# get the release of the OS
def get_os_release():
	return platform.release()

# get the privilege level, True if it is enough to run.
def get_privilege_level():
	os_type = get_os_type()
	if (os_type == OS_LINUX) or (os_type == OS_MACOSX):
		if os.getuid() == 0:
			return True
		else:
			return False

	if os_type == OS_WINDOWS:
		import ctypes
		if ctypes.windll.shell32.IsUserAnAdmin():
			return True
		else:
			return False

	return False


# check if the forwarding was set properly.
def check_router_settings(config):
	os_type = get_os_type()
	if os_type == OS_LINUX:
		if open('/proc/sys/net/ipv4/ip_forward','r').read()[0:1] == "0":
			internal_print("The IP forwarding is not set.", -1)
			internal_print("Please use the following two commands to set it properly (root needed):\n#\tsysctl -w net.ipv4.ip_forward=1\n#\tiptables -t nat -A POSTROUTING -s {0}/{1} -o [YOUR_INTERFACE/e.g./eth0] -j MASQUERADE\n".format(config.get("Global", "serverip"), config.get("Global", "servernetmask")))

			return False

	if os_type == OS_MACOSX:
		import ctypes
		import ctypes.util

		# load libc
		libc_name = ctypes.util.find_library('c')
		libc = ctypes.CDLL(libc_name, use_errno=True)

		# get value of forwarding with sysctl
		fw_value = ctypes.c_int(-1)

		err = libc.sysctlbyname("net.inet.ip.forwarding", ctypes.byref(fw_value), ctypes.byref(ctypes.c_uint(4)), None, 0)
		if err < 0:
			err = ctypes.get_errno()
			internal_print("sysctl failed: {0} : {1}".format(err, os.strerror(err)), -1)
			return False

		if fw_value.value != 1:
			internal_print("The IP forwarding is not set.", -1)
			internal_print("Please use the following commands to set it properly (root needed):\n#\tsysctl -w net.inet.ip.forwarding=1\nPut the following line into the /etc/pf.conf after the \'nat-anchor \"com.apple/*\"' line:\n#\tnat on en0 from {0}/{1} to any -> (en0)\nThen load the config file with pfctl:\n#\tpfctl -f /etc/pf.conf -e -v".format(config.get("Global", "serverip"), config.get("Global", "servernetmask")))

			return False

	if os_type == OS_WINDOWS:
		import _winreg as registry
		#HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\IPEnableRouter - DWORD 1 - enable
		#"Routing and Remote Access" service - Enable, start
		PATH = "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\"

		try:
			regkey = registry.OpenKey(registry.HKEY_LOCAL_MACHINE, PATH)
			router_value = registry.QueryValueEx(regkey, "IPEnableRouter")[0]
		except WindowsError as e:
			internal_print("Cannot get IPEnableRouter value. Registry key cannot be found: {0}".format(e), -1)
			return False

		if router_value != 1:
			internal_print("The IP forwarding is not set.", -1)
			internal_print("Please set the IPEnableRouter value to 1 with the following command:\n\treg add HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters /t REG_DWORD /v IPEnableRouter /d 1 /f\n\tMoreover you need to enable and start the \"Routing and Remote Access\" service.\n")

			return False


	return True


# main config sanity check. If something missing from the Global section, or 
# from the filesystem then it shouts.
def config_sanity_check(config, serverorclient):
	dirlist = ["modules", "support", "encryption", "authentication", "misc"]

	for d in dirlist:
		if not os.path.isdir(d):
			internal_print("The '{0}' directory is missing. Make sure you have it with the necessary files.".format(d), -1)

			return False

	if not config.has_section("Global"):
		internal_print("config file missing 'Global' section", -1)

		return False

	if not config.has_option("Global", "remoteserverip"):
		internal_print("'remoteserverip' option is missing from 'Global' section", -1)

		return False

	if not is_ipv4(config.get("Global", "remoteserverip")) and not is_ipv6(config.get("Global", "remoteserverip")) :
		internal_print("'remoteserverip' should be ipv4 or ipv6 address in 'Global' section", -1)

		return False

	if not config.has_option("Global", "mtu"):
		internal_print("'mtu' option is missing from 'Global' section", -1)

		return False

	if serverorclient:
		if not config.has_option("Global", "serverif"):
			internal_print("'serverif' option is missing from 'Global' section", -1)

			return False

		if not config.has_option("Global", "serverip"):
			internal_print("'serverip' option is missing from 'Global' section", -1)

			return False

		if not config.has_option("Global", "servernetmask"):
			internal_print("'servernetmask' option is missing from 'Global' section", -1)

			return False

		if not config.has_option("Global", "serverbind"):
			internal_print("'serverbind' option is missing from 'Global' section", -1)

			return False

	else:
		if not config.has_option("Global", "clientif"):
			internal_print("'clientif' option is missing from 'Global' section", -1)

			return False

		if not config.has_option("Global", "clientip"):
			internal_print("'clientip' option is missing from 'Global' section", -1)

			return False

		if not config.has_option("Global", "clientnetmask"):
			internal_print("'clientnetmask' option is missing from 'Global' section", -1)

			return False

	if config.has_option("Global", "scope"):
		scopefile = config.get("Global", "scope")
		if not os.path.isfile(scopefile) and scopefile:
			internal_print("File '{0}' does not exists. Delete 'scope' option from config or create scope file.".format(scopefile), -1)

			return False

	return True

# dummy function to check whether it is control channel or not.
def is_control_channel(control_character):
	if control_character == None:
		return False
	if (ord(control_character) & 0x80) == ord(CONTROL_CHANNEL_BYTE):
		return True
	else:
		return False

# Shamelessly stolen regular expressions, any of them could be wrong
def is_hostname(s):
	return bool(re.match("^(([a-zA-Z]|[a-zA-Z][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9])$", s))

def is_ipv4(s):
	return bool(re.match("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", s))

def is_ipv6(s):
	too_long = "^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$"
	return bool(re.match(too_long, s))


def check_line_type(line):
	# check if it looks valid
	if not bool(re.match("^([0-9\.\-/]*)$", line)):
		return 0

	# ip/mask format
	if bool(re.match("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(/[0-9]{1,2})$", line)):
		return 1

	# x.y.z.w-v format
	if bool(re.match("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\-[0-9]{1,3})$", line)):
		return 2

	# ip format
	if bool(re.match("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", line)):
		return 3



	return -1

def parse_scope_file(filename):
	if not filename:
		return []

	f = open(filename, "r")
	content = f.read()
	f.close()

	lines = content.split("\n")
	scope = []

	for line in lines:
		if line:
			if line[0:1] == "#":
				# skip comments
				continue

			# get type of addressing, parse it accordingly
			type_ = check_line_type(line)
			if (type_ == 0) or (type_ == -1):
				internal_print("Erroneous line in scope definition: {0}".format(line), -1)

			if type_ == 1:
				regexp = re.match("^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/([0-9]{1,3})$", line)
				range_ip = struct.unpack(">I", socket.inet_aton(regexp.group(1)))[0]
				network = socket.inet_ntoa(struct.pack(">I", range_ip & ((2**int(regexp.group(2)))-1)<<32-int(regexp.group(2))))
				add = (network, socket.inet_ntoa(struct.pack(">I", ((2**int(regexp.group(2)))-1)<<32-int(regexp.group(2)))), regexp.group(2))
				if add not in scope:
					scope.append(add)

			if type_ == 2:
				regexp = re.match("^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\.([0-9]{1,3})\-([0-9]{1,3})$", line)
				for i in xrange(int(regexp.group(2)), int(regexp.group(3))+1):
					add = ("{0}.{1}".format(regexp.group(1), i), "255.255.255.255", "32")
					if add not in scope:
						scope.append(add)

			if type_ == 3:
				add = (line, "255.255.255.255", "32")
				if add not in scope:
					scope.append(add)

	return scope

# ANSI escape codes are only supported from version 10
if get_os_type() == OS_WINDOWS:
	if int(get_os_version()[0:get_os_version().find(".")]) < 10:
		colour = False
