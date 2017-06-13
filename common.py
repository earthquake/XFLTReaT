import sys

if "common.py" in sys.argv[0]:
	print "[-] Instead of poking around just try: python xfltreat.py --help"
	sys.exit(-1)

import struct
import random
import socket
import os
import re

DATA_CHANNEL_BYTE 	 = "\x01"
CONTROL_CHANNEL_BYTE = "\x00"

CONTROL_CHECK   		 = "XFLT>CHECK!"
CONTROL_CHECK_RESULT 	 = "XFLT>CHECK_RESULT"
CONTROL_AUTH    		 = "XFLT>AUTH!"
CONTROL_AUTH_OK 		 = "XFLT>AUTH_OK"
CONTROL_AUTH_NOTOK 		 = "XFLT>AUTH_NOTOK"
CONTROL_LOGOFF 			 = "XFLT>LOGOFF!"
CONTROL_DUMMY_PACKET	 = "XFLT>DUMMY_PACKET"

# severity levels:
# 	0	always
#	1	verbose (common.VERBOSE)
#	2	debug   (common.DEBUG)
# feedback levels:
#	-1	negativ
#	0	neutral
#	1	positive

VERBOSE = 1
DEBUG   = 2
def internal_print(message, feedback = 0, verbosity = 0, severity = 0):
	debug = ""
	if severity == 2:
		debug = "DEBUG: "
	if verbosity >= severity:
		if feedback == -1:
			prefix = "\033[91m[-]"
		if feedback == 0:
			prefix = "\033[39m[*]"
		if feedback == 1:
			prefix = "\033[92m[+]"
		print "%s %s%s\033[39m" % (prefix, debug, message)

def config_sanity_check(config, serverorclient):
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

	return True

def check_gen():
	number1 = random.randint(0, 4294967295)
	number2 = random.randint(0, 4294967295)
	number3 = number1 ^ number2

	return (struct.pack(">II", number1, number2), struct.pack(">I", number3))

def check_calc(leftover):
	numbers = struct.unpack(">II", leftover)
	return struct.pack(">I", numbers[0] ^ numbers[1])

def auth_first_step(clientip, sd):
	client_public_source_ip = sd.getsockname()[0]
	client_public_source_port = sd.getsockname()[1]
	client_private_ip = clientip

	return socket.inet_aton(client_private_ip)+socket.inet_aton(client_public_source_ip)+struct.pack(">H", client_public_source_port)

def authenticate(msg):
	#do real auth
	#private IP come from the client, is this secure?
	return True

def init_client_stateful(msg, addr, client, packetselector):
	## TODO error handling
	client_private_ip = msg[0:4]
	client_public_source_ip = socket.inet_aton(addr[0])
	client_public_source_port = addr[1]

	for c in packetselector.get_clients():
		if c.get_private_ip_addr() == client_private_ip:
			packetselector.delete_client(c)

	pipe_r, pipe_w = os.pipe()
	client.set_pipes_fdnum(pipe_r, pipe_w)
	client.set_pipes_fd(os.fdopen(pipe_r, "r"), os.fdopen(pipe_w, "w"))

	client.set_public_ip_addr(client_public_source_ip)
	client.set_public_src_port(client_public_source_port)
	client.set_private_ip_addr(client_private_ip)
	client.set_authenticated(True)

	return

def init_client_stateless(msg, addr, client, packetselector, clients):
	## TODO error handling
	client_private_ip = msg[0:4]
	client_public_source_ip = socket.inet_aton(addr[0])
	client_public_source_port = addr[1]

	for c in clients:
		if c.get_private_ip_addr() == client_private_ip:
			delete_client_stateless(clients, c)

	for c in packetselector.get_clients():
		if c.get_private_ip_addr() == client_private_ip:
			packetselector.delete_client(c)

	pipe_r, pipe_w = os.pipe()
	client.set_pipes_fdnum(pipe_r, pipe_w)
	client.set_pipes_fd(os.fdopen(pipe_r, "r"), os.fdopen(pipe_w, "w"))

	client.set_public_ip_addr(client_public_source_ip)
	client.set_public_src_port(client_public_source_port)
	client.set_private_ip_addr(client_private_ip)
	client.set_authenticated(True)

	return

def delete_client_stateless(clients, client):
	clients.remove(client)
	client.get_pipe_r_fd().close()
	client.get_pipe_w_fd().close()

def lookup_client_priv(msg, clients):
	client_private_ip = msg[16:20]

	for c in clients:
		if c.get_private_ip_addr() == client_private_ip:
			return c

	return None

def lookup_client_pub(clients, addr):
	client_public_ip = socket.inet_aton(addr[0])

	for c in clients:
		if (c.get_public_ip_addr() == client_public_ip) and (c.get_public_src_port() == addr[1]):
			return c

	return None

# Shamelessly stolen regular expressions, any of them could be wrong
def is_hostname(s):
	return bool(re.match("^(([a-zA-Z]|[a-zA-Z][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9])$", s))

def is_ipv4(s):
	return bool(re.match("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", s))

def is_ipv6(s):
	return bool(re.match("^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$", s))