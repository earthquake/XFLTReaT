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

if "SOCKS.py" in sys.argv[0]:
	print("[-] Instead of poking around just try: python xfltreat.py --help")
	sys.exit(-1)

import socket
import time
import select
import os
import struct
import threading

#local files
import TCP_generic
from interface import Interface
import client
import common
import support.socks_proto as SOCKS_proto

class SOCKS_thread(TCP_generic.TCP_generic_thread):
	def __init__(self, threadID, serverorclient, tunnel, packetselector, comms_socket, client_addr, auth_module, verbosity, config, module_name):
		super(SOCKS_thread, self).__init__(threadID, serverorclient, tunnel, packetselector, comms_socket, client_addr, auth_module, verbosity, config, module_name)

class SOCKS(TCP_generic.TCP_generic):

	module_name = "SOCKS Proxy (version 4, 4a, 5)"
	module_configname = "SOCKS"
	module_description = """SOCKS Proxy support for version 4, 4a, 5. This 
		module is based on the TCP_generic module.
		"""
	module_os_support = common.OS_LINUX | common.OS_MACOSX | common.OS_WINDOWS

	def __init__(self):
		super(SOCKS, self).__init__()
		self.socks = SOCKS_proto.SOCKS_proto()

		return

	def socks_handshake(self, server_socket):
		version = self.config.get(self.get_module_configname(), "version")
		if (version == "4") or (version == "4a"):
			if self.config.has_option(self.get_module_configname(), "userid"):
				userid = self.config.get(self.get_module_configname(), "userid")+"\x00"
			else:
				userid = "\x00"

			if version == "4":
				server_socket.send(struct.pack(">BBH4s", self.socks.SOCKS4_VERSION, self.socks.SOCKS4_CD, 
					int(self.config.get(self.get_module_configname(), "serverport")), 
					socket.inet_aton(self.config.get("Global", "remoteserverip")))+userid)
			else:
				if self.config.has_option("Global", "remoteserverhost"):
					if not common.is_hostname(self.config.get("Global", "remoteserverhost")):
						common.internal_print("[Global] remoteserverhost value is not a hostname", -1)

						return False
					domain = self.config.get("Global", "remoteserverhost")+"\x00"
					server_socket.send(struct.pack(">BBH4s", self.socks.SOCKS4_VERSION, self.socks.SOCKS4_CD, 
						int(self.config.get(self.get_module_configname(), "serverport")), 
						socket.inet_aton("0.0.0.1"))+userid+domain)
				else:
					common.internal_print("Missing remoteserverhost attribute from config [Global] section", -1)

					return False

			response = server_socket.recv(8)

			if (response[0:1] == self.socks.SOCKS4_OK) and (response[1:2] == self.socks.SOCKS4_RESPONSES[0]):
				common.internal_print("Connection was made through the proxy server", 1)
			else:
				if len(response) > 1:
					if (response[1:2] in self.socks.SOCKS4_RESPONSES):
						for i in range(len(self.socks.SOCKS4_RESPONSES)):
							if response[1:2] == self.socks.SOCKS4_RESPONSES[i]:
								common.internal_print("Connection failed through the proxy server: {0}".format(self.socks.SOCKS4_RESPONSES_STR[i]), -1)
						return False
				common.internal_print("Connection failed through the proxy server: Unknown error", -1)
				return False

		if version == "5":
			# send greeting with auth method list
			greeting = struct.pack(">BB", self.socks.SOCKS5_VERSION, len(self.socks.SOCKS5_AUTH_METHODS))
			for i in range(len(self.socks.SOCKS5_AUTH_METHODS)):
				greeting += self.socks.SOCKS5_AUTH_METHODS[i][0]
			server_socket.send(greeting)

			# receive response with selected auth method
			response = server_socket.recv(2)
			if (len(response) != 2) or (response[0:1] != chr(self.socks.SOCKS5_VERSION)):
				common.internal_print("Connection failed through the proxy server: Unknown error", -1)
				return False

			if response[1:2] == self.socks.SOCKS5_REJECT_METHODS:
				common.internal_print("Connection failed through the proxy server: Authentication methods rejected", -1)
				return False

			for i in range(len(self.socks.SOCKS5_AUTH_METHODS)):
				if response[1:2] == self.socks.SOCKS5_AUTH_METHODS[i][0]:
					if self.socks.SOCKS5_AUTH_METHODS[i][1](self.config, server_socket):
						
						if self.config.has_option("Global", "remoteserverhost"):
							remoteserverhost = self.config.get("Global", "remoteserverhost")
							if not (common.is_hostname(remoteserverhost) or 
								common.is_ipv4(remoteserverhost) or common.is_ipv6(remoteserverhost)):
								common.internal_print("[Global] remoteserverhost value is not ipv4, ipv6 or a hostname", -1)

								return False

						else:
							common.internal_print("Missing remoteserverhost attribute from config [Global] section", -1)

							return False

						if common.is_ipv4(remoteserverhost):
							host_type = self.socks.SOCKS5_ADDR_TYPE[0]
							connect_string = struct.pack(">BBBB4sH", self.socks.SOCKS5_VERSION, 
								self.socks.SOCKS5_CD, 0, host_type,
								socket.inet_aton(remoteserverhost),
								int(self.config.get(self.get_module_configname(), "serverport")))

						if common.is_hostname(remoteserverhost):
							host_type = self.socks.SOCKS5_ADDR_TYPE[1]
							connect_string = struct.pack(">BBBBB", self.socks.SOCKS5_VERSION, 
								self.socks.SOCKS5_CD, 0, host_type, len(remoteserverhost))
							connect_string += remoteserverhost+struct.pack(">H", int(self.config.get(self.get_module_configname(), "serverport")))

						if common.is_ipv6(remoteserverhost):
							host_type = self.socks.SOCKS5_ADDR_TYPE[2]
							connect_string = struct.pack(">BBBB16sH", self.socks.SOCKS5_VERSION, 
								self.socks.SOCKS5_CD, 0, host_type,
								socket.inet_pton(socket.AF_INET6, remoteserverhost),
								int(self.config.get(self.get_module_configname(), "serverport")))
						
							

						server_socket.send(connect_string)

						response = server_socket.recv(4096)
						if (len(response) < 4) or (response[0:1] != chr(self.socks.SOCKS5_VERSION)):
							common.internal_print("Connection failed through the proxy server: Connection error to the server", -1)
							return False

						if response[1:2] == self.socks.SOCKS5_RESPONSES[0]:
							return True

						if response[1:2] not in self.socks.SOCKS5_RESPONSES:
							common.internal_print("Connection failed through the proxy server: Unknown error code", -1)
							return False

						for i in range(len(self.socks.SOCKS5_RESPONSES)):
							if response[1:2] == self.socks.SOCKS5_RESPONSES[i]:
								common.internal_print("Connection failed through the proxy server: {0}".format(self.socks.SOCKS5_RESPONSES_STR[i]), -1)
								return False

						return False
					else:
						return False

			common.internal_print("Connection failed through the proxy server: Strange response (Authentication method)", -1)
			return False


		return True

	def sanity_check(self):
		if not super(SOCKS, self).sanity_check():
			return False
		if not self.config.has_option(self.get_module_configname(), "proxyip"):
			common.internal_print("'proxyip' option is missing from '{0}' section".format(self.get_module_configname()), -1)

			return False

		if not self.config.has_option(self.get_module_configname(), "proxyport"):
			common.internal_print("'proxyport' option is missing from '{0}' section".format(self.get_module_configname()), -1)

			return False		

		if not common.is_ipv4(self.config.get(self.get_module_configname(), "proxyip")) and not common.is_ipv6(self.config.get(self.get_module_configname(), "proxyip")):
			common.internal_print("'proxyip' should be ipv4 or ipv6 address in '{0}' section".format(self.get_module_configname()), -1)

			return False

		return True

	def connect(self):
		try:
			version = self.config.get(self.get_module_configname(), "version")
			common.internal_print("Starting client: {0}, Version: {1} ({2}:{3})".format(self.get_module_name(), version, self.config.get(self.get_module_configname(), "proxyip"), int(self.config.get(self.get_module_configname(), "proxyport"))))

			client_fake_thread = None

			server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			server_socket.settimeout(3)
			server_socket.connect((self.config.get(self.get_module_configname(), "proxyip"), int(self.config.get(self.get_module_configname(), "proxyport"))))

			if self.socks_handshake(server_socket):
				client_fake_thread = SOCKS_thread(0, 0, self.tunnel, None, server_socket, None, self.auth_module, self.verbosity, self.config, self.get_module_name())
				client_fake_thread.do_auth()
				client_fake_thread.communication(False)

			server_socket.close()

		except KeyboardInterrupt:
			if client_fake_thread:
				client_fake_thread.do_logoff()
			self.cleanup(server_socket)
			raise
		except socket.error:
			common.internal_print("Connection error: {0}".format(self.get_module_name()), -1)
			self.cleanup(server_socket)
			raise

		self.cleanup(server_socket)

		return


	def check(self):
		try:
			version = self.config.get(self.get_module_configname(), "version")
			common.internal_print("Checking module on server: {0}, Version: {1} ({2}:{3})".format(self.get_module_name(), version, self.config.get(self.get_module_configname(), "proxyip"), self.config.get(self.get_module_configname(), "proxyport")))

			server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			server_socket.settimeout(3)
			server_socket.connect((self.config.get(self.get_module_configname(), "proxyip"), int(self.config.get(self.get_module_configname(), "proxyport"))))

			if self.socks_handshake(server_socket):
				client_fake_thread = SOCKS_thread(0, 0, None, None, server_socket, None, self.auth_module, self.verbosity, self.config, self.get_module_name())
				client_fake_thread.do_check()
				client_fake_thread.communication(True)

			server_socket.close()

		except socket.timeout:
			common.internal_print("Checking failed: {0}".format(self.get_module_name()), -1)
			self.cleanup(server_socket)
		except socket.error as exception:
			if exception.args[0] == 111:
				common.internal_print("Checking failed: {0}".format(self.get_module_name()), -1)
			else:
				common.internal_print("Connection error: {0}".format(self.get_module_name()), -1)
			self.cleanup(server_socket)

		return

	def get_intermediate_hop(self, config):
		if config.has_option(self.get_module_configname(), "proxyip"):
			if common.is_ipv4(config.get(self.get_module_configname(), "proxyip")) or common.is_ipv6(config.get(self.get_module_configname(), "proxyip")):
				remoteserverip = config.get(self.get_module_configname(), "proxyip")

				return remoteserverip
		return ""