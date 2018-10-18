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

if "HTTP_CONNECT.py" in sys.argv[0]:
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

class HTTP_CONNECT_thread(TCP_generic.TCP_generic_thread):
	def __init__(self, threadID, serverorclient, tunnel, packetselector, comms_socket, client_addr, authentication, encryption_module, verbosity, config, module_name):
		super(HTTP_CONNECT_thread, self).__init__(threadID, serverorclient, tunnel, packetselector, comms_socket, client_addr, authentication, encryption_module, verbosity, config, module_name)

class HTTP_CONNECT(TCP_generic.TCP_generic):

	module_name = "HTTP CONNECT"
	module_configname = "HTTP_CONNECT"
	module_description = """HTTP CONNECT support for using XFLTReaT over 
		proxies.
		This module was tested with Squid3, default config.
		"""
	module_os_support = common.OS_LINUX | common.OS_MACOSX | common.OS_WINDOWS | common.OS_FREEBSD

	def http_connect_request(self, server_socket):
		if self.config.has_option("Global", "remoteserverhost"):
			if not common.is_hostname(self.config.get("Global", "remoteserverhost")):
				common.internal_print("[Global] remoteserverhost value is not a hostname", -1)

				return False
			else:
				remoteserver = self.config.get("Global", "remoteserverhost")

		else:
			if self.config.has_option("Global", "remoteserverip"):
				if not common.is_ipv4(self.config.get("Global", "remoteserverip")):
					common.internal_print("[Global] remoteserverip value is not an IPv4 address", -1)

					return False
				remoteserver = self.config.get("Global", "remoteserverip")


		serverport = int(self.config.get(self.get_module_configname(), "serverport"))
		request = "CONNECT {0}:{1} HTTP/1.1\r\nHost: {2}\r\n\r\n".format(remoteserver, serverport, remoteserver)

		server_socket.send(request)
		
		response = server_socket.recv(4096)

		if response[9:12] != "200":
			common.internal_print("Connection failed: {0}".format(response[0:response.find("\n")]), -1)

			return False

		return True

	def sanity_check(self):
		if not super(HTTP_CONNECT, self).sanity_check():
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
			common.internal_print("Starting client: {0} ({1}:{2})".format(self.get_module_name(), self.config.get(self.get_module_configname(), "proxyip"), int(self.config.get(self.get_module_configname(), "proxyport"))))

			client_fake_thread = None

			server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			server_socket.settimeout(3)
			server_socket.connect((self.config.get(self.get_module_configname(), "proxyip"), int(self.config.get(self.get_module_configname(), "proxyport"))))

			if self.http_connect_request(server_socket):
				client_fake_thread = HTTP_CONNECT_thread(0, 0, self.tunnel, None, server_socket, None, self.authentication, self.encryption_module, self.verbosity, self.config, self.get_module_name())
				client_fake_thread.do_hello()
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
			common.internal_print("Checking module on server: {0} ({1}:{2})".format(self.get_module_name(), self.config.get(self.get_module_configname(), "proxyip"), self.config.get(self.get_module_configname(), "proxyport")))
			
			server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			server_socket.settimeout(3)
			server_socket.connect((self.config.get(self.get_module_configname(), "proxyip"), int(self.config.get(self.get_module_configname(), "proxyport"))))

			if self.http_connect_request(server_socket):
				client_fake_thread = HTTP_CONNECT_thread(0, 0, None, None, server_socket, None, self.authentication, self.encryption_module, self.verbosity, self.config, self.get_module_name())
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