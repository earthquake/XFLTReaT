import sys

if "HTTP_CONNECT.py" in sys.argv[0]:
	print "[-] Instead of poking around just try: python xfltreat.py --help"
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
	def __init__(self, threadID, serverorclient, tunnel, packetselector, comms_socket, client_addr, verbosity, config, module_name):
		super(HTTP_CONNECT_thread, self).__init__(threadID, serverorclient, tunnel, packetselector, comms_socket, client_addr, verbosity, config, module_name)

class HTTP_CONNECT(TCP_generic.TCP_generic):

	module_name = "HTTP CONNECT"
	module_configname = "HTTP_CONNECT"
	module_description = """HTTP CONNECT support for using XFLTReaT over 
		proxies.
		This module was tested with Squid3, default config.
		"""

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
				return False


		serverport = int(self.config.get(self.get_module_configname(), "serverport"))
		request = "CONNECT %s:%d HTTP/1.1\r\nHost: %s\r\n\r\n" % (remoteserver, serverport, remoteserver)

		server_socket.send(request)
		
		response = server_socket.recv(4096)

		if response[0:12] != "HTTP/1.1 200":
			common.internal_print("Connection failed: {0}".format(response[0:response.find("\n")]), -1)

			return False

		return True

	def sanity_check(self):
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

	def client(self):
		try:
			if not self.sanity_check():
				return
			common.internal_print("Starting client: {0} ({1}:{2})".format(self.get_module_name(), self.config.get(self.get_module_configname(), "proxyip"), int(self.config.get(self.get_module_configname(), "proxyport"))))

			client_fake_thread = None

			server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			server_socket.settimeout(3)
			server_socket.connect((self.config.get(self.get_module_configname(), "proxyip"), int(self.config.get(self.get_module_configname(), "proxyport"))))

			if self.http_connect_request(server_socket):
				client_fake_thread = HTTP_CONNECT_thread(0, 0, self.tunnel, None, server_socket, None, self.verbosity, self.config, self.get_module_name())
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
			if not self.sanity_check():
				return
			common.internal_print("Checking module on server: {0} ({1}:{2})".format(self.get_module_name(), self.config.get(self.get_module_configname(), "proxyip"), self.config.get(self.get_module_configname(), "proxyport")))
			
			server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			server_socket.settimeout(3)
			server_socket.connect((self.config.get(self.get_module_configname(), "proxyip"), int(self.config.get(self.get_module_configname(), "proxyport"))))

			if self.http_connect_request(server_socket):
				client_fake_thread = HTTP_CONNECT_thread(0, 0, None, None, server_socket, None, self.verbosity, self.config, self.get_module_name())
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