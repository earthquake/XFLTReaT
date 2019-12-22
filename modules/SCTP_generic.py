# MIT License

# Copyright (c) 2017 Darren Martyn
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

if "SCTP_generic.py" in sys.argv[0]:
	print("[-] Instead of poking around just try: python xfltreat.py --help")
	sys.exit(-1)

import socket
import time
import select
import os
import struct
import threading

#local files
from modules import Stateful_module
from modules import TCP_generic
import client
import common

class SCTP_generic_thread(TCP_generic.TCP_generic_thread):
	def __init__(self, threadID, serverorclient, tunnel, packetselector, comms_socket, client_addr, authentication, encryption_module, verbosity, config, module_name):
		super(SCTP_generic_thread, self).__init__(threadID, serverorclient, tunnel, packetselector, comms_socket, client_addr, authentication, encryption_module, verbosity, config, module_name)
		threading.Thread.__init__(self)
		self.module_short = "SCTP"

		return

	def communication_win(self, is_check):
		return True

class SCTP_generic(TCP_generic.TCP_generic):
	module_name = "SCTP generic"
	module_configname = "SCTP_generic"
	module_description = """Generic SCTP module that can listen on any port.
		This module lacks of any encryption or encoding, which comes to the interface
		goes to the socket back and forth. Nothing special.
		"""
	module_os_support = common.OS_LINUX

	def __init__(self):
		super(SCTP_generic, self).__init__()
		self.server_socket = None

		# bit hacky, but it needs to be loaded somewhere.
		if self.os_check():
			import sctp
			self.sctp = sctp

		return

	def stop(self):
		self._stop = True

		if self.threads:
			for t in self.threads:
				t.stop()
		
		# not so nice solution to get rid of the block of listen()
		# unfortunately close() does not help on the block
		try:
			server_socket = self.sctp.sctpsocket_tcp(socket.AF_INET)
			if self.config.get("Global", "serverbind") == "0.0.0.0":
				server_socket.connect(("127.0.0.1", int(self.config.get(self.get_module_configname(), "serverport"))))
			else:
				server_socket.connect((self.config.get("Global", "serverbind"), int(self.config.get(self.get_module_configname(), "serverport"))))
		except:
			pass

		return

	def sanity_check(self):
		if not self.config.has_option(self.get_module_configname(), "serverport"):
			common.internal_print("'serverport' option is missing from '{0}' section".format(self.get_module_configname()), -1)

			return False

		try:
			convert = int(self.config.get(self.get_module_configname(), "serverport"))
		except:
			common.internal_print("'serverport' is not an integer in '{0}' section".format(self.get_module_configname()), -1)
			return False

		return True

	def serve(self):
		client_socket = server_socket = None
		self.threads = []
		threadsnum = 0

		common.internal_print("Starting module: {0} on {1}:{2}".format(self.get_module_name(), self.config.get("Global", "serverbind"), int(self.config.get(self.get_module_configname(), "serverport"))))
		
		server_socket = self.sctp.sctpsocket_tcp(socket.AF_INET)
		server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		try:
			server_socket.bind((self.config.get("Global", "serverbind"), int(self.config.get(self.get_module_configname(), "serverport"))))
			while not self._stop:
				server_socket.listen(1) #?? 1 ??
				client_socket, client_addr = server_socket.accept()
				common.internal_print(("Client connected: {0}".format(client_addr)), 0, self.verbosity, common.DEBUG)

				threadsnum = threadsnum + 1
				thread = SCTP_generic_thread(threadsnum, 1, self.tunnel, self.packetselector, client_socket, client_addr, self.authentication, self.encryption_module, self.verbosity, self.config, self.get_module_name())
				thread.start()
				self.threads.append(thread)
			if self._stop:
				self.stop()

		except socket.error as exception:
			# [Errno 98] Address already in use
			if exception.args[0] != 98:
				raise
			else:
				common.internal_print("Starting failed, port is in use: {0} on {1}:{2}".format(self.get_module_name(), self.config.get("Global", "serverbind"), int(self.config.get(self.get_module_configname(), "serverport"))), -1)

		self.cleanup(server_socket)

		return

	def connect(self):
		try:
			common.internal_print("Starting client: {0}".format(self.get_module_name()))

			client_fake_thread = None

			server_socket = self.sctp.sctpsocket_tcp(socket.AF_INET)
			server_socket.settimeout(3)
			server_socket.connect((self.config.get("Global", "remoteserverip"), int(self.config.get(self.get_module_configname(), "serverport"))))

			client_fake_thread = SCTP_generic_thread(0, 0, self.tunnel, None, server_socket, None, self.authentication, self.encryption_module, self.verbosity, self.config, self.get_module_name())
			client_fake_thread.do_hello()
			client_fake_thread.communication(False)

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
			common.internal_print("Checking module on server: {0}".format(self.get_module_name()))

			server_socket = self.sctp.sctpsocket_tcp(socket.AF_INET)
			server_socket.settimeout(3)
			server_socket.connect((self.config.get("Global", "remoteserverip"), int(self.config.get(self.get_module_configname(), "serverport"))))
			client_fake_thread = SCTP_generic_thread(0, 0, None, None, server_socket, None, self.authentication, self.encryption_module, self.verbosity, self.config, self.get_module_name())
			client_fake_thread.do_check()
			client_fake_thread.communication(True)

			self.cleanup(server_socket)

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

	def cleanup(self, socket):
		common.internal_print("Shutting down module: {0}".format(self.get_module_name()))
		socket.close()

		return