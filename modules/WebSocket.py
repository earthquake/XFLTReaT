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

if "WebSocket.py" in sys.argv[0]:
	print("[-] Instead of poking around just try: python xfltreat.py --help")
	sys.exit(-1)

import socket
import time
import select
import os
import struct
import threading
import base64

#local files
from modules import Stateful_module
from modules import TCP_generic
import client
import common
import support.websocket_proto as WebSocket_proto

class WebSocket_thread(TCP_generic.TCP_generic_thread):
	def __init__(self, threadID, serverorclient, tunnel, packetselector, comms_socket, client_addr, authentication, encryption_module, verbosity, config, module_name):
		super(WebSocket_thread, self).__init__(threadID, serverorclient, tunnel, packetselector, comms_socket, client_addr, authentication, encryption_module, verbosity, config, module_name)

		self.WebSocket_proto = WebSocket_proto.WebSocket_Proto()

		return

	def communication_initialization(self):
		try:
		
			common.internal_print("Waiting for upgrade request", 0, self.verbosity, common.DEBUG)
			response = self.comms_socket.recv(4096).decode('ascii')

			if len(response) == 0:
				common.internal_print("Connection was dropped", 0, self.verbosity, common.DEBUG)
				self.cleanup()
				sys.exit(-1)
			handshake_key = self.WebSocket_proto.get_handshake_init(response)
			if handshake_key == None:
				common.internal_print("No WebSocket-Key in request", -1, self.verbosity, common.DEBUG)
				self.cleanup()
				sys.exit(-1)

			handshake = self.WebSocket_proto.calculate_handshake(handshake_key)
			response = self.WebSocket_proto.switching_protocol(handshake)
			self.comms_socket.send(response.encode('ascii'))
		except Exception as e:
			common.internal_print("Socket error: {0}".format(e), -1, self.verbosity, common.DEBUG)
			self.cleanup()
			sys.exit(-1)

		return

	def send(self, channel_type, message, additional_data):
		if channel_type == common.CONTROL_CHANNEL_BYTE:
			transformed_message = self.transform(self.encryption, common.CONTROL_CHANNEL_BYTE+message, 1)
		else:
			transformed_message = self.transform(self.encryption, common.DATA_CHANNEL_BYTE+message, 1)

		websocket_msg = self.WebSocket_proto.build_message(self.serverorclient, 2, transformed_message)

		common.internal_print("WebSocket sent: {0} -> {1}".format(len(transformed_message), len(websocket_msg)), 0, self.verbosity, common.DEBUG)

		# WORKAROUND?!
		# Windows: It looks like when the buffer fills up the OS does not do
		# congestion control, instead throws and exception/returns with
		# WSAEWOULDBLOCK which means that we need to try it again later.
		# So we sleep 100ms and hope that the buffer has more space for us.
		# If it does then it sends the data, otherwise tries it in an infinite
		# loop...
		while True:
			try:
				return self.comms_socket.send(websocket_msg)
			except socket.error as se:
				if se.args[0] == 10035: # WSAEWOULDBLOCK
					time.sleep(0.1)
					pass
				else:
					raise

	def recv(self):
		messages = []
		message = self.partial_message + self.comms_socket.recv(4096)
		if len(message) == len(self.partial_message):
			self._stop = True

		if len(message) < 2:
			return messages

		while True:
			length2b = message[0:2]
			length_type = self.WebSocket_proto.get_length_type(length2b)
			if length_type == -1:
				common.internal_print("Malformed WebSocket packet", -1, self.verbosity, common.DEBUG)
				return ""

			masked = self.WebSocket_proto.is_masked(length2b)
			header_length = self.WebSocket_proto.get_header_length(masked, length_type)
			
			if len(message) < header_length:
				common.internal_print("Malformed WebSocket packet: wrong header length", -1, self.verbosity, common.DEBUG)
				return ""

			data_length = self.WebSocket_proto.get_data_length(message[:header_length], masked, length_type)
			length = data_length + header_length

			if len(message) >= length:
				messages.append(self.transform(self.encryption, self.WebSocket_proto.get_data(message[0:length], header_length, data_length), 0))
				common.internal_print("WebSocket read: {0} -> {1}".format(length, len(messages[len(messages)-1])), 0, self.verbosity, common.DEBUG)
				self.partial_message = ""
				message = message[length:]
			else:
				self.partial_message = message
				break

			if len(message) < 2:
				self.partial_message = message
				break

		return messages


class WebSocket(TCP_generic.TCP_generic):

	module_name = "WebSocket"
	module_configname = "WebSocket"
	module_description = """
		"""
	module_os_support = common.OS_LINUX

	def __init__(self):
		super(WebSocket, self).__init__()
		self.server_socket = None
		self.WebSocket_proto = WebSocket_proto.WebSocket_Proto()

		return

	def websocket_upgrade(self, server_socket):

		base64.b64encode(os.urandom(9)).decode('ascii').replace("/", "").replace("+", "")
		request = self.WebSocket_proto.upgrade(base64.b64encode(os.urandom(9)).decode('ascii').replace("/", "").replace("+", ""), self.config.get("Global", "remoteserverhost"), self.config.get(self.get_module_configname(), "serverport"), 13)
		server_socket.send(request.encode('ascii'))
		
		response = server_socket.recv(4096)
		if response[9:12] != b"101":
			common.internal_print("Connection failed: {0}".format(response[0:response.decode('ascii').find("\n")]), -1)

			return False

		return True

	def sanity_check(self):
		if not super(WebSocket, self).sanity_check():
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


		if not self.config.has_option("Global", "remoteserverhost"):
			common.internal_print("'remoteserverhost' option is missing from 'Global' section", -1)

			return False

		if not common.is_hostname(self.config.get("Global", "remoteserverhost")) and not common.is_ipv4(self.config.get("Global", "remoteserverhost")) and not common.is_ipv6(self.config.get("Global", "remoteserverhost")):
			common.internal_print("'remoteserverhost' should be a hostname 'Global' section", -1)

			return False

		return True

	def serve(self):
		client_socket = server_socket = None
		self.threads = []
		threadsnum = 0

		common.internal_print("Starting module: {0} on {1}:{2}".format(self.get_module_name(), self.config.get("Global", "serverbind"), int(self.config.get(self.get_module_configname(), "serverport"))))
		
		server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

		try:
			server_socket.bind((self.config.get("Global", "serverbind"), int(self.config.get(self.get_module_configname(), "serverport"))))
			while not self._stop:
				server_socket.listen(1) #?? 1 ??
				client_socket, client_addr = server_socket.accept()
				common.internal_print(("Client connected: {0}".format(client_addr)), 0, self.verbosity, common.DEBUG)

				threadsnum = threadsnum + 1
				thread = WebSocket_thread(threadsnum, 1, self.tunnel, self.packetselector, client_socket, client_addr, self.authentication, self.encryption_module, self.verbosity, self.config, self.get_module_name())
				thread.start()
				self.threads.append(thread)

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

			server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			server_socket.settimeout(3)
			server_socket.connect((self.config.get(self.get_module_configname(), "proxyip"), int(self.config.get(self.get_module_configname(), "proxyport"))))

			if self.websocket_upgrade(server_socket):
				client_fake_thread = WebSocket_thread(0, 0, self.tunnel, None, server_socket, None, self.authentication, self.encryption_module, self.verbosity, self.config, self.get_module_name())
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

			server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			server_socket.settimeout(3)
			server_socket.connect((self.config.get(self.get_module_configname(), "proxyip"), int(self.config.get(self.get_module_configname(), "proxyport"))))
			
			if self.websocket_upgrade(server_socket):
				client_fake_thread = WebSocket_thread(0, 0, None, None, server_socket, None, self.authentication, self.encryption_module, self.verbosity, self.config, self.get_module_name())
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

	def get_intermediate_hop(self, config):
		if config.has_option(self.get_module_configname(), "proxyip"):
			if common.is_ipv4(config.get(self.get_module_configname(), "proxyip")) or common.is_ipv6(config.get(self.get_module_configname(), "proxyip")):
				remoteserverip = config.get(self.get_module_configname(), "proxyip")

				return remoteserverip
		return ""