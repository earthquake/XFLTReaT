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

if "TCP_generic.py" in sys.argv[0]:
	print "[-] Instead of poking around just try: python xfltreat.py --help"
	sys.exit(-1)

import socket
import time
import select
import os
import struct
import threading

#local files
import Stateful_module
import client
import common

class TCP_generic_thread(Stateful_module.Stateful_thread):
	def __init__(self, threadID, serverorclient, tunnel, packetselector, comms_socket, client_addr, auth_module, verbosity, config, module_name):
		super(TCP_generic_thread, self).__init__()
		threading.Thread.__init__(self)
		self._stop = False
		self.threadID = threadID
		self.tunnel_r = None
		self.tunnel_w = tunnel
		self.packetselector = packetselector
		self.comms_socket = comms_socket
		self.client_addr = client_addr
		self.auth_module = auth_module
		self.verbosity = verbosity
		self.serverorclient = serverorclient
		self.config = config
		self.module_name = module_name
		self.check_result = None
		self.timeout = 3.0
		self.partial_message = ""

		self.client = None
		self.authenticated = False

		return

	def communication_initialization(self):
		self.client = client.Client()
		self.client.set_socket(self.comms_socket)

		return

	# check request: generating a challenge and sending it to the server
	# in case the answer is that is expected, the targer is a valid server
	def do_check(self):
		message, self.check_result = self.checks.check_default_generate_challenge()
		self.send(common.CONTROL_CHANNEL_BYTE, common.CONTROL_CHECK+message, None)

		return

	# basic authentication support. mostly placeholder for a proper 
	# authentication. Time has not come yet.
	def do_auth(self):
		message = self.auth_module.send_details(self.config.get("Global", "clientip"))
		self.send(common.CONTROL_CHANNEL_BYTE, common.CONTROL_AUTH+message, None)

		return

	# Polite signal towards the server to tell that the client is leaving
	# Can be spoofed? if there is no encryption. Who cares?
	def do_logoff(self):
		self.send(common.CONTROL_CHANNEL_BYTE, common.CONTROL_LOGOFF, None)

		return

	def send(self, channel_type, message, additional_data):
		if channel_type == common.CONTROL_CHANNEL_BYTE:
			transformed_message = self.transform(common.CONTROL_CHANNEL_BYTE+message, 1)
		else:
			transformed_message = self.transform(common.DATA_CHANNEL_BYTE+message, 1)

		common.internal_print("TCP sent: {0}".format(len(transformed_message)), 0, self.verbosity, common.DEBUG)

		# WORKAROUND?!
		# Windows: It looks like when the buffer fills up the OS does not do
		# congestion control, instead throws and exception/returns with
		# WSAEWOULDBLOCK which means that we need to try it again later.
		# So we sleep 100ms and hope that the buffer has more space for us.
		# If it does then it sends the data, otherwise tries it in an infinite
		# loop...
		while True:
			try:
				return self.comms_socket.send(struct.pack(">H", len(transformed_message))+transformed_message)
			except socket.error as se:
				if se.args[0] == 10035: # WSAEWOULDBLOCK
					time.sleep(0.1)
					pass
				else:
					raise


	def recv(self):
		messages = []
		message = self.partial_message + self.comms_socket.recv(4096)

		if len(message) < 2:
			return messages

		while True:
			length = struct.unpack(">H", message[0:2])[0]+2
			if len(message) >= length:
				messages.append(self.transform(message[2:length], 0))
				common.internal_print("TCP read22: {0}".format(len(messages[len(messages)-1])), 0, self.verbosity, common.DEBUG)
				self.partial_message = ""
				message = message[length:]
			else:
				self.partial_message = message
				break

			if len(message) < 2:
				self.partial_message = message
				break

		return messages

	def cleanup(self):
		try:
			self.comms_socket.close()
		except:
			pass

		if self.serverorclient:
			self.packetselector.delete_client(self.client)

	def communication_win(self, is_check):
		import win32event
		import win32file
		import win32api
		import pywintypes
		import winerror

		# event for the socket
		hEvent_sock = win32event.CreateEvent(None, 0, 0, None)
		win32file.WSAEventSelect(self.comms_socket, hEvent_sock, win32file.FD_READ)

		# event, overlapped struct for the pipe or tunnel
		hEvent_pipe = win32event.CreateEvent(None, 0, 0, None) # for reading from the pipe
		overlapped_pipe = pywintypes.OVERLAPPED()
		overlapped_pipe.hEvent = hEvent_pipe

		# buffer for the packets
		message_readfile = win32file.AllocateReadBuffer(4096)

		# showing if we already async reading or not
		not_reading_already = True
		first_run = True
		while not self._stop:
			try:
				if not self.tunnel_r:
					# user is not authenticated yet, so there is no pipe
					# only checking the socket for data
					rc = win32event.WaitForSingleObject(hEvent_sock, int(self.timeout*1000))
				else:
					# client mode so we have the socket and tunnel as well
					# or the client authenticated and the pipe was created
					if first_run or not_reading_already:
						# no ReadFile was called before or finished, so we
						# are calling it again
						hr, _ = win32file.ReadFile(self.tunnel_r, message_readfile, overlapped_pipe)
						not_reading_already = first_run = False

					if (hr == winerror.ERROR_IO_PENDING):
						# well, this was an async read, so we need to wait
						# until it happens
						rc = win32event.WaitForMultipleObjects([hEvent_sock, hEvent_pipe], 0, int(self.timeout*1000))
						if rc == winerror.WAIT_TIMEOUT:
							# timed out, just rerun and wait
							continue
					else:
						if hr != 0:
							common.internal_print("TCP ReadFile failed: {0}".format(hr), -1)
							raise

				if rc < 0x80: # STATUS_ABANDONED_WAIT_0
					if rc == 0:
						# socket got signalled
						not_reading_already = False
						messages = self.recv()
						for message in messages:
							# looping through the messages from socket
							if len(message) == 0:
								# this could happen when the socket died or
								# partial message was read.
								continue

							if common.is_control_channel(message[0:1]):
								# parse control messages
								if self.controlchannel.handle_control_messages(self, message[len(common.CONTROL_CHANNEL_BYTE):], None):
									continue
								else:
									self.stop()
									break

							if self.authenticated:
								try:
									# write packet to the tunnel
									self.packet_writer(message[len(common.CONTROL_CHANNEL_BYTE):])
								except OSError as e:
									print e # wut?
								except Exception as e:
									if e.args[0] == 995:
										common.internal_print("Interface disappered, exiting thread: {0}".format(e), -1)
										self.stop()
										continue

									print "exception2 %d" % len(message[len(common.CONTROL_CHANNEL_BYTE):])
									print e
					if rc == 1:
						# pipe/tunnel got signalled
						not_reading_already = True
						if (overlapped_pipe.InternalHigh < 4) or (message_readfile[0:1] != "\x45"): #Only care about IPv4
							# too small which should not happen or not IPv4, so we just drop it.
							continue

						# reading out the packet from the buffer and discarding the rest
						readytogo = message_readfile[0:overlapped_pipe.InternalHigh]
						self.send(common.DATA_CHANNEL_BYTE, readytogo, None)

			except win32api.error as e:
				common.internal_print("TCP Exception: {0}".format(e), -1)

		self.cleanup()

		return True


	def communication_unix(self, is_check):
		rlist = [self.comms_socket]
		wlist = []
		xlist = []

		while not self._stop:
			if self.tunnel_r:
				rlist = [self.tunnel_r, self.comms_socket]
			try:
				readable, writable, exceptional = select.select(rlist, wlist, xlist, self.timeout)
			except select.error, e:
				break	
			if self._stop:
				self.comms_socket.close()
				break
			try:
				for s in readable:
					if (s is self.tunnel_r) and not self._stop:
						message = self.packet_reader(self.tunnel_r, True, self.serverorclient)
						while True:
							if (len(message) < 4) or (message[0:1] != "\x45"): #Only care about IPv4
								break
							packetlen = struct.unpack(">H", message[2:4])[0] # IP Total length
							if packetlen > len(message):
								message += self.packet_reader(self.tunnel_r, False, self.serverorclient)

							readytogo = message[0:packetlen]
							message = message[packetlen:]
							self.send(common.DATA_CHANNEL_BYTE, readytogo, None)

					if (s is self.comms_socket) and not self._stop:
						messages = self.recv()
						for message in messages:
							if len(message) == 0:
								continue

							if common.is_control_channel(message[0:1]):
								if self.controlchannel.handle_control_messages(self, message[len(common.CONTROL_CHANNEL_BYTE):], None):
									continue
								else:
									self.stop()
									break

							if self.authenticated:
								try:
									self.packet_writer(message[len(common.CONTROL_CHANNEL_BYTE):])
								except OSError as e:
									print "self.partial_message: %r" % self.partial_message
									print "message: %r" % message
									print e # wut?
								except Exception as e:
									print e

			except (socket.error, OSError, IOError):
				if self.serverorclient:
					common.internal_print("Client lost. Closing down thread.", -1)
					self.cleanup()

					return
				if not self.serverorclient:
					common.internal_print("Server lost. Closing connection.", -1)
					self.comms_socket.close()
				break
			except:
				print "another error"
				raise

		self.cleanup()

		return True


class TCP_generic(Stateful_module.Stateful_module):

	module_name = "TCP generic"
	module_configname = "TCP_generic"
	module_description = """Generic TCP module that can listen on any port.
		This module lacks of any encryption or encoding, which comes to the interface
		goes to the socket back and forth. Nothing special.
		"""
	module_os_support = common.OS_LINUX | common.OS_MACOSX | common.OS_WINDOWS

	def __init__(self):
		super(TCP_generic, self).__init__()
		self.server_socket = None

		return

	def stop(self):
		self._stop = True

		if self.threads:
			for t in self.threads:
				t.stop()
		
		# not so nice solution to get rid of the block of accept()
		# unfortunately close() does not help on the block
		try:
			server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			serverbind = self.config.get("Global", "serverbind")
			if serverbind == "0.0.0.0":
				# windows does not like to connect to 0.0.0.0
				serverbind = "127.0.0.1"

			server_socket.connect((serverbind, int(self.config.get(self.get_module_configname(), "serverport"))))
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
		
		server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		try:
			server_socket.bind((self.config.get("Global", "serverbind"), int(self.config.get(self.get_module_configname(), "serverport"))))
			while not self._stop:
				server_socket.listen(1) #?? 1 ??
				client_socket, client_addr = server_socket.accept()
				common.internal_print(("Client connected: {0}".format(client_addr)), 0, self.verbosity, common.DEBUG)

				threadsnum = threadsnum + 1
				thread = TCP_generic_thread(threadsnum, 1, self.tunnel, self.packetselector, client_socket, client_addr, self.auth_module, self.verbosity, self.config, self.get_module_name())
				thread.start()
				self.threads.append(thread)
			if self._stop:
				self.stop()

		except socket.error as exception:
			# [Errno 98] Address already in use
			if ((self.os_type == common.OS_LINUX) and (exception.args[0] == 98)) or ((self.os_type == common.OS_MACOSX) and (exception.args[0] == 48)):
				common.internal_print("Starting failed, port is in use: {0} on {1}:{2}".format(self.get_module_name(), self.config.get("Global", "serverbind"), int(self.config.get(self.get_module_configname(), "serverport"))), -1)
			else:
				raise

		self.cleanup(server_socket)

		return

	def connect(self):
		try:
			common.internal_print("Starting client: {0}".format(self.get_module_name()))

			client_fake_thread = None

			server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			server_socket.settimeout(3)
			server_socket.connect((self.config.get("Global", "remoteserverip"), int(self.config.get(self.get_module_configname(), "serverport"))))

			client_fake_thread = TCP_generic_thread(0, 0, self.tunnel, None, server_socket, None, self.auth_module, self.verbosity, self.config, self.get_module_name())
			client_fake_thread.do_auth()
			client_fake_thread.communication(False)

		except KeyboardInterrupt:
			if client_fake_thread:
				client_fake_thread.do_logoff()
			self.cleanup(server_socket)
			raise
		except socket.error as e:
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
			server_socket.connect((self.config.get("Global", "remoteserverip"), int(self.config.get(self.get_module_configname(), "serverport"))))
			client_fake_thread = TCP_generic_thread(0, 0, None, None, server_socket, None, self.auth_module, self.verbosity, self.config, self.get_module_name())
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