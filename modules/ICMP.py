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

if "ICMP.py" in sys.argv[0]:
	print("[-] Instead of poking around just try: python xfltreat.py --help")
	sys.exit(-1)

import socket
import time
import select
import os
import struct
import threading
import random
import subprocess

#local files
import Stateless_module
import encryption
import client
import common
from support.icmp_proto import ICMP_Proto
from support.icmp_proto import ICMP_Client

class ICMP(Stateless_module.Stateless_module):

	module_name = "ICMP"
	module_configname = "ICMP"
	module_description = """ICMP type 8+0 module. Sends ping requests and 
	responses. Just an ordinary ping tunnel."""
	module_os_support = common.OS_LINUX | common.OS_MACOSX | common.OS_WINDOWS

	def __init__(self):
		super(ICMP, self).__init__()
		self.icmp = ICMP_Proto()
		self.ICMP_sequence = 0
		# identifier lottery
		self.ICMP_identifier = int(random.random() * 65535)
		# serverport lottery, not like it matters
		self.ICMP_fake_serverport = int(random.random() * 65535)
		# prefix to make it easier to detect xfl packets
		self.ICMP_prefix = "XFL"
		self.timeout = 2.0
		# if the recv-sent>threshold:
		self.TRACKING_THRESHOLD = 50
		# then we cut back the difference with adjust:
		self.TRACKING_ADJUST = 20

		return

	def init_client(self, control_message, additional_data):
		addr = additional_data[0]
		identifier = additional_data[1]
		sequence = additional_data[2]

		client_local = ICMP_Client()
		client_local.set_ICMP_received_identifier(identifier)
		client_local.set_ICMP_received_sequence(sequence)
		client_local.set_ICMP_sent_identifier(identifier)
		client_local.set_ICMP_sent_sequence(sequence)

		client_private_ip = control_message[0:4]
		client_public_source_ip = socket.inet_aton(addr[0])
		client_public_source_port = addr[1]

		# If this private IP is already used, the server removes that client.
		# For example: client reconnect on connection reset, duplicated configs
		# and yes, this can be used to kick somebody off the tunnel

		# close client related pipes
		for c in self.clients:
			if c.get_private_ip_addr() == client_private_ip:
				save_to_close = c
				self.clients.remove(c)
				if c.get_pipe_r() in self.rlist:
					self.rlist.remove(c.get_pipe_r())

		found = False
		for c in self.packetselector.get_clients():
			if c.get_private_ip_addr() == client_private_ip:
				found = True
				self.packetselector.delete_client(c)

		# If client was created but not added to the PacketSelector, then the
		# pipes still need to be closed. This could happen when the authenti-
		# cation fails or gets interrupted.
		if not found:
			if self.os_type == common.OS_WINDOWS:
				import win32file

				try:
					win32file.CloseHandle(save_to_close.get_pipe_r())
					win32file.CloseHandle(save_to_close.get_pipe_w())
				except:
					pass
			else:
				try:
					save_to_close.get_pipe_r_fd().close()
					save_to_close.get_pipe_w_fd().close()
				except:
					pass

		# creating new pipes for the client
		pipe_r, pipe_w = os.pipe()
		client_local.set_pipes_fdnum(pipe_r, pipe_w)
		client_local.set_pipes_fd(os.fdopen(pipe_r, "r"), os.fdopen(pipe_w, "w"))

		# set connection related things and authenticated to True
		client_local.set_public_ip_addr(client_public_source_ip)
		client_local.set_public_src_port(client_public_source_port)
		client_local.set_private_ip_addr(client_private_ip)

		client_local.get_encryption().set_module(self.encryption.get_module())
		self.encryption = client_local.get_encryption()

		if self.encryption.get_module().get_step_count():
			# add encryption steps
			self.merge_cmh(self.encryption.get_module().get_cmh_struct())

		if self.authentication.get_step_count():
			# add authentication steps
			self.merge_cmh(self.authentication.get_cmh_struct())

		client_local.set_initiated(True)
		self.clients.append(client_local)

		return

	def lookup_client_pub(self, additional_data):
		addr = additional_data[0]
		identifier = additional_data[1]
		client_public_ip = socket.inet_aton(addr[0])

		for c in self.clients:
			if (c.get_public_ip_addr() == client_public_ip) and (c.get_ICMP_received_identifier() == identifier):
				return c

		return None

	def post_authentication_server(self, control_message, additional_data):
		addr = additional_data[0]
		identifier = additional_data[1]
		c = self.lookup_client_pub((addr, identifier))
		if c.get_initiated():
			c.set_authenticated(True)
			self.packetselector.add_client(c)
			if c.get_pipe_r() not in self.rlist:
				self.rlist.append(c.get_pipe_r())
			return True

		return False

	def remove_initiated_client(self, control_message, additional_data):
		addr = additional_data[0]
		identifier = additional_data[1]
		c = self.lookup_client_pub((addr, identifier))
		if c:
			self.packetselector.delete_client(c)
			if c.get_authenticated():
				self.rlist.remove(c.get_pipe_r())
			self.clients.remove(c)

		return

	def communication_initialization(self):
		self.clients = []
		if self.serverorclient:
			if self.os_type == common.OS_LINUX:
				ps = subprocess.Popen(["cat", "/proc/sys/net/ipv4/icmp_echo_ignore_all"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
				(stdout, stderr) = ps.communicate()
				if stderr:
					common.internal_print("Error: deleting default route: {0}".format(stderr), -1)
					sys.exit(-1)
				self.orig_ieia_value = stdout[0:1]
				os.system("echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all")

		if self.serverorclient:
			self.ICMP_send = self.icmp.ICMP_ECHO_RESPONSE
		else:
			self.ICMP_send = self.icmp.ICMP_ECHO_REQUEST
		return

	def modify_additional_data(self, additional_data, serverorclient):
		if serverorclient:
			c = self.lookup_client_pub(additional_data)
			if c:
				c.set_ICMP_sent_sequence(additional_data[2])
			return additional_data
		else:
			# increment sequence in additional data
			self.ICMP_sequence += 1
			return (additional_data[0], additional_data[1], self.ICMP_sequence, additional_data[3])

	# check request: generating a challenge and sending it to the server
	# in case the answer is that is expected, the targer is a valid server
	def do_check(self):
		message, self.check_result = self.checks.check_default_generate_challenge()
		self.send(common.CONTROL_CHANNEL_BYTE, common.CONTROL_CHECK+message, 
			(self.server_tuple, self.ICMP_identifier, 0, 0))

		return

	# start talking to the server
	# do authentication or encryption first
	def do_hello(self):
		# TODO: maybe change this later to push some more info, not just the 
		# private IP
		message = socket.inet_aton(self.config.get("Global", "clientip"))
		self.send(common.CONTROL_CHANNEL_BYTE, common.CONTROL_INIT+message, 
			(self.server_tuple, self.ICMP_identifier, self.ICMP_sequence, 0))

	# Polite signal towards the server to tell that the client is leaving
	# Can be spoofed? if there is no encryption. Who cares?
	def do_logoff(self):
		self.send(common.CONTROL_CHANNEL_BYTE, common.CONTROL_LOGOFF, 
			(self.server_tuple, self.ICMP_identifier, self.ICMP_sequence, 0))

		return

	def do_dummy_packet(self, identifier, sequence):
		self.send(common.CONTROL_CHANNEL_BYTE, common.CONTROL_DUMMY_PACKET, 
			(self.server_tuple, identifier, sequence, 0))

		return

	def send(self, channel_type, message, additional_data):
		addr = additional_data[0]
		identifier = additional_data[1]
		sequence = additional_data[2]
		queue_length = additional_data[3]

		if queue_length < 256:
			ql = chr(queue_length)
		else:
			ql = chr(255)

		if channel_type == common.CONTROL_CHANNEL_BYTE:
			transformed_message = self.transform(self.get_client_encryption(additional_data), ql+common.CONTROL_CHANNEL_BYTE+message, 1)
		else:
			transformed_message = self.transform(self.get_client_encryption(additional_data), ql+common.DATA_CHANNEL_BYTE+message, 1)

		common.internal_print("ICMP sent: {0} seq: {1} id: {2}".format(len(transformed_message), sequence, identifier), 0, self.verbosity, common.DEBUG)

		packet = self.icmp.create_packet(self.ICMP_send, identifier, sequence,
			self.ICMP_prefix+struct.pack(">H", len(transformed_message))+transformed_message)

		# WORKAROUND?!
		# Windows: It looks like when the buffer fills up the OS does not do
		# congestion control, instead throws and exception/returns with
		# WSAEWOULDBLOCK which means that we need to try it again later.
		# So we sleep 100ms and hope that the buffer has more space for us.
		# If it does then it sends the data, otherwise tries it in an infinite
		# loop...
		while True:
			try:
				return self.comms_socket.sendto(packet, addr)
			except socket.error as se:
				if se.args[0] == 10035: # WSAEWOULDBLOCK
					time.sleep(0.1)
					pass
				else:
					raise

	def recv(self):
		message, addr = self.comms_socket.recvfrom(1508)

		identifier = struct.unpack("<H", message[24:26])[0]
		sequence = struct.unpack(">H", message[26:28])[0]

		if message[28:28+len(self.ICMP_prefix)] != self.ICMP_prefix:
			return ("", None, None, None, None)

		message = message[28+len(self.ICMP_prefix):]

		length = struct.unpack(">H", message[0:2])[0]
		if (length+2 != len(message)):
			common.internal_print("Error length mismatch {0} {1}".format(length, len(message)), -1)
			return ("", None, None, None, None)

		message = self.transform(self.get_client_encryption((addr, identifier, 0, 0)), message[2:length+2], 0)
		queue_length = struct.unpack(">B", message[0:1])[0]
		common.internal_print("ICMP read: {0} seq: {1} id: {2}".format(length, sequence, identifier), 0, self.verbosity, common.DEBUG)

		return message[1:], addr, identifier, sequence, queue_length

	def communication_win(self, is_check):
		import win32event
		import win32file
		import win32api
		import pywintypes
		import winerror

		# event for the socket
		hEvent_sock = win32event.CreateEvent(None, 0, 0, None)
		win32file.WSAEventSelect(self.comms_socket, hEvent_sock, win32file.FD_READ)

		# descriptor list
		self.rlist = [self.comms_socket]
		# overlapped list
		self.olist = [0]
		# event list
		self.elist = [hEvent_sock]
		# message buffer list
		self.mlist = [0]
		# id of the read object - put in this if it was read
		self.ulist = []
		if not self.serverorclient and self.tunnel:
				# client mode
				# objects created for the tunnel and put in the corresponding
				# lists
				hEvent_pipe = win32event.CreateEvent(None, 0, 0, None) # for reading from the pipe
				overlapped_pipe = pywintypes.OVERLAPPED()
				overlapped_pipe.hEvent = hEvent_pipe
				message_buffer = win32file.AllocateReadBuffer(4096)
				self.rlist.append(self.tunnel)
				self.olist.append(overlapped_pipe)
				self.elist.append(hEvent_pipe)
				self.mlist.append(message_buffer)
				self.ulist.append(1)

		while not self._stop:
			try:
				if not self.tunnel:
					# check or server mode without client only with socket
					#message, addr = self.comms_socket.recvfrom(1508)
					rc = win32event.WaitForSingleObject(hEvent_sock, int(self.timeout*1000))
					if rc == winerror.WAIT_TIMEOUT:
						# timed out, just rerun and wait
						continue

				else:
					if self.ulist:
						# there is somebody waiting to be read
						for idx in self.ulist:
							# issueing ReadFile on all not yet read mailslots/tunnel
							hr, _ = win32file.ReadFile(self.rlist[idx], self.mlist[idx], self.olist[idx])
							if (hr != 0) and (hr != winerror.ERROR_IO_PENDING):
								common.internal_print("UDP ReadFile failed: {0}".format(hr), -1)
								raise

						self.ulist = []

					# waiting to get some data somewhere
					rc = win32event.WaitForMultipleObjects(self.elist, 0, int(self.timeout*1000))
					if rc == winerror.WAIT_TIMEOUT:
						# timed out, just rerun and wait
						continue

				if rc < 0x80: # STATUS_ABANDONED_WAIT_0
					if rc > 0:
						# the tunnel or one of the mailslots got signalled
						self.ulist.append(rc)
						if (self.olist[rc].InternalHigh < 4) or (self.mlist[rc][0:1] != "\x45"): #Only care about IPv4
							continue

						readytogo = self.mlist[rc][0:self.olist[rc].InternalHigh]

						if self.serverorclient:
							c = self.lookup_client_priv(readytogo)
							if c:
								# if the differece between the received and set sequences too big
								# some routers/firewalls just drop older sequences. If it gets
								# too big, we just drop the older ones and use the latest X packet
								# this helps on stabality.
								if (c.get_ICMP_received_sequence() - c.get_ICMP_sent_sequence()) >= self.TRACKING_THRESHOLD:
									c.set_ICMP_sent_sequence(c.get_ICMP_received_sequence() - self.TRACKING_ADJUST)

								# get client related values: identifier and sequence number
								identifier = c.get_ICMP_sent_identifier()
								sequence = c.get_ICMP_sent_sequence()

								# queueing every packet first
								c.queue_put(readytogo)
								# are there any packets to answer?
								if (c.get_ICMP_received_sequence() - sequence) == 0:
									continue
								else:
									request_num = 0
									# if there is less packet than that we have in the queue
									# then we cap the outgoing packet number
									if (c.get_ICMP_received_sequence() - sequence) < (c.queue_length()):
										number_to_get = (c.get_ICMP_received_sequence() - sequence)
									else:
										# send all packets from the queue
										number_to_get = c.queue_length()

									for i in range(0, number_to_get):
										# get first packet
										readytogo = c.queue_get()
										# is it he last one we are sending now?
										if i == (number_to_get - 1):
											# if the last one and there is more in the queue
											# then we ask for dummy packets
											request_num = c.queue_length()
										# go packets go!
										self.send(common.DATA_CHANNEL_BYTE, readytogo,
											((socket.inet_ntoa(c.get_public_ip_addr()), c.get_public_src_port()),
											identifier, sequence + i + 1, request_num))

									sequence = (sequence + i + 1) % 65536
									c.set_ICMP_sent_sequence(sequence)
							else:
								# there is no client with that IP
								common.internal_print("Client not found, strange?!", 0, self.verbosity, common.DEBUG)
								continue
						else:
							if self.authenticated:
								# whatever we have from the tunnel, just encapsulate it
								# and send it out
								self.ICMP_sequence = (self.ICMP_sequence + 1) % 65536
								self.send(common.DATA_CHANNEL_BYTE, readytogo,
									(self.server_tuple, self.ICMP_identifier, self.ICMP_sequence, 0)) #??
							else:
								common.internal_print("Spoofed packets, strange?!", 0, self.verbosity, common.DEBUG)
								continue
					if rc == 0:
						# socket got signalled
						message, addr, identifier, sequence, queue_length = self.recv()

						if len(message) == 0:
							continue

						c = None
						if self.serverorclient:
							self.authenticated = False
							c = self.lookup_client_pub((addr, 0))
							if c:
								c.set_ICMP_received_identifier(identifier)
								# packets does not arrive in order sometime
								# if higher sequence arrived already, then we
								# do not modify
								# 16bit integer MAX could be a bit tricky, a
								# threshold had to be introduced to make it
								# fail safe. Hacky but should work.
								ICMP_THRESHOLD = 100
								if (sequence > c.get_ICMP_received_sequence()) or ((sequence < ICMP_THRESHOLD) and ((sequence + 65536)>c.get_ICMP_received_sequence()) and (c.get_ICMP_received_sequence()>ICMP_THRESHOLD)):
									c.set_ICMP_received_sequence(sequence)
						else:
							if queue_length:
								common.internal_print("sending {0} dummy packets".format(queue_length), 0, self.verbosity, common.DEBUG)
								for i in range(queue_length+10):
									self.ICMP_sequence = (self.ICMP_sequence + 1) % 65536
									self.do_dummy_packet(self.ICMP_identifier,
										self.ICMP_sequence)

						if common.is_control_channel(message[0:1]):
							if self.controlchannel.handle_control_messages(self, message[len(common.CONTROL_CHANNEL_BYTE):], (addr, identifier, sequence, 0)):
								continue
							else:
								self.stop()
								break

						if c:
							self.authenticated = c.get_authenticated()

						if self.authenticated:
							try:
								self.packet_writer(message[len(common.CONTROL_CHANNEL_BYTE):])
							except OSError as e:
								print(e)

			except win32api.error as e:
				common.internal_print("UDP Exception: {0}".format(e), -1)
			except socket.error as se:
				if se.args[0] == 10054: # port is unreachable
					common.internal_print("Server's port is unreachable: {0}".format(se), -1)
					self._stop = True

		return True


	def communication_unix(self, is_check):
		sequence = 0
		identifier = 0
		self.rlist = [self.comms_socket]
		if not self.serverorclient and self.tunnel:
				self.rlist = [self.tunnel, self.comms_socket]
		wlist = []
		xlist = []

		while not self._stop:
			try:
				readable, writable, exceptional = select.select(self.rlist, wlist, xlist, self.timeout)
			except select.error, e:
				common.internal_print("select.error: %r".format(e), -1)
				break
			try:
				if not readable:
					if is_check:
						raise socket.timeout
					if not self.serverorclient:
						if self.authenticated:
							self.ICMP_sequence = (self.ICMP_sequence + 1) % 65536
							self.do_dummy_packet(self.ICMP_identifier, self.ICMP_sequence)
							common.internal_print("Keep alive sent", 0, self.verbosity, common.DEBUG)
					continue

				for s in readable:
					if (s in self.rlist) and not (s is self.comms_socket):
						message = self.packet_reader(s, True, self.serverorclient)
						while True:
							if (len(message) < 4) or (message[0:1] != "\x45"): #Only care about IPv4
								break
							packetlen = struct.unpack(">H", message[2:4])[0] # IP Total length
							if packetlen > len(message):
								message += self.packet_reader(s, False, self.serverorclient)

							readytogo = message[0:packetlen]
							message = message[packetlen:]
							if self.serverorclient:
								c = self.lookup_client_priv(readytogo)

								if c:
									# if the differece between the received and set sequences too big
									# some routers/firewalls just drop older sequences. If it gets 
									# too big, we just drop the older ones and use the latest X packet
									# this helps on stabality.
									if (c.get_ICMP_received_sequence() - c.get_ICMP_sent_sequence()) >= self.TRACKING_THRESHOLD:
										c.set_ICMP_sent_sequence(c.get_ICMP_received_sequence() - self.TRACKING_ADJUST)

									# get client related values: identifier and sequence number
									identifier = c.get_ICMP_sent_identifier()
									sequence = c.get_ICMP_sent_sequence()

									# queueing every packet first
									c.queue_put(readytogo)
									# are there any packets to answer?
									if (c.get_ICMP_received_sequence() - sequence) == 0:
										continue
									else:
										request_num = 0
										# if there is less packet than that we have in the queue
										# then we cap the outgoing packet number
										if (c.get_ICMP_received_sequence() - sequence) < (c.queue_length()):
											number_to_get = (c.get_ICMP_received_sequence() - sequence)
										else:
											# send all packets from the queue
											number_to_get = c.queue_length()

										for i in range(0, number_to_get):

											# get first packet
											readytogo = c.queue_get()
											# is it he last one we are sending now?
											if i == (number_to_get - 1):
												# if the last one and there is more in the queue
												# then we ask for dummy packets
												request_num = c.queue_length()
											# go packets go!
											self.send(common.DATA_CHANNEL_BYTE, readytogo,
												((socket.inet_ntoa(c.get_public_ip_addr()), c.get_public_src_port()),
												identifier, sequence + i + 1, request_num))

										sequence = (sequence + i + 1) % 65536
										c.set_ICMP_sent_sequence(sequence)
								else:
									# there is no client with that IP
									common.internal_print("Client not found, strange?!", 0, self.verbosity, common.DEBUG)
									continue

							else:
								if self.authenticated:
									# whatever we have from the tunnel, just encapsulate it
									# and send it out
									self.ICMP_sequence = (self.ICMP_sequence + 1) % 65536
									self.send(common.DATA_CHANNEL_BYTE, readytogo,
										(self.server_tuple, self.ICMP_identifier, self.ICMP_sequence, 0)) #??
								else:
									common.internal_print("Spoofed packets, strange?!", 0, self.verbosity, common.DEBUG)
									continue


					if s is self.comms_socket:
						message, addr, identifier, sequence, queue_length = self.recv()
						
						if len(message) == 0:
							continue

						c = None
						if self.serverorclient:
							self.authenticated = False
							c = self.lookup_client_pub((addr, identifier))
							if c:
								c.set_ICMP_received_identifier(identifier)
								# packets does not arrive in order sometime
								# if higher sequence arrived already, then we
								# do not modify
								# 16bit integer MAX could be a bit tricky, a
								# threshold had to be introduced to make it
								# fail safe. Hacky but should work.
								ICMP_THRESHOLD = 100
								if (sequence > c.get_ICMP_received_sequence()) or ((sequence < ICMP_THRESHOLD) and ((sequence + 65536)>c.get_ICMP_received_sequence()) and (c.get_ICMP_received_sequence()>ICMP_THRESHOLD)):
									c.set_ICMP_received_sequence(sequence)
						else:
							if queue_length:
								common.internal_print("sending {0} dummy packets".format(queue_length), 0, self.verbosity, common.DEBUG)
								for i in range(queue_length+10):
									self.ICMP_sequence = (self.ICMP_sequence + 1) % 65536
									self.do_dummy_packet(self.ICMP_identifier,
										self.ICMP_sequence)

						if common.is_control_channel(message[0:1]):
							if self.controlchannel.handle_control_messages(self, message[len(common.CONTROL_CHANNEL_BYTE):], (addr, identifier, sequence, 0)):
								continue
							else:
								self.stop()
								break

						if c:
							self.authenticated = c.get_authenticated()
							
						if self.authenticated:
							try:
								self.packet_writer(message[len(common.CONTROL_CHANNEL_BYTE):])
							except OSError as e:
								print(e)

			except (socket.error, OSError):
				raise
				if self.serverorclient:
					self.comms_socket.close()
				break
			except:
				print("another error")
				raise

		return

	def serve(self):
		server_socket = None
		self.serverorclient = 1

		try:
			common.internal_print("Starting module: {0} on {1}".format(self.get_module_name(), self.config.get("Global", "serverbind")))
		
			server_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
			if (self.os_type == common.OS_WINDOWS) or (self.os_type == common.OS_MACOSX):
				common.internal_print("This module can be run in client mode only on this operating system.", -1)

				self.cleanup()
				return

			self.comms_socket = server_socket
			self.authenticated = False

			self.communication_initialization()
			self.communication(False) 
			
		except KeyboardInterrupt:

				self.cleanup()
				return

		self.cleanup()

		return

	def connect(self):
		try:
			common.internal_print("Starting client: {0}".format(self.get_module_name()))

			server_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
			if self.os_type == common.OS_WINDOWS:
				# this should give back the default route interface IP
				default_host_ip = socket.gethostbyname(socket.gethostname())
				server_socket.bind((default_host_ip, 0))

			self.server_tuple = (self.config.get("Global", "remoteserverip"), self.ICMP_fake_serverport)
			self.comms_socket = server_socket
			self.serverorclient = 0
			self.authenticated = False

			self.communication_initialization()
			self.do_hello()
			self.communication(False)

		except KeyboardInterrupt:
			self.do_logoff()
			self.cleanup()
			raise

		self.cleanup()

		return

	def check(self):
		try:
			common.internal_print("Checking module on server: {0}".format(self.get_module_name()))

			server_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
			if self.os_type == common.OS_WINDOWS:
				# this should give back the default route interface IP
				default_host_ip = socket.gethostbyname(socket.gethostname())
				server_socket.bind((default_host_ip, 0))

			self.server_tuple = (self.config.get("Global", "remoteserverip"), self.ICMP_fake_serverport)
			self.comms_socket = server_socket
			self.serverorclient = 0
			self.authenticated = False
			self.communication_initialization()
			self.do_check()
			self.communication(True)

		except KeyboardInterrupt:
			self.cleanup()
			raise
		except socket.timeout:
			common.internal_print("Checking failed: {0}".format(self.get_module_name()), -1)

		self.cleanup()

		return

	def cleanup(self):
		common.internal_print("Shutting down module: {0}".format(self.get_module_name()))
		if self.serverorclient:
			if self.os_type == common.OS_LINUX:
				os.system("echo {0} > /proc/sys/net/ipv4/icmp_echo_ignore_all".format(self.orig_ieia_value)) #???
		try:
			self.comms_socket.close()
		except:
			pass
		try:
			os.close(self.tunnel)
		except:
			pass




