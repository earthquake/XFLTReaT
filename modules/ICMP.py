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
	print "[-] Instead of poking around just try: python xfltreat.py --help"
	sys.exit(-1)

import socket
import time
import select
import os
import struct
import threading
import random

#local files
import Stateless_module
import client
import common
from support.icmp_proto import ICMP_Proto
from support.icmp_proto import ICMP_Client

#TODO: reverse check from the server
# if the client does not answer, the packets does not go thru
# seq must be modified.

class ICMP(Stateless_module.Stateless_module):

	module_name = "ICMP"
	module_configname = "ICMP"
	module_description = """...
	ICMP
	...
	"""

	def __init__(self):
		super(ICMP, self).__init__()
		self.icmp = ICMP_Proto()
		self.ICMP_sequence = 0
		self.ICMP_identifier = int(random.random() * 65535)
		self.ICMP_fake_serverport = int(random.random() * 65535)
		self.ICMP_prefix = "XFL"
		self.timeout = 2.0
		self.TRACKING_THRESHOLD = 50
		self.TRACKING_ADJUST = 20

		return

	def setup_authenticated_client(self, control_message, additional_data):
		addr = additional_data[0]
		identifier = additional_data[1]
		sequence = additional_data[2]

		client_local = ICMP_Client()
		common.init_client_stateless(control_message, addr, client_local, 
			self.packetselector, self.clients)
		self.clients.append(client_local)
		self.packetselector.add_client(client_local)
		if client_local.get_pipe_r() not in self.rlist:
			self.rlist.append(client_local.get_pipe_r())
		client_local.set_ICMP_received_identifier(identifier)
		client_local.set_ICMP_received_sequence(sequence)
		client_local.set_ICMP_sent_identifier(identifier)
		client_local.set_ICMP_sent_sequence(sequence)

		self.send(common.CONTROL_CHANNEL_BYTE, common.CONTROL_AUTH_OK, additional_data)

		return

	def remove_authenticated_client(self, additional_data):
		addr = additional_data[0] # ICMP specific
		c = common.lookup_client_pub(self.clients, addr)
		if c:
			self.packetselector.delete_client(c)
			self.rlist.remove(c.get_pipe_r())
			common.delete_client_stateless(self.clients, c)

		return

	def communication_initialization(self):
		self.clients = []
		os.system("echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all") #???

		if self.serverorclient:
			self.ICMP_send = self.icmp.ICMP_ECHO_RESPONSE
		else:
			self.ICMP_send = self.icmp.ICMP_ECHO_REQUEST
		return

	def do_check(self):
		message, self.check_result = self.checks.check_default_generate_challenge()
		self.send(common.CONTROL_CHANNEL_BYTE, common.CONTROL_CHECK+message, (self.server_tuple, self.ICMP_identifier, 0, 0)) #??

		return

	def do_auth(self):
		message = self.auth_module.send_details(self.config.get("Global", "clientip"))
		self.send(common.CONTROL_CHANNEL_BYTE, common.CONTROL_AUTH+message, (self.server_tuple, self.ICMP_identifier, 0, 0)) #??

		return

	def do_logoff(self):
		self.send(common.CONTROL_CHANNEL_BYTE, common.CONTROL_LOGOFF, (self.server_tuple, self.ICMP_identifier, 0, 0)) #??

		return

	def do_dummy_packet(self, identifier, sequence):
		self.send(common.CONTROL_CHANNEL_BYTE, common.CONTROL_DUMMY_PACKET, 
			(self.server_tuple, identifier, sequence, 0)) #??

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
			transformed_message = self.transform(ql+common.CONTROL_CHANNEL_BYTE+message, 1)
		else:
			transformed_message = self.transform(ql+common.DATA_CHANNEL_BYTE+message, 1)

		common.internal_print("ICMP sent: {0} seq: {1} id: {2}".format(len(transformed_message), sequence, identifier), 0, self.verbosity, common.DEBUG)

		return self.comms_socket.sendto(
			self.icmp.create_packet(self.ICMP_send, identifier, sequence, 
			self.ICMP_prefix+struct.pack(">H", len(transformed_message))+transformed_message), 
			addr)

	def recv(self):
		# self.transform is missing, TODO
		message, addr = self.comms_socket.recvfrom(1508)

		identifier = struct.unpack("<H", message[24:26])[0]
		#sequence = struct.unpack("<H", message[26:28])[0]
		sequence = struct.unpack(">H", message[26:28])[0]
		
		if message[28:28+len(self.ICMP_prefix)] != self.ICMP_prefix:
			return ("", None, None, None, None)

		message = message[28+len(self.ICMP_prefix):]
		length, queue_length = struct.unpack(">HB", message[0:3])
		length += 2

		if (length != len(message)):
			common.internal_print("Error length mismatch {0} {1}".format(length, len(message)), -1)
			return ("", None, None, None, None)

		common.internal_print("ICMP read: {0} seq: {1} id: {2}".format(len(message)-2, sequence, identifier), 0, self.verbosity, common.DEBUG)

		return message[3:], addr, identifier, sequence, queue_length

	def communication(self, is_check):
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
				print e
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
						message = os.read(s, 4096)
						while True:
							if (len(message) < 4) or (message[0:1] != "\x45"): #Only care about IPv4
								break
							packetlen = struct.unpack(">H", message[2:4])[0] # IP Total length
							if packetlen > len(message):
								message += os.read(s, 4096)

							readytogo = message[0:packetlen]
							message = message[packetlen:]
							if self.serverorclient:
								c = common.lookup_client_priv(self.clients, readytogo)

								if c:
									# if the differece between the received and set sequences too big
									# some routers/firewalls just drop older sequences. If it gets 
									# too big, we just drop the older ones and use the latest X packet
									# this helps on stabality.
									if (c.get_ICMP_received_sequence()-c.get_ICMP_sent_sequence()) >= self.TRACKING_THRESHOLD:
										c.set_ICMP_sent_sequence(c.get_ICMP_received_sequence()-self.TRACKING_ADJUST)

									identifier = c.get_ICMP_sent_identifier()
									sequence = c.get_ICMP_sent_sequence()

									if (c.get_ICMP_received_sequence() - sequence) == 0:
										c.queue_put(readytogo)
										continue
									else:
										if c.queue_length():
											c.queue_put(readytogo)
											i = 0
											if (c.get_ICMP_received_sequence() - sequence) < (c.queue_length()):
												number_to_get = (c.get_ICMP_received_sequence() - sequence)
											else:
												number_to_get = c.queue_length()
											for i in range(number_to_get - 1):
												readytogo = c.queue_get()
												self.send(common.DATA_CHANNEL_BYTE, readytogo,
													((socket.inet_ntoa(c.get_public_ip_addr()), c.get_public_src_port()), 
													identifier, (sequence + i + 1), 0)) #??
											readytogo = c.queue_get()
											sequence += i
										

										sequence = (sequence + 1) % 65536
										c.set_ICMP_sent_sequence(sequence)
										self.send(common.DATA_CHANNEL_BYTE, readytogo,
											((socket.inet_ntoa(c.get_public_ip_addr()), c.get_public_src_port()), 
											identifier, sequence, c.queue_length())) #??


								else:
									common.internal_print("Client not found, strange?!", 0, self.verbosity, common.DEBUG)
									continue

							else:
								if self.authenticated:
									self.ICMP_sequence = (self.ICMP_sequence + 1) % 65536
									self.send(common.DATA_CHANNEL_BYTE, readytogo, 
										(self.server_tuple, self.ICMP_identifier, self.ICMP_sequence, 0)) #??
									sequence = self.ICMP_sequence # del this line
									identifier = self.ICMP_identifier # del this line
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
							c = common.lookup_client_pub(self.clients, addr)
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
								os.write(self.tunnel, message[len(common.CONTROL_CHANNEL_BYTE):])
							except OSError as e:
								print e

			except (socket.error, OSError):
				raise
				if self.serverorclient:
					self.comms_socket.close()
				break
			except:
				print "another error"
				raise

		return

	def serve(self):
		server_socket = None
		try:
			common.internal_print("Starting module: {0} on {1}".format(self.get_module_name(), self.config.get("Global", "serverbind")))
		
			server_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
			whereto = (self.config.get("Global", "serverbind"), self.ICMP_fake_serverport)

			self.comms_socket = server_socket
			self.serverorclient = 1
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
			self.server_tuple = (self.config.get("Global", "remoteserverip"), self.ICMP_fake_serverport)
			self.comms_socket = server_socket
			self.serverorclient = 0
			self.authenticated = False

			self.communication_initialization()
			self.do_auth()
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
		os.system("echo 0 > /proc/sys/net/ipv4/icmp_echo_ignore_all") #???
		try:
			self.comms_socket.close()
		except:
			pass
		try:
			os.close(self.tunnel)
		except:
			pass




