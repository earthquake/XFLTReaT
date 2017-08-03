import sys

if "UDP_generic.py" in sys.argv[0]:
	print "[-] Instead of poking around just try: python xfltreat.py --help"
	sys.exit(-1)

import socket
import time
import select
import os
import struct
import threading

#local files
import Stateless_module
import client
import common

class UDP_generic(Stateless_module.Stateless_module):

	module_name = "UDP generic"
	module_configname = "UDP_generic"
	module_description = """Generic UDP module that can listen on any port.
	This module lacks of any encryption or encoding, which comes to the interface
	goes to the socket back and forth. Northing special.
	"""

	def __init__(self):
		super(UDP_generic, self).__init__()

		return

	def communication_initialization(self):
		self.clients = []

		return

	def do_check(self):
		message, self.check_result = common.check_gen()
		self.send(common.CONTROL_CHANNEL_BYTE, common.CONTROL_CHECK+message, (self.server_tuple))

		return

	def do_auth(self):
		message = common.auth_first_step(self.config.get("Global", "clientip"), self.comms_socket)
		self.send(common.CONTROL_CHANNEL_BYTE, common.CONTROL_AUTH+message, (self.server_tuple))

		return

	def do_logoff(self):
		self.send(common.CONTROL_CHANNEL_BYTE, common.CONTROL_LOGOFF, (self.server_tuple))

		return

	def send(self, type, message, additional_data):
		addr = additional_data
		if type == common.CONTROL_CHANNEL_BYTE:
			transformed_message = self.transform(common.CONTROL_CHANNEL_BYTE+message, 1)
		else:
			transformed_message = self.transform(common.DATA_CHANNEL_BYTE+message, 1)

		common.internal_print("UDP sent: {0}".format(len(transformed_message)), 0, self.verbosity, common.DEBUG)
		
		return self.comms_socket.sendto(struct.pack(">H", len(transformed_message))+transformed_message, addr)

	def recv(self):
		message = ""
		length2b, addr = self.comms_socket.recvfrom(2, socket.MSG_PEEK)

		if len(length2b) == 0:
			if self.serverorclient:
				common.internal_print("WTF? Client lost. Closing down thread.", -1)
			else:
				common.internal_print("WTF? Server lost. Closing down.", -1)

			return ("", None)

		if len(length2b) != 2:
			return ("", None)
		
		length = struct.unpack(">H", length2b)[0]+2
		message, addr = self.comms_socket.recvfrom(length, socket.MSG_TRUNC)
		if (length != len(message)):
			common.internal_print("Error length mismatch", -1)
			return ("", None)

		common.internal_print("UDP read: {0}".format(len(message)-2), 0, self.verbosity, common.DEBUG)

		return message[2:], addr

	def communication(self, is_check):
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

			if (not readable) and is_check:
				raise socket.timeout
			try:
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
								c = common.lookup_client_priv(readytogo, self.clients)
								if c:
									self.send(common.DATA_CHANNEL_BYTE,
										readytogo, ((socket.inet_ntoa(c.get_public_ip_addr()), c.get_public_src_port())))
								else:
									common.internal_print("Client not found, strange?!", 0, self.verbosity, common.DEBUG)
									continue
							else:
								if self.authenticated:
									self.send(common.DATA_CHANNEL_BYTE, readytogo, (self.server_tuple))


					if s is self.comms_socket:
						message, addr = self.recv()
						if len(message) == 0:
							continue

						c = None
						if self.serverorclient:
							self.authenticated = False
							c = common.lookup_client_pub(self.clients, addr)

						if common.is_control_channel(message[0:1]):
							if self.controlchannel.handle_control_messages(self, message[len(common.CONTROL_CHANNEL_BYTE):], (addr)):
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
		server_socket = None
		if not self.sanity_check():
			return 
		try:
			common.internal_print("Starting server: {0} on {1}:{2}".format(self.get_module_name(), self.config.get("Global", "serverbind"), int(self.config.get(self.get_module_configname(), "serverport"))))
		
			server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			whereto = (self.config.get("Global", "serverbind"), int(self.config.get(self.get_module_configname(), "serverport")))
			server_socket.bind(whereto)
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
		if not self.sanity_check():
			return 
		try:
			common.internal_print("Starting client: {0}".format(self.get_module_name()))
			server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			self.server_tuple = (self.config.get("Global", "remoteserverip"), int(self.config.get(self.get_module_configname(), "serverport")))
			self.comms_socket = server_socket
			self.serverorclient = 0
			self.authenticated = False

			self.do_auth()
			self.communication(False)

		except KeyboardInterrupt:
			self.do_logoff()
			self.cleanup()
			raise
		except socket.error:
			self.cleanup()
			raise

		self.cleanup()

		return

	def check(self):
		if not self.sanity_check():
			return 
		try:
			common.internal_print("Checking module on server: {0}".format(self.get_module_name()))

			server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			self.server_tuple = (self.config.get("Global", "remoteserverip"), int(self.config.get(self.get_module_configname(), "serverport")))
			self.comms_socket = server_socket
			self.serverorclient = 0
			self.authenticated = True

			self.do_check()
			self.communication(True)

		except KeyboardInterrupt:
			self.cleanup()
			raise
		except socket.timeout:
			common.internal_print("Checking failed: {0}".format(self.get_module_name()), -1)
		except socket.error:
			self.cleanup()
			raise

		self.cleanup()

		return

	def cleanup(self):
		common.internal_print("Shutting down module: {0}".format(self.get_module_name()))
		try:
			self.comms_socket.close()
		except:
			pass
		try:
			os.close(self.tunnel)
		except:
			pass




