import sys

if "DNS_32.py" in sys.argv[0]:
	print "[-] Instead of poking around just try: python xfltreat.py --help"
	sys.exit(-1)

import socket
import time
import select
import os
import struct
import threading
import random
import math
import os.path

#local files
import UDP_generic
from interface import Interface
import client
import common
import encoding
from support.dns_proto import DNS_common
from support.dns_proto import DNS_Proto

class DNS_32(UDP_generic.UDP_generic):

	module_name = "DNS 32"
	module_configname = "DNS_32"
	module_description = """DNS 32
	"""

	def __init__(self):
		super(DNS_32, self).__init__()
		self.DNS_common = DNS_common()
		self.DNS_proto = DNS_Proto()
		self.DNS_transaction_id = int(random.random() * 65535)
		self.Encodings = encoding.Encodings()
		self.zone = []

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
		data = ""
		if type == common.CONTROL_CHANNEL_BYTE:
			transformed_message = self.transform(common.CONTROL_CHANNEL_BYTE+message, 1)
		else:
			transformed_message = self.transform(common.DATA_CHANNEL_BYTE+message, 1)

		if self.serverorclient:
			#self.transaction_id = (self.transaction_id + 1) % 65536
			packet = self.DNS_proto.build_answer(self.transaction_id, ["NULL", transformed_message], self.orig_question)

		else:
			RRtype = self.DNS_proto.reverse_RR_type_num("NULL")
			edata = self.Encodings.base32(transformed_message, True).replace("=", "-")
			for i in range(0,int(math.ceil(float(len(edata))/63))):
				data += edata[i*63:(i+1)*63]+"."

			packet = self.DNS_proto.build_query(int(random.random() * 65535), data, self.hostname, RRtype)

		#return self.comms_socket.sendto(struct.pack(">H", len(transformed_message))+transformed_message, addr)
		#packet = "A&\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00(ABMEMTCUHZAVKVCIEEFASADEAAAAAAAAAA------\x08xfltreat\x04info\x00\x00\n\x00\x01"
		print 1
		print "%r" % packet
		print 2
		print addr

		common.internal_print("DNS packet sent: {0}".format(len(packet)), 0, self.verbosity, common.DEBUG)
		
		return self.comms_socket.sendto(packet, addr)

	def recv(self):
		raw_message = ""
		raw_message, addr = self.comms_socket.recvfrom(65535)#, socket.MSG_PEEK) # WUT TODO

		if len(raw_message) == 0:
			if self.serverorclient:
				common.internal_print("WTF? Client lost. Closing down thread.", -1)
			else:
				common.internal_print("WTF? Server lost. Closing down.", -1)

			return ("", None)

		if not self.DNS_proto.is_valid_dns(raw_message, self.hostname):
			common.internal_print("Invalid packet received", -1)

			return ("", None)

		(transaction_id, queryornot, short_hostname, qtype, orig_question, answer_data, total_length) = self.DNS_proto.parse_dns(raw_message, self.hostname)
		if transaction_id == None:
			common.internal_print("Malformed DNS packet received", -1)

			return ("", None)

		#print "%r" % orig_question
		#print "%r" % answer_data
		#print total_length

		if (self.serverorclient and not queryornot) or (not self.serverorclient and queryornot):
			common.internal_print("Server received answer or client received query.", -1)
			return ("", None)

		if self.serverorclient:
			record = self.DNS_proto.get_record(short_hostname, qtype, self.zone)
			if record:
				answer = self.DNS_proto.build_answer(transaction_id, record, orig_question)
				self.comms_socket.sendto(answer, addr)

				return ("", None)
			else:
				self.transaction_id = transaction_id
				self.orig_question = orig_question
				edata = short_hostname.replace(".", "").replace("-", "=")
				print edata
				message = self.Encodings.base32(edata, False)
				# if NULL, get hostname data, put in queque or return assembled
		else:	
			message = answer_data
			# if NULL, get rdata, return rdata

		'''
		length = struct.unpack(">H", length2b)[0]+2
		message, addr = self.comms_socket.recvfrom(length, socket.MSG_TRUNC)
		if (length != len(message)):
			common.internal_print("Error length mismatch", -1)
			return ("", None)
		'''
		common.internal_print("DNS packet read: {0}".format(len(message)), 0, self.verbosity, common.DEBUG)

		return message, addr

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
						print message
						print addr
						print self.authenticated
						if len(message) == 0:
							continue

						c = None
						if self.serverorclient:
							self.authenticated = False
							c = common.lookup_client_pub(self.clients, addr)
							print c

						if message[0:len(common.CONTROL_CHANNEL_BYTE)] == common.CONTROL_CHANNEL_BYTE:
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
			common.internal_print("'serverport' option is missing from '{0}' section, using default 53/udp".format(self.get_module_configname()))
			self.serverport = 53
		else:
			try:
				self.serverport = int(self.config.get(self.get_module_configname(), "serverport"))
			except:
				common.internal_print("'serverport' is not an integer in '{0}' section".format(self.get_module_configname()), -1)

				return False

		if not self.config.has_option(self.get_module_configname(), "hostname"):
			common.internal_print("'hostname' option is missing from '{0}' section.".format(self.get_module_configname()))
			
			return False
		else:
			self.hostname = self.config.get(self.get_module_configname(), "hostname")
			if not common.is_hostname(self.hostname):
				common.internal_print("'hostname' is not a domain name.".format(self.get_module_configname()), -1)

				return False
			if self.hostname[len(self.hostname)-1:] != ".":
				self.hostname += "."

		if self.config.has_option(self.get_module_configname(), "zonefile"):
			self.zonefile = self.config.get(self.get_module_configname(), "zonefile")
			if not os.path.isfile(self.zonefile):
				common.internal_print("File '{0}'' does not exists. Delete 'zonefile' line from config or create file.".format(self.get_module_configname()), -1)

				return False

		if not self.config.has_option(self.get_module_configname(), "nameserver"):
			self.nameserver = self.DNS_common.get_nameserver()
			if self.nameserver:
				common.internal_print("'nameserver' option is missing from '{0}' section, using system default.".format(self.get_module_configname()))

				return True
			else:
				common.internal_print("'nameserver' option is missing from '{0}' section and could not be determined.".format(self.get_module_configname()), -1)

				return False
		else:
			self.nameserver = self.config.get(self.get_module_configname(), "nameserver")
			if not (common.is_ipv4(self.nameserver) or common.is_ipv6(self.nameserver)):
				common.internal_print("'nameserver' is not an ipv4 or ipv6 address in '{0}' section".format(self.get_module_configname()), -1)

				return False

		return True

	def serve(self):
		server_socket = None
		if not self.sanity_check():
			return 
		if self.zonefile:
			(hostname, self.ttl, self.zone) = self.DNS_common.parse_zone_file(self.zonefile)
			if hostname and (hostname+"." != self.hostname):
				common.internal_print("'hostname' in '{0}' section does not match with the zonefile's origin".format(self.get_module_configname()), -1)
				return
		try:
			common.internal_print("Starting server: {0} on {1}:{2}".format(self.get_module_name(), self.config.get("Global", "serverbind"), self.serverport))
		
			server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			whereto = (self.config.get("Global", "serverbind"), self.serverport)
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

	def client(self):
		if not self.sanity_check():
			return 
		try:
			common.internal_print("Using nameserver: {0}".format(self.nameserver))
			common.internal_print("Starting client: {0}".format(self.get_module_name()))

			server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			self.server_tuple = (self.nameserver, self.serverport)
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
			common.internal_print("Using nameserver: {0}".format(self.nameserver))
			common.internal_print("Checking module on server: {0}".format(self.get_module_name()))

			server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			self.server_tuple = (self.nameserver, self.serverport)
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

	def get_intermediate_hop(self, config):
		if config.has_option(self.get_module_configname(), "nameserver"):
			if common.is_ipv4(config.get(self.get_module_configname(), "nameserver")) or common.is_ipv6(config.get(self.get_module_configname(), "nameserver")):
				remoteserverip = config.get(self.get_module_configname(), "nameserver")

				return remoteserverip
		else:
			remoteserverip = self.DNS_common.get_nameserver()

			return remoteserverip

		return ""
