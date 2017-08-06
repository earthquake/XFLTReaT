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
import Queue

#local files
import UDP_generic
from interface import Interface
import client
import common
import encoding
from support.dns_proto import DNS_common
from support.dns_proto import DNS_Proto
from support.dns_proto import DNS_Queue


class DNS_32(UDP_generic.UDP_generic):

	module_name = "DNS 32"
	module_configname = "DNS_32"
	module_description = """DNS 32
	"""

	def __init__(self):
		super(DNS_32, self).__init__()
		self.DNS_common = DNS_common()
		self.DNS_proto = DNS_Proto()
		self.query_queue = DNS_Queue()
		self.cache_queue = DNS_Queue()
		self.to_be_resent_queue = Queue.Queue()
		self.seems_to_be_lost_queue = DNS_Queue()
		self.answer_queue = Queue.Queue()
		self.Encodings = encoding.Encodings()
		self.zone = []
		self.DNS_query_timeout = 4
		self.select_timeout = 2.0
		self.lost_expiry = 20
		self.qpacket_number = 0
		self.apacket_number = 0
		self.qfragments = {}
		self.afragments = {}
		self.qlast_fragments = {}
		self.alast_fragments = {}
		self.qMTU = 130 - 3
		self.aMTU = 353 - 3
		self.old_packet_number = 0

		self.cmh_struct  = {
			# num : [string to look for, function, server(1) or client(0), return on success, return on failure]
			# return value meanings: True  - module continues
			#						 False - module thread terminates
			# in case of Stateless modules, the whole module terminates if the return value is False
			0  : [common.CONTROL_CHECK, 		self.controlchannel.cmh_check_query, 1, True, True],
			1  : [common.CONTROL_CHECK_RESULT, 	self.controlchannel.cmh_check_check, 0, True, False],
			2  : [common.CONTROL_AUTH, 			self.controlchannel.cmh_auth, 1, True, True],
			3  : [common.CONTROL_AUTH_OK, 		self.controlchannel.cmh_auth_ok, 0, True, False],
			4  : [common.CONTROL_AUTH_NOTOK, 	self.controlchannel.cmh_auth_not_ok, 0, True, False],
			5  : [common.CONTROL_LOGOFF, 		self.controlchannel.cmh_logoff, 1, True, False],
			6  : [common.CONTROL_DUMMY_PACKET, 	self.controlchannel.cmh_dummy_packet, 1, True, True],
			7  : [common.CONTROL_RESEND_PACKET, self.controlchannel.cmh_resend_packet, 1, True, True]
		}

		return

	def communication_initialization(self):
		self.clients = []

		return

	def setup_authenticated_client(self, control_message, additional_data):
		addr = additional_data[0] # UDP specific
		client_local = client.Client()
		common.init_client_stateless(control_message, addr, client_local, self.packetselector, self.clients)
		self.clients.append(client_local)
		self.packetselector.add_client(client_local)
		if client_local.get_pipe_r() not in self.rlist:
			self.rlist.append(client_local.get_pipe_r())
		self.send(common.CONTROL_CHANNEL_BYTE, common.CONTROL_AUTH_OK, additional_data)

		return

	def remove_authenticated_client(self, additional_data):
		addr = additional_data[0] # UDP specific
		c = common.lookup_client_pub(self.clients, addr)
		if c:
			self.packetselector.delete_client(c)
			self.rlist.remove(c.get_pipe_r())
			common.delete_client_stateless(self.clients, c)

		return

	def do_check(self):
		message, self.check_result = self.checks.check_default_generate_challange()
		self.send(common.CONTROL_CHANNEL_BYTE, common.CONTROL_CHECK+message, self.server_tuple)

		return

	def do_auth(self):
		message = self.auth_module.send_details(self.config.get("Global", "clientip"))
		self.send(common.CONTROL_CHANNEL_BYTE, common.CONTROL_AUTH+message, self.server_tuple)

		return

	def do_logoff(self):
		self.send(common.CONTROL_CHANNEL_BYTE, common.CONTROL_LOGOFF, self.server_tuple)

		return

	def do_dummy_packet(self):
		chrset = "abcdefghijklmnopqrstuvwxyz0123456789-"
		random_content = ""
		for i in range(0, 25):
			rpos = random.randint(0,len(chrset)-1)
			random_content += chrset[rpos]

		#random_content = 
		self.send(common.CONTROL_CHANNEL_BYTE, common.CONTROL_DUMMY_PACKET + random_content, self.server_tuple)

		return

	def request_resend(self):
		# what is bigger than MTU? should check for size
		# encode like this: xPPP PPP OOOO
		# x if fragments number is 1
		# PPP PPPP 7 bit packet number
		# OOOO optional if x > 1 then fragment number
		# shift, concat values
		if self.seems_to_be_lost_queue.length():
			message = ""
			for i in range(0,self.seems_to_be_lost_queue.length()):
				p = self.seems_to_be_lost_queue.get()
				message += chr(p[0])+chr(p[1])

			print "request sent!"
			self.send(common.CONTROL_CHANNEL_BYTE, common.CONTROL_RESEND_PACKET + message, self.server_tuple)

			return True

		return False

	def parse_missing_packets(self, message):
		# rewrite as in request_resend
		message = message[len(common.CONTROL_RESEND_PACKET):]
		while len(message):
			packet_number = ord(message[0:1])
			fragment_number = ord(message[1:2])
			message = message[2:]
			print (packet_number, fragment_number)
			self.to_be_resent_queue.put((packet_number, fragment_number))

		self.send(None, None, None)

	def send(self, type_, message, additional_data):
		addr = additional_data
		#queue_length = additional_data[1]
		fragment = ""

		ql = "\x00" # queue length required bytes
		data = ""

		'''
		if type == common.CONTROL_CHANNEL_BYTE:
			transformed_message = self.transform(ql+common.CONTROL_CHANNEL_BYTE+message, 1)
		else:
			transformed_message = self.transform(ql+common.DATA_CHANNEL_BYTE+message, 1)
		'''
		if type_ == common.CONTROL_CHANNEL_BYTE:
			channel_byte = common.CONTROL_CHANNEL_BYTE
		else:
			channel_byte = common.DATA_CHANNEL_BYTE

		i = 0
		if self.serverorclient:
			self.query_queue.remove_expired(int(time.time()) - self.DNS_query_timeout)
			self.cache_queue.remove_expired(int(time.time()) - self.lost_expiry)
			if (type_ != None) and (message != None):
				readytogo = message
				while len(readytogo) > self.aMTU:
					fragment = self.DNS_common.create_fragment_header(ord(channel_byte), 0, self.apacket_number, i, 0)+readytogo[0:self.aMTU]
					readytogo = readytogo[self.aMTU:]
					self.answer_queue.put(fragment)
					self.cache_queue.put((int(time.time()), self.apacket_number, i, fragment))
					i += 1
				
				fragment = self.DNS_common.create_fragment_header(ord(channel_byte), 0, self.apacket_number, i, 1)+readytogo[0:]
				self.answer_queue.put(fragment)
				self.cache_queue.put((int(time.time()), self.apacket_number, i, fragment))
				self.apacket_number = (self.apacket_number + 1) % 0x7F

			#print "answer queue length: %d" % self.answer_queue.qsize()
			#aq_l = self.answer_queue.qsize()
			print "TBRQ: %d" % self.to_be_resent_queue.qsize()
			aq_l = self.answer_queue.qsize() + self.to_be_resent_queue.qsize()
			qq_l = self.query_queue.length()
			if (qq_l <= 1) and not common.is_control_channel(type_):
				return 0
			
			#print "(%d > 2) and (%d > 1)" % (qq_l, aq_l)
			while (qq_l > 2) and (aq_l > 1):
				#print "2222"
				if self.to_be_resent_queue.qsize():
					(pn, fn) = self.to_be_resent_queue.get()
					message = self.cache_queue.get_specific(pn, fn)
				else:
					message = self.answer_queue.get()
				aq_l -= 1
				qq_l -= 1

				transformed_message = self.transform(ql+message, 1)
				(temp, transaction_id, orig_question, addr) = self.query_queue.get()
				packet = self.DNS_proto.build_answer(transaction_id, ["NULL", transformed_message], orig_question)
				self.comms_socket.sendto(packet, addr)
				#common.internal_print("DNS packet sent: {0}".format(len(transformed_message)), 0, self.verbosity, common.DEBUG)
				pn = self.DNS_common.get_packet_number_from_header(message[1:3])
				fn = self.DNS_common.get_fragment_number_from_header(message[1:3])
				common.internal_print("DNS packet sent: {0} - packet number: {1} / fragment: {2}".format(len(message), pn, fn), 0, self.verbosity, common.DEBUG)

			if self.to_be_resent_queue.qsize():
				(pn, fn) = self.to_be_resent_queue.get()
				message = self.cache_queue.get_specific(pn, fn)
				print "sending"
				print (pn, fn)
			else:
				message = self.answer_queue.get()

			aq_l = self.answer_queue.qsize() + self.to_be_resent_queue.qsize()
			#print "3333"

			if aq_l < 256:
				ql = chr(aq_l)
			else:
				ql = chr(255)
			transformed_message = self.transform(ql+message, 1)
			(temp, transaction_id, orig_question, addr) = self.query_queue.get()
			packet = self.DNS_proto.build_answer(transaction_id, ["NULL", transformed_message], orig_question)

			pn = self.DNS_common.get_packet_number_from_header(message[1:3])
			fn = self.DNS_common.get_fragment_number_from_header(message[1:3])
			common.internal_print("DNS packet sent: {0} - packet number: {1} / fragment: {2}".format(len(message), pn, fn), 0, self.verbosity, common.DEBUG)
		else:
			RRtype = self.DNS_proto.reverse_RR_type_num("NULL")
			

			#print "sent s= %r" % message
			while len(message) > self.qMTU:
				#print "range(0, int(math.floor((len(message)-1)/float(self.qMTU))) = %d" %  int(math.floor((len(message)-1)/float(self.qMTU)))
				fragment = ql+self.DNS_common.create_fragment_header(ord(channel_byte), 0, self.qpacket_number, i, 0)+message[0:self.qMTU]
				message = message[self.qMTU:]
				efragment = self.Encodings.base64(fragment, True).replace("=", "-")
				data = ""
				for j in range(0,int(math.ceil(float(len(efragment))/63))):
					data += efragment[j*63:(j+1)*63]+"."
				packet = self.DNS_proto.build_query(int(random.random() * 65535), data, self.hostname, RRtype)
				common.internal_print("DNS packet sent_: {0} - packet number: {1} / fragment: {2}".format(len(fragment), self.qpacket_number, i), 0, self.verbosity, common.DEBUG)
				self.comms_socket.sendto(packet, addr)
				i += 1

			fragment = ql+self.DNS_common.create_fragment_header(ord(channel_byte), 0, self.qpacket_number, i, 1)+message[0:self.qMTU]
			efragment = self.Encodings.base64(fragment, True).replace("=", "-")
			data = ""
			for h in range(0,int(math.ceil(float(len(efragment))/63))):
				data += efragment[h*63:(h+1)*63]+"."

			packet = self.DNS_proto.build_query(int(random.random() * 65535), data, self.hostname, RRtype)
			common.internal_print("DNS packet sent: {0} - packet number: {1} / fragment: {2}".format(len(fragment), self.qpacket_number, i), 0, self.verbosity, common.DEBUG)		
			self.qpacket_number = (self.qpacket_number + 1) % 0x7F
					
		return self.comms_socket.sendto(packet, addr)

	def recv(self):
		raw_message = ""
		raw_message, addr = self.comms_socket.recvfrom(4096, socket.MSG_PEEK) # WUT TODO
		#print "%r" % raw_message

		if len(raw_message) == 0:
			if self.serverorclient:
				common.internal_print("WTF? Client lost. Closing down thread.", -1)
			else:
				common.internal_print("WTF? Server lost. Closing down.", -1)

			return ("", None, 0)

		if not self.DNS_proto.is_valid_dns(raw_message, self.hostname):
			raw_message2, addr2 = self.comms_socket.recvfrom(len(raw_message))
			#print "szar : %r" % raw_message 
			#print "szar2: %r" % raw_message2
			common.internal_print("Invalid packet received", -1)

			return ("", None, 0)

		(transaction_id, queryornot, short_hostname, qtype, orig_question, answer_data, total_length) = self.DNS_proto.parse_dns(raw_message, self.hostname)
		raw_message2, addr2 = self.comms_socket.recvfrom(total_length)
		#print "%r" % raw_message
		#print "%r" % raw_message2
		if transaction_id == None:
			common.internal_print("Malformed DNS packet received", -1)

			return ("", None, 0)

		#print "Message read: %d - real length: %d" % (len(raw_message), total_length)

		if (self.serverorclient and not queryornot) or (not self.serverorclient and queryornot):
			common.internal_print("Server received answer or client received query.", -1)
			return ("", None, 0)

		if self.serverorclient:
			record = self.DNS_proto.get_record(short_hostname, qtype, self.zone)
			if record:
				answer = self.DNS_proto.build_answer(transaction_id, record, orig_question)
				self.comms_socket.sendto(answer, addr)

				return ("", None, 0)
			else:
				if self.query_queue.is_item(orig_question):
					common.internal_print("Query received for the same domain, impatient NS?", -1)

					return ("", None, 0)

				edata = short_hostname.replace(".", "").replace("-", "=")
				try:
					message = self.Encodings.base64(edata, False)
				except:
					return ("", None, 0)
				self.query_queue.put((int(time.time()), transaction_id, orig_question, addr))
				queue_length = 0

				header = message[1:3]
				packet_number = self.DNS_common.get_packet_number_from_header(header)
				fragment_number = self.DNS_common.get_fragment_number_from_header(header)
				common.internal_print("DNS fragment read: {0} packet number: {1} / fragment: {2}".format(len(message), packet_number, fragment_number), 0, self.verbosity, common.DEBUG)
				if packet_number not in self.qfragments:
					self.qfragments[packet_number] = {}
				self.qfragments[packet_number][fragment_number] = message

				if self.DNS_common.is_last_fragment(header):
					self.qlast_fragments[packet_number] = fragment_number

				if packet_number in self.qlast_fragments:
					if len(self.qfragments[packet_number])-1 == self.qlast_fragments[packet_number]:
						message = message[0:2]
						for i in range(0, len(self.qfragments[packet_number])):
							message += self.qfragments[packet_number][i][3:]
						del self.qfragments[packet_number]
						del self.qlast_fragments[packet_number]
					else:
						return ("", None, 0)
				else:
					return ("", None, 0)
		else:
			message = answer_data
			if not len(message):
				return ("", None, 0)
			header = message[1:3]
			packet_number = self.DNS_common.get_packet_number_from_header(header)
			fragment_number = self.DNS_common.get_fragment_number_from_header(header)

			if packet_number > (self.old_packet_number + 1):
				for i in range(self.old_packet_number + 1, packet_number):
					if not self.seems_to_be_lost_queue.is_item_full((i, 0)):
						self.seems_to_be_lost_queue.put((i, 0))
			
			if packet_number > self.old_packet_number:
				self.old_packet_number = packet_number

			#print "recv s= %r" % message
			#print self.DNS_common.get_fragment_number_from_header(header)
			#print self.DNS_common.is_last_fragment(header)
			common.internal_print("DNS fragment read: {0} packet number: {1} / fragment: {2}".format(len(message), packet_number, fragment_number), 0, self.verbosity, common.DEBUG)
			
			if packet_number not in self.afragments:
				self.afragments[packet_number] = {}
			self.afragments[packet_number][fragment_number] = message
			self.seems_to_be_lost_queue.remove_specific(packet_number, fragment_number)
			print "TBRQ: %d" % self.seems_to_be_lost_queue.length()

			if self.DNS_common.is_last_fragment(header):
				self.alast_fragments[packet_number] = fragment_number

			if packet_number in self.alast_fragments:
				if len(self.afragments[packet_number])-1 == self.alast_fragments[packet_number]:
					message = message[0:2]
					for i in range(0, len(self.afragments[packet_number])):
						message += self.afragments[packet_number][i][3:]
					del self.afragments[packet_number]
					del self.alast_fragments[packet_number]
					print self.afragments
				else:
					for i in range(0, len(self.afragments[packet_number])):
						if i not in self.afragments[packet_number]:
							self.seems_to_be_lost_queue.put((packet_number, i))
					return ("", None, 0)
			else:
				self.seems_to_be_lost_queue.put((packet_number, fragment_number+1))
				return ("", None, 0)
			#'''

		queue_length = ord(message[0:1])
		#print "queue_length for dummy: %d" % queue_length
		message = message[1:]

		common.internal_print("DNS packet read: {0} packet number: {1}".format(len(message), packet_number), 0, self.verbosity, common.DEBUG)

		return message, addr, queue_length

	def communication(self, is_check):
		self.rlist = [self.comms_socket]
		if not self.serverorclient and self.tunnel:
				self.rlist = [self.tunnel, self.comms_socket]
		wlist = []
		xlist = []

		while not self._stop:
			try:
				readable, writable, exceptional = select.select(self.rlist, wlist, xlist, self.select_timeout)
			except select.error, e:
				print error
				break

			try:
				if not readable:
					if is_check:
						raise socket.timeout
					if self.serverorclient:
						self.send(None, None, None)
						'''
						aq_l = self.answer_queue.qsize()
						qq_l = self.query_queue.length()

						if (qq_l < 2) or (aq_l == 0):
							continue

						while (qq_l > 2) and (aq_l > 1):
							aq_l -= 1
							qq_l -= 1
							readytogo = self.answer_queue.get()
							self.send(common.DATA_CHANNEL_BYTE,
								readytogo, ((socket.inet_ntoa(c.get_public_ip_addr()), c.get_public_src_port())))

						readytogo = self.answer_queue.get()
						aq_l = self.answer_queue.qsize()
						self.send(common.DATA_CHANNEL_BYTE,
							readytogo, ((socket.inet_ntoa(c.get_public_ip_addr()), c.get_public_src_port())))
						'''
					else:
						if self.authenticated:
							if not self.request_resend():
								self.do_dummy_packet()
							common.internal_print("DEBUG: Keep alive sent", 0, self.verbosity, common.DEBUG)
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
								c = self.clients[0]#common.lookup_client_priv(readytogo, self.clients)
								if c:
									self.send(common.DATA_CHANNEL_BYTE,
										readytogo, (socket.inet_ntoa(c.get_public_ip_addr()), c.get_public_src_port()))

								else:
									common.internal_print("Client not found, strange?!", 0, self.verbosity, common.DEBUG)
									continue

							else:
								if self.authenticated:
									self.send(common.DATA_CHANNEL_BYTE, readytogo, self.server_tuple)

					if s is self.comms_socket:
						message, addr, queue_length = self.recv()

						if len(message) == 0:
							continue

						c = None
						if self.serverorclient:
							self.authenticated = False
							if len(self.clients):
								c = self.clients[0]#common.lookup_client_pub(self.clients, addr)
							else:
								c = None
						else:
							if queue_length:
								common.internal_print("sending {0} dummy packets".format(queue_length), 0, self.verbosity, common.DEBUG)
								for i in range(queue_length+1):
									self.do_dummy_packet()

						if common.is_control_channel(message[0:1]):
							if self.controlchannel.handle_control_messages(self, message[len(common.CONTROL_CHANNEL_BYTE):], (addr, 0)):
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
								print "os.write: %r" % message[len(common.CONTROL_CHANNEL_BYTE):] 
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

	def connect(self):
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
