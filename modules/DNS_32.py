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
from support.dns_proto import DNS_Client

#iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -o xfl0 -j TCPMSS --set-mss 112
class DNS_32(UDP_generic.UDP_generic):

	module_name = "DNS 32"
	module_configname = "DNS_32"
	module_description = """DNS 32
	"""

	def __init__(self):
		super(DNS_32, self).__init__()
		self.DNS_common = DNS_common()
		self.DNS_proto = DNS_Proto()
		
		self.zone = []
		self.DNS_query_timeout = 1.0
		self.select_timeout = 1.0
		self.lost_expiry = 20
		self.qpacket_number = 0

		self.afragments = {}
		
		self.alast_fragments = {}
		self.qMTU = 130 - 3
		self.old_packet_number = 0
		self.next_userid = 0
		self.userid = 0
		self.recordtype = "A"
		self.encoding_class = encoding.Base32()
		self.encoding_needed = True

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

	def auth_ok_setup(self, additional_data):
		self.userid = additional_data[1]
		return


	def burn_unanswered_packets(self):
		for c in self.clients:
			expired_num = c.get_query_queue().how_many_expired(int(time.time() - self.DNS_query_timeout))
			while expired_num:
				(temp, transaction_id, orig_question, addr) = c.get_query_queue().get_an_expired(int(time.time() - self.DNS_query_timeout))
				expired_num -= 1
				packet = self.DNS_proto.build_answer(transaction_id, None, orig_question)
				self.comms_socket.sendto(packet, addr)

		return

	def communication_initialization(self):
		self.clients = []
		# add user 0 to non-user comms
		client_local = DNS_Client()
		self.clients.append(client_local)
		client_local.set_userid(0)
		client_local.set_recordtype("CNAME")
		client_local.set_encoding_class(encoding.Base32())

		return

	def setup_authenticated_client(self, control_message, additional_data):
		addr = additional_data[0] # UDP specific
		client_local = DNS_Client()
		common.init_client_stateless(control_message, addr, client_local, self.packetselector, self.clients)
		self.clients.append(client_local)
		self.packetselector.add_client(client_local)
		if client_local.get_pipe_r() not in self.rlist:
			self.rlist.append(client_local.get_pipe_r())

		self.next_userid = (self.next_userid + 1) % self.DNS_common.get_userid_length()
		additional_data = (additional_data[0], self.next_userid, client_local)
		client_local.set_userid(self.next_userid)
		client_local.set_recordtype("CNAME")
		client_local.set_encoding_class(encoding.Base32())
		client_local.set_encoding_needed(True)

		# moving query to new client
		client_local.get_query_queue().put(common.lookup_client_userid(self.clients, 0).get_query_queue().get())

		self.send(common.CONTROL_CHANNEL_BYTE, common.CONTROL_AUTH_OK, additional_data)

		return

	def remove_authenticated_client(self, additional_data):
		addr = additional_data[0] # UDP specific
		userid = additional_data[1] # UDP specific
		if userid:
			c = common.lookup_client_userid(self.clients, userid)
			if c:
				self.packetselector.delete_client(c)
				self.rlist.remove(c.get_pipe_r())
				common.delete_client_stateless(self.clients, c)

		return

	def do_check(self):
		message, self.check_result = self.checks.check_default_generate_challange()
		self.send(common.CONTROL_CHANNEL_BYTE, common.CONTROL_CHECK+message, (self.server_tuple, 0, None))

		return

	def do_auth(self):
		message = self.auth_module.send_details(self.config.get("Global", "clientip"))
		self.send(common.CONTROL_CHANNEL_BYTE, common.CONTROL_AUTH+message, (self.server_tuple, 0, None))

		return

	def do_logoff(self):
		self.send(common.CONTROL_CHANNEL_BYTE, common.CONTROL_LOGOFF, (self.server_tuple, self.userid, None))

		return

	def do_dummy_packet(self):
		chrset = "abcdefghijklmnopqrstuvwxyz0123456789-"
		random_content = ""
		for i in range(0, 25):
			rpos = random.randint(0,len(chrset)-1)
			random_content += chrset[rpos]

		#random_content = 
		self.send(common.CONTROL_CHANNEL_BYTE, common.CONTROL_DUMMY_PACKET + random_content, (self.server_tuple, self.userid, None))

		return

	def send(self, channel_type, message, additional_data):
		addr = additional_data[0]
		userid = additional_data[1]
		current_client = additional_data[2]

		fragment = ""

		ql = "\x00" # queue length required bytes
		data = ""

		if channel_type == common.CONTROL_CHANNEL_BYTE:
			channel_byte = common.CONTROL_CHANNEL_BYTE
		else:
			channel_byte = common.DATA_CHANNEL_BYTE

		i = 0

		if self.serverorclient:
			# server side
			self.burn_unanswered_packets()

			# creating packet and saving to the queue
			fragment = self.DNS_common.create_fragment_header(ord(channel_byte), current_client.get_apacket_number(), i, 1)+message
			current_client.get_answer_queue().put(fragment)
			current_client.set_apacket_number((current_client.get_apacket_number() + 1) % 0x3FF)

			RRtype = self.DNS_proto.reverse_RR_type(current_client.get_recordtype())
			
			#check answer and query queues, send as many answers as many queries-1 we had
			aq_l = current_client.get_answer_queue().qsize()
			qq_l = current_client.get_query_queue().qsize()
			if (qq_l <= 1) and not common.is_control_channel(channel_type):
				# not enough queries, sorry
				# one should be held back, for requesting more queries.
				return 0
			
			while (qq_l > 2) and (aq_l > 1):
				message = current_client.get_answer_queue().get()
				aq_l -= 1
				qq_l -= 1

				if current_client.get_encoding_needed():
					pre_message = current_client.get_encoding_class().encode(ql+message)
				else:
					pre_message = ql+message

				transformed_message = RRtype[2](self.DNS_common.get_character_from_userid(userid)+self.transform(pre_message, 1))

				(temp, transaction_id, orig_question, addr) = current_client.get_query_queue().get()
				packet = self.DNS_proto.build_answer(transaction_id, [current_client.get_recordtype(), "", transformed_message], orig_question)
				self.comms_socket.sendto(packet, addr)

				pn = self.DNS_common.get_packet_number_from_header(transformed_message[1:3])
				fn = self.DNS_common.get_fragment_number_from_header(transformed_message[1:3])
				common.internal_print("\033[92mDNS packet sent!: {0} - packet number: {1} / fragment: {2}\033[39m".format(len(message), pn, fn), 0, self.verbosity, common.DEBUG)

			# last message to send
			message = current_client.get_answer_queue().get()
			aq_l = current_client.get_answer_queue().qsize()

			pn = self.DNS_common.get_packet_number_from_header(message[0:2])
			fn = self.DNS_common.get_fragment_number_from_header(message[0:2])

			if aq_l < 256:
				ql = chr(aq_l)
			else:
				ql = chr(255)

			if current_client.get_encoding_needed():
				pre_message = current_client.get_encoding_class().encode(ql+message)
			else:
				pre_message = ql+message

			transformed_message = RRtype[2](self.DNS_common.get_character_from_userid(userid)+self.transform(pre_message, 1))
			(temp, transaction_id, orig_question, addr) = current_client.get_query_queue().get()
			packet = self.DNS_proto.build_answer(transaction_id, [current_client.get_recordtype(), "", transformed_message], orig_question)

			common.internal_print("\033[92mDNS packet sent?: {0} - packet number: {1} / fragment: {2}\033[39m\033[39m".format(len(message), pn, fn), 0, self.verbosity, common.DEBUG)
		else:
			# client side
			RRtype = self.DNS_proto.reverse_RR_type_num(self.recordtype)
			
			while len(message) > self.qMTU:
				fragment = ql+self.DNS_common.create_fragment_header(ord(channel_byte), self.qpacket_number, i, 0)+message[0:self.qMTU]
				message = message[self.qMTU:]
				efragment = self.DNS_common.get_character_from_userid(userid)+self.encoding_class.encode(fragment)
				data = ""
				for j in range(0,int(math.ceil(float(len(efragment))/63))):
					data += efragment[j*63:(j+1)*63]+"."
				packet = self.DNS_proto.build_query(int(random.random() * 65535), data, self.hostname, RRtype)
				common.internal_print("\033[92mDNS packet sent_: {0} - packet number: {1} / fragment: {2}\033[39m".format(len(fragment), self.qpacket_number, i), 0, self.verbosity, common.DEBUG)
				self.comms_socket.sendto(packet, addr)
				i += 1

			fragment = ql+self.DNS_common.create_fragment_header(ord(channel_byte), self.qpacket_number, i, 1)+message[0:self.qMTU]
			efragment = self.DNS_common.get_character_from_userid(userid)+self.encoding_class.encode(fragment)
			data = ""
			for h in range(0,int(math.ceil(float(len(efragment))/63))):
				data += efragment[h*63:(h+1)*63]+"."

			packet = self.DNS_proto.build_query(int(random.random() * 65535), data, self.hostname, RRtype)
			common.internal_print("\033[92mDNS packet sent: {0} - packet number: {1} / fragment: {2}\033[39m".format(len(fragment), self.qpacket_number, i), 0, self.verbosity, common.DEBUG)		
			self.qpacket_number = (self.qpacket_number + 1) % 0x3FF
					
		return self.comms_socket.sendto(packet, addr)

	def recv(self):
		raw_message = ""
		raw_message, addr = self.comms_socket.recvfrom(4096, socket.MSG_PEEK) # WUT TODO

		if len(raw_message) == 0:
			# this cannot really happen, if it does we just ignore it.
			if self.serverorclient:
				common.internal_print("WTF? Client lost. Closing down thread.", -1)
			else:
				common.internal_print("WTF? Server lost. Closing down.", -1)

			return ("", None, 0, 0)

		# basic check to see if it looks like a proper DNS message
		if not self.DNS_proto.is_valid_dns(raw_message, self.hostname):
			raw_message2, addr2 = self.comms_socket.recvfrom(len(raw_message))
			common.internal_print("Invalid DNS packet received", -1)

			return ("", None, 0, 0)

		# this should be a valid message, parse to get the important parts
		(transaction_id, queryornot, short_hostname, qtype, orig_question, answer_data, total_length) = self.DNS_proto.parse_dns(raw_message, self.hostname)
		# it was parsed, we know the corrent length, let's get it from the buffer
		# and leave the rest there
		raw_message2, addr2 = self.comms_socket.recvfrom(total_length)
		if transaction_id == None:
			common.internal_print("Malformed DNS packet received", -1)

			return ("", None, 0, 0)

		# server should receive queries, client should receive answers only
		if (self.serverorclient and not queryornot) or (not self.serverorclient and queryornot):
			common.internal_print("Server received answer or client received query.", -1)
			return ("", None, 0, 0)

		if self.serverorclient:
			#server side
			# burn packets even when we read, make sure nothing useless staying there
			self.burn_unanswered_packets()

			# can we answer from the zonefile?
			record = self.DNS_proto.get_record(short_hostname, qtype, self.zone)
			if record:
				# yes we can, act like a DNS server.
				answer = self.DNS_proto.build_answer(transaction_id, record, orig_question)
				self.comms_socket.sendto(answer, addr)

				return ("", None, 0, 0)
			else:
				# no zonefile record was found, this must be a tunnel message
				edata = short_hostname.replace(".", "")
				userid = self.DNS_common.get_userid_from_character(edata[0:1])
				current_client = common.lookup_client_userid(self.clients, userid)
				if not current_client:
					# no such client, drop this packet.
					return ("", None, 0, 0)

				edata = edata[1:]
				if len(edata) < 4:
					return ("", None, 0, 0)
				try:
					message = self.encoding_class.decode(edata)
				except:
					return ("", None, 0, 0)

				header = message[1:3]
				packet_number = self.DNS_common.get_packet_number_from_header(header)
				fragment_number = self.DNS_common.get_fragment_number_from_header(header)
				if current_client == None:
					return ("", None, 0, 0)

				if current_client.get_query_queue().is_item(orig_question):
					current_client.get_query_queue().replace(orig_question, (int(time.time()), transaction_id, orig_question, addr))

					return ("", None, 0, 0)

				current_client.get_query_queue().put((int(time.time()), transaction_id, orig_question, addr))
				queue_length = 0

				common.internal_print("\033[33mDNS fragment read1: {0} packet number: {1} / fragment: {2}\033[39m".format(len(message), packet_number, fragment_number), 0, self.verbosity, common.DEBUG)
				if packet_number not in current_client.get_qfragments():
					current_client.get_qfragments()[packet_number] = {}
				current_client.get_qfragments()[packet_number][fragment_number] = message

				if self.DNS_common.is_last_fragment(header):
					current_client.get_qlast_fragments()[packet_number] = fragment_number

				if packet_number in current_client.get_qlast_fragments():
					if len(current_client.get_qfragments()[packet_number])-1 == current_client.get_qlast_fragments()[packet_number]:
						message = message[0:2]
						for i in range(0, len(current_client.get_qfragments()[packet_number])):
							message += current_client.get_qfragments()[packet_number][i][3:]
						del current_client.get_qfragments()[packet_number]
						del current_client.get_qlast_fragments()[packet_number]
					else:
						return ("", None, 0, 0)
				else:
					return ("", None, 0, 0)
		else:
			answer_data = self.DNS_proto.reverse_RR_type(self.recordtype)[3](answer_data)
			userid = self.DNS_common.get_userid_from_character(answer_data[0:1])
			message = answer_data[1:]
			
			if not len(message):
				return ("", None, 0, 0)
			if self.encoding_needed:
				message = self.encoding_class.decode(message)
			header = message[1:3]
			packet_number = self.DNS_common.get_packet_number_from_header(header)
			fragment_number = self.DNS_common.get_fragment_number_from_header(header)

			message = message[0:2]+message[3:]
			common.internal_print("\033[33mDNS fragment read2: {0} packet number: {1} / fragment: {2}\033[39m".format(len(message), packet_number, fragment_number), 0, self.verbosity, common.DEBUG)

		queue_length = ord(message[0:1])
		message = message[1:]

		return message, addr, queue_length, userid

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
					if not self.serverorclient:
						if self.authenticated:
							#if not self.request_resend():
							self.do_dummy_packet()
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
									self.send(common.DATA_CHANNEL_BYTE, readytogo, (None, c.get_userid(), c))
								else:
									common.internal_print("Client not found, strange?!", 0, self.verbosity, common.DEBUG)
									continue

							else:
								if self.authenticated:
									self.send(common.DATA_CHANNEL_BYTE, readytogo, (self.server_tuple, self.userid, None))

					if s is self.comms_socket:
						message, addr, queue_length, userid = self.recv()

						if len(message) == 0:
							continue

						c = None
						if self.serverorclient:
							self.authenticated = False
							c = common.lookup_client_userid(self.clients, userid)
						else:
							if queue_length:
								common.internal_print("sending {0} dummy packets".format(queue_length), 0, self.verbosity, common.DEBUG)
								for i in range(queue_length+1):
									self.do_dummy_packet()

						if common.is_control_channel(message[0:1]):
							if self.controlchannel.handle_control_messages(self, message[len(common.CONTROL_CHANNEL_BYTE):], (addr, userid, c)):
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
			common.internal_print("Starting module: {0} on {1}:{2}".format(self.get_module_name(), self.config.get("Global", "serverbind"), self.serverport))
		
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
