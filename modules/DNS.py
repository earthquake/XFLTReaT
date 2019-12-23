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

if "DNS.py" in sys.argv[0]:
	print("[-] Instead of poking around just try: python xfltreat.py --help")
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
import queue
import string
import binascii

#local files
from modules import UDP_generic
from interface import Interface
import client
import common
import encoding
import encryption
from support.dns_proto import DNS_common
from support.dns_proto import DNS_Proto
from support.dns_proto import DNS_Queue
from support.dns_proto import DNS_Client
from interface import Interface # meh

class DNS(UDP_generic.UDP_generic):

	module_name = "DNS"
	module_configname = "DNS"
	module_description = """DNS module with zone file support, base32, base64 etc.
	"""
	module_os_support = common.OS_LINUX

	def __init__(self):
		super(DNS, self).__init__()
		self.DNS_common = DNS_common()
		self.DNS_proto = DNS_Proto()
		
		self.zone = []
		self.zonefile = None
		self.DNS_query_timeout = 2.05 # going lower than 1.0 could introduce problems ATM
		self.DNS_query_repeat_timeout = 10.0 # remove expired from repeated queue
		self.select_timeout = 1.1
		self.qpacket_number = 0

		self.afragments = {}

		self.alast_fragments = {}
		self.old_packet_number = 0
		self.next_userid = 0
		self.userid = 0
		self.recordtype = "A"
		self.RRtype_num = self.DNS_proto.reverse_RR_type_num(self.recordtype)
		self.upload_encoding_class = encoding.Base32()
		self.download_encoding_class = encoding.Base32()
		self.settings = None

		# autotune match string, length matters because it will be always base32
		self.CONTROL_AUTOTUNE = b"XFLT>ATN"
		self.CONTROL_AUTOTUNE_CLIENT = b"XFLT>ATC"
		self.CONTROL_TUNEME = b"XFLT>TNM"

		self.direct_check = b"XFLT>DIRECT"
		self.direct_result = b"XFLT>DIRECT_YEPP"

		# adding two DNS specific control message handler
		self.cmh_struct[len(self.cmh_struct)] = [self.CONTROL_AUTOTUNE,		self.cmh_autotune, 1, True, True]
		self.cmh_struct[len(self.cmh_struct)] = [self.CONTROL_TUNEME,			self.cmh_tune, 1, True, True]

		# list of encodings for the upstream
		self.upload_encoding_list = {
			0	:	encoding.Base32(),
			1	: 	encoding.Base64_DNS(),
			2	:	encoding.Base91(),
			3	:	encoding.Base128()
		}

		# list of encodings for the downstream
		self.download_encoding_list = {
			0	:	encoding.Base32(),
			1	: 	encoding.Base64_DNS(),
			2	:	encoding.Base128(),
			3	: 	encoding.id()
		}

		# record list must be prioritized: 0 - best ; last - worse
		self.record_list = {
			0	: ["NULL", 1600],		# best option
			1	: ["PRIVATE", 1600],	# second best option
			2	: ["CNAME", 510]
		}

		# creating auto tune prefix
		self.autotune_match = encoding.Base32().encode(self.CONTROL_AUTOTUNE)[:-1]

		return

	def set_mtu_ugly(self, cap):
		# sorry about this, this is a hack
		# no better solution till the custom fragmentation is not implemented
		interface = Interface()
		interface.set_mtu(self.config.get("Global", "clientif"), cap)
		cap -= 40 # IP+TCP
		os.system("iptables -t mangle -F")
		os.system("iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -o {0} -j TCPMSS --set-mss {1}".format(self.config.get("Global", "clientif"), cap))

		return

	# autotune control message handler
	# this handler answers to the tune requests to find the best bandwidth
	def cmh_autotune(self, module, message, additional_data, cm):
		print(message)
		message = message[len(self.CONTROL_AUTOTUNE)+2:]
		print(message)
		# get tune type, requested record type, length and encoding for crafting the answer
		(query_type, RRtype, length, encode_class) = struct.unpack("<BHHH", message[0:7])
		if self.DNS_proto.get_RR_type(RRtype)[0] == None:
			return True
		
		# extra parameters added to be able to response in the proper way
		additional_data = additional_data + (True, self.download_encoding_list[encode_class], self.DNS_proto.get_RR_type(RRtype)[0])		
		if (query_type == 0) or (query_type == 3):
			# record && downstream length discovery
			message = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length)).encode('ascii')
		if query_type == 1:
			# A record name length discovery
			message = struct.pack("<I", binascii.crc32(message[7:]))
		if query_type == 2:
			# checking download encoding, echoing back request payload
			message = message[7:]

		module.send(common.CONTROL_CHANNEL_BYTE, self.CONTROL_AUTOTUNE_CLIENT+message, additional_data)
		return True

	# tune control message handler
	# client sets the record type and encodings by calling this
	# server side
	def cmh_tune(self, module, message, additional_data, cm):
		c = additional_data[2]
		if c.get_query_queue().qsize():
			(temp, transaction_id, orig_question, addr, requery_count) = c.get_query_queue().get()
			packet = self.DNS_proto.build_answer(transaction_id, None, orig_question)
			self.comms_socket.sendto(packet, addr)
		(record_type, up_encoding, down_encoding, dl) = struct.unpack("<HHHH", message[len(self.CONTROL_TUNEME):])
		c.set_recordtype(self.record_list[record_type][0])
		c.set_upload_encoding_class(self.upload_encoding_list[up_encoding])
		c.set_download_encoding_class(self.download_encoding_list[down_encoding])

		return True

	# client_side
	def post_authentication_client(self, control_message, additional_data):
		self.authenticated = True
		if self.settings:
			self.do_changesettings(additional_data)

		return

	# client side
	def do_changesettings(self, additional_data):
		message = struct.pack("<HHHH", self.settings[4], self.settings[0], self.settings[1], self.settings[3])
		self.send(common.CONTROL_CHANNEL_BYTE, self.CONTROL_TUNEME+message, additional_data)

		if (self.record_list[self.settings[4]][0] == "CNAME"):
			self.recordtype = self.settings[5]
		else:
			self.recordtype = self.record_list[self.settings[4]][0]
		self.RRtype_num = self.DNS_proto.reverse_RR_type_num(self.recordtype)
		self.upload_encoding_class = self.upload_encoding_list[self.settings[0]]
		self.download_encoding_class = self.download_encoding_list[self.settings[1]]

		self.qMTU = self.DNS_proto.reverse_RR_type("A")[4](self.settings[2]-1, self.hostname, 3, self.upload_encoding_class)
		self.set_mtu_ugly(self.DNS_proto.reverse_RR_type(self.recordtype)[4](self.settings[3]-1, "", 3, self.download_encoding_class))

		return

	# function used for autotuning, crafting tune type requests, sending the 
	# packets then checking the answer.
	# return
	# True: if the packet went thru and the answer is correct. Encoding, size
	# 	were correct
	# False: packet failed. Too big or crippled packet, wrong encoding etc.
	def do_autotune_core(self, server_socket, tune_type, upload_length, download_length, upload_encoding, download_encoding, upload_record_type, download_record_type):
		if download_record_type == "CNAME":
			# A or CNAME request for CNAME response
			download_RRtype_num = self.DNS_proto.reverse_RR_type_num(upload_record_type)
		else:
			# X request for X response
			download_RRtype_num = self.DNS_proto.reverse_RR_type_num(download_record_type)
		common.internal_print("Sending requset u-r: {0} d-r: {1} u-e: {2} d-e: {3} u-l: {4} d-l: {5}".format(upload_record_type, download_record_type, self.upload_encoding_list[upload_encoding].get_name(), self.download_encoding_list[download_encoding].get_name(), upload_length, download_length), 0, self.verbosity, common.VERBOSE)

		# prefixing the message with the static key and the encoding type, encoded by base32
		prefix = self.upload_encoding_list[0].encode(self.CONTROL_AUTOTUNE + struct.pack("<H", upload_encoding))
		# requesting tune_type check. Answer should be:
		# download_record_type record type
		# download_length characters long 
		# download_encoding should be used for downstream
		second_prefix = struct.pack("<BHHH", tune_type, self.DNS_proto.reverse_RR_type_num(download_record_type), download_length, download_encoding)

		# 0 - basic record discovery
		if tune_type == 0:
			message = prefix+self.upload_encoding_list[upload_encoding].encode(second_prefix)
			payload = self.DNS_proto.reverse_RR_type(upload_record_type)[2](self.DNS_common.get_character_from_userid(0)+message)

		# 1 - content check with the most famous cryptographically secure hash algorithm (pun intended)
		print(0)
		if tune_type == 1:
			cap = self.DNS_proto.reverse_RR_type(upload_record_type)[4](upload_length-len(prefix), self.hostname, 0, self.upload_encoding_list[upload_encoding])
			
			random_message = bytearray(random.choice(range(128,255)) for _ in range(cap - len(second_prefix)))
			crc = struct.pack("<I", binascii.crc32(random_message))
			message = prefix+self.upload_encoding_list[upload_encoding].encode(second_prefix+random_message)
			print(message)
			payload = self.DNS_proto.reverse_RR_type(upload_record_type)[2](self.DNS_common.get_character_from_userid(0)+message)

		# 2 - content check for encoding
		print(1)
		if tune_type == 2:
			# BIND9 fails to forward response if: Plaintext + pre+postfixed by "."
			#random_message = "."+''.join(random.choice(''.join(chr(x) for x in range(0,255))) for _ in range(upload_length-2))+b"."
			random_message = b"."+bytearray(random.choice(range(0,255)) for _ in range(upload_length-2))+b"."
			message = prefix+self.upload_encoding_list[upload_encoding].encode(second_prefix+random_message)
			payload = self.DNS_proto.reverse_RR_type(upload_record_type)[2](self.DNS_common.get_character_from_userid(0)+message)

		print(2)
		# 3 - capped payload for maximum downstream
		if tune_type == 3:
			cap = self.DNS_proto.reverse_RR_type(upload_record_type)[4](upload_length-len(prefix), self.hostname, 0, self.upload_encoding_list[upload_encoding])
			download_RRtype = self.DNS_proto.reverse_RR_type(download_record_type)
			# calculating the maximum number of bytes that can be transferred with X record type and Y encoding
			cap_length = download_RRtype[4](download_length, "", 0, self.download_encoding_list[download_encoding])
			cap_length -= len(self.CONTROL_AUTOTUNE_CLIENT)+3

			second_prefix = struct.pack("<BHHH", 0, self.DNS_proto.reverse_RR_type_num(download_record_type), cap_length, download_encoding)
			random_message = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(cap - len(second_prefix))).encode('ascii')
			message = prefix+self.upload_encoding_list[upload_encoding].encode(second_prefix+random_message)
			payload = self.DNS_proto.reverse_RR_type(upload_record_type)[2](self.DNS_common.get_character_from_userid(0)+message)

		# building the packet
		packet = self.DNS_proto.build_query(int(random.random() * 65535), payload, self.hostname, download_RRtype_num)

		# packet sent
		server_socket.sendto(packet, self.server_tuple)
		try:
			raw_message, addr = server_socket.recvfrom(4096)
		except socket.timeout:
			common.internal_print("The DNS server did not answer to the request.", -1)
			return False

		# parsing the packet, error message if there is an error
		(transaction_id, queryornot, short_hostname, qtype, orig_question, answer_data, total_length, reason) = self.DNS_proto.parse_dns(raw_message, self.hostname)
		if reason:
			common.internal_print(self.DNS_proto.response_codes[reason], -1, self.verbosity, common.DEBUG)
			return False

		# get payload from the answer
		answer_data = self.DNS_proto.reverse_RR_type(download_record_type)[3](answer_data)
		message = answer_data[1:]
		# decode payload to get the real content
		message = self.download_encoding_list[download_encoding].decode(message)

		# checks for different discovery modes
		if tune_type == 0:
			message = message[len(self.CONTROL_AUTOTUNE_CLIENT)+3:]
			if len(message) != download_length:
				common.internal_print("Request for '{0}' record with '{1}' encoding failed: wrong length".format(download_record_type, self.upload_encoding_list[upload_encoding].get_name()), -1, self.verbosity, common.VERBOSE)
				return False

		if tune_type == 1:
			if crc != message[len(self.CONTROL_AUTOTUNE_CLIENT)+3:]:
				common.internal_print("Request for '{0}' record with '{1}' encoding failed: integrity error".format(upload_record_type, self.upload_encoding_list[upload_encoding].get_name()), -1, self.verbosity, common.VERBOSE)
				return False

		if tune_type == 2:
			message = message[len(self.CONTROL_AUTOTUNE_CLIENT)+3:]
			if message != random_message:
				common.internal_print("Request for '{0}' record with '{1}' encoding failed: message mismatch".format(download_record_type, self.download_encoding_list[download_encoding].get_name()), -1, self.verbosity, common.VERBOSE)
				return False

		if tune_type == 3:
			message = message[len(self.CONTROL_AUTOTUNE_CLIENT)+3:]
			if len(message) != cap_length:
				common.internal_print("Request for '{0}' record with '{1}' encoding failed: wrong capped length".format(download_record_type, self.upload_encoding_list[upload_encoding].get_name()), -1, self.verbosity, common.VERBOSE)
				return False

		common.internal_print("Request succeed: u-r: {0} d-r: {1} u-e: {2} d-e: {3} u-l: {4} d-l: {5}".format(upload_record_type, download_record_type, self.upload_encoding_list[upload_encoding].get_name(), self.download_encoding_list[download_encoding].get_name(), upload_length, download_length), 1, self.verbosity, common.VERBOSE)

		return True

	# Finding the best packet type for maximum bandwith
	# It does the following in this order:
	# 1. Raw connection over udp/53, not over DNS. If this works, then no DNS
	# 	is needed, udp/53 can be used without any overhead, just in raw.
	# 2. Simple, short A record with CNAME response - this is just a test for 
	#	DNS, if this fails then the DNS server is not working or XFL is stopped
	# 3. upstream encoding test. Check with Base32, Base64 etc. Some servers 
	#	are RFC compliant in this, and case insensitives.
	# 4. Testing the maximum encoded upstream length. Some DNS servers does not
	#	like 255 long DNS names.
	# 5. Finding the best record type for downstream, which is NULL. This is in
	#	reverse order. The best comes first. If one is found, that will be used
	# 6. Looking for the best encoding for downstream.
	# 7. Looking for the maximum downstream length.
	def do_autotune(self, server_socket):
		server_socket.settimeout(1)
		
		server_socket.sendto(self.direct_check, self.server_tuple)
		try:
			raw_message, addr = server_socket.recvfrom(4096)
			if len(raw_message) >= len(self.direct_result):
				if raw_message[0:len(self.direct_result)]:
					common.internal_print("Direct connection can be made, please use the UDP Generic module on port 53", -1)
		except socket.timeout:
			pass
		
		server_socket.settimeout(2)

		# check A+CNAME record
		upload_length = 0
		download_length = 30
		upload_encoding = 0
		download_encoding = 0
		upload_record_type = "A"
		download_record_type = "CNAME"
		if self.do_autotune_core(server_socket, 0, upload_length, download_length, upload_encoding, download_encoding, upload_record_type, download_record_type):
			common.internal_print("A record can be used for upstream.", 1)
			A_CNAME = True
			best_upload_record_type = "A"
		else:
			# check CNAME+CNAME record
			upload_length = 0
			download_length = 30
			upload_encoding = 0
			download_encoding = 0
			upload_record_type = "CNAME"
			download_record_type = "CNAME"
			if self.do_autotune_core(server_socket, 0, upload_length, download_length, upload_encoding, download_encoding, upload_record_type, download_record_type):
				common.internal_print("CNAME record can be used for upstream.", 1)
				best_upload_record_type = "CNAME"
			else:
				return False

		# A record encoding test
		best_upload_encoding = 0
		for upload_encoding in self.upload_encoding_list:
			download_encoding = 0
			upload_length = 50
			download_length = 10
			upload_record_type = best_upload_record_type
			download_record_type = "CNAME"
			if self.do_autotune_core(server_socket, 1, upload_length, download_length, upload_encoding, download_encoding, upload_record_type, download_record_type):
				best_upload_encoding = upload_encoding
		
		common.internal_print("Record 'A' with {0} encoding found to be the best for upstream.".format(self.upload_encoding_list[best_upload_encoding].get_name()), 1)


		# A/CNAME length discovery
		# 510 is a stupid hardcoded number for no reason
		l = 0
		m = 510

		best_upload_length = 0
		while True:
			if l == (m - 1):
				length = l
				break
			upload_encoding = best_upload_encoding
			download_encoding = 0
			upload_length = (l + m)/2
			download_length = 0
			upload_record_type = best_upload_record_type
			download_record_type = "CNAME"

			if self.do_autotune_core(server_socket, 1, upload_length, download_length, upload_encoding, download_encoding, upload_record_type, download_record_type):
				l = upload_length
				best_upload_length = upload_length
			else:
				m = upload_length

			if upload_length < 20:
				common.internal_print("Sorry mate, {0} bytes are just too low to do anything... Tunnelling will not be possible over this bandwidth".format(upload_length), -1)
				return False
		
		common.internal_print("Record 'A' with '{0}' encoding can be used with maximum length of {1}".format(self.upload_encoding_list[best_upload_encoding].get_name(), best_upload_length), 1)

		# record discovery
		best_download_record_type = 0
		for r in self.record_list:
			upload_encoding = best_upload_encoding
			download_encoding = 0
			upload_length = 0
			download_length = 50
			upload_record_type = best_upload_record_type
			download_record_type = self.record_list[r][0]
			
			if self.do_autotune_core(server_socket, 0, upload_length, download_length, upload_encoding, download_encoding, upload_record_type, download_record_type):
				best_download_record_type = r
				break

		common.internal_print("Record '{0}' can be used for downstream.".format(self.record_list[best_download_record_type][0]), 1)

		# get best encoding for the best record type
		best_download_encoding = 0
		for download_encoding in self.download_encoding_list:
			# hacky again, but do not use CNAME with plaintext
			if (self.download_encoding_list[best_download_encoding].get_name() == "Plaintext") and (download_record_type == "CNAME"):
				continue
			upload_encoding = best_upload_encoding
			upload_length = 50
			download_length = 50
			upload_record_type = best_upload_record_type
			download_record_type = self.record_list[best_download_record_type][0]
			if self.do_autotune_core(server_socket, 2, upload_length, download_length, upload_encoding, download_encoding, upload_record_type, download_record_type):
				best_download_encoding = download_encoding

		common.internal_print("Record '{0}' can be used with encoding '{1}' for downstream.".format(self.record_list[best_download_record_type][0], self.download_encoding_list[best_download_encoding].get_name()), 1)


		# get max througput
		l = 0
		m = self.record_list[best_download_record_type][1]
		while True:
			if l == m - 1:
				download_length = l
				break

			download_length = (l + m)/2
			upload_encoding = best_upload_encoding
			download_encoding = best_download_encoding
			upload_length = best_upload_length
			upload_record_type = best_upload_record_type
			download_record_type = self.record_list[best_download_record_type][0]
			
			if download_length < 20:
				common.internal_print("Sorry mate, {0} bytes are just too low to do anything... Tunnelling will not be possible over this bandwidth".format(download_length), -1)
				return False

			if self.do_autotune_core(server_socket, 3, upload_length, download_length, upload_encoding, download_encoding, upload_record_type, download_record_type):
				l = download_length
				best_download_length = download_length
			else:
				m = download_length

		common.internal_print("Record '{0}' will be used with encoding '{1}' and length {2} for downstream.".format(self.record_list[best_download_record_type][0], self.download_encoding_list[best_download_encoding].get_name(), best_download_length), 1)

		# save config for maximum bandwidth
		self.settings = (best_upload_encoding, best_download_encoding, best_upload_length, best_download_length, best_download_record_type, best_upload_record_type)

		server_socket.settimeout(0)

		return True

	# if there are more questions than answers, then the DNS server starts to
	# whine after a while. It's better to send back answers with errors.
	def burn_unanswered_packets(self):
		for c in self.clients:
			expired_num = c.get_query_queue().how_many_expired(time.time() - self.DNS_query_timeout)
			while expired_num:
				(temp, transaction_id, orig_question, addr, requery_count) = c.get_query_queue().get_an_expired(time.time() - self.DNS_query_timeout)
				expired_num -= 1
				packet = self.DNS_proto.build_answer(transaction_id, None, orig_question)
				self.comms_socket.sendto(packet, addr)

		return

	# looking for client, based on the userid
	def lookup_client_pub(self, additional_data):
		userid = additional_data[1]

		for c in self.clients:
			if c.get_userid() == userid:
				return c

		return None

	def communication_initialization(self):
		self.clients = []
		# add user 0 to non-user comms
		client_local = DNS_Client()
		self.clients.append(client_local)
		client_local.set_userid(0)
		client_local.set_recordtype("CNAME")
		client_local.set_upload_encoding_class(encoding.Base32())
		client_local.set_download_encoding_class(encoding.Base32())

		return

	def init_client(self, control_message, additional_data):
		addr = additional_data[0]

		client_local = DNS_Client()
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

		self.next_userid = (self.next_userid % (self.DNS_common.get_userid_length() - 1)) + 1
		#!!!additional_data = (additional_data[0], self.next_userid, client_local)
		client_local.set_userid(self.next_userid)
		client_local.set_recordtype("CNAME")
		client_local.set_upload_encoding_class(encoding.Base32())
		client_local.set_download_encoding_class(encoding.Base32())

		# moving query to new client
		client_local.get_query_queue().put(self.lookup_client_pub((None, 0)).get_query_queue().get())
		self.clients.append(client_local)

		return

	def modify_additional_data(self, additional_data, serverorclient):
		if serverorclient:
			c = self.lookup_client_pub((None, self.next_userid))
			additional_data = (additional_data[0], self.next_userid, c)
			return additional_data
		else:
			return additional_data

	def post_init_client(self, control_message, additional_data):
		self.userid = additional_data[1]
		super(DNS, self).post_init_client(control_message, additional_data)

	def post_authentication_server(self, control_message, additional_data):
		c = self.lookup_client_pub(additional_data)
		if c.get_initiated():
			c.set_authenticated(True)
			self.packetselector.add_client(c)
			if c.get_pipe_r() not in self.rlist:
				self.rlist.append(c.get_pipe_r())
			return True

		return False

	def remove_initiated_client(self, control_message, additional_data):
		userid = additional_data[1]
		if userid:
			c = self.lookup_client_pub(additional_data)
			if c:
				self.packetselector.delete_client(c)
				if c.get_authenticated():
					self.rlist.remove(c.get_pipe_r())
				self.clients.remove(c)

		return

	def get_client_encryption(self, additional_data):
		if self.serverorclient:
			c = self.lookup_client_pub(additional_data)
			if c and additional_data[1] != 0:
				return c.get_encryption()
			else:
				e = encryption.Encryption_details()
				e.set_module(self.encryption_module)
				return e
		else:
			return self.encryption

	# not sure if this is the right way
	def post_encryption_client(self, control_message, additional_data):
		# ugly delay. Make sure that the key exchange finalized before auth
		time.sleep(0.2)
		if not self.authentication.get_step_count():
			# no encryption
			self.post_authentication_client()
		else:
			# add encryption steps
			self.merge_cmh(self.authentication.get_cmh_struct())
			# get and send encryption initialization message

			message = self.authentication.authentication_init_msg()
			self.send(common.CONTROL_CHANNEL_BYTE, message, self.modify_additional_data(additional_data, 0))
		

		return

	# check request: generating a challenge and sending it to the server
	# in case the answer is that is expected, the targer is a valid server
	def do_check(self):
		message, self.check_result = self.checks.check_default_generate_challenge()
		self.send(common.CONTROL_CHANNEL_BYTE, common.CONTROL_CHECK+message, 
			(self.server_tuple, 0, None))

		return

	# start talking to the server
	# do authentication or encryption first
	def do_hello(self):
		# TODO: maybe change this later to push some more info, not only the 
		# private IP
		message = socket.inet_aton(self.config.get("Global", "clientip"))
		self.send(common.CONTROL_CHANNEL_BYTE, common.CONTROL_INIT+message, 
			 (self.server_tuple, 0, None))

	# Polite signal towards the server to tell that the client is leaving
	# Can be spoofed? if there is no encryption. Who cares?
	def do_logoff(self):
		self.send(common.CONTROL_CHANNEL_BYTE, common.CONTROL_LOGOFF, (self.server_tuple, self.userid, None))

		return

	def do_dummy_packet(self):
		chrset = "abcdefghijklmnopqrstuvwxyz0123456789-"
		random_content = ""
		for i in range(0, 25):
			rpos = random.randint(0,len(chrset)-1)
			random_content += chrset[rpos]

		self.send(common.CONTROL_CHANNEL_BYTE, common.CONTROL_DUMMY_PACKET + random_content, (self.server_tuple, self.userid, None))

		return

	def fragmentnq(self, channel_byte, current_client, message):
		fragment = self.DNS_common.create_fragment_header(channel_byte, current_client.get_apacket_number(), 0, 1)+message
		current_client.get_answer_queue().put(fragment)
		current_client.set_apacket_number((current_client.get_apacket_number() + 1) % 0x3FF)

		return

	def send(self, channel_type, message, additional_data):
		addr = additional_data[0]
		userid = additional_data[1]
		current_client = additional_data[2]

		ql = "\x00" # queue length required bytes
		fragment = ""
		data = ""

		if channel_type == common.CONTROL_CHANNEL_BYTE:
			channel_byte = common.CONTROL_CHANNEL_BYTE
		else:
			channel_byte = common.DATA_CHANNEL_BYTE

		message = self.transform(self.get_client_encryption((None, userid)), message, 1)

		if self.serverorclient:
			# server side
			# answering all expired and unused queries
			self.burn_unanswered_packets()

			# creating packets and saving them to the queue
			self.fragmentnq(ord(channel_byte), current_client, message)

			RRtype = self.DNS_proto.reverse_RR_type(current_client.get_recordtype())
			
			aq_l = current_client.get_answer_queue().qsize()-1
			qq_l = current_client.get_query_queue().qsize()
			if (qq_l > 0) and common.is_control_channel(channel_type):
				message = current_client.get_answer_queue().get_last()

				if aq_l < 256:
					ql = bytes([aq_l])
				else:
					ql = b"\xFF"

				encoding_class = current_client.get_download_encoding_class()
				record_type = current_client.get_recordtype()

				if len(additional_data) == 6:
					encoding_needed = additional_data[3]
					encoding_class = additional_data[4]
					record_type = additional_data[5]
					RRtype = self.DNS_proto.reverse_RR_type(record_type)

				pre_message = encoding_class.encode(ql+message)

				transformed_message = RRtype[2](self.DNS_common.get_character_from_userid(userid)+pre_message)
				(temp, transaction_id, orig_question, addr, requery_count) = current_client.get_query_queue().get()
				packet = self.DNS_proto.build_answer(transaction_id, [record_type, "", transformed_message], orig_question)

				pn = self.DNS_common.get_packet_number_from_header(message[0:2])
				fn = self.DNS_common.get_fragment_number_from_header(message[0:2])
				common.internal_print("DNS packet sent???: {0} - packet number: {1} / fragment: {2}".format(len(message), pn, fn), 0, self.verbosity, common.DEBUG)
				self.comms_socket.sendto(packet, addr)

				return

			#check answer and query queues, send as many answers as many queries-1 we had
			aq_l = current_client.get_answer_queue().qsize()
			qq_l = current_client.get_query_queue().qsize()

			# this must be data, if there is not more than one query cached, then we quit
			if (qq_l <= 1):
				# not enough queries, sorry
				# one should be held back, for requesting more queries.
				return 0
			# TODO control message priority?

			top = 0
			if (qq_l > 1) and (aq_l > 0):
				if (qq_l-aq_l)<2:
					top = qq_l - 1
				else:
					top = aq_l

			for i in range(0, top):
				message = current_client.get_answer_queue().get()
				if i == (top - 1):
					if (aq_l - i - 1) < 256:
						ql = chr(aq_l - i -1)
					else:
						ql = chr(255)

				pre_message = current_client.get_download_encoding_class().encode(ql+message)
				transformed_message = RRtype[2](self.DNS_common.get_character_from_userid(userid)+pre_message)
				(temp, transaction_id, orig_question, addr, requery_count) = current_client.get_query_queue().get()
				packet = self.DNS_proto.build_answer(transaction_id, [current_client.get_recordtype(), "", transformed_message], orig_question)
				self.comms_socket.sendto(packet, addr)

				pn = self.DNS_common.get_packet_number_from_header(message[0:2])
				fn = self.DNS_common.get_fragment_number_from_header(message[0:2])
				common.internal_print("DNS packet sent!: {0} - packet number: {1} / fragment: {2}".format(len(message), pn, fn), 0, self.verbosity, common.DEBUG)
		else:
			i = 0
			# client side
			while len(message) > self.qMTU:
				fragment = ql+self.DNS_common.create_fragment_header(ord(channel_byte), self.qpacket_number, i, 0)+message[0:self.qMTU]
				message = message[self.qMTU:]
				efragment = self.DNS_common.get_character_from_userid(userid)+self.upload_encoding_class.encode(fragment)
				data = ""
				# TODO pack record hostname?
				for j in range(0,int(math.ceil(float(len(efragment))/63.0))):
					data += efragment[j*63:(j+1)*63]+"."
				packet = self.DNS_proto.build_query(int(random.random() * 65535), data, self.hostname, self.RRtype_num)
				common.internal_print("DNS packet sent_: {0} - packet number: {1} / fragment: {2}".format(len(fragment), self.qpacket_number, i), 0, self.verbosity, common.DEBUG)
				self.comms_socket.sendto(packet, addr)
				i += 1

			fragment = ql+self.DNS_common.create_fragment_header(ord(channel_byte), self.qpacket_number, i, 1)+message[0:self.qMTU]
			efragment = self.DNS_common.get_character_from_userid(userid)+self.upload_encoding_class.encode(fragment)
			data = ""
			# TODO pack record hostname?
			for h in range(0,int(math.ceil(float(len(efragment))/63.0))):
				data += efragment[h*63:(h+1)*63]+"."

			packet = self.DNS_proto.build_query(int(random.random() * 65535), data, self.hostname, self.RRtype_num)
			common.internal_print("DNS packet sent: {0} - packet number: {1} / fragment: {2}".format(len(fragment), self.qpacket_number, i), 0, self.verbosity, common.DEBUG)		
			self.qpacket_number = (self.qpacket_number + 1) % 0x3FF

			self.comms_socket.sendto(packet, addr)
					
		return 

	def recv(self):
		raw_message = b""
		raw_message, addr = self.comms_socket.recvfrom(4096, socket.MSG_PEEK)

		if len(raw_message) == 0:
			# this cannot really happen, if it does we just ignore it.
			if self.serverorclient:
				common.internal_print("WTF? Client lost. Closing down thread.", -1)
			else:
				common.internal_print("WTF? Server lost. Closing down.", -1)

			return ("", None, 0, 0)

		# can be accessed directly?
		if len(raw_message) >= len(self.direct_check):
			if raw_message[0:len(self.direct_check)] == self.direct_check:
				raw_message2, addr2 = self.comms_socket.recvfrom(len(self.direct_check))
				common.internal_print("Direct check received.", 0, self.verbosity, common.VERBOSE)
				self.comms_socket.sendto(self.direct_result, addr)

				return ("", None, 0, 0)

		# basic check to see if it looks like a proper DNS message
		if not self.DNS_proto.is_valid_dns(raw_message, self.hostname):
			raw_message2, addr2 = self.comms_socket.recvfrom(len(raw_message))
			common.internal_print("Invalid DNS packet received", -1, self.verbosity, common.DEBUG)

			return ("", None, 0, 0)

		# this should be a valid message, parse to get the important parts
		(transaction_id, queryornot, short_hostname, qtype, orig_question, answer_data, total_length, reason) = self.DNS_proto.parse_dns(raw_message, self.hostname)
		# it was parsed, we know the corrent length, let's get it from the buffer
		# and leave the rest there
		if total_length == None:
			total_length = len(raw_message)
		raw_message2, addr2 = self.comms_socket.recvfrom(total_length)

		if reason:
			common.internal_print(self.DNS_proto.response_codes[reason], -1, self.verbosity, common.DEBUG)
			return ("", None, 0, 0)

		# server should receive queries, client should receive answers only
		if (self.serverorclient and not queryornot) or (not self.serverorclient and queryornot):
			common.internal_print("Server received answer or client received query.", -1)
			return ("", None, 0, 0)

		if self.serverorclient:
			#server side
			# can we answer from the zonefile?
			record = self.DNS_proto.get_record(short_hostname, qtype, self.zone)
			if record:
				# yes we can, act like a DNS server.
				answer = self.DNS_proto.build_answer(transaction_id, record, orig_question)
				self.comms_socket.sendto(answer, addr)

				return ("", None, 0, 0)
			else:
				# no zonefile record was found, this must be a tunnel message
				edata = short_hostname.replace(b".", b"")
				userid = self.DNS_common.get_userid_from_character(edata[0:1])
				print(userid)
				current_client = self.lookup_client_pub((None, userid))
				print(current_client)

				if not current_client:
					# no such client, drop this packet.
					return ("", None, 0, 0)

				# cutting off the first character which is the user auth related data
				edata = edata[1:]
				if len(edata) < 4:
					# way too short, no need to bother
					return ("", None, 0, 0)

				# Saving the query details to be able to answer if the item
				# is already found, we replace it the reason why there is 
				# mutiple queries with the same details is that the DNS 
				# client/server is impatient and thinks that the packet was 
				# lost.
				if current_client.get_query_queue().is_item2(orig_question):
					current_client.get_query_queue().replace_with_increase(orig_question, (time.time(), transaction_id, orig_question, addr, 0))
					# burn packets even when we read, make sure nothing useless staying there
					self.burn_unanswered_packets()

					return ("", None, 0, 0)

				# burn packets even when we read, make sure nothing useless staying there
				self.burn_unanswered_packets()
				# Saving the query's original question to the repeated_queue. 
				# If the same request shows up again, we just ignore it.
				# This is different than the query_queue, because there are 
				# some cases when the DNS server resends a query that was 
				# already answered (TOCTOU maybe?), so the packet would be 
				# duplicated. This was the reason behind an early bug with 
				# ICMP dups.
				current_client.get_repeated_queue().remove_expired(time.time()-self.DNS_query_repeat_timeout)
				if not current_client.get_repeated_queue().is_item1(orig_question):
					current_client.get_repeated_queue().put((time.time(), orig_question))
				else:
					return ("", None, 0, 0)

				# if query details are new, just put them into the queue
				current_client.get_query_queue().put((time.time(), transaction_id, orig_question, addr, 0))

				# dummy check for prefix match
				# if the prefix matches, then this is an autotune test request
				# instead of a real IP packet
				if len(edata) > len(self.autotune_match):
					if edata[0:len(self.autotune_match)] == self.autotune_match:
						prefix = self.upload_encoding_list[0].decode(edata[0:len(self.autotune_match)+4])
						encoding_i = struct.unpack("<H", prefix[-2:])[0]
						postfix = self.upload_encoding_list[encoding_i].decode(edata[len(self.autotune_match)+4:])

						return (common.CONTROL_CHANNEL_BYTE+prefix+postfix, addr, 0, 0)

				try:
					# trying to decode with the client related encoding
					# reason for failing could be:
					# 1. packet corruption by an intermediate DNS server/relay
					# 2. spoofed packet
					# 3. the tune message to upgrade the encoding was lost
					# 4. cannot think any other reasons
					message = current_client.get_upload_encoding_class().decode(edata)
				except:
					return ("", None, 0, 0)

				header = message[1:3]
				packet_number = self.DNS_common.get_packet_number_from_header(header)
				fragment_number = self.DNS_common.get_fragment_number_from_header(header)

				common.internal_print("DNS fragment read1: {0} packet number: {1} / fragment: {2}".format(len(message), packet_number, fragment_number), 0, self.verbosity, common.DEBUG)
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

				message = message[0:2]+self.transform(self.get_client_encryption((None, userid)), message[2:], 0)
		else:
			answer_data = self.DNS_proto.reverse_RR_type(self.recordtype)[3](answer_data)
			userid = self.DNS_common.get_userid_from_character(answer_data[0:1])
			message = answer_data[1:]

			if not len(message):
				return ("", None, 0, 0)

			message = self.download_encoding_class.decode(message)
			header = message[1:3]
			packet_number = self.DNS_common.get_packet_number_from_header(header)
			fragment_number = self.DNS_common.get_fragment_number_from_header(header)

			message = message[0:2]+self.transform(self.get_client_encryption((None, userid)), message[3:], 0)
			common.internal_print("DNS fragment read2: {0} packet number: {1} / fragment: {2}".format(len(message), packet_number, fragment_number), 0, self.verbosity, common.DEBUG)

		queue_length = ord(message[0:1])
		message = message[1:]

		return message, addr, queue_length, userid

	def communication_unix(self, is_check):
		self.rlist = [self.comms_socket]
		unauth_counter = 0.0
		if not self.serverorclient and self.tunnel:
				self.rlist = [self.tunnel, self.comms_socket]
		wlist = []
		xlist = []

		while not self._stop:
			try:
				readable, writable, exceptional = select.select(self.rlist, wlist, xlist, self.select_timeout)
			except select.error as e:
				print(e)
				break

			try:
				if not readable:
					if is_check:
						raise socket.timeout
					if not self.serverorclient:
						# send dummy packets for keep alive, only if 
						# authenticated
						if self.authenticated:
							self.do_dummy_packet()
							common.internal_print("Keep alive sent", 0, self.verbosity, common.DEBUG)
						else:
							# if no answer comes back from the server in 
							# 5 seconds, then just quit
							unauth_counter += 1.0
							if (unauth_counter*self.select_timeout)>5.0:
								common.internal_print("Auth timed out. Is there any rate limit on your DNS?", -1, self.verbosity, common.DEBUG)
								self.stop()
								break
					continue

				for s in readable:
					if (s in self.rlist) and not (s is self.comms_socket):
						message = os.read(s, 4096)
						while True:
							if (len(message) < 4) or (message[0:1] != b"\x45"): #Only care about IPv4
								break
							packetlen = struct.unpack(">H", message[2:4])[0] # IP Total length
							if packetlen > len(message):
								message += os.read(s, 4096)

							readytogo = message[0:packetlen]
							message = message[packetlen:]
							if self.serverorclient:
								c = self.lookup_client_priv(readytogo)
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
							c = self.lookup_client_pub((None, userid))
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
								print("os.write: {0}".format(message[len(common.CONTROL_CHANNEL_BYTE):]))
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
			self.hostname = self.config.get(self.get_module_configname(), "hostname").encode('ascii')
			if not common.is_hostname(self.hostname.decode('ascii')):
				common.internal_print("'hostname' is not a domain name.".format(self.get_module_configname()), -1)

				return False
			if self.hostname[len(self.hostname)-1:] != b".":
				self.hostname += b"."

		if self.config.has_option(self.get_module_configname(), "zonefile"):
			self.zonefile = self.config.get(self.get_module_configname(), "zonefile")
			if not os.path.isfile(self.zonefile):
				common.internal_print("File '{0}' does not exists. Delete 'zonefile' line from config or create file.".format(self.zonefile), -1)

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
		if self.zonefile:
			(hostname, self.ttl, self.zone) = self.DNS_common.parse_zone_file(self.zonefile)
			if hostname and (hostname+b"." != self.hostname):
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
		try:
			common.internal_print("Using nameserver: {0}".format(self.nameserver))
			common.internal_print("Starting client: {0}".format(self.get_module_name()))

			server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			self.server_tuple = (self.nameserver, self.serverport)
			self.comms_socket = server_socket
			self.serverorclient = 0
			self.authenticated = False
			self.qMTU = self.DNS_proto.reverse_RR_type("A")[4](254, self.hostname, 3, self.upload_encoding_class)

			if self.do_autotune(server_socket):
				self.do_hello()
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
		try:
			common.internal_print("Using nameserver: {0}".format(self.nameserver))
			common.internal_print("Checking module on server: {0}".format(self.get_module_name()))

			server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			self.server_tuple = (self.nameserver, self.serverport)
			self.comms_socket = server_socket
			self.serverorclient = 0
			self.authenticated = False
			self.qMTU = self.DNS_proto.reverse_RR_type("A")[4](255, self.hostname, 4, self.upload_encoding_class)

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
		#ugly hack to be removed later
		os.system("iptables -t mangle -F")
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
